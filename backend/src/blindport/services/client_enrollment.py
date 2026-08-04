"""Durable, idempotent enrollment of client-controlled mTLS keys."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from sqlalchemy import update
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session

from ..core.ca import get_ca_cert_pem, issue_client_cert_for_public_key
from ..core.models import ClientCredential


class ClientEnrollmentConflictError(ValueError):
    """The request conflicts with the credential already bound to the user."""


@dataclass(frozen=True)
class ClientEnrollment:
    instance_id: str
    generation: int
    ca_cert_pem: str
    client_cert_pem: str
    serial: str
    not_before: datetime
    not_after: datetime
    renew_after: datetime


def _aware(value: datetime) -> datetime:
    """Return a UTC-aware datetime because SQLite drops timezone information."""
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _response(credential: ClientCredential) -> ClientEnrollment:
    return ClientEnrollment(
        instance_id=credential.instance_id,
        generation=credential.generation,
        ca_cert_pem=get_ca_cert_pem(),
        client_cert_pem=credential.client_cert_pem,
        serial=credential.serial,
        not_before=_aware(credential.not_before),
        not_after=_aware(credential.not_after),
        renew_after=_aware(credential.renew_after),
    )


def _load(session: Session, user_id: int) -> ClientCredential | None:
    return session.get(ClientCredential, user_id, populate_existing=True)


def _matches(
    credential: ClientCredential,
    instance_id: str,
    fingerprint: str,
    generation: int,
) -> bool:
    return (
        credential.instance_id == instance_id
        and credential.public_key_fingerprint == fingerprint
        and credential.generation == generation
    )


def _raise_conflict(
    credential: ClientCredential | None,
    instance_id: str,
    fingerprint: str,
    generation: int,
) -> None:
    if credential is None:
        raise ClientEnrollmentConflictError("instance_id is already enrolled")
    if credential.instance_id != instance_id:
        raise ClientEnrollmentConflictError("a different instance_id is already enrolled")
    if credential.public_key_fingerprint != fingerprint:
        raise ClientEnrollmentConflictError("a different public key is already enrolled")
    if generation < credential.generation:
        raise ClientEnrollmentConflictError("generation is stale")
    raise ClientEnrollmentConflictError("generation must advance by exactly one")


def _new_credential(
    user_id: int,
    account_id: UUID,
    instance_id: str,
    fingerprint: str,
    generation: int,
    public_key: Ed25519PublicKey,
) -> ClientCredential:
    issued = issue_client_cert_for_public_key(account_id, UUID(instance_id), public_key)
    renew_after = issued.not_before + (issued.not_after - issued.not_before) * 2 / 3
    now = datetime.now(UTC)
    return ClientCredential(
        user_id=user_id,
        instance_id=instance_id,
        public_key_fingerprint=fingerprint,
        generation=generation,
        client_cert_pem=issued.client_cert_pem,
        serial=f"{issued.serial:x}",
        not_before=issued.not_before,
        not_after=issued.not_after,
        renew_after=renew_after,
        created_at=now,
        updated_at=now,
    )


def enroll_client_certificate(
    session: Session,
    user_id: int,
    account_id: UUID,
    instance_id: str,
    generation: int,
    csr_pem: str,
) -> ClientEnrollment:
    """Enroll or renew one user's credential with retry-safe generation semantics."""
    csr = x509.load_pem_x509_csr(csr_pem.encode("ascii"))
    public_key = csr.public_key()
    if not isinstance(public_key, Ed25519PublicKey):  # schema is the API boundary guard
        raise ValueError("CSR public key must be Ed25519")
    public_bytes = public_key.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    fingerprint = hashlib.sha256(public_bytes).hexdigest()
    current = _load(session, user_id)

    if current is None:
        if generation != 1:
            raise ClientEnrollmentConflictError("first enrollment requires generation 1")
        candidate = _new_credential(
            user_id, account_id, instance_id, fingerprint, generation, public_key
        )
        session.add(candidate)
        try:
            session.commit()
        except IntegrityError:
            session.rollback()
            winner = _load(session, user_id)
            if winner is not None and _matches(winner, instance_id, fingerprint, generation):
                return _response(winner)
            _raise_conflict(winner, instance_id, fingerprint, generation)
        return _response(_load(session, user_id) or candidate)

    if _matches(current, instance_id, fingerprint, generation):
        return _response(current)
    if current.instance_id != instance_id or current.public_key_fingerprint != fingerprint:
        _raise_conflict(current, instance_id, fingerprint, generation)
    if generation != current.generation + 1:
        _raise_conflict(current, instance_id, fingerprint, generation)

    candidate = _new_credential(
        user_id, account_id, instance_id, fingerprint, generation, public_key
    )
    result = session.execute(
        update(ClientCredential)
        .where(
            ClientCredential.user_id == user_id,
            ClientCredential.instance_id == instance_id,
            ClientCredential.public_key_fingerprint == fingerprint,
            ClientCredential.generation == current.generation,
        )
        .values(
            generation=candidate.generation,
            client_cert_pem=candidate.client_cert_pem,
            serial=candidate.serial,
            not_before=candidate.not_before,
            not_after=candidate.not_after,
            renew_after=candidate.renew_after,
            updated_at=candidate.updated_at,
        )
        .execution_options(synchronize_session=False)
    )
    if result.rowcount == 1:
        session.commit()
        winner = _load(session, user_id)
        if winner is None:  # pragma: no cover - the conditional update cannot delete a row
            raise RuntimeError("client credential disappeared")
        return _response(winner)

    session.rollback()
    winner = _load(session, user_id)
    if winner is not None and _matches(winner, instance_id, fingerprint, generation):
        return _response(winner)
    _raise_conflict(winner, instance_id, fingerprint, generation)
