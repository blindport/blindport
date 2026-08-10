"""Payment orchestration with ownership-aware, one-time settlement transitions."""

from __future__ import annotations

import hashlib
import hmac
import math
from datetime import UTC, datetime, timedelta
from urllib.parse import urlencode
from uuid import UUID, uuid4

from sqlalchemy import func, update
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, select

from ..adapters.base import (
    LightningInvoiceState,
    NwcAdapterError,
    NwcLookupState,
    NwcPaymentState,
)
from ..adapters.factory import (
    get_lightning_adapter,
    get_nwc_adapter,
)
from ..config import settings
from ..core.models import (
    AgentOrder,
    BillingTerm,
    DeliveryMode,
    NotificationCategory,
    NotificationKind,
    Payment,
    PaymentMethod,
    PaymentStatus,
    ProductType,
    Subscription,
    SubscriptionStatus,
    User,
)
from . import subscriptions as subs
from .notifications import queue_notification
from .nwc_credentials import decrypt_nwc_credential

_TERMINAL_STATUSES = (
    PaymentStatus.PAID,
    PaymentStatus.EXPIRED,
    PaymentStatus.FAILED,
)
_LND_BACKED_METHODS = (
    PaymentMethod.LIGHTNING,
    PaymentMethod.NWC,
    PaymentMethod.STABLECOIN_SWAP,
)
_DEFINITIVE_PAY_REJECTION_CODES = frozenset(
    {
        "expired",
        "insufficient_balance",
        "payment_failed",
        "quota_exceeded",
        "restricted",
        "unauthorized",
        "unsupported_capability",
        "unsupported_encryption",
    }
)
_RETRY_BLOCKING_ERROR_CODES = frozenset(
    {
        "invalid_preimage",
        "payment_hash_mismatch",
        "preimage_mismatch",
        "settlement_unconfirmed",
    }
)


class DisabledPaymentMethodError(ValueError):
    """The requested payment integration is not enabled by configuration."""


class PaymentProviderError(RuntimeError):
    """A provider operation failed without invalidating durable local state."""


class OpenPaymentConflictError(ValueError):
    """A different payment attempt already owns this subscription's reservation."""

    def __init__(self, payment: Payment) -> None:
        self.payment = payment
        super().__init__(
            f"a {payment.method.value} payment is already {payment.status.value} for this "
            "subscription"
        )


def _utcnow() -> datetime:
    return datetime.now(UTC)


def require_payment_method_enabled(method: PaymentMethod) -> None:
    """Reject disabled payment methods before any provider adapter is called."""
    if not settings.is_payment_method_enabled(method):
        raise DisabledPaymentMethodError(f"payment method {method.value} is disabled")


def _aware(value: datetime | None) -> datetime | None:
    """Return ``value`` as a UTC-aware datetime. SQLite drops timezone info."""
    if value is not None and value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value


def _reload_payment(session: Session, payment_id: int) -> Payment:
    payment = session.get(Payment, payment_id, populate_existing=True)
    if payment is None:  # pragma: no cover - foreign keys prevent normal deletion
        raise RuntimeError("payment disappeared")
    return payment


def _lock_payment(session: Session, payment_id: int) -> Payment:
    payment = session.exec(
        select(Payment)
        .where(Payment.id == payment_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    ).one_or_none()
    if payment is None:  # pragma: no cover - foreign keys prevent normal deletion
        raise RuntimeError("payment disappeared")
    return payment


def _conditional_status_update(
    session: Session,
    payment_id: int,
    expected: PaymentStatus,
    status: PaymentStatus,
    **values: object,
) -> bool:
    result = session.execute(
        update(Payment)
        .where(Payment.id == payment_id, Payment.status == expected)
        .values(status=status, **values)
        .execution_options(synchronize_session=False)
    )
    return result.rowcount == 1


def _expire_payment(session: Session, payment: Payment) -> Payment:
    payment_id = payment.id
    if payment_id is None:
        raise ValueError("payment has no id")
    if not _conditional_status_update(
        session, payment_id, PaymentStatus.PENDING, PaymentStatus.EXPIRED
    ):
        session.rollback()
        return _reload_payment(session, payment_id)
    subscription = session.get(Subscription, payment.subscription_id)
    if subscription is not None:
        subs.release_reservation(session, subscription, payment_id)
    session.commit()
    return _reload_payment(session, payment_id)


def expire_pending_payment(session: Session, payment: Payment) -> Payment:
    """Conditionally expire one pending payment without overwriting newer state."""
    if payment.id is None:
        raise ValueError("payment has no id")
    current = _reload_payment(session, payment.id)
    if current.status != PaymentStatus.PENDING:
        return current
    return _expire_payment(session, current)


def _payment_eligibility_deadline(subscription: Subscription) -> datetime | None:
    deadlines = [
        deadline
        for deadline in (
            _aware(subscription.reservation_expires_at),
            subs.domain_payment_eligibility_deadline(subscription),
        )
        if deadline is not None
    ]
    return min(deadlines) if deadlines else None


def _bounded_invoice_expiry(deadline: datetime | None) -> int | None:
    if deadline is None:
        return None
    remaining = math.floor((deadline - _utcnow()).total_seconds())
    expiry = remaining - settings.PAYMENT_EXPIRY_SAFETY_SECONDS
    if expiry < settings.PAYMENT_MIN_PAYABLE_SECONDS:
        raise ValueError("payment eligibility window is too short to create a payable invoice")
    return expiry


def _local_expiry(deadline: datetime | None, seconds: int) -> datetime:
    expires_at = _utcnow() + timedelta(seconds=seconds)
    return min(expires_at, deadline) if deadline is not None else expires_at


def _lightning_memo(payment: Payment, subscription: Subscription) -> str:
    if payment.method == PaymentMethod.NWC:
        suffix = " NWC auto-pay"
    elif payment.method == PaymentMethod.STABLECOIN_SWAP:
        suffix = " stablecoin swap"
    else:
        suffix = f" {subscription.product.value}"
    return f"Blindport subscription {subscription.public_id}{suffix}"


def stablecoin_markup_sats(base_amount_sats: int) -> int:
    """Return the configured basis-point markup, rounded up to one satoshi."""
    if base_amount_sats <= 0:
        raise ValueError("base payment amount must be positive")
    numerator = base_amount_sats * settings.STABLECOIN_SWAP_MARKUP_BPS
    return (numerator + 9_999) // 10_000


def stablecoin_checkout_url(payment: Payment) -> str | None:
    """Build a Boltz web URL that prefills this payment's BOLT11 destination."""
    if payment.method != PaymentMethod.STABLECOIN_SWAP or not payment.invoice:
        return None
    query = urlencode(
        {
            "sendAsset": settings.STABLECOIN_SWAP_DEFAULT_ASSET,
            "receiveAsset": "LN",
            "destination": payment.invoice,
        }
    )
    return f"{settings.BOLTZ_WEB_URL}/?{query}"


def _invoice_preimage(payment: Payment) -> bytes:
    if not payment.invoice_idempotency_key:
        raise RuntimeError("Lightning payment has no durable invoice identity")
    try:
        identity = UUID(payment.invoice_idempotency_key).bytes
    except ValueError as e:
        raise RuntimeError("Lightning payment has an invalid invoice identity") from e
    return hmac.new(
        settings.lnd_invoice_hmac_key_bytes,
        b"blindport:lnd-invoice:v1:" + identity,
        hashlib.sha256,
    ).digest()


def _stage_lightning_invoice(
    session: Session,
    payment: Payment,
    subscription: Subscription,
    eligibility_deadline: datetime | None,
    invoice_expiry: int | None,
) -> None:
    configured_expiry = (
        settings.STABLECOIN_SWAP_INVOICE_EXPIRY_SECONDS
        if payment.method == PaymentMethod.STABLECOIN_SWAP
        else settings.LND_INVOICE_EXPIRY_SECONDS
    )
    requested_expiry = min(
        configured_expiry,
        invoice_expiry or configured_expiry,
    )
    payment.invoice_idempotency_key = str(uuid4())
    payment.payment_hash = hashlib.sha256(_invoice_preimage(payment)).hexdigest()
    payment.expires_at = _local_expiry(eligibility_deadline, requested_expiry)
    session.add(payment)
    session.commit()


def _bind_invoice(session: Session, payment: Payment, invoice) -> Payment:
    payment_id = payment.id
    if payment_id is None:
        raise ValueError("payment has no id")
    if invoice.payment_hash != payment.payment_hash:
        raise RuntimeError("provider invoice hash does not match payment outbox")
    provider_deadline = _utcnow() + timedelta(seconds=invoice.expires_in_seconds)
    subscription = session.get(Subscription, payment.subscription_id)
    if subscription is None:
        raise RuntimeError("payment subscription disappeared")
    eligibility_deadline = _payment_eligibility_deadline(subscription)
    expires_at = (
        min(provider_deadline, eligibility_deadline)
        if eligibility_deadline is not None
        else provider_deadline
    )
    result = session.execute(
        update(Payment)
        .where(
            Payment.id == payment_id,
            Payment.status == PaymentStatus.PENDING,
            Payment.invoice.is_(None),  # type: ignore[union-attr]
            Payment.payment_hash == invoice.payment_hash,
        )
        .values(invoice=invoice.payment_request, expires_at=expires_at)
        .execution_options(synchronize_session=False)
    )
    if result.rowcount == 1:
        session.commit()
    else:
        session.rollback()
    return _reload_payment(session, payment_id)


def ensure_lightning_invoice(session: Session, payment: Payment) -> Payment:
    """Recover or issue the exact durable LND invoice for a pending payment."""
    if payment.method not in _LND_BACKED_METHODS:
        return payment
    if payment.id is None:
        raise ValueError("payment has no id")
    payment = _reload_payment(session, payment.id)
    if payment.status != PaymentStatus.PENDING or payment.invoice:
        return payment
    # PostgreSQL production replicas must serialize the provider boundary with
    # expiry and binding. SQLite ignores FOR UPDATE and is single-process only.
    payment = _lock_payment(session, payment.id)
    if payment.status != PaymentStatus.PENDING or payment.invoice:
        return payment
    subscription = session.get(Subscription, payment.subscription_id)
    if subscription is None:
        raise RuntimeError("payment subscription disappeared")
    preimage = _invoice_preimage(payment)
    expected_hash = hashlib.sha256(preimage).hexdigest()
    if payment.payment_hash != expected_hash:
        raise RuntimeError("Lightning payment hash does not match durable invoice identity")
    memo = _lightning_memo(payment, subscription)
    deadline = _aware(payment.expires_at)
    remaining = math.floor((deadline - _utcnow()).total_seconds()) if deadline else 0
    adapter = get_lightning_adapter()
    try:
        if remaining <= 0:
            invoice = adapter.lookup_invoice(expected_hash, payment.amount_sats, memo)
            if invoice is None:
                return _expire_payment(session, payment)
        else:
            invoice = adapter.create_or_lookup_invoice(
                payment.amount_sats,
                memo,
                preimage,
                expiry_seconds=remaining,
            )
    except Exception as e:
        raise PaymentProviderError("Lightning invoice provider is unavailable") from e
    return _bind_invoice(session, payment, invoice)


def _release_failed_nwc_payment(
    session: Session,
    payment: Payment,
    error_code: str,
    *,
    require_lease: bool = False,
) -> Payment:
    payment_id = payment.id
    if payment_id is None:
        raise ValueError("payment has no id")
    if payment.payment_hash:
        lnd_state = _lnd_invoice_state(payment)
        if lnd_state == LightningInvoiceState.SETTLED:
            return _finalize_payment(session, payment, PaymentStatus.PENDING)
        if lnd_state == LightningInvoiceState.ACCEPTED:
            return _save_nwc_observation(session, payment, NwcPaymentState.PENDING.value)
    statement = update(Payment).where(
        Payment.id == payment_id, Payment.status == PaymentStatus.PENDING
    )
    if require_lease:
        if payment.nwc_lease_token is None:
            return _reload_payment(session, payment_id)
        statement = statement.where(Payment.nwc_lease_token == payment.nwc_lease_token)
    result = session.execute(
        statement.values(
            status=PaymentStatus.FAILED,
            nwc_state=NwcPaymentState.FAILED.value,
            nwc_error_code=error_code,
            nwc_lease_until=None,
            nwc_lease_token=None,
        ).execution_options(synchronize_session=False)
    )
    if result.rowcount != 1:
        session.rollback()
        return _reload_payment(session, payment_id)
    subscription = session.get(Subscription, payment.subscription_id)
    if subscription is not None:
        subscription.auto_renew = False
        subs.release_reservation(session, subscription, payment_id)
        session.add(subscription)
    session.commit()
    return _reload_payment(session, payment_id)


def _verify_nwc_result(
    session: Session,
    payment: Payment,
    *,
    returned_payment_hash: str | None,
    preimage: str | None,
    fees_paid_msats: int | None,
) -> Payment | None:
    if returned_payment_hash is not None and returned_payment_hash != payment.payment_hash:
        return _save_nwc_observation(
            session, payment, NwcPaymentState.UNKNOWN.value, error_code="payment_hash_mismatch"
        )
    if preimage is not None:
        try:
            preimage_hash = hashlib.sha256(bytes.fromhex(preimage)).hexdigest()
        except ValueError:
            return _save_nwc_observation(
                session, payment, NwcPaymentState.UNKNOWN.value, error_code="invalid_preimage"
            )
        if preimage_hash != payment.payment_hash:
            return _save_nwc_observation(
                session, payment, NwcPaymentState.UNKNOWN.value, error_code="preimage_mismatch"
            )
        payment.nwc_preimage_hash = preimage_hash
    if fees_paid_msats is not None:
        payment.nwc_fees_paid_msats = fees_paid_msats
    return None


def _save_nwc_observation(
    session: Session,
    payment: Payment,
    state: str,
    *,
    error_code: str | None = None,
) -> Payment:
    payment_id = payment.id
    if payment_id is None:
        raise ValueError("payment has no id")
    statement = update(Payment).where(
        Payment.id == payment_id, Payment.status == PaymentStatus.PENDING
    )
    values: dict[str, object] = {
        "nwc_state": state,
        "nwc_error_code": error_code,
        "nwc_last_lookup_at": payment.nwc_last_lookup_at,
        "nwc_preimage_hash": payment.nwc_preimage_hash,
        "nwc_fees_paid_msats": payment.nwc_fees_paid_msats,
    }
    if payment.nwc_lease_token is None:
        statement = statement.where(Payment.nwc_lease_token.is_(None))  # type: ignore[union-attr]
    else:
        statement = statement.where(Payment.nwc_lease_token == payment.nwc_lease_token)
        values.update(nwc_lease_until=None, nwc_lease_token=None)
    result = session.execute(
        statement.values(**values).execution_options(synchronize_session=False)
    )
    if result.rowcount != 1:
        session.rollback()
        return _reload_payment(session, payment_id)
    session.commit()
    return _reload_payment(session, payment_id)


def _nwc_database_clock(session: Session):
    if session.get_bind().dialect.name == "postgresql":
        return func.now()
    return _utcnow()


def _claim_nwc_lease(session: Session, payment: Payment) -> Payment | None:
    payment_id = payment.id
    if payment_id is None:
        raise ValueError("payment has no id")
    now = _nwc_database_clock(session)
    lease_token = uuid4().hex
    result = session.execute(
        update(Payment)
        .where(
            Payment.id == payment_id,
            Payment.status == PaymentStatus.PENDING,
            (Payment.nwc_lease_until.is_(None) | (Payment.nwc_lease_until <= now)),  # type: ignore[union-attr,operator]
        )
        .values(
            nwc_lease_until=now + timedelta(seconds=settings.NWC_PAYMENT_LEASE_SECONDS),
            nwc_lease_token=lease_token,
        )
        .execution_options(synchronize_session=False)
    )
    if result.rowcount != 1:
        session.rollback()
        return None
    session.commit()
    return _reload_payment(session, payment_id)


def _record_nwc_send_attempt(session: Session, payment: Payment) -> Payment | None:
    payment_id = payment.id
    lease_token = payment.nwc_lease_token
    if payment_id is None:
        raise ValueError("payment has no id")
    if lease_token is None:
        return None
    now = _nwc_database_clock(session)
    result = session.execute(
        update(Payment)
        .where(
            Payment.id == payment_id,
            Payment.status == PaymentStatus.PENDING,
            Payment.nwc_lease_token == lease_token,
            Payment.nwc_lease_until > now,  # type: ignore[operator]
            (Payment.nwc_next_attempt_at.is_(None) | (Payment.nwc_next_attempt_at <= now)),  # type: ignore[union-attr,operator]
        )
        .values(
            nwc_attempt_count=Payment.nwc_attempt_count + 1,
            nwc_first_attempt_at=func.coalesce(Payment.nwc_first_attempt_at, now),
            nwc_last_attempt_at=now,
            nwc_next_attempt_at=now
            + timedelta(seconds=settings.NWC_RETRY_BASE_SECONDS * (2**payment.nwc_attempt_count)),
            nwc_state="sending",
            nwc_error_code=None,
        )
        .execution_options(synchronize_session=False)
    )
    if result.rowcount != 1:
        session.rollback()
        return None
    session.commit()
    return _reload_payment(session, payment_id)


def _nwc_user(session: Session, payment: Payment) -> User:
    subscription = session.get(Subscription, payment.subscription_id)
    user = session.get(User, subscription.user_id) if subscription else None
    if user is None:
        raise RuntimeError("payment account disappeared")
    return user


def _lnd_invoice_state(payment: Payment) -> LightningInvoiceState:
    if not payment.payment_hash:
        raise RuntimeError("LND-backed payment has no payment hash")
    try:
        return get_lightning_adapter().invoice_state(payment.payment_hash)
    except Exception as error:
        raise PaymentProviderError("Lightning invoice provider is unavailable") from error


def _reconcile_nwc_payment(session: Session, payment: Payment) -> Payment:
    if payment.method != PaymentMethod.NWC or payment.status != PaymentStatus.PENDING:
        return payment
    if not payment.invoice or not payment.payment_hash:
        return payment

    lnd_state = _lnd_invoice_state(payment)
    if lnd_state == LightningInvoiceState.SETTLED:
        return _finalize_payment(session, payment, PaymentStatus.PENDING)
    if lnd_state == LightningInvoiceState.CANCELED:
        return _release_failed_nwc_payment(session, payment, "lnd_invoice_canceled")
    if lnd_state == LightningInvoiceState.ACCEPTED:
        return _save_nwc_observation(session, payment, NwcPaymentState.PENDING.value)

    last_lookup_at = _aware(payment.nwc_last_lookup_at)
    if (
        payment.nwc_attempt_count > 0
        and last_lookup_at is not None
        and last_lookup_at + timedelta(seconds=settings.NWC_LOOKUP_INTERVAL_SECONDS) > _utcnow()
    ):
        return _reload_payment(session, payment.id)  # type: ignore[arg-type]

    claimed = _claim_nwc_lease(session, payment)
    if claimed is None:
        return _reload_payment(session, payment.id)  # type: ignore[arg-type]
    payment = claimed
    user = _nwc_user(session, payment)
    try:
        nwc_uri = decrypt_nwc_credential(user, payment.nwc_credential_generation)
    except ValueError:
        if payment.nwc_attempt_count == 0:
            return _release_failed_nwc_payment(
                session, payment, "credential_unavailable", require_lease=True
            )
        return _save_nwc_observation(
            session, payment, NwcPaymentState.UNKNOWN.value, error_code="credential_unavailable"
        )
    adapter = get_nwc_adapter()

    if payment.nwc_attempt_count > 0:
        retry_blocked = (
            payment.nwc_state == NwcPaymentState.SETTLED.value
            or payment.nwc_preimage_hash == payment.payment_hash
            or payment.nwc_error_code in _RETRY_BLOCKING_ERROR_CODES
        )
        try:
            lookup = adapter.lookup_invoice(nwc_uri, payment.payment_hash)
        except NwcAdapterError as error:
            payment.nwc_last_lookup_at = _utcnow()
            _save_nwc_observation(
                session, payment, NwcPaymentState.UNKNOWN.value, error_code=error.code
            )
            raise PaymentProviderError("NWC payment lookup is unavailable") from error
        payment.nwc_last_lookup_at = _utcnow()
        invalid = _verify_nwc_result(
            session,
            payment,
            returned_payment_hash=lookup.payment_hash,
            preimage=lookup.preimage,
            fees_paid_msats=lookup.fees_paid_msats,
        )
        if invalid is not None:
            return invalid
        if lookup.state in (NwcLookupState.SETTLED, NwcLookupState.PENDING):
            payment = _save_nwc_observation(session, payment, lookup.state.value)
            if _lnd_invoice_state(payment) == LightningInvoiceState.SETTLED:
                return _finalize_payment(session, payment, PaymentStatus.PENDING)
            return payment
        if lookup.state in (NwcLookupState.UNKNOWN, NwcLookupState.UNSUPPORTED):
            return _save_nwc_observation(session, payment, lookup.state.value)
        if lookup.state not in (NwcLookupState.FAILED, NwcLookupState.NOT_FOUND):
            return _save_nwc_observation(session, payment, NwcPaymentState.UNKNOWN.value)

        if retry_blocked:
            return _save_nwc_observation(
                session,
                payment,
                NwcPaymentState.UNKNOWN.value,
                error_code="settlement_unconfirmed",
            )

        next_attempt = _aware(payment.nwc_next_attempt_at)
        if next_attempt is not None and next_attempt > _utcnow():
            return _save_nwc_observation(session, payment, lookup.state.value)
        if payment.nwc_attempt_count >= settings.NWC_MAX_PAYMENT_ATTEMPTS:
            return _release_failed_nwc_payment(
                session, payment, "attempts_exhausted", require_lease=True
            )

    recorded = _record_nwc_send_attempt(session, payment)
    if recorded is None:
        return _reload_payment(session, payment.id)  # type: ignore[arg-type]
    payment = recorded
    try:
        pay_result = adapter.pay_invoice(nwc_uri, payment.invoice)
    except NwcAdapterError as error:
        if not error.retryable and error.code in _DEFINITIVE_PAY_REJECTION_CODES:
            return _release_failed_nwc_payment(session, payment, error.code, require_lease=True)
        _save_nwc_observation(
            session, payment, NwcPaymentState.UNKNOWN.value, error_code=error.code
        )
        raise PaymentProviderError("NWC payment provider is unavailable") from error
    bind_hash = getattr(adapter, "bind_payment_hash", None)
    if callable(bind_hash):
        bind_hash(payment.invoice, payment.payment_hash)
    invalid = _verify_nwc_result(
        session,
        payment,
        returned_payment_hash=None,
        preimage=pay_result.preimage,
        fees_paid_msats=pay_result.fees_paid_msats,
    )
    if invalid is not None:
        return invalid
    payment = _save_nwc_observation(session, payment, pay_result.state.value)
    if _lnd_invoice_state(payment) == LightningInvoiceState.SETTLED:
        return _finalize_payment(session, payment, PaymentStatus.PENDING)
    return payment


def create_payment(
    session: Session,
    subscription: Subscription,
    method: PaymentMethod,
    billing_term: BillingTerm | None = None,
    agent_order_id: int | None = None,
) -> Payment:
    """Reserve capacity and create one bounded external payment request."""
    require_payment_method_enabled(method)
    subs.reap_expired_domain_claims(session)
    session.refresh(subscription)
    selected_term = billing_term or subscription.billing_term
    if subscription.product == ProductType.IP:
        if subscription.delivery != DeliveryMode.WIREGUARD:
            raise ValueError("Blindport IP is available with WireGuard delivery only")
        if subscription.billing_term != BillingTerm.YEARLY:
            raise ValueError("WireGuard Blindport IP is available with yearly billing only")
        if selected_term != BillingTerm.YEARLY:
            raise ValueError("WireGuard Blindport IP is available with yearly billing only")
    if agent_order_id is not None:
        order = session.get(AgentOrder, agent_order_id)
        if order is None or order.subscription_id != subscription.id:
            raise ValueError("agent order does not belong to the subscription")
        linked = session.exec(
            select(Payment).where(Payment.agent_order_id == agent_order_id)
        ).first()
        if linked is not None:
            if (
                linked.subscription_id != subscription.id
                or linked.method != method
                or linked.billing_term != selected_term
            ):
                raise ValueError("agent order already has an incompatible payment")
            if linked.status == PaymentStatus.PENDING:
                return check_and_settle_payment(session, linked)
            return linked
    existing_payments = session.exec(
        select(Payment).where(
            Payment.subscription_id == subscription.id,
            Payment.status.in_((PaymentStatus.PENDING, PaymentStatus.PROCESSING)),  # type: ignore[union-attr]
        )
    ).all()
    for existing in existing_payments:
        if agent_order_id is not None and existing.agent_order_id != agent_order_id:
            raise ValueError("subscription already has an unrelated open payment")
        if existing.status == PaymentStatus.PROCESSING:
            raise OpenPaymentConflictError(existing)
        existing = check_and_settle_payment(session, existing)
        if existing.status == PaymentStatus.PENDING:
            if existing.method == method and existing.billing_term == selected_term:
                return existing
            raise OpenPaymentConflictError(existing)

    subs.require_product_billing_term(subscription.product, subscription.delivery, selected_term)
    subs.require_billing_term_enabled(selected_term)
    session.exec(
        select(User)
        .where(User.id == subscription.user_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    ).one()
    open_payment_ids = set(
        session.exec(
            select(Payment.id)
            .join(Subscription, Subscription.id == Payment.subscription_id)
            .where(
                Subscription.user_id == subscription.user_id,
                Payment.status.in_((PaymentStatus.PENDING, PaymentStatus.PROCESSING)),  # type: ignore[union-attr]
            )
        ).all()
    )
    reservation_payment_ids = {
        payment_id
        for payment_id in session.exec(
            select(Subscription.reservation_payment_id).where(
                Subscription.user_id == subscription.user_id,
                Subscription.reservation_payment_id.is_not(None),  # type: ignore[union-attr]
            )
        ).all()
        if payment_id is not None
    }
    if len(open_payment_ids | reservation_payment_ids) >= settings.ACCOUNT_MAX_OPEN_PAYMENTS:
        raise subs.AccountLimitError(
            "account has reached the open payment/reservation limit "
            f"({settings.ACCOUNT_MAX_OPEN_PAYMENTS})"
        )

    subs.expire_elapsed_subscriptions(session, [subscription])
    subs.reap_elapsed_resource_holds(session)
    session.refresh(subscription)
    subs.require_domain_payment_ready(subscription)
    if subscription.status == SubscriptionStatus.CANCELLED:
        raise ValueError("cancelled subscription cannot be paid; create a new subscription")

    base_amount_sats = (
        subscription.monthly_price_sats
        if selected_term == BillingTerm.MONTHLY
        else subscription.yearly_price_sats
    )
    markup_sats = (
        stablecoin_markup_sats(base_amount_sats) if method == PaymentMethod.STABLECOIN_SWAP else 0
    )
    payment = Payment(
        subscription_id=subscription.id,  # type: ignore[arg-type]
        agent_order_id=agent_order_id,
        method=method,
        billing_term=selected_term,
        period_days=subs.billing_period_days(selected_term),
        amount_sats=base_amount_sats + markup_sats,
        markup_sats=markup_sats,
        status=PaymentStatus.PENDING,
    )
    session.add(payment)
    try:
        session.flush()
        if payment.id is None:  # pragma: no cover - flush assigns integer primary keys
            raise RuntimeError("payment id was not assigned")
        subs.reserve_subscription_resource(session, subscription, payment.id)
        eligibility_deadline = _payment_eligibility_deadline(subscription)
        invoice_expiry = _bounded_invoice_expiry(eligibility_deadline)

        if method in (PaymentMethod.LIGHTNING, PaymentMethod.STABLECOIN_SWAP):
            _stage_lightning_invoice(
                session, payment, subscription, eligibility_deadline, invoice_expiry
            )
            return ensure_lightning_invoice(session, payment)
        elif method == PaymentMethod.NWC:
            user = session.get(User, subscription.user_id)
            if user is None or not user.has_nwc:
                raise ValueError("user has no NWC wallet configured")
            payment.nwc_credential_generation = user.nwc_generation
            _stage_lightning_invoice(
                session, payment, subscription, eligibility_deadline, invoice_expiry
            )
            payment = ensure_lightning_invoice(session, payment)
            return _reconcile_nwc_payment(session, payment)
        else:  # pragma: no cover - PaymentMethod is exhaustive
            raise ValueError(f"unsupported payment method: {method}")

        session.add(payment)
        session.commit()
    except IntegrityError as e:
        session.rollback()
        if agent_order_id is not None:
            linked = session.exec(
                select(Payment).where(Payment.agent_order_id == agent_order_id)
            ).first()
            if linked is not None:
                if (
                    linked.subscription_id == subscription.id
                    and linked.method == method
                    and linked.billing_term == selected_term
                ):
                    if linked.status == PaymentStatus.PENDING:
                        return check_and_settle_payment(session, linked)
                    return linked
                raise ValueError("agent order already has an incompatible payment") from e
        competing = session.exec(
            select(Payment).where(
                Payment.subscription_id == subscription.id,
                Payment.status.in_((PaymentStatus.PENDING, PaymentStatus.PROCESSING)),  # type: ignore[union-attr]
            )
        ).first()
        if competing is not None:
            if agent_order_id is not None:
                raise ValueError("subscription already has an unrelated open payment") from e
            if (
                competing.status == PaymentStatus.PENDING
                and competing.method == method
                and competing.billing_term == selected_term
            ):
                return check_and_settle_payment(session, competing)
            raise OpenPaymentConflictError(competing) from e
        raise
    except Exception:
        session.rollback()
        raise
    return _reload_payment(session, payment.id)


def _payment_started_before_expiry(payment: Payment, subscription: Subscription) -> bool:
    created_at = _aware(payment.created_at)
    period_end = _aware(subscription.current_period_end)
    return created_at is not None and period_end is not None and created_at <= period_end


def _finalize_payment(
    session: Session,
    payment: Payment,
    expected_status: PaymentStatus,
    **payment_values: object,
) -> Payment:
    """Grant exactly one period using one conditional payment/subscription transaction."""
    payment_id = payment.id
    if payment_id is None:
        raise ValueError("payment has no id")
    paid_at = _utcnow()
    if not _conditional_status_update(
        session,
        payment_id,
        expected_status,
        PaymentStatus.PAID,
        paid_at=paid_at,
        **payment_values,
    ):
        session.rollback()
        return _reload_payment(session, payment_id)

    payment = _reload_payment(session, payment_id)
    if payment.period_days != subs.billing_period_days(payment.billing_term):
        session.rollback()
        raise ValueError("payment billing snapshot has an invalid period")
    if payment.amount_sats <= 0:
        session.rollback()
        raise ValueError("payment billing snapshot has an invalid amount")
    if payment.markup_sats < 0 or payment.markup_sats >= payment.amount_sats:
        session.rollback()
        raise ValueError("payment billing snapshot has an invalid markup")
    subscription = session.get(Subscription, payment.subscription_id, populate_existing=True)
    if subscription is None:
        session.rollback()
        raise RuntimeError("payment subscription disappeared")
    try:
        subs.require_domain_payment_settlement_ready(subscription, payment)
    except Exception:
        session.rollback()
        raise
    subscription.billing_term = payment.billing_term
    is_renewal = subscription.status == SubscriptionStatus.ACTIVE or (
        subscription.product in (ProductType.IP, ProductType.PORT)
        and subscription.resource_quarantined_until is not None
        and subscription.reservation_payment_id is None
        and _payment_started_before_expiry(payment, subscription)
    )
    if is_renewal:
        subs.renew_subscription(session, subscription, payment.period_days)
    else:
        subs.activate_subscription(session, subscription, payment_id, payment.period_days)
    user = session.get(User, subscription.user_id)
    if (
        settings.REMINDER_EMAIL_ENABLED
        and user is not None
        and not user.is_suspended
        and user.has_notification_email
        and subscription.current_period_end is not None
    ):
        kind = (
            NotificationKind.SUBSCRIPTION_RENEWED
            if is_renewal
            else NotificationKind.SUBSCRIPTION_ACTIVATED
        )
        queue_notification(
            session,
            user,
            NotificationCategory.ACCOUNT,
            kind,
            f"payment:{payment_id}:{kind.value}",
            subscription=subscription,
            payment=payment,
            event_at=subscription.current_period_end,
        )
    session.commit()
    return _reload_payment(session, payment_id)


def check_and_settle_payment(session: Session, payment: Payment) -> Payment:
    """Poll provider state before applying local expiry to a pending payment."""
    if payment.method not in _LND_BACKED_METHODS:
        return payment
    # Disabling stablecoin checkout stops new invoice creation, but an invoice
    # already handed to a customer must still settle or expire normally.
    if payment.method != PaymentMethod.STABLECOIN_SWAP:
        require_payment_method_enabled(payment.method)
    if payment.status in _TERMINAL_STATUSES or payment.status == PaymentStatus.PROCESSING:
        return payment

    if payment.method in _LND_BACKED_METHODS:
        payment = ensure_lightning_invoice(session, payment)
        if payment.status != PaymentStatus.PENDING:
            return payment
        if payment.method == PaymentMethod.NWC:
            return _reconcile_nwc_payment(session, payment)

    settled = False
    if payment.method in (PaymentMethod.LIGHTNING, PaymentMethod.STABLECOIN_SWAP):
        try:
            settled = bool(
                payment.payment_hash
                and get_lightning_adapter().is_invoice_paid(payment.payment_hash)
            )
        except Exception as e:
            raise PaymentProviderError("Lightning invoice provider is unavailable") from e
    if settled:
        return _finalize_payment(session, payment, PaymentStatus.PENDING)

    expires_at = _aware(payment.expires_at)
    if expires_at is not None and expires_at <= _utcnow():
        return _expire_payment(session, payment)
    return _reload_payment(session, payment.id)  # type: ignore[arg-type]
