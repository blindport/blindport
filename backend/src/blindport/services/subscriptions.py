"""Subscription lifecycle and scarce relay resource reservations."""

from __future__ import annotations

import secrets
from collections.abc import Callable, Iterable
from datetime import UTC, datetime, timedelta

from loguru import logger
from sqlalchemy import or_, text, update
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, select

from ..config import settings
from ..core.hostnames import canonicalize_hostname
from ..core.models import (
    BillingTerm,
    DeliveryMode,
    NotificationCategory,
    NotificationKind,
    Payment,
    PaymentMethod,
    PaymentStatus,
    ProductType,
    RelayHostnameScope,
    Subscription,
    SubscriptionStatus,
    Transport,
    User,
)
from . import ip_leases
from .allocator import NoCapacityError, ResourceAllocator
from .catalog import require_product_available
from .domain_verification import DomainVerificationResult, DomainVerifier
from .notifications import queue_notification

MONTHLY_PERIOD_DAYS = 30
YEARLY_PERIOD_DAYS = 365
_SCARCE_PRODUCTS = (ProductType.IP, ProductType.PORT)
_TERMINAL_PAYMENT_STATUSES = (
    PaymentStatus.PAID,
    PaymentStatus.EXPIRED,
    PaymentStatus.FAILED,
)


class AccountLimitError(RuntimeError):
    """A durable per-account subscription or payment limit was reached."""


class SubscriptionCancellationConflict(RuntimeError):
    """A pending subscription cannot be cancelled without risking payment loss."""


def billing_period_days(term: BillingTerm) -> int:
    """Return the fixed service period for a supported billing term."""
    return MONTHLY_PERIOD_DAYS if term == BillingTerm.MONTHLY else YEARLY_PERIOD_DAYS


def require_billing_term_enabled(term: BillingTerm) -> None:
    """Keep yearly issuance gated until a migration-first rollout is complete."""
    if term == BillingTerm.YEARLY and not settings.BILLING_YEARLY_ENABLED:
        raise ValueError("yearly billing is not enabled")


def require_product_billing_term(
    product: ProductType,
    delivery: DeliveryMode,
    term: BillingTerm,
) -> None:
    """Enforce product-specific terms independently of HTTP request validation."""
    if product == ProductType.IP:
        if delivery != DeliveryMode.WIREGUARD:
            raise ValueError("Blindport IP is available with WireGuard delivery only")
        if term != BillingTerm.YEARLY:
            raise ValueError("WireGuard Blindport IP is available with yearly billing only")


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _aware(value: datetime | None) -> datetime | None:
    if value is not None and value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value


def domain_challenge_name(domain: str) -> str:
    """Return the stable TXT owner name for a canonical customer domain."""
    name = f"_blindport-challenge.{domain}"
    if len(name) > 253:
        raise ValueError("domain is too long for DNS ownership verification")
    return name


def domain_challenge_value(token: str) -> str:
    return f"blindport-verification={token}"


def wildcard_route_name(domain: str) -> str:
    """Return the DNS wildcard record name for a canonical Relay base domain."""
    name = f"*.{domain}"
    if len(name) > 253:
        raise ValueError("domain is too long for DNS wildcard routing")
    return name


def _validate_wildcard_base_domain(domain: str) -> None:
    if len(domain.split(".")) < 2:
        raise ValueError("wildcard Relay base domain must contain at least two labels")
    if any(
        domain == suffix or suffix.endswith(f".{domain}")
        for suffix in settings.relay_managed_suffixes_list
    ):
        raise ValueError("wildcard Relay base domain cannot equal or contain a managed suffix")


def _is_managed_domain(domain: str) -> bool:
    suffixes = settings.relay_managed_suffixes_list
    if domain in suffixes:
        raise ValueError("managed suffix apex cannot be claimed as a customer domain")
    return any(domain.endswith(f".{suffix}") for suffix in suffixes)


def _domain_claim_ttl(domain_is_managed: bool) -> timedelta:
    seconds = (
        settings.RELAY_MANAGED_DOMAIN_CLAIM_TTL_SECONDS
        if domain_is_managed
        else settings.RELAY_DOMAIN_CLAIM_TTL_SECONDS
    )
    return timedelta(seconds=seconds)


def domain_payment_eligibility_deadline(sub: Subscription) -> datetime | None:
    """Return the last instant at which a Blindport Relay payment may be started."""
    if sub.product != ProductType.RELAY:
        return None
    if sub.status == SubscriptionStatus.PENDING:
        return _aware(sub.domain_claim_expires_at)
    if sub.status == SubscriptionStatus.EXPIRED:
        return _aware(sub.domain_renewal_grace_expires_at)
    if sub.status == SubscriptionStatus.ACTIVE:
        period_end = _aware(sub.current_period_end)
        if period_end is not None:
            return period_end + timedelta(seconds=settings.RELAY_RENEWAL_GRACE_SECONDS)
    return None


def _reconcile_domain_payment(session: Session, payment: Payment) -> Payment:
    # Import at call time because payments owns orchestration and imports this
    # lifecycle module. Keeping the cycle out of module initialization is required.
    from .payments import check_and_settle_payment, expire_pending_payment

    if payment.status == PaymentStatus.PROCESSING:
        return payment
    if payment.method in {
        PaymentMethod.LIGHTNING,
        PaymentMethod.NWC,
        PaymentMethod.STABLECOIN_SWAP,
    }:
        return check_and_settle_payment(session, payment)
    return expire_pending_payment(session, payment)


def reap_expired_domain_claims(session: Session) -> int:
    """Reconcile payments, then cancel elapsed unpaid domain claims and holds."""
    now = _utcnow()

    elapsed_active = session.exec(
        select(Subscription).where(
            Subscription.product == ProductType.RELAY,
            Subscription.status == SubscriptionStatus.ACTIVE,
            or_(
                Subscription.current_period_end.is_(None),  # type: ignore[union-attr]
                Subscription.current_period_end <= now,  # type: ignore[operator]
            ),
        )
    ).all()
    expire_elapsed_subscriptions(session, elapsed_active)

    pending_without_deadlines = session.exec(
        select(Subscription).where(
            Subscription.product == ProductType.RELAY,
            Subscription.status == SubscriptionStatus.PENDING,
            Subscription.domain.is_not(None),  # type: ignore[union-attr]
            Subscription.domain_claim_expires_at.is_(None),  # type: ignore[union-attr]
        )
    ).all()
    initialized = False
    for sub in pending_without_deadlines:
        anchor = _aware(sub.created_at) or _aware(sub.updated_at) or now
        result = session.execute(
            update(Subscription)
            .where(
                Subscription.id == sub.id,
                Subscription.status == SubscriptionStatus.PENDING,
                Subscription.domain.is_not(None),  # type: ignore[union-attr]
                Subscription.domain_claim_expires_at.is_(None),  # type: ignore[union-attr]
            )
            .values(
                domain_claim_expires_at=anchor + _domain_claim_ttl(sub.domain_is_managed),
                updated_at=now,
            )
            .execution_options(synchronize_session=False)
        )
        initialized = result.rowcount == 1 or initialized
    if initialized:
        session.commit()

    # Existing expired rows may predate the explicit renewal deadline. Anchor
    # their hold to the recorded period end (or last lifecycle update), not now.
    expired_without_deadlines = session.exec(
        select(Subscription).where(
            Subscription.product == ProductType.RELAY,
            Subscription.status == SubscriptionStatus.EXPIRED,
            Subscription.domain.is_not(None),  # type: ignore[union-attr]
            Subscription.domain_renewal_grace_expires_at.is_(None),  # type: ignore[union-attr]
        )
    ).all()
    initialized = False
    grace = timedelta(seconds=settings.RELAY_RENEWAL_GRACE_SECONDS)
    for sub in expired_without_deadlines:
        anchor = _aware(sub.current_period_end) or _aware(sub.updated_at) or now
        result = session.execute(
            update(Subscription)
            .where(
                Subscription.id == sub.id,
                Subscription.status == SubscriptionStatus.EXPIRED,
                Subscription.domain.is_not(None),  # type: ignore[union-attr]
                Subscription.domain_renewal_grace_expires_at.is_(None),  # type: ignore[union-attr]
            )
            .values(domain_renewal_grace_expires_at=anchor + grace, updated_at=now)
            .execution_options(synchronize_session=False)
        )
        initialized = result.rowcount == 1 or initialized
    if initialized:
        session.commit()

    release_values = {
        "status": SubscriptionStatus.CANCELLED,
        "domain": None,
        "relay_pool_domain": None,
        "domain_is_managed": False,
        "domain_verification_token": None,
        "domain_verified_at": None,
        "domain_claim_expires_at": None,
        "domain_renewal_grace_expires_at": None,
        "auto_renew": False,
        "upgrade_from_subscription_id": None,
        "upgrade_credit_sats": 0,
        "upgrade_source_period_end": None,
        "updated_at": now,
    }
    candidates = session.exec(
        select(Subscription).where(
            Subscription.product == ProductType.RELAY,
            Subscription.domain.is_not(None),  # type: ignore[union-attr]
            or_(
                (
                    (Subscription.status == SubscriptionStatus.PENDING)
                    & (Subscription.domain_claim_expires_at.is_not(None))  # type: ignore[union-attr]
                    & (Subscription.domain_claim_expires_at <= now)  # type: ignore[operator]
                ),
                (
                    (Subscription.status == SubscriptionStatus.EXPIRED)
                    & (Subscription.domain_renewal_grace_expires_at.is_not(None))  # type: ignore[union-attr]
                    & (Subscription.domain_renewal_grace_expires_at <= now)  # type: ignore[operator]
                ),
            ),
        )
    ).all()
    released = 0
    for sub in candidates:
        open_payment = session.exec(
            select(Payment).where(
                Payment.subscription_id == sub.id,
                Payment.status.in_((PaymentStatus.PENDING, PaymentStatus.PROCESSING)),  # type: ignore[union-attr]
            )
        ).first()
        if open_payment is not None:
            if open_payment.status == PaymentStatus.PROCESSING:
                continue
            try:
                _reconcile_domain_payment(session, open_payment)
            except Exception as e:
                session.rollback()
                logger.warning(
                    "retaining expired Blindport Relay claim {} after payment reconciliation failed: {}",
                    sub.public_id,
                    e,
                )
                continue

        session.expire_all()
        current = session.get(Subscription, sub.id)
        if current is None or current.domain is None:
            continue
        open_payment_exists = (
            select(Payment.id)
            .where(
                Payment.subscription_id == current.id,
                Payment.status.in_((PaymentStatus.PENDING, PaymentStatus.PROCESSING)),  # type: ignore[union-attr]
            )
            .exists()
        )
        if current.status == SubscriptionStatus.PENDING:
            deadline_filter = (
                Subscription.domain_claim_expires_at.is_not(None)  # type: ignore[union-attr]
                & (Subscription.domain_claim_expires_at <= now)  # type: ignore[operator]
            )
        elif current.status == SubscriptionStatus.EXPIRED:
            deadline_filter = (
                Subscription.domain_renewal_grace_expires_at.is_not(None)  # type: ignore[union-attr]
                & (Subscription.domain_renewal_grace_expires_at <= now)  # type: ignore[operator]
            )
        else:
            continue
        result = session.execute(
            update(Subscription)
            .where(
                Subscription.id == current.id,
                Subscription.status == current.status,
                Subscription.domain.is_not(None),  # type: ignore[union-attr]
                deadline_filter,
                ~open_payment_exists,
            )
            .values(**release_values)
            .execution_options(synchronize_session=False)
        )
        if result.rowcount == 1:
            session.commit()
            released += 1
        else:
            session.rollback()
    return released


def require_domain_payment_ready(sub: Subscription) -> None:
    """Reject payment unless a Blindport Relay claim is managed or ownership-verified."""
    if sub.product != ProductType.RELAY:
        return
    if sub.status == SubscriptionStatus.CANCELLED or not sub.domain:
        raise ValueError(
            "Blindport Relay domain expired and was released; create a new subscription"
        )
    deadline = domain_payment_eligibility_deadline(sub)
    if sub.status == SubscriptionStatus.PENDING and (deadline is None or deadline <= _utcnow()):
        raise ValueError("Blindport Relay domain claim expired; create a new subscription")
    if sub.status == SubscriptionStatus.EXPIRED and (deadline is None or deadline <= _utcnow()):
        raise ValueError("Blindport Relay renewal grace expired; create a new subscription")
    if sub.domain_is_managed:
        return
    if sub.domain_verified_at is None:
        raise ValueError("domain ownership must be verified before payment")


def require_domain_payment_settlement_ready(sub: Subscription, payment: Payment) -> None:
    """Validate ownership and that this payment began within domain eligibility."""
    if sub.product != ProductType.RELAY:
        return
    if sub.status == SubscriptionStatus.CANCELLED or not sub.domain:
        raise ValueError(
            "Blindport Relay domain expired and was released; create a new subscription"
        )
    if not sub.domain_is_managed and sub.domain_verified_at is None:
        raise ValueError("domain ownership must be verified before payment")
    deadline = domain_payment_eligibility_deadline(sub)
    created_at = _aware(payment.created_at)
    if deadline is None or created_at is None or created_at > deadline:
        raise ValueError("payment was not created during Blindport Relay domain eligibility")


def verify_subscription_domain(
    session: Session,
    sub: Subscription,
    verifier_factory: Callable[[], DomainVerifier],
    *,
    force: bool = False,
) -> DomainVerificationResult:
    """Verify a custom domain claim, optionally refreshing prior DNS proof."""
    reap_expired_domain_claims(session)
    session.refresh(sub)
    if sub.product != ProductType.RELAY:
        raise ValueError("subscription is not a Blindport Relay subscription")
    deadline = _aware(sub.domain_claim_expires_at)
    if sub.status == SubscriptionStatus.CANCELLED or not sub.domain:
        raise ValueError("domain claim expired; create a new subscription")
    if sub.domain_is_managed:
        return DomainVerificationResult(True, "provider-managed domain requires no DNS proof")
    if sub.domain_verified_at is not None and not force:
        return DomainVerificationResult(True, "domain ownership is already verified")
    if sub.status != SubscriptionStatus.PENDING and not force:
        raise ValueError("domain claim is not pending verification")
    if sub.status == SubscriptionStatus.PENDING and deadline is None:
        raise ValueError("domain claim has no active verification challenge")

    verifier = verifier_factory()
    if sub.relay_hostname_scope == RelayHostnameScope.WILDCARD:
        if not sub.domain_verification_token or not sub.relay_pool_domain:
            raise ValueError("wildcard domain claim has no active verification challenge")
        verification = verifier.verify_txt(
            domain_challenge_name(sub.domain),
            domain_challenge_value(sub.domain_verification_token),
        )
    elif sub.domain_verification_token:
        name = domain_challenge_name(sub.domain)
        expected = domain_challenge_value(sub.domain_verification_token)
        verification = verifier.verify_txt(name, expected)
    elif sub.relay_pool_domain:
        verification = verifier.verify_cname(sub.domain, sub.relay_pool_domain)
    else:
        raise ValueError("domain claim has no active verification challenge")
    if not verification.verified:
        return verification

    now = _utcnow()
    if force and sub.domain_verified_at is not None:
        sub.domain_verified_at = now
        sub.updated_at = now
        session.add(sub)
        session.commit()
        session.refresh(sub)
        return verification
    result = session.execute(
        update(Subscription)
        .where(
            Subscription.id == sub.id,
            Subscription.status == SubscriptionStatus.PENDING,
            Subscription.domain_is_managed.is_(False),  # type: ignore[union-attr]
            Subscription.domain_verified_at.is_(None),  # type: ignore[union-attr]
            Subscription.domain_verification_token == sub.domain_verification_token,
            Subscription.relay_pool_domain == sub.relay_pool_domain,
            Subscription.domain_claim_expires_at > now,  # type: ignore[operator]
        )
        .values(
            domain_verified_at=now,
            domain_verification_token=(
                sub.domain_verification_token
                if sub.relay_hostname_scope == RelayHostnameScope.WILDCARD
                else None
            ),
            updated_at=now,
        )
        .execution_options(synchronize_session=False)
    )
    if result.rowcount != 1:
        session.rollback()
        raise ValueError("domain claim expired before verification completed")
    session.commit()
    session.refresh(sub)
    return verification


def uses_unique_cname_target(sub: Subscription) -> bool:
    """Return whether a custom relay claim uses a generated per-claim target."""
    target = sub.relay_pool_domain
    if not target or "." not in target:
        return False
    label = target.split(".", 1)[0]
    return len(label) == 32 and all(character in "0123456789abcdef" for character in label)


def requires_domain_renewal_verification(sub: Subscription) -> bool:
    """Return whether the customer claim must be checked before a renewal payment."""
    return sub.relay_hostname_scope == RelayHostnameScope.WILDCARD or uses_unique_cname_target(sub)


def _relay_domain_conflict(
    session: Session,
    domain: str,
    scope: RelayHostnameScope,
    *,
    exclude_subscription_id: int | None = None,
) -> bool:
    """Check live Relay claims while the caller holds the custom-domain lock."""
    wildcard_domains = session.exec(
        select(Subscription.domain).where(
            Subscription.product == ProductType.RELAY,
            Subscription.relay_hostname_scope == RelayHostnameScope.WILDCARD,
            Subscription.domain.is_not(None),  # type: ignore[union-attr]
            Subscription.id != exclude_subscription_id,
        )
    ).all()
    live_wildcard_domains = [
        wildcard_domain for wildcard_domain in wildcard_domains if wildcard_domain
    ]
    if scope == RelayHostnameScope.WILDCARD:
        if any(
            wildcard_domain == domain
            or wildcard_domain.endswith(f".{domain}")
            or domain.endswith(f".{wildcard_domain}")
            for wildcard_domain in live_wildcard_domains
        ):
            return True
        return (
            session.exec(
                select(Subscription.id).where(
                    Subscription.product == ProductType.RELAY,
                    Subscription.relay_hostname_scope == RelayHostnameScope.EXACT,
                    Subscription.domain.like(f"%.{domain}"),  # type: ignore[union-attr]
                    Subscription.id != exclude_subscription_id,
                )
            ).first()
            is not None
        )
    return any(domain.endswith(f".{wildcard_domain}") for wildcard_domain in live_wildcard_domains)


def expire_elapsed_subscriptions(
    session: Session,
    subscriptions: Iterable[Subscription],
) -> list[Subscription]:
    """Conditionally revoke elapsed subscriptions and retain bounded resource holds."""
    rows = list(subscriptions)
    now = _utcnow()
    changed = False
    for sub in rows:
        if sub.status != SubscriptionStatus.ACTIVE:
            continue
        period_end = _aware(sub.current_period_end)
        if period_end is not None and period_end > now:
            continue
        values: dict[str, object] = {
            "status": SubscriptionStatus.EXPIRED,
            "reservation_expires_at": None,
            "reservation_payment_id": None,
            "updated_at": now,
        }
        if sub.product in _SCARCE_PRODUCTS and sub.assigned_ip:
            quarantine_seconds = (
                settings.IP_REUSE_QUARANTINE_SECONDS
                if sub.product == ProductType.IP
                else settings.RESOURCE_REUSE_QUARANTINE_SECONDS
            )
            quarantine_until = now + timedelta(seconds=quarantine_seconds)
            values["resource_quarantined_until"] = quarantine_until
        elif sub.product == ProductType.RELAY:
            values["domain_renewal_grace_expires_at"] = (period_end or now) + timedelta(
                seconds=settings.RELAY_RENEWAL_GRACE_SECONDS
            )
        result = session.execute(
            update(Subscription)
            .where(
                Subscription.id == sub.id,
                Subscription.status == SubscriptionStatus.ACTIVE,
                Subscription.current_period_end == sub.current_period_end,
            )
            .values(**values)
            .execution_options(synchronize_session=False)
        )
        if result.rowcount == 1:
            if sub.product == ProductType.IP:
                ip_leases.quarantine(session, sub, quarantine_until)
            user = session.get(User, sub.user_id)
            if (
                settings.REMINDER_EMAIL_ENABLED
                and user is not None
                and not user.is_suspended
                and user.has_notification_email
                and period_end is not None
            ):
                queue_notification(
                    session,
                    user,
                    NotificationCategory.ACCOUNT,
                    NotificationKind.SUBSCRIPTION_EXPIRED,
                    f"subscription:{sub.id}:expired:{period_end.isoformat()}",
                    subscription=sub,
                    event_at=period_end,
                )
            changed = True
    if changed:
        session.commit()
        for sub in rows:
            session.refresh(sub)
    return rows


def create_subscription(
    session: Session,
    user: User,
    product: ProductType,
    domain: str | None = None,
    transport: Transport = Transport.TCP,
    delivery: DeliveryMode = DeliveryMode.FRAMED,
    billing_term: BillingTerm = BillingTerm.MONTHLY,
    relay_hostname_scope: RelayHostnameScope = RelayHostnameScope.EXACT,
    *,
    commit: bool = True,
    reap_domains: bool = True,
    relay_conflict_exclude_subscription_id: int | None = None,
    allow_one_additional_subscription: bool = False,
) -> Subscription:
    """Create a pending subscription, optionally leaving its transaction to the caller."""
    require_product_billing_term(product, delivery, billing_term)
    require_billing_term_enabled(billing_term)
    if transport != Transport.TCP and product != ProductType.PORT:
        raise ValueError("UDP transport is supported only for Blindport Port subscriptions")
    if delivery != DeliveryMode.FRAMED and product != ProductType.IP:
        raise ValueError("WireGuard delivery is supported only for Blindport IP subscriptions")
    if delivery == DeliveryMode.WIREGUARD and not settings.wireguard_enabled:
        raise ValueError("WireGuard Blindport IP delivery is not configured")
    if product == ProductType.RELAY and not domain:
        raise ValueError("domain is required for Blindport Relay subscriptions")
    if relay_hostname_scope != RelayHostnameScope.EXACT and product != ProductType.RELAY:
        raise ValueError(
            "wildcard hostname scope is supported only for Blindport Relay subscriptions"
        )
    domain_is_managed = False
    domain_verification_token = None
    domain_verified_at = None
    domain_claim_expires_at = None
    relay_pool_domain = None
    if product == ProductType.RELAY:
        domain = canonicalize_hostname(domain or "")
        if relay_hostname_scope == RelayHostnameScope.WILDCARD:
            _validate_wildcard_base_domain(domain)
        domain_is_managed = _is_managed_domain(domain)
        if relay_hostname_scope == RelayHostnameScope.WILDCARD and domain_is_managed:
            raise ValueError("wildcard Relay hostnames must use a customer-owned base domain")
        if relay_hostname_scope == RelayHostnameScope.WILDCARD:
            domain_challenge_name(domain)
            wildcard_route_name(domain)
        if reap_domains:
            reap_expired_domain_claims(session)
    else:
        domain = None
        relay_hostname_scope = RelayHostnameScope.EXACT

    if user.id is None:
        raise ValueError("user has no id")
    session.exec(select(User).where(User.id == user.id).with_for_update()).one()
    active_count = len(
        session.exec(
            select(Subscription.id).where(
                Subscription.user_id == user.id,
                Subscription.status != SubscriptionStatus.CANCELLED,
            )
        ).all()
    )
    allowed_subscriptions = settings.ACCOUNT_MAX_NON_CANCELLED_SUBSCRIPTIONS + int(
        allow_one_additional_subscription
    )
    if active_count >= allowed_subscriptions:
        raise AccountLimitError(
            f"account has reached the non-cancelled subscription limit ({allowed_subscriptions})"
        )
    if product == ProductType.RELAY:
        pending_relay_claims = len(
            session.exec(
                select(Subscription.id).where(
                    Subscription.user_id == user.id,
                    Subscription.product == ProductType.RELAY,
                    Subscription.status == SubscriptionStatus.PENDING,
                    Subscription.domain.is_not(None),  # type: ignore[union-attr]
                )
            ).all()
        )
        if pending_relay_claims >= settings.ACCOUNT_MAX_PENDING_RELAY_CLAIMS:
            raise AccountLimitError(
                "account has reached the unpaid Relay claim limit "
                f"({settings.ACCOUNT_MAX_PENDING_RELAY_CLAIMS})"
            )
    if domain_is_managed and session.get_bind().dialect.name == "postgresql":
        # Serialize claims against the operator-configured global cap.
        session.execute(text("SELECT pg_advisory_xact_lock(1886547825)"))
    require_product_available(
        session,
        product,
        delivery=delivery,
        transport=transport,
        domain_is_managed=domain_is_managed,
        relay_hostname_scope=relay_hostname_scope,
    )

    if product == ProductType.RELAY:
        if not domain_is_managed and session.get_bind().dialect.name == "postgresql":
            session.execute(text("SELECT pg_advisory_xact_lock(1886547826)"))
        existing = session.exec(select(Subscription).where(Subscription.domain == domain)).first()
        if existing is not None:
            raise ValueError("domain already has a subscription")
        if _relay_domain_conflict(
            session,
            domain or "",
            relay_hostname_scope,
            exclude_subscription_id=relay_conflict_exclude_subscription_id,
        ):
            raise ValueError("domain conflicts with an existing Relay hostname scope")
        now = _utcnow()
        domain_claim_expires_at = now + _domain_claim_ttl(domain_is_managed)
        if domain_is_managed:
            domain_verified_at = now
        elif relay_hostname_scope == RelayHostnameScope.WILDCARD:
            domain_verification_token = secrets.token_hex(16)
            relay_pool_domain = ResourceAllocator(session).allocate_relay_pool_domain()
        else:
            relay_pool_domain = ResourceAllocator(session).allocate_relay_cname_target()
    monthly = {
        ProductType.IP: 0,
        ProductType.PORT: settings.PORT_MONTHLY_SATS,
        ProductType.RELAY: (
            settings.RELAY_WILDCARD_MONTHLY_SATS
            if relay_hostname_scope == RelayHostnameScope.WILDCARD
            else settings.RELAY_MONTHLY_SATS
        ),
    }[product]
    yearly = {
        ProductType.IP: settings.IP_YEARLY_SATS,
        ProductType.PORT: settings.PORT_YEARLY_SATS,
        ProductType.RELAY: (
            settings.RELAY_WILDCARD_YEARLY_SATS
            if relay_hostname_scope == RelayHostnameScope.WILDCARD
            else settings.RELAY_YEARLY_SATS
        ),
    }[product]
    sub = Subscription(
        user_id=user.id,  # type: ignore[arg-type]
        product=product,
        delivery=delivery,
        status=SubscriptionStatus.PENDING,
        domain=domain,
        relay_hostname_scope=relay_hostname_scope,
        relay_pool_domain=relay_pool_domain,
        domain_is_managed=domain_is_managed,
        domain_verification_token=domain_verification_token,
        domain_verified_at=domain_verified_at,
        domain_claim_expires_at=domain_claim_expires_at,
        transport=transport,
        billing_term=billing_term,
        monthly_price_sats=monthly,
        yearly_price_sats=yearly,
    )
    session.add(sub)
    try:
        if commit:
            session.commit()
        else:
            session.flush()
    except IntegrityError as e:
        session.rollback()
        if domain is not None:
            existing = session.exec(
                select(Subscription).where(Subscription.domain == domain)
            ).first()
            if existing is not None:
                raise ValueError("domain already has a subscription") from e
        raise
    if commit:
        session.refresh(sub)
    return sub


def has_pending_upgrade(session: Session, source: Subscription) -> bool:
    """Return whether an active source is reserved for a pending wildcard upgrade."""
    if source.id is None:
        return False
    return (
        session.exec(
            select(Subscription.id).where(
                Subscription.upgrade_from_subscription_id == source.id,
                Subscription.status == SubscriptionStatus.PENDING,
            )
        ).first()
        is not None
    )


def create_wildcard_upgrade(
    session: Session,
    user: User,
    source: Subscription,
    billing_term: BillingTerm,
) -> Subscription:
    """Create a pending wildcard claim linked to one active exact Relay source."""
    if user.id is None or source.id is None:
        raise ValueError("subscription is unavailable")
    reap_expired_domain_claims(session)
    session.exec(
        select(User)
        .where(User.id == user.id)
        .with_for_update()
        .execution_options(populate_existing=True)
    ).one()
    source = session.exec(
        select(Subscription)
        .where(Subscription.id == source.id, Subscription.user_id == user.id)
        .with_for_update()
        .execution_options(populate_existing=True)
    ).one_or_none()
    if source is None:
        raise ValueError("subscription not found")
    now = _utcnow()
    if (
        source.product != ProductType.RELAY
        or source.relay_hostname_scope != RelayHostnameScope.EXACT
        or source.status != SubscriptionStatus.ACTIVE
        or not source.domain
        or source.domain_is_managed
        or (_aware(source.current_period_end) or now) <= now
    ):
        raise ValueError(
            "only an active customer-owned exact Relay subscription with remaining service can upgrade"
        )
    labels = source.domain.split(".")
    if len(labels) < 2:
        raise ValueError("exact Relay hostname cannot upgrade to a wildcard base domain")
    wildcard_base = ".".join(labels[1:])
    _validate_wildcard_base_domain(wildcard_base)
    if has_pending_upgrade(session, source):
        raise ValueError("subscription already has a pending wildcard upgrade")
    source_open_payment = session.exec(
        select(Payment.id).where(
            Payment.subscription_id == source.id,
            Payment.status.in_((PaymentStatus.PENDING, PaymentStatus.PROCESSING)),  # type: ignore[union-attr]
        )
    ).first()
    if source_open_payment is not None:
        raise ValueError("subscription has an open payment and cannot upgrade")
    target = create_subscription(
        session,
        user,
        ProductType.RELAY,
        domain=wildcard_base,
        relay_hostname_scope=RelayHostnameScope.WILDCARD,
        billing_term=billing_term,
        commit=False,
        reap_domains=False,
        relay_conflict_exclude_subscription_id=source.id,
        allow_one_additional_subscription=True,
    )
    source_price = (
        source.monthly_price_sats
        if source.billing_term == BillingTerm.MONTHLY
        else source.yearly_price_sats
    )
    remaining_seconds = max(0, int((_aware(source.current_period_end) - now).total_seconds()))  # type: ignore[operator]
    credit = (remaining_seconds * source_price) // (
        billing_period_days(source.billing_term) * 86_400
    )
    target_price = (
        target.monthly_price_sats
        if billing_term == BillingTerm.MONTHLY
        else target.yearly_price_sats
    )
    target.upgrade_from_subscription_id = source.id
    target.upgrade_credit_sats = min(credit, target_price)
    target.upgrade_source_period_end = source.current_period_end
    session.add(target)
    try:
        session.commit()
    except IntegrityError as error:
        session.rollback()
        raise ValueError("subscription already has a pending wildcard upgrade") from error
    session.refresh(target)
    return target


def cancel_pending_subscription(session: Session, sub: Subscription) -> Subscription:
    """Cancel one unpaid pending subscription after reconciling every open payment."""
    if sub.id is None:
        raise ValueError("subscription has no id")

    # Payment creation serializes on the account row. Use the same lock so a
    # cancellation and a new invoice cannot both proceed from a stale pending row.
    session.exec(
        select(User)
        .where(User.id == sub.user_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    ).one()
    current = session.exec(
        select(Subscription)
        .where(Subscription.id == sub.id)
        .execution_options(populate_existing=True)
    ).one_or_none()
    if current is None:
        raise ValueError("subscription not found")
    if current.status != SubscriptionStatus.PENDING:
        raise ValueError("only pending subscriptions can be cancelled")

    open_payments = session.exec(
        select(Payment).where(
            Payment.subscription_id == current.id,
            Payment.status.in_((PaymentStatus.PENDING, PaymentStatus.PROCESSING)),  # type: ignore[union-attr]
        )
    ).all()
    for payment in open_payments:
        if payment.status == PaymentStatus.PROCESSING:
            raise SubscriptionCancellationConflict(
                "payment processing is in progress; wait before cancelling"
            )
        from .payments import check_and_settle_payment

        reconciled = check_and_settle_payment(session, payment)
        if reconciled.status in (PaymentStatus.PENDING, PaymentStatus.PROCESSING):
            raise SubscriptionCancellationConflict(
                "a payment is still pending; complete it or wait for it to expire"
            )

    session.expire_all()
    # Reacquire the account lock because payment reconciliation may have committed.
    session.exec(
        select(User)
        .where(User.id == current.user_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    ).one()
    current = session.exec(
        select(Subscription)
        .where(Subscription.id == current.id)
        .execution_options(populate_existing=True)
    ).one_or_none()
    if current is None:
        raise ValueError("subscription not found")
    if current.status != SubscriptionStatus.PENDING:
        raise SubscriptionCancellationConflict(
            "payment settled while cancellation was requested; subscription was not cancelled"
        )
    open_payment_exists = (
        select(Payment.id)
        .where(
            Payment.subscription_id == current.id,
            Payment.status.in_((PaymentStatus.PENDING, PaymentStatus.PROCESSING)),  # type: ignore[union-attr]
        )
        .exists()
    )
    result = session.execute(
        update(Subscription)
        .where(
            Subscription.id == current.id,
            Subscription.status == SubscriptionStatus.PENDING,
            ~open_payment_exists,
        )
        .values(
            status=SubscriptionStatus.CANCELLED,
            assigned_ip=None,
            assigned_port=None,
            reservation_expires_at=None,
            reservation_payment_id=None,
            resource_quarantined_until=None,
            domain=None,
            relay_pool_domain=None,
            domain_is_managed=False,
            domain_verification_token=None,
            domain_verified_at=None,
            domain_claim_expires_at=None,
            domain_renewal_grace_expires_at=None,
            auto_renew=False,
            upgrade_from_subscription_id=None,
            upgrade_credit_sats=0,
            upgrade_source_period_end=None,
            updated_at=_utcnow(),
        )
        .execution_options(synchronize_session=False)
    )
    if result.rowcount != 1:
        session.rollback()
        raise SubscriptionCancellationConflict(
            "a payment is still pending; complete it or wait for it to expire"
        )
    ip_leases.release(session, current, "pending subscription cancelled")
    session.commit()
    cancelled = session.get(Subscription, sub.id, populate_existing=True)
    if cancelled is None:  # pragma: no cover - foreign keys prevent normal deletion
        raise RuntimeError("subscription disappeared")
    return cancelled


def release_reservation(session: Session, sub: Subscription, payment_id: int) -> bool:
    """Release only the unpaid scarce reservation owned by ``payment_id``."""
    if (
        sub.status == SubscriptionStatus.ACTIVE
        or sub.reservation_payment_id != payment_id
        or sub.reservation_expires_at is None
    ):
        return False
    ip_leases.release(session, sub, "payment reservation released")
    sub.assigned_ip = None
    sub.assigned_port = None
    sub.reservation_expires_at = None
    sub.reservation_payment_id = None
    sub.updated_at = _utcnow()
    session.add(sub)
    return True


def reap_elapsed_resource_holds(session: Session) -> None:
    """Release elapsed quarantines and settle or expire elapsed payment-owned holds."""
    now = _utcnow()
    quarantined = session.exec(
        select(Subscription).where(
            Subscription.resource_quarantined_until.is_not(None),  # type: ignore[union-attr]
        )
    ).all()
    for sub in quarantined:
        deadline = _aware(sub.resource_quarantined_until)
        if sub.status != SubscriptionStatus.EXPIRED or deadline is None or deadline > now:
            continue

        open_payment = session.exec(
            select(Payment).where(
                Payment.subscription_id == sub.id,
                Payment.status.in_((PaymentStatus.PENDING, PaymentStatus.PROCESSING)),  # type: ignore[union-attr]
            )
        ).first()
        if open_payment is not None:
            if open_payment.status == PaymentStatus.PROCESSING:
                continue
            try:
                from .payments import check_and_settle_payment

                check_and_settle_payment(session, open_payment)
            except Exception as e:
                session.rollback()
                logger.warning(
                    "retaining expired {} assignment for subscription {} after payment "
                    "reconciliation failed: {}",
                    sub.product.value,
                    sub.public_id,
                    e,
                )
                continue

        session.expire_all()
        open_payment_exists = (
            select(Payment.id)
            .where(
                Payment.subscription_id == sub.id,
                Payment.status.in_((PaymentStatus.PENDING, PaymentStatus.PROCESSING)),  # type: ignore[union-attr]
            )
            .exists()
        )
        result = session.execute(
            update(Subscription)
            .where(
                Subscription.id == sub.id,
                Subscription.status == SubscriptionStatus.EXPIRED,
                Subscription.resource_quarantined_until.is_not(None),  # type: ignore[union-attr]
                Subscription.resource_quarantined_until <= now,  # type: ignore[operator]
                ~open_payment_exists,
            )
            .values(
                assigned_ip=None,
                assigned_port=None,
                resource_quarantined_until=None,
                updated_at=now,
            )
            .execution_options(synchronize_session=False)
        )
        if result.rowcount == 1:
            ip_leases.release(session, sub, "resource quarantine elapsed")
            session.commit()
        else:
            session.rollback()

    reservations = session.exec(
        select(Subscription).where(
            Subscription.reservation_expires_at.is_not(None),  # type: ignore[union-attr]
        )
    ).all()
    for sub in reservations:
        deadline = _aware(sub.reservation_expires_at)
        if deadline is None or deadline > now:
            continue
        payment_id = sub.reservation_payment_id
        if payment_id is None:
            ip_leases.release(session, sub, "orphaned reservation elapsed")
            sub.assigned_ip = None
            sub.assigned_port = None
            sub.reservation_expires_at = None
            sub.updated_at = now
            session.add(sub)
            session.commit()
            continue
        payment = session.get(Payment, payment_id, populate_existing=True)
        if payment is None or payment.status in _TERMINAL_PAYMENT_STATUSES:
            if release_reservation(session, sub, payment_id):
                session.commit()
            continue
        if payment.status == PaymentStatus.PROCESSING:
            continue

        # Provider-backed payments must be checked before local expiration so a
        # boundary settlement is credited instead of releasing its assignment.
        from .payments import DisabledPaymentMethodError, check_and_settle_payment

        try:
            check_and_settle_payment(session, payment)
        except DisabledPaymentMethodError:
            session.rollback()
            logger.warning(
                "retaining expired {} reservation for subscription {} while payment method "
                "{} is disabled",
                sub.product.value,
                sub.public_id,
                payment.method.value,
            )


def reserve_subscription_resource(
    session: Session,
    sub: Subscription,
    payment_id: int,
) -> bool:
    """Reserve current capacity for one payment without committing the transaction."""
    if sub.status == SubscriptionStatus.ACTIVE or sub.product == ProductType.RELAY:
        return False
    quarantine_end = _aware(sub.resource_quarantined_until)
    if sub.assigned_ip and quarantine_end and quarantine_end > _utcnow():
        raise NoCapacityError(
            f"{sub.product.value} assignment is quarantined; retry after "
            f"{quarantine_end.isoformat()}"
        )
    if sub.assigned_ip or sub.reservation_expires_at or sub.reservation_payment_id:
        raise NoCapacityError(f"{sub.product.value} assignment is not yet reusable")

    candidates: list[tuple[str, int | None]]
    if sub.product == ProductType.IP:
        ips = (
            settings.wireguard_public_ips_list
            if sub.delivery == DeliveryMode.WIREGUARD
            else settings.relay_public_ips_list
        )
        candidates = [(ip, None) for ip in ips]
        no_capacity = "no Blindport IP capacity"
    elif sub.product == ProductType.PORT:
        ports = (
            settings.relay_shared_udp_ports_list
            if sub.transport == Transport.UDP
            else settings.relay_shared_tcp_ports_list
        )
        candidates = [(ip, port) for ip in settings.relay_shared_ips_list for port in ports]
        no_capacity = "no Blindport Port capacity"
    else:  # pragma: no cover - ProductType is exhaustive
        return False

    for ip, port in candidates:
        try:
            with session.begin_nested():
                now = _utcnow()
                sub.assigned_ip = ip
                sub.assigned_port = port
                sub.reservation_expires_at = now + timedelta(
                    seconds=settings.RESOURCE_RESERVATION_TTL_SECONDS
                )
                sub.reservation_payment_id = payment_id
                sub.resource_quarantined_until = None
                sub.updated_at = now
                session.add(sub)
                if sub.product == ProductType.IP:
                    ip_leases.reserve(session, sub, payment_id, ip)
                session.flush()
        except IntegrityError:
            session.refresh(sub)
            continue
        return True
    raise NoCapacityError(no_capacity)


def activate_subscription(
    session: Session,
    sub: Subscription,
    reservation_payment_id: int | None,
    period_days: int,
) -> Subscription:
    """Convert the caller's reservation into an active billing period."""
    if sub.product in _SCARCE_PRODUCTS:
        if sub.reservation_payment_id != reservation_payment_id:
            raise NoCapacityError(f"{sub.product.value} reservation is no longer available")
        if sub.product == ProductType.IP and not sub.assigned_ip:
            raise NoCapacityError("Blindport IP reservation is no longer available")
        if sub.product == ProductType.PORT and not (sub.assigned_ip and sub.assigned_port):
            raise NoCapacityError("Blindport Port reservation is no longer available")
    if sub.product == ProductType.RELAY:
        if not sub.domain or (not sub.domain_is_managed and sub.domain_verified_at is None):
            raise ValueError("Blindport Relay domain ownership is not eligible for activation")
        if not sub.relay_pool_domain:
            sub.relay_pool_domain = ResourceAllocator(session).allocate_relay_pool_domain()
    now = _utcnow()
    sub.status = SubscriptionStatus.ACTIVE
    sub.current_period_start = now
    sub.current_period_end = now + timedelta(days=period_days)
    sub.domain_claim_expires_at = None
    sub.domain_renewal_grace_expires_at = None
    sub.reservation_expires_at = None
    sub.reservation_payment_id = None
    sub.resource_quarantined_until = None
    sub.updated_at = now
    session.add(sub)
    ip_leases.activate(session, sub)
    return sub


def renew_subscription(session: Session, sub: Subscription, period_days: int) -> Subscription:
    """Extend the billing period by the settled payment's fixed term."""
    now = _utcnow()
    period_end = _aware(sub.current_period_end)
    base = period_end if period_end and period_end > now else now
    sub.current_period_start = now
    sub.current_period_end = base + timedelta(days=period_days)
    sub.status = SubscriptionStatus.ACTIVE
    sub.domain_renewal_grace_expires_at = None
    sub.resource_quarantined_until = None
    sub.updated_at = now
    session.add(sub)
    ip_leases.activate(session, sub)
    return sub
