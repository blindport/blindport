"""SQLModel database tables."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from uuid import UUID, uuid4

from sqlalchemy import (
    CheckConstraint,
    Column,
    DateTime,
    Enum,
    Index,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlmodel import Field, SQLModel


def _utcnow() -> datetime:
    return datetime.now(UTC)


class ProductType(StrEnum):
    IP = "ip"
    PORT = "port"
    RELAY = "relay"


def _enum_values(enum_type: type[StrEnum]) -> list[str]:
    return [member.value for member in enum_type]


class BillingTerm(StrEnum):
    MONTHLY = "monthly"
    YEARLY = "yearly"


class Transport(StrEnum):
    TCP = "tcp"
    UDP = "udp"


class DeliveryMode(StrEnum):
    FRAMED = "framed"
    WIREGUARD = "wireguard"


class SubscriptionStatus(StrEnum):
    PENDING = "pending"  # awaiting first payment
    ACTIVE = "active"
    EXPIRED = "expired"
    CANCELLED = "cancelled"


class IPLeaseState(StrEnum):
    RESERVED = "reserved"
    ACTIVE = "active"
    QUARANTINED = "quarantined"
    RELEASED = "released"


class IPLeaseDelivery(StrEnum):
    FRAMED = "framed"
    WIREGUARD = "wireguard"


class PaymentMethod(StrEnum):
    LIGHTNING = "lightning"
    CASHU = "cashu"
    NWC = "nwc"
    STABLECOIN_SWAP = "stablecoin_swap"


class PaymentStatus(StrEnum):
    PENDING = "pending"
    PROCESSING = "processing"
    PAID = "paid"
    EXPIRED = "expired"
    FAILED = "failed"


class AgentOrderState(StrEnum):
    AWAITING_DOMAIN = "awaiting_domain"
    AWAITING_PAYMENT = "awaiting_payment"
    PAYMENT_PENDING = "payment_pending"
    ACTIVE = "active"
    ATTENTION_REQUIRED = "attention_required"


class ReminderKind(StrEnum):
    SEVEN_DAY = "7_day"
    ONE_DAY = "1_day"


class ReminderDeliveryState(StrEnum):
    QUEUED = "queued"
    SENDING = "sending"
    SENT = "sent"
    DELIVERY_AMBIGUOUS = "delivery_ambiguous"
    CANCELLED = "cancelled"
    FAILED = "failed"
    EXPIRED = "expired"


class AnnouncementState(StrEnum):
    DRAFT = "draft"
    QUEUED = "queued"
    COMPLETED = "completed"
    CANCELLED = "cancelled"


class AnnouncementDeliveryState(StrEnum):
    QUEUED = "queued"
    SENDING = "sending"
    SENT = "sent"
    DELIVERY_AMBIGUOUS = "delivery_ambiguous"
    CANCELLED = "cancelled"
    FAILED = "failed"


class User(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    public_id: UUID = Field(default_factory=uuid4, index=True, unique=True, nullable=False)
    # Display form of the token shown once at signup. We keep it nullable; the
    # hashed_token below is the source of truth for auth.
    display_token: str | None = None
    hashed_token: str = Field(index=True, unique=True)
    is_admin: bool = False
    is_suspended: bool = False
    created_at: datetime = Field(default_factory=_utcnow, sa_type=DateTime(timezone=True))
    last_seen_at: datetime | None = Field(default=None, sa_type=DateTime(timezone=True))
    has_nwc: bool = False
    nwc_ciphertext: str | None = Field(default=None, sa_type=Text)
    nwc_key_version: str | None = Field(default=None, max_length=32)
    nwc_generation: int = 0
    nwc_capabilities: str | None = None
    nwc_last_validated_at: datetime | None = Field(default=None, sa_type=DateTime(timezone=True))
    has_reminder_email: bool = False
    reminder_email_ciphertext: str | None = Field(default=None, sa_type=Text)
    reminder_email_key_version: str | None = Field(default=None, max_length=32)
    reminder_email_generation: int = 0
    has_service_email: bool = False
    service_email_ciphertext: str | None = Field(default=None, sa_type=Text)
    service_email_key_version: str | None = Field(default=None, max_length=32)
    service_email_generation: int = 0


# Keep the revoked rolling-deployment column in schema metadata without mapping
# it onto User. Application code cannot accidentally read or write plaintext.
User.__table__.append_column(Column("nwc_uri", String(), nullable=True))


class ClientCredential(SQLModel, table=True):
    __table_args__ = (UniqueConstraint("instance_id", name="uq_clientcredential_instance_id"),)

    user_id: int = Field(foreign_key="user.id", primary_key=True)
    instance_id: str = Field(max_length=36)
    public_key_fingerprint: str = Field(max_length=64)
    generation: int
    client_cert_pem: str
    serial: str = Field(max_length=40)
    not_before: datetime = Field(sa_type=DateTime(timezone=True))
    not_after: datetime = Field(sa_type=DateTime(timezone=True))
    renew_after: datetime = Field(sa_type=DateTime(timezone=True))
    created_at: datetime = Field(default_factory=_utcnow, sa_type=DateTime(timezone=True))
    updated_at: datetime = Field(default_factory=_utcnow, sa_type=DateTime(timezone=True))


class WireGuardPeer(SQLModel, table=True):
    user_id: int = Field(foreign_key="user.id", primary_key=True)
    instance_id: str = Field(max_length=36)
    public_key: str = Field(max_length=44, unique=True)
    generation: int
    created_at: datetime = Field(default_factory=_utcnow, sa_type=DateTime(timezone=True))
    updated_at: datetime = Field(default_factory=_utcnow, sa_type=DateTime(timezone=True))


class Subscription(SQLModel, table=True):
    __table_args__ = (
        UniqueConstraint(
            "assigned_ip",
            "assigned_port",
            "transport",
            name="uq_subscription_port_tuple",
        ),
        Index(
            "uq_subscription_dedicated_ip",
            "assigned_ip",
            unique=True,
            sqlite_where=text("product = 'ip'"),
            postgresql_where=text("product = 'ip'"),
        ),
    )

    id: int | None = Field(default=None, primary_key=True)
    public_id: UUID = Field(default_factory=uuid4, index=True, unique=True, nullable=False)
    user_id: int = Field(foreign_key="user.id", index=True)
    product: ProductType = Field(
        sa_type=Enum(ProductType, values_callable=_enum_values, name="producttype")
    )
    delivery: DeliveryMode = DeliveryMode.FRAMED
    status: SubscriptionStatus = SubscriptionStatus.PENDING
    # Resource assignment.
    assigned_ip: str | None = None  # dedicated for IP, shared for PORT
    assigned_port: int | None = None  # for PORT
    transport: Transport = Transport.TCP
    domain: str | None = Field(default=None, unique=True)  # for RELAY
    relay_pool_domain: str | None = None  # for RELAY
    domain_is_managed: bool = False
    domain_verification_token: str | None = None
    domain_verified_at: datetime | None = Field(default=None, sa_type=DateTime(timezone=True))
    domain_claim_expires_at: datetime | None = Field(default=None, sa_type=DateTime(timezone=True))
    domain_renewal_grace_expires_at: datetime | None = Field(
        default=None, sa_type=DateTime(timezone=True)
    )
    reservation_expires_at: datetime | None = Field(default=None, sa_type=DateTime(timezone=True))
    # Ownership is checked by the reservation lifecycle. Avoid a nonessential
    # database FK cycle between subscriptions and payments.
    reservation_payment_id: int | None = Field(default=None, index=True)
    resource_quarantined_until: datetime | None = Field(
        default=None, sa_type=DateTime(timezone=True)
    )
    # Billing.
    billing_term: BillingTerm = Field(
        default=BillingTerm.MONTHLY,
        sa_type=Enum(BillingTerm, values_callable=_enum_values, name="billingterm"),
        sa_column_kwargs={"server_default": text("'monthly'")},
    )
    monthly_price_sats: int
    yearly_price_sats: int = Field(
        default=0,
        sa_column_kwargs={"server_default": text("0")},
    )
    current_period_start: datetime | None = Field(default=None, sa_type=DateTime(timezone=True))
    current_period_end: datetime | None = Field(default=None, sa_type=DateTime(timezone=True))
    auto_renew: bool = False  # tied to NWC
    created_at: datetime = Field(default_factory=_utcnow, sa_type=DateTime(timezone=True))
    updated_at: datetime = Field(default_factory=_utcnow, sa_type=DateTime(timezone=True))


class IPLease(SQLModel, table=True):
    __table_args__ = (
        CheckConstraint(
            "state IN ('reserved', 'active', 'quarantined', 'released')",
            name="ck_iplease_state",
        ),
        CheckConstraint("smtp_fee_paid_sats >= 0", name="ck_iplease_smtp_fee_nonnegative"),
        Index(
            "uq_iplease_unreleased_address",
            "address",
            unique=True,
            sqlite_where=text("released_at IS NULL"),
            postgresql_where=text("released_at IS NULL"),
        ),
        Index(
            "uq_iplease_unreleased_subscription",
            "subscription_id",
            unique=True,
            sqlite_where=text("released_at IS NULL"),
            postgresql_where=text("released_at IS NULL"),
        ),
        Index("ix_iplease_subscription_created", "subscription_id", "created_at"),
    )

    id: int | None = Field(default=None, primary_key=True)
    public_id: UUID = Field(default_factory=uuid4, index=True, unique=True, nullable=False)
    subscription_id: int = Field(foreign_key="subscription.id")
    reservation_payment_id: int | None = Field(default=None, index=True)
    address: str = Field(max_length=45)
    delivery: IPLeaseDelivery = Field(
        sa_type=Enum(IPLeaseDelivery, values_callable=_enum_values, name="ipleasedelivery")
    )
    state: IPLeaseState = Field(
        default=IPLeaseState.RESERVED,
        sa_type=Enum(IPLeaseState, values_callable=_enum_values, name="ipleasestate"),
        sa_column_kwargs={"server_default": text("'reserved'")},
    )
    reserved_at: datetime = Field(sa_type=DateTime(timezone=True))
    activated_at: datetime | None = Field(default=None, sa_type=DateTime(timezone=True))
    expired_at: datetime | None = Field(default=None, sa_type=DateTime(timezone=True))
    quarantined_at: datetime | None = Field(default=None, sa_type=DateTime(timezone=True))
    quarantine_until: datetime | None = Field(default=None, sa_type=DateTime(timezone=True))
    released_at: datetime | None = Field(default=None, sa_type=DateTime(timezone=True))
    release_reason: str | None = Field(default=None, max_length=255)
    imported: bool = False
    smtp_enabled: bool = False
    smtp_intended_use: str | None = Field(default=None, max_length=500)
    smtp_fee_paid_sats: int = 0
    smtp_reviewed_at: datetime | None = Field(default=None, sa_type=DateTime(timezone=True))
    smtp_reviewed_by: str | None = Field(default=None, max_length=100)
    smtp_review_reference: str | None = Field(default=None, max_length=200)
    smtp_revoked_at: datetime | None = Field(default=None, sa_type=DateTime(timezone=True))
    smtp_revocation_reason: str | None = Field(default=None, max_length=255)
    created_at: datetime = Field(default_factory=_utcnow, sa_type=DateTime(timezone=True))
    updated_at: datetime = Field(default_factory=_utcnow, sa_type=DateTime(timezone=True))


class AgentOrder(SQLModel, table=True):
    __table_args__ = (
        UniqueConstraint("user_id", "order_key", name="uq_agentorder_user_order_key"),
    )

    id: int | None = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="user.id", index=True)
    order_key: str = Field(max_length=63)
    subscription_id: int = Field(foreign_key="subscription.id", unique=True)
    product: ProductType = Field(
        sa_type=Enum(ProductType, values_callable=_enum_values, name="producttype")
    )
    billing_term: BillingTerm = Field(
        sa_type=Enum(BillingTerm, values_callable=_enum_values, name="billingterm")
    )
    delivery: DeliveryMode = Field(sa_type=Enum(DeliveryMode, name="deliverymode"))
    transport: Transport = Field(sa_type=Enum(Transport, name="transport"))
    domain: str | None = None
    created_at: datetime = Field(default_factory=_utcnow, sa_type=DateTime(timezone=True))
    updated_at: datetime = Field(default_factory=_utcnow, sa_type=DateTime(timezone=True))


class Payment(SQLModel, table=True):
    __table_args__ = (
        Index(
            "uq_payment_open_subscription",
            "subscription_id",
            unique=True,
            sqlite_where=text("status IN ('PENDING', 'PROCESSING')"),
            postgresql_where=text("status IN ('PENDING', 'PROCESSING')"),
        ),
        Index(
            "uq_payment_payment_hash",
            "payment_hash",
            unique=True,
            sqlite_where=text("payment_hash IS NOT NULL"),
            postgresql_where=text("payment_hash IS NOT NULL"),
        ),
        Index(
            "uq_payment_invoice_idempotency_key",
            "invoice_idempotency_key",
            unique=True,
            sqlite_where=text("invoice_idempotency_key IS NOT NULL"),
            postgresql_where=text("invoice_idempotency_key IS NOT NULL"),
        ),
        Index(
            "uq_payment_agent_order_id",
            "agent_order_id",
            unique=True,
            sqlite_where=text("agent_order_id IS NOT NULL"),
            postgresql_where=text("agent_order_id IS NOT NULL"),
        ),
    )

    id: int | None = Field(default=None, primary_key=True)
    subscription_id: int = Field(foreign_key="subscription.id", index=True)
    agent_order_id: int | None = Field(default=None, foreign_key="agentorder.id")
    method: PaymentMethod
    status: PaymentStatus = PaymentStatus.PENDING
    billing_term: BillingTerm = Field(
        default=BillingTerm.MONTHLY,
        sa_type=Enum(BillingTerm, values_callable=_enum_values, name="billingterm"),
        sa_column_kwargs={"server_default": text("'monthly'")},
    )
    period_days: int = Field(default=30, sa_column_kwargs={"server_default": text("30")})
    amount_sats: int
    markup_sats: int = Field(default=0, sa_column_kwargs={"server_default": text("0")})
    # For Lightning: BOLT11 invoice + payment_hash. For Cashu: token reference.
    invoice: str | None = None
    payment_hash: str | None = None
    invoice_idempotency_key: str | None = None
    cashu_token: str | None = None
    nwc_state: str | None = Field(default=None, max_length=32)
    nwc_attempt_count: int = 0
    nwc_first_attempt_at: datetime | None = Field(default=None, sa_type=DateTime(timezone=True))
    nwc_last_attempt_at: datetime | None = Field(default=None, sa_type=DateTime(timezone=True))
    nwc_next_attempt_at: datetime | None = Field(default=None, sa_type=DateTime(timezone=True))
    nwc_last_lookup_at: datetime | None = Field(default=None, sa_type=DateTime(timezone=True))
    nwc_lease_until: datetime | None = Field(default=None, sa_type=DateTime(timezone=True))
    nwc_lease_token: str | None = Field(default=None, max_length=32)
    nwc_error_code: str | None = Field(default=None, max_length=64)
    nwc_preimage_hash: str | None = Field(default=None, max_length=64)
    nwc_fees_paid_msats: int | None = None
    nwc_credential_generation: int | None = None
    created_at: datetime = Field(default_factory=_utcnow, sa_type=DateTime(timezone=True))
    paid_at: datetime | None = Field(default=None, sa_type=DateTime(timezone=True))
    expires_at: datetime | None = Field(default=None, sa_type=DateTime(timezone=True))


# This pre-production request-ID column is retained for old replicas but no
# longer participates in the mapped payment contract.
Payment.__table__.append_column(Column("nwc_request_id", String(), nullable=True))


class ReminderDelivery(SQLModel, table=True):
    __table_args__ = (
        UniqueConstraint(
            "subscription_id",
            "current_period_end",
            "kind",
            name="uq_reminderdelivery_subscription_period_kind",
        ),
        CheckConstraint(
            "attempt_count >= 0 AND attempt_count <= 20",
            name="ck_reminderdelivery_attempt_count",
        ),
        Index("ix_reminderdelivery_due", "state", "next_attempt_at", "id"),
    )

    id: int | None = Field(default=None, primary_key=True)
    subscription_id: int = Field(foreign_key="subscription.id", index=True)
    current_period_end: datetime = Field(sa_type=DateTime(timezone=True))
    recipient_generation: int
    kind: ReminderKind = Field(
        sa_type=Enum(ReminderKind, values_callable=_enum_values, name="reminderkind")
    )
    state: ReminderDeliveryState = Field(
        default=ReminderDeliveryState.QUEUED,
        sa_type=Enum(
            ReminderDeliveryState,
            values_callable=_enum_values,
            name="reminderdeliverystate",
        ),
        sa_column_kwargs={"server_default": text("'queued'")},
    )
    attempt_count: int = Field(default=0, sa_column_kwargs={"server_default": text("0")})
    error_code: str | None = Field(default=None, max_length=64)
    created_at: datetime = Field(default_factory=_utcnow, sa_type=DateTime(timezone=True))
    updated_at: datetime = Field(default_factory=_utcnow, sa_type=DateTime(timezone=True))
    last_attempt_at: datetime | None = Field(default=None, sa_type=DateTime(timezone=True))
    next_attempt_at: datetime | None = Field(default=None, sa_type=DateTime(timezone=True))
    sent_at: datetime | None = Field(default=None, sa_type=DateTime(timezone=True))
    terminal_at: datetime | None = Field(default=None, sa_type=DateTime(timezone=True))
    lease_token: str | None = Field(default=None, max_length=32)
    lease_until: datetime | None = Field(default=None, sa_type=DateTime(timezone=True))


class Announcement(SQLModel, table=True):
    __table_args__ = (
        CheckConstraint("recipient_count >= 0", name="ck_announcement_recipient_count"),
        CheckConstraint("length(body) <= 10000", name="ck_announcement_body_length"),
    )

    id: int | None = Field(default=None, primary_key=True)
    state: AnnouncementState = Field(
        default=AnnouncementState.DRAFT,
        sa_type=Enum(AnnouncementState, values_callable=_enum_values, name="announcementstate"),
        sa_column_kwargs={"server_default": text("'draft'")},
    )
    subject: str = Field(max_length=160)
    body: str = Field(max_length=10_000, sa_type=Text)
    author_marker: str = Field(max_length=100)
    recipient_count: int = Field(default=0, sa_column_kwargs={"server_default": text("0")})
    created_at: datetime = Field(default_factory=_utcnow, sa_type=DateTime(timezone=True))
    queued_at: datetime | None = Field(default=None, sa_type=DateTime(timezone=True))
    completed_at: datetime | None = Field(default=None, sa_type=DateTime(timezone=True))
    cancelled_at: datetime | None = Field(default=None, sa_type=DateTime(timezone=True))


class AnnouncementDelivery(SQLModel, table=True):
    __table_args__ = (
        UniqueConstraint(
            "announcement_id", "user_id", name="uq_announcementdelivery_campaign_user"
        ),
        CheckConstraint(
            "attempt_count >= 0 AND attempt_count <= 20",
            name="ck_announcementdelivery_attempt_count",
        ),
        Index("ix_announcementdelivery_due", "state", "next_attempt_at", "id"),
    )

    id: int | None = Field(default=None, primary_key=True)
    announcement_id: int = Field(foreign_key="announcement.id", index=True)
    user_id: int = Field(foreign_key="user.id", index=True)
    recipient_generation: int
    state: AnnouncementDeliveryState = Field(
        default=AnnouncementDeliveryState.QUEUED,
        sa_type=Enum(
            AnnouncementDeliveryState,
            values_callable=_enum_values,
            name="announcementdeliverystate",
        ),
        sa_column_kwargs={"server_default": text("'queued'")},
    )
    attempt_count: int = Field(default=0, sa_column_kwargs={"server_default": text("0")})
    error_code: str | None = Field(default=None, max_length=64)
    created_at: datetime = Field(default_factory=_utcnow, sa_type=DateTime(timezone=True))
    updated_at: datetime = Field(default_factory=_utcnow, sa_type=DateTime(timezone=True))
    last_attempt_at: datetime | None = Field(default=None, sa_type=DateTime(timezone=True))
    next_attempt_at: datetime | None = Field(default=None, sa_type=DateTime(timezone=True))
    sent_at: datetime | None = Field(default=None, sa_type=DateTime(timezone=True))
    terminal_at: datetime | None = Field(default=None, sa_type=DateTime(timezone=True))
    lease_token: str | None = Field(default=None, max_length=32)
    lease_until: datetime | None = Field(default=None, sa_type=DateTime(timezone=True))


class RateLimitBucket(SQLModel, table=True):
    __table_args__ = (
        UniqueConstraint(
            "scope",
            "identifier_hash",
            "window_start",
            name="uq_ratelimitbucket_scope_identifier_window",
        ),
        Index("ix_ratelimitbucket_expires_at_id", "expires_at", "id"),
    )

    id: int | None = Field(default=None, primary_key=True)
    scope: str = Field(max_length=64)
    identifier_hash: str = Field(max_length=64)
    window_start: datetime = Field(sa_type=DateTime(timezone=True))
    request_count: int
    expires_at: datetime = Field(sa_type=DateTime(timezone=True))


class RateLimitMaintenance(SQLModel, table=True):
    name: str = Field(primary_key=True, max_length=64)
    next_cleanup_at: datetime = Field(sa_type=DateTime(timezone=True))
    bucket_count: int = 0
