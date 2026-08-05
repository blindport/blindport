"""Pydantic schemas for API I/O."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .models import (
    AgentOrderState,
    BillingTerm,
    DeliveryMode,
    PaymentMethod,
    PaymentStatus,
    ProductType,
    SubscriptionStatus,
    Transport,
)
from .wireguard import canonical_wireguard_key


class SignupResponse(BaseModel):
    """One-time response containing the user's new bearer token."""

    token: str = Field(..., description="Bearer token. Save it now; cannot be recovered.")
    user_id: int


class AccountSignupResponse(BaseModel):
    """One-time v2 response containing the token and public account identity."""

    token: str = Field(..., description="Bearer token. Save it now; cannot be recovered.")
    account_id: UUID


class MeResponse(BaseModel):
    user_id: int
    is_admin: bool
    created_at: datetime
    subscriptions: list[SubscriptionResponse] = Field(default_factory=list)


class AccountMeResponse(BaseModel):
    account_id: UUID
    is_admin: bool
    created_at: datetime
    subscriptions: list[SubscriptionResponse] = Field(default_factory=list)


class CatalogCapacityResponse(BaseModel):
    total: int | None = None
    available: int | None = None
    framed_available: int | None = None
    wireguard_available: int | None = None
    tcp_available: int | None = None
    udp_available: int | None = None
    managed_domains_available: int | None = None
    customer_domains_available: bool | None = None


class CatalogProductResponse(BaseModel):
    product: ProductType
    enabled: bool
    sales_paused: bool
    monthly_price_sats: int
    yearly_price_sats: int
    available: bool
    sold_out: bool
    capacity: CatalogCapacityResponse


class CatalogResponse(BaseModel):
    products: list[CatalogProductResponse]
    managed_suffixes: list[str] = Field(default_factory=list)
    yearly_billing_enabled: bool


class AccountStatusResponse(BaseModel):
    user_id: int
    is_suspended: bool


class PublicAccountStatusResponse(BaseModel):
    account_id: UUID
    is_suspended: bool


class CreateSubscriptionRequest(BaseModel):
    product: ProductType
    billing_term: BillingTerm = BillingTerm.MONTHLY
    delivery: DeliveryMode = DeliveryMode.FRAMED
    location: str | None = None  # advisory only in v0
    domain: str | None = None  # required for RELAY
    transport: Transport = Transport.TCP

    @model_validator(mode="after")
    def validate_transport(self) -> CreateSubscriptionRequest:
        if self.transport != Transport.TCP and self.product != ProductType.PORT:
            raise ValueError("UDP transport is supported only for Blindport Port subscriptions")
        if self.delivery != DeliveryMode.FRAMED and self.product != ProductType.IP:
            raise ValueError("WireGuard delivery is supported only for Blindport IP subscriptions")
        return self


class AnonymousOrderRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    product: ProductType
    billing_term: BillingTerm = BillingTerm.MONTHLY
    delivery: DeliveryMode = DeliveryMode.FRAMED
    domain: str | None = None
    transport: Transport = Transport.TCP

    @model_validator(mode="after")
    def validate_transport(self) -> AnonymousOrderRequest:
        if self.transport != Transport.TCP and self.product != ProductType.PORT:
            raise ValueError("UDP transport is supported only for Blindport Port subscriptions")
        if self.delivery != DeliveryMode.FRAMED and self.product != ProductType.IP:
            raise ValueError("WireGuard delivery is supported only for Blindport IP subscriptions")
        return self


class SubscriptionResponse(BaseModel):
    id: UUID
    product: ProductType
    delivery: DeliveryMode
    status: SubscriptionStatus
    assigned_ip: str | None = None
    assigned_port: int | None = None
    transport: Transport
    domain: str | None = None
    relay_pool_domain: str | None = None
    domain_is_managed: bool = False
    domain_verified_at: datetime | None = None
    domain_verification_expires_at: datetime | None = None
    domain_renewal_grace_expires_at: datetime | None = None
    domain_challenge_name: str | None = None
    domain_challenge_value: str | None = None
    record_type: str | None = None
    record_name: str | None = None
    record_target: str | None = None
    monthly_price_sats: int
    yearly_price_sats: int
    billing_term: BillingTerm
    period_days: int
    current_period_start: datetime | None = None
    current_period_end: datetime | None = None
    auto_renew: bool


class AnonymousOrderResponse(BaseModel):
    token: str = Field(..., description="Bearer token. Save it now; cannot be recovered.")
    account_id: UUID
    monthly_price_sats: int
    yearly_price_sats: int
    billing_term: BillingTerm
    period_days: int
    subscription: SubscriptionResponse


class AgentOrderRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    product: ProductType = Field(strict=False)
    domain: str | None = None
    transport: Transport = Field(default=Transport.TCP, strict=False)
    delivery: DeliveryMode = Field(default=DeliveryMode.FRAMED, strict=False)
    billing_term: BillingTerm = Field(default=BillingTerm.MONTHLY, strict=False)

    @field_validator("domain")
    @classmethod
    def validate_domain(cls, value: str | None) -> str | None:
        if value is None:
            return None
        from .hostnames import canonicalize_hostname

        return canonicalize_hostname(value)

    @model_validator(mode="after")
    def validate_spec(self) -> AgentOrderRequest:
        if self.delivery == DeliveryMode.WIREGUARD:
            raise ValueError("WireGuard delivery is not supported for agent orders")
        if self.transport != Transport.TCP and self.product != ProductType.PORT:
            raise ValueError("UDP transport is supported only for Blindport Port subscriptions")
        if self.product == ProductType.RELAY and self.domain is None:
            raise ValueError("domain is required for Blindport Relay subscriptions")
        if self.product != ProductType.RELAY and self.domain is not None:
            raise ValueError("domain is supported only for Blindport Relay subscriptions")
        return self


class AgentOrderResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    order_key: str
    subscription: SubscriptionResponse
    payment: PaymentResponse | None = None
    state: AgentOrderState


class DomainVerificationResponse(BaseModel):
    verified: bool
    detail: str
    subscription: SubscriptionResponse


class CreatePaymentRequest(BaseModel):
    subscription_id: UUID
    method: PaymentMethod
    billing_term: BillingTerm | None = None


class PaymentResponse(BaseModel):
    id: int
    subscription_id: UUID
    method: PaymentMethod
    status: PaymentStatus
    amount_sats: int
    base_amount_sats: int
    markup_sats: int
    billing_term: BillingTerm
    period_days: int
    invoice: str | None = None
    payment_hash: str | None = None
    lightning_uri: str | None = None
    qr_svg: str | None = None
    stablecoin_checkout_url: str | None = None
    stablecoin_asset: str | None = None
    cashu_token_required: bool | None = None  # for cashu: payment requires user-submitted token
    nwc_state: str | None = None
    nwc_attempt_count: int = 0
    nwc_error_code: str | None = None
    expires_at: datetime | None = None

    @field_validator("expires_at")
    @classmethod
    def normalize_expiry_timezone(cls, value: datetime | None) -> datetime | None:
        if value is not None and value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value


class PaymentConflictResponse(BaseModel):
    detail: str
    existing_payment: PaymentResponse


class SubmitCashuTokenRequest(BaseModel):
    payment_id: int
    cashu_token: str


class CashuQuoteRequest(BaseModel):
    """Ask the trusted mint to mint a bolt11 invoice the user can pay."""

    payment_id: int


class CashuMintAndRedeemRequest(BaseModel):
    """Ask the backend to mint ecash against a paid quote and settle the payment."""

    payment_id: int
    quote_id: str
    mint_url: str | None = None


class CashuQuoteResponse(BaseModel):
    payment_id: int
    quote_id: str
    bolt11: str
    amount_sats: int
    mint_url: str
    expires_at: int = 0
    lightning_uri: str = ""
    qr_svg: str = ""


class SetNwcRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    nwc_uri: str
    auto_renew_subscription_id: UUID | None = None


class NwcStatusResponse(BaseModel):
    has_nwc: bool
    capabilities: tuple[str, ...] = ()
    last_validated_at: datetime | None = None


class SetReminderEmailRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: str = Field(min_length=3, max_length=254)


class ReminderEmailStatusResponse(BaseModel):
    configured: bool


class RelayProvisioningResponse(BaseModel):
    """Returned to the Linux client at /api/v1/client/config.

    The relay endpoint and the client's bearer token are everything the
    daemon needs to connect.
    """

    relay_endpoint: str  # host:port
    relay_endpoints: list[str]
    assigned_ip: str | None = None
    assigned_port: int | None = None
    transport: Transport
    domain: str | None = None
    product: ProductType
    subscription_id: UUID


class ClientVersionResponse(BaseModel):
    version: str


class ClientCertResponse(BaseModel):
    """Issued mTLS material for the client<->relay tunnel.

    The CA cert pins which relay the client trusts; the client cert identity is
    bound to the account resolved from the bearer token. This endpoint also
    returns the private key, so the certificate is not a second factor. All
    values are PEM, ASCII-safe.
    """

    ca_cert_pem: str
    client_cert_pem: str
    client_key_pem: str
    not_after: str  # ISO-8601 UTC
    serial: str  # hex, lowercase, no 0x prefix


class ClientCertificateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    instance_id: str = Field(min_length=36, max_length=36)
    generation: int = Field(ge=1, le=2_147_483_647)
    csr_pem: str = Field(min_length=1, max_length=16_384)

    @field_validator("instance_id")
    @classmethod
    def validate_canonical_instance_id(cls, value: str) -> str:
        try:
            parsed = UUID(value)
        except ValueError as error:
            raise ValueError("instance_id must be a canonical UUID") from error
        if str(parsed) != value:
            raise ValueError("instance_id must be a canonical UUID")
        return value

    @field_validator("csr_pem")
    @classmethod
    def validate_canonical_csr(cls, value: str) -> str:
        try:
            csr = x509.load_pem_x509_csr(value.encode("ascii"))
        except (UnicodeEncodeError, ValueError) as error:
            raise ValueError("csr_pem must contain one canonical PEM CSR") from error
        canonical = csr.public_bytes(serialization.Encoding.PEM).decode("ascii")
        if value != canonical:
            raise ValueError("csr_pem must contain one canonical PEM CSR")
        if not csr.is_signature_valid:
            raise ValueError("CSR signature is invalid")
        if not isinstance(csr.public_key(), Ed25519PublicKey):
            raise ValueError("CSR public key must be Ed25519")
        return value


class ClientCertificateResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    instance_id: str
    generation: int
    ca_cert_pem: str
    client_cert_pem: str
    serial: str
    not_before: datetime
    not_after: datetime
    renew_after: datetime


class WireGuardKeyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    instance_id: str = Field(min_length=36, max_length=36)
    generation: int = Field(ge=1, le=2_147_483_647)
    public_key: str = Field(min_length=44, max_length=44)
    signature: str = Field(min_length=88, max_length=88)

    @field_validator("instance_id")
    @classmethod
    def validate_canonical_instance_id(cls, value: str) -> str:
        return ClientCertificateRequest.validate_canonical_instance_id(value)

    @field_validator("public_key")
    @classmethod
    def validate_public_key(cls, value: str) -> str:
        return canonical_wireguard_key(value, "public_key")

    @field_validator("signature")
    @classmethod
    def validate_signature(cls, value: str) -> str:
        import base64

        try:
            decoded = base64.b64decode(value, validate=True)
        except ValueError as error:
            raise ValueError("signature must be canonical base64") from error
        if len(decoded) != 64 or base64.b64encode(decoded).decode("ascii") != value:
            raise ValueError("signature must encode exactly 64 bytes")
        return value


class WireGuardConfigResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    instance_id: str
    generation: int
    public_key: str | None = None
    assigned_prefixes: list[str]
    relay_public_key: str
    endpoint: str
    mtu: int
    persistent_keepalive_seconds: int


# Resolve forward refs
MeResponse.model_rebuild()
AccountMeResponse.model_rebuild()
AgentOrderResponse.model_rebuild()
