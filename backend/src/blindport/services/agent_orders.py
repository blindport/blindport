"""Idempotent label-driven subscription ordering."""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, select

from ..config import settings
from ..core.models import (
    AgentOrder,
    AgentOrderState,
    BillingTerm,
    DeliveryMode,
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
from . import payments as payments_svc
from . import subscriptions as subs_svc


class AgentOrderConflictError(RuntimeError):
    """An existing order key was replayed with a different immutable spec."""


@dataclass(frozen=True)
class AgentOrderSpec:
    product: ProductType
    billing_term: BillingTerm
    delivery: DeliveryMode
    transport: Transport
    domain: str | None
    relay_hostname_scope: RelayHostnameScope = RelayHostnameScope.EXACT


@dataclass(frozen=True)
class AgentOrderResult:
    order: AgentOrder
    subscription: Subscription
    payment: Payment | None
    state: AgentOrderState


def _compatible(order: AgentOrder, spec: AgentOrderSpec) -> bool:
    return (
        order.product == spec.product
        and order.billing_term == spec.billing_term
        and order.delivery == spec.delivery
        and order.transport == spec.transport
        and order.domain == spec.domain
        and order.relay_hostname_scope == spec.relay_hostname_scope
    )


def _load_order(session: Session, user_id: int, order_key: str) -> AgentOrder | None:
    return session.exec(
        select(AgentOrder).where(
            AgentOrder.user_id == user_id,
            AgentOrder.order_key == order_key,
        )
    ).first()


def _order_subscription(session: Session, order: AgentOrder) -> Subscription:
    subscription = session.get(Subscription, order.subscription_id)
    if subscription is None:  # pragma: no cover - enforced by the database FK
        raise RuntimeError("agent order subscription disappeared")
    return subscription


def _get_or_create_order(
    session: Session,
    user: User,
    order_key: str,
    spec: AgentOrderSpec,
) -> tuple[AgentOrder, Subscription]:
    if user.id is None:
        raise ValueError("user has no id")

    if spec.product == ProductType.RELAY:
        subs_svc.reap_expired_domain_claims(session)

    if session.get_bind().dialect.name == "sqlite":
        session.connection().exec_driver_sql("BEGIN IMMEDIATE")
    session.exec(
        select(User)
        .where(User.id == user.id)
        .with_for_update()
        .execution_options(populate_existing=True)
    ).one()

    existing = _load_order(session, user.id, order_key)
    if existing is not None:
        if not _compatible(existing, spec):
            session.rollback()
            raise AgentOrderConflictError("order key already exists with a different specification")
        subscription = _order_subscription(session, existing)
        session.commit()
        return existing, subscription

    try:
        subscription = subs_svc.create_subscription(
            session,
            user=user,
            product=spec.product,
            domain=spec.domain,
            relay_hostname_scope=spec.relay_hostname_scope,
            transport=spec.transport,
            delivery=spec.delivery,
            billing_term=spec.billing_term,
            commit=False,
            reap_domains=False,
        )
        if subscription.id is None:  # pragma: no cover - flush assigns the primary key
            raise RuntimeError("subscription id was not assigned")
        order = AgentOrder(
            user_id=user.id,
            order_key=order_key,
            subscription_id=subscription.id,
            product=spec.product,
            billing_term=spec.billing_term,
            delivery=spec.delivery,
            transport=spec.transport,
            domain=spec.domain,
            relay_hostname_scope=spec.relay_hostname_scope,
        )
        session.add(order)
        session.commit()
        session.refresh(order)
        session.refresh(subscription)
        return order, subscription
    except IntegrityError:
        session.rollback()
        existing = _load_order(session, user.id, order_key)
        if existing is None:
            raise
        if not _compatible(existing, spec):
            raise AgentOrderConflictError(
                "order key already exists with a different specification"
            ) from None
        return existing, _order_subscription(session, existing)


def _linked_payment(session: Session, order_id: int | None) -> Payment | None:
    if order_id is None:
        return None
    return session.exec(select(Payment).where(Payment.agent_order_id == order_id)).first()


def _result_state(subscription: Subscription, payment: Payment | None) -> AgentOrderState:
    if subscription.status == SubscriptionStatus.ACTIVE:
        return AgentOrderState.ACTIVE
    if payment is None:
        return AgentOrderState.AWAITING_PAYMENT
    if payment.status in (PaymentStatus.PENDING, PaymentStatus.PROCESSING):
        return AgentOrderState.PAYMENT_PENDING
    return AgentOrderState.ATTENTION_REQUIRED


def put_agent_order(
    session: Session,
    user: User,
    order_key: str,
    spec: AgentOrderSpec,
) -> AgentOrderResult:
    """Create or replay an order without ever turning its initial payment into a renewal."""
    order, subscription = _get_or_create_order(session, user, order_key, spec)
    payment = _linked_payment(session, order.id)

    if subscription.status == SubscriptionStatus.ACTIVE:
        return AgentOrderResult(order, subscription, payment, AgentOrderState.ACTIVE)
    if subscription.status != SubscriptionStatus.PENDING:
        return AgentOrderResult(order, subscription, payment, AgentOrderState.ATTENTION_REQUIRED)
    if (
        subscription.product == ProductType.RELAY
        and not subscription.domain_is_managed
        and subscription.domain_verified_at is None
    ):
        return AgentOrderResult(order, subscription, payment, AgentOrderState.AWAITING_DOMAIN)
    if payment is not None and payment.status in (
        PaymentStatus.PAID,
        PaymentStatus.EXPIRED,
        PaymentStatus.FAILED,
    ):
        return AgentOrderResult(order, subscription, payment, AgentOrderState.ATTENTION_REQUIRED)
    if not user.has_nwc or not settings.is_payment_method_enabled(PaymentMethod.NWC):
        return AgentOrderResult(order, subscription, payment, _result_state(subscription, payment))

    try:
        if payment is None:
            payment = payments_svc.create_payment(
                session,
                subscription,
                PaymentMethod.NWC,
                spec.billing_term,
                agent_order_id=order.id,
            )
        elif payment.status == PaymentStatus.PENDING:
            payment = payments_svc.check_and_settle_payment(session, payment)
    except payments_svc.PaymentProviderError:
        session.rollback()
        payment = _linked_payment(session, order.id)
        if payment is None:
            raise
        subscription = _order_subscription(session, order)
        return AgentOrderResult(order, subscription, payment, AgentOrderState.PAYMENT_PENDING)

    session.refresh(subscription)
    return AgentOrderResult(order, subscription, payment, _result_state(subscription, payment))
