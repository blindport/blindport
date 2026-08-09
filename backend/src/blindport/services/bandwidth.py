"""Privacy-preserving daily per-subscription bandwidth accounting."""

from __future__ import annotations

import asyncio
from contextlib import suppress
from datetime import UTC, date, datetime, timedelta
from uuid import UUID

from sqlmodel import Session, select

from ..config import settings
from ..core.models import RelayBandwidthCursor, Subscription, SubscriptionDailyBandwidth
from ..db import session_scope

_MAX_INT64 = 9_223_372_036_854_775_807


class BandwidthCounterDecreaseError(ValueError):
    """A newer relay sequence attempted to reduce a cumulative counter."""


class BandwidthUnknownSubscriptionError(ValueError):
    """A relay report referenced an unknown subscription public identifier."""


class BandwidthAggregateOverflowError(ValueError):
    """A daily aggregate cannot represent another positive cumulative delta."""


class BandwidthReport:
    """Validated inbound relay totals without traffic-level metadata."""

    def __init__(self, subscription_id: UUID, day: date, ingress_bytes: int, egress_bytes: int) -> None:
        self.subscription_id = subscription_id
        self.day = day
        self.ingress_bytes = ingress_bytes
        self.egress_bytes = egress_bytes


def ingest_daily_bandwidth(
    session: Session,
    *,
    edge_id: str,
    boot_id: UUID,
    sequence: int,
    reports: list[BandwidthReport],
) -> None:
    """Atomically apply higher-sequence cumulative counter deltas.

    Subscription row locks serialize new cursor and aggregate rows across relay
    edges. Existing cursor and aggregate rows are additionally locked on
    PostgreSQL. SQLite accepts the same SQLModel calls while its write lock
    provides the equivalent test behavior.
    """
    public_ids = {report.subscription_id for report in reports}
    subscriptions = session.exec(
        select(Subscription)
        .where(Subscription.public_id.in_(public_ids))  # type: ignore[union-attr]
        .order_by(Subscription.id)
        .with_for_update()
        .execution_options(populate_existing=True)
    ).all()
    by_public_id = {subscription.public_id: subscription for subscription in subscriptions}
    if len(by_public_id) != len(public_ids):
        raise BandwidthUnknownSubscriptionError("subscription not found")

    resolved = sorted(
        ((by_public_id[report.subscription_id], report) for report in reports),
        key=lambda pair: (pair[0].id or 0, pair[1].day),
    )
    for subscription, report in resolved:
        subscription_id = subscription.id
        if subscription_id is None:  # pragma: no cover, persisted rows always have an ID.
            raise RuntimeError("subscription has no internal ID")
        cursor = session.exec(
            select(RelayBandwidthCursor)
            .where(
                RelayBandwidthCursor.edge_id == edge_id,
                RelayBandwidthCursor.boot_id == boot_id,
                RelayBandwidthCursor.subscription_id == subscription_id,
                RelayBandwidthCursor.day == report.day,
            )
            .with_for_update()
            .execution_options(populate_existing=True)
        ).one_or_none()
        if cursor is not None and sequence <= cursor.sequence:
            continue
        previous_ingress = cursor.ingress_bytes if cursor is not None else 0
        previous_egress = cursor.egress_bytes if cursor is not None else 0
        if report.ingress_bytes < previous_ingress or report.egress_bytes < previous_egress:
            raise BandwidthCounterDecreaseError("cumulative bandwidth counter decreased")

        ingress_delta = report.ingress_bytes - previous_ingress
        egress_delta = report.egress_bytes - previous_egress
        aggregate = session.exec(
            select(SubscriptionDailyBandwidth)
            .where(
                SubscriptionDailyBandwidth.subscription_id == subscription_id,
                SubscriptionDailyBandwidth.day == report.day,
            )
            .with_for_update()
            .execution_options(populate_existing=True)
        ).one_or_none()
        if aggregate is None:
            aggregate = SubscriptionDailyBandwidth(
                subscription_id=subscription_id,
                day=report.day,
                ingress_bytes=ingress_delta,
                egress_bytes=egress_delta,
            )
            session.add(aggregate)
        else:
            if (
                ingress_delta > _MAX_INT64 - aggregate.ingress_bytes
                or egress_delta > _MAX_INT64 - aggregate.egress_bytes
            ):
                raise BandwidthAggregateOverflowError("daily bandwidth aggregate exceeds int64")
            aggregate.ingress_bytes += ingress_delta
            aggregate.egress_bytes += egress_delta
            session.add(aggregate)
        if cursor is None:
            session.add(
                RelayBandwidthCursor(
                    edge_id=edge_id,
                    boot_id=boot_id,
                    subscription_id=subscription_id,
                    day=report.day,
                    sequence=sequence,
                    ingress_bytes=report.ingress_bytes,
                    egress_bytes=report.egress_bytes,
                )
            )
        else:
            cursor.sequence = sequence
            cursor.ingress_bytes = report.ingress_bytes
            cursor.egress_bytes = report.egress_bytes
            session.add(cursor)


def cleanup_daily_bandwidth(session: Session, *, now: datetime | None = None) -> tuple[int, int]:
    """Delete bounded stale cursor rows before bounded expired daily aggregates."""
    current = now or datetime.now(UTC)
    source_cutoff = current.date() - timedelta(days=settings.BANDWIDTH_INGEST_MAX_AGE_DAYS)
    aggregate_cutoff = current.date() - timedelta(days=settings.BANDWIDTH_RETENTION_DAYS)
    source_rows = session.exec(
        select(RelayBandwidthCursor)
        .where(RelayBandwidthCursor.day < source_cutoff)
        .order_by(
            RelayBandwidthCursor.day,
            RelayBandwidthCursor.edge_id,
            RelayBandwidthCursor.subscription_id,
        )
        .limit(settings.BANDWIDTH_CLEANUP_BATCH_SIZE)
    ).all()
    for row in source_rows:
        session.delete(row)
    if len(source_rows) == settings.BANDWIDTH_CLEANUP_BATCH_SIZE:
        return len(source_rows), 0

    aggregate_rows = session.exec(
        select(SubscriptionDailyBandwidth)
        .where(SubscriptionDailyBandwidth.day < aggregate_cutoff)
        .order_by(SubscriptionDailyBandwidth.day, SubscriptionDailyBandwidth.subscription_id)
        .limit(settings.BANDWIDTH_CLEANUP_BATCH_SIZE)
    ).all()
    for row in aggregate_rows:
        session.delete(row)
    return len(source_rows), len(aggregate_rows)


async def run_bandwidth_cleanup(stop_event: asyncio.Event) -> None:
    """Run bounded cleanup periodically, independently of payment workers."""
    while not stop_event.is_set():
        with session_scope() as session:
            cleanup_daily_bandwidth(session)
            session.commit()
        with suppress(TimeoutError):
            await asyncio.wait_for(
                stop_event.wait(), timeout=settings.BANDWIDTH_CLEANUP_INTERVAL_SECONDS
            )
