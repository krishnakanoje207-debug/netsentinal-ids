"""The activity strip: alerts raised and flows scored, per minute.

The two counts are not equally available. Alerts are this system's own record in
PostgreSQL and are always served. Flow counts come from ClickHouse and are best
effort: unset, unreachable, failing or slow, they are null with ``flows_available``
false. Never zero, which would claim a quiet network, and never an error for the
whole response, which would hide alerts that are there.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, Query

from netsentinel_api.config import Settings
from netsentinel_api.deps import AlertRepoDep, SettingsDep, require
from netsentinel_api.rbac import ALERTS_READ
from netsentinel_api.schemas import ActivityBucketOut, ActivityOut
from netsentinel_api.services.flows import FlowCountError, counter_from

logger = logging.getLogger("netsentinel.activity")

router = APIRouter(tags=["activity"])

MINUTE = timedelta(minutes=1)


# An unconfigured ClickHouse is a feature that is off, not a fault, so it is said once
# per process rather than on every dashboard poll. A configured one failing is a fault
# and is logged each time.
_said_unconfigured = False


def _flow_counts(settings: Settings, since: datetime) -> dict[datetime, int] | None:
    """Flows per minute, or None with the reason logged."""
    global _said_unconfigured
    try:
        counter = counter_from(settings)
        if counter is None:
            if not _said_unconfigured:
                logger.warning(
                    "activity served without flow counts: ClickHouse is not configured "
                    "(NETSENTINEL_CLICKHOUSE_URL, NETSENTINEL_CLICKHOUSE_USER, "
                    "NETSENTINEL_CLICKHOUSE_PASSWORD)"
                )
                _said_unconfigured = True
            return None
        return counter.per_minute(since)
    # ValueError is a URL that is not http or https.
    except (FlowCountError, ValueError) as exc:
        logger.warning("activity served without flow counts: %s", exc)
        return None


@router.get("/activity", response_model=ActivityOut)
def activity(
    alerts: AlertRepoDep,
    settings: SettingsDep,
    _: Annotated[object, Depends(require(ALERTS_READ))],
    minutes: Annotated[int, Query(ge=5, le=240)] = 60,
) -> ActivityOut:
    """One bucket per minute, oldest first; the newest is the current, partial minute."""
    newest = datetime.now(timezone.utc).replace(second=0, microsecond=0)
    starts = [newest - MINUTE * back for back in range(minutes - 1, -1, -1)]

    raised = alerts.per_minute(starts[0])
    flows = _flow_counts(settings, starts[0])
    return ActivityOut(
        minutes=minutes,
        until=newest + MINUTE,
        buckets=[
            ActivityBucketOut(
                start=start,
                alerts=raised.get(start, 0),
                flows=None if flows is None else flows.get(start, 0),
            )
            for start in starts
        ],
        flows_available=flows is not None,
    )
