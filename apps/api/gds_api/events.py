"""Phase 10.4: Redis Streams-backed event publishing for live mission progress. Streams
(XADD/XREAD), not plain Pub/Sub - Pub/Sub has no persistence, so a browser tab opening a
mission page after it's already progressed, or reconnecting after a real Docker-Desktop/
WSL2 network hiccup, would silently miss every earlier event. Redis Streams map onto
SSE's built-in Last-Event-ID reconnect mechanism (stream entry ID -> SSE id: field) -
see docs/adr/0011 for the full design.

Every event is deliberately minimal - {"type": ..., "mission_id": ...} - the frontend's
job on receiving ANY event is just "refetch the real server-rendered state now" (the
exact same fetch a client-side router.refresh() already does for polling), not to
reconcile a hand-rolled wire protocol client-side. This is what makes the SSE upgrade a
real timing improvement (event-driven instead of a 3s poll) without needing a parallel,
harder-to-verify client-side state model.
"""

import json
from datetime import UTC, datetime
from typing import Any

from redis.asyncio import Redis

from gds_api.config import settings
from gds_api.logging_config import get_logger

_logger = get_logger("gds_api.events")

# Bounds real memory growth per mission's stream - a mission with more real events than
# this only matters for a live-watching client anyway, not for replay of ancient history.
_STREAM_MAXLEN = 200
_STREAM_TTL_SECONDS = 3600


def _get_redis() -> Redis:
    # Same "fresh client per call" pattern as memory.py's _get_redis() and the same
    # reason: an async connection pool binds to whichever event loop first used it.
    # Publish calls here are short-lived (one XADD), so this costs nothing extra.
    return Redis(host=settings.redis_host, port=settings.redis_port, decode_responses=True)


def mission_stream_key(mission_id: str) -> str:
    return f"mission:{mission_id}:events"


async def publish_mission_event(mission_id: str, event_type: str, **data: Any) -> None:
    """Called from workflows/activities.py after each committed state transition
    (task created, approval required, task completed/denied, mission finished).
    Best-effort and deliberately swallows its own errors - a publish failure must never
    fail the real mission work it's reporting on. The polling fallback (existing
    router.refresh()-based AutoRefresh) means a lost event is a UX delay, not silent
    data loss - the real state is always in Postgres regardless of whether this
    publish succeeded.

    Phase 15, Part M: adds a real server-side `timestamp` to every event - free (no
    extra query), useful for ordering/debugging beyond what the Redis Stream entry ID
    alone conveys. Does not add workflow_run_id/tenant_id/step_id/agent_id as separate
    fields - see docs/architecture/workflow-reconciliation.md's "Redis/SSE role" section
    for why: mission_id is already the sole correlation key every real consumer
    (streaming.py's tenant check, the frontend's refetch-on-any-event pattern) needs,
    and per-event-type fields (task_id, verb, etc.) already exist where relevant. Adding
    the rest would be speculative enrichment with no current real consumer."""
    payload = json.dumps(
        {
            "type": event_type,
            "mission_id": mission_id,
            "timestamp": datetime.now(UTC).isoformat(),
            **data,
        },
        default=str,
    )
    try:
        async with _get_redis() as r:
            key = mission_stream_key(mission_id)
            await r.xadd(key, {"payload": payload}, maxlen=_STREAM_MAXLEN, approximate=True)
            await r.expire(key, _STREAM_TTL_SECONDS)
    except Exception:  # noqa: BLE001 - best-effort, logged not raised, see docstring
        _logger.warning("events.publish_failed", mission_id=mission_id, event_type=event_type)
