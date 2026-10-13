"""Phase 10.4: real-time SSE streaming of a mission's (or a real chat turn's - a turn
IS a Mission, see gds_api.models.Mission.conversation_thread_id) progress, replacing the
frontend's poll-every-3-seconds AutoRefresh with genuine event-driven updates. Real
events (gds_api.events, published from workflows/activities.py after each committed
state transition) via Redis Streams, not a second, separate conversation-level stream -
a conversation's live-updating need is always "watch the one currently-running turn,"
and that turn already has its own real mission_id to stream directly. See
docs/adr/0011 for the full design and the real spike that verified StreamingResponse
works correctly (progressive delivery, real disconnect-cancellation) behind this app's
real RequestLoggingMiddleware.
"""

import json
import uuid
from collections.abc import AsyncGenerator

from fastapi import APIRouter, Depends, HTTPException, Request, status
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.responses import StreamingResponse

from gds_api.config import settings
from gds_api.db import get_db
from gds_api.events import mission_stream_key
from gds_api.logging_config import get_logger
from gds_api.metrics import sse_connections_active, sse_events_sent_total, sse_heartbeats_sent_total
from gds_api.models import Mission
from gds_api.security import CurrentUser, require_permission

router = APIRouter(tags=["streaming"])

_logger = get_logger("gds_api.streaming")

# How long a single XREAD BLOCK call waits for a new entry before looping again - not a
# poll interval (XREAD returns immediately the instant a real event arrives; this is
# only the idle-connection heartbeat cadence, keeping some proxies from timing out).
_BLOCK_MS = 15_000


def _get_stream_redis() -> Redis:
    # Deliberately NOT the same "fresh client per call" pattern memory.py/events.py use
    # for short-lived publish calls - a stream subscriber needs one connection held open
    # for the life of the browser connection, with its own lifecycle (opened when the
    # SSE request starts, closed in the generator's finally block), not reconnect-per-
    # event. Still fresh per *request* (never a module-level singleton reused across
    # requests/event loops), same underlying reason as the other _get_redis() functions.
    return Redis(host=settings.redis_host, port=settings.redis_port, decode_responses=True)


async def _mission_event_stream(
    request: Request, mission_id: str, last_id: str
) -> AsyncGenerator[str, None]:
    redis = _get_stream_redis()
    stream_key = mission_stream_key(mission_id)
    sse_connections_active.inc()
    try:
        while True:
            if await request.is_disconnected():
                break
            try:
                result = await redis.xread({stream_key: last_id}, block=_BLOCK_MS, count=20)
            except Exception as exc:
                _logger.warning(
                    "streaming.xread_failed",
                    mission_id=mission_id,
                    error=str(exc),
                    error_type=type(exc).__name__,
                )
                break
            if not result:
                # Idle heartbeat (a comment line - ignored by EventSource, but keeps the
                # connection visibly alive for anything watching raw bytes, e.g. curl -N).
                # EDP-008 Part 8 found this specific yield doesn't reliably reach the
                # client (see docs/reviews/phase-21-8-api-and-sse-hardening.md) -
                # counting it here regardless, so a real deployment's Grafana dashboard
                # can show connections staying open with zero matching heartbeat growth,
                # the exact signature of that live-verified defect.
                sse_heartbeats_sent_total.inc()
                yield ": heartbeat\n\n"
                continue
            # redis-py's XReadResponse type is a real union (list[list[Any]] | dict[...]
            # | dict[...]) covering response shapes this async client with a plain
            # streams dict never actually returns - narrowing here is a real runtime
            # safety check, not just satisfying mypy.
            assert isinstance(result, list)
            for _stream_name, entries in result:
                for entry_id, fields in entries:
                    last_id = entry_id
                    payload = fields.get("payload", "{}")
                    try:
                        parsed = json.loads(payload)
                    except json.JSONDecodeError:
                        parsed = {}
                    sse_events_sent_total.labels(
                        event_type=str(parsed.get("type", "unknown"))
                    ).inc()
                    yield f"id: {entry_id}\ndata: {payload}\n\n"
                    if parsed.get("type") == "mission_finished":
                        return
    finally:
        sse_connections_active.dec()
        await redis.aclose()


@router.get("/missions/{mission_id}/stream")
async def stream_mission(
    mission_id: uuid.UUID,
    request: Request,
    current_user: CurrentUser = Depends(require_permission("missions:read")),
    db: AsyncSession = Depends(get_db),
) -> StreamingResponse:
    mission = await db.get(Mission, mission_id)
    if mission is None or mission.tenant_id != current_user.tenant_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Mission not found")

    # Real reconnect support: EventSource automatically resends whatever id: it last saw
    # as the Last-Event-ID request header on reconnect - Redis Streams' own entry IDs
    # map onto this directly, so a browser tab that reconnects after a real network
    # hiccup resumes exactly where it left off instead of silently missing events (the
    # real gap plain Redis Pub/Sub would have left - see docs/adr/0011).
    last_id = request.headers.get("Last-Event-ID", "0")
    return StreamingResponse(
        _mission_event_stream(request, str(mission_id), last_id),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            # Disables response buffering in nginx-style reverse proxies that would
            # otherwise defeat real-time delivery - irrelevant to this local dev stack
            # today, but a real, correct header to send regardless.
            "X-Accel-Buffering": "no",
        },
    )
