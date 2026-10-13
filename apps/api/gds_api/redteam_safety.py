"""Phase 8: the real safety boundary every Red Team tool must pass through before it
runs - checked in this exact order (cheapest, most global check first) by
gds_api.tool_gateway's three recon tools:

1. ensure_not_emergency_stopped - a real, per-tenant kill switch (RedTeamSafetyState).
   Engaging it (POST /red-team/emergency-stop) blocks every Red Team tool call
   immediately, tenant-wide, regardless of any target's authorization.
2. ensure_target_authorized - the target must have a real, unexpired, unrevoked
   AuthorizedTarget row (see gds_api.models.AuthorizedTarget's docstring for why this is
   a separate, stronger record than Watchlist).
3. ensure_rate_limit_ok - a real Redis INCR+EXPIRE limiter, scoped per
   tenant+target and bounded by that target's own max_actions_per_hour (not a single
   global constant - the authorizer sets the bound per target).

None of these three functions may be bypassed: every Red Team tool in tool_gateway.py
calls all three before doing anything else, and all three are exercised for real (not
mocked) in tests/test_redteam.py.

Every refusal writes a real audit event here, not just on success: gds_api.tool_gateway.
execute_tool only audits successful calls (see its own docstring), which would leave a
blind spot for exactly the events a safety boundary most needs recorded - who tried to
run a Red Team tool against what, and why it was refused.
"""

import uuid
from datetime import UTC, datetime
from typing import NoReturn

from redis.asyncio import Redis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from gds_api.audit import record_audit_event
from gds_api.config import settings
from gds_api.models import AuthorizedTarget, RedTeamSafetyState


def _get_redis() -> Redis:
    # Fresh client per call, not a module-level singleton - same event-loop-binding
    # reasoning as gds_api.memory._get_redis()/gds_api.rate_limit._get_redis().
    return Redis(host=settings.redis_host, port=settings.redis_port, decode_responses=True)


async def get_safety_state(db: AsyncSession, tenant_id: uuid.UUID) -> RedTeamSafetyState:
    state = await db.get(RedTeamSafetyState, tenant_id)
    if state is None:
        state = RedTeamSafetyState(tenant_id=tenant_id, emergency_stop_engaged=False)
        db.add(state)
        await db.flush()
    return state


async def _refuse(
    db: AsyncSession, *, tenant_id: uuid.UUID, user_id: uuid.UUID, reason: str, target: str | None
) -> NoReturn:
    await record_audit_event(
        db,
        tenant_id=tenant_id,
        user_id=user_id,
        action="redteam.refused",
        detail={"reason": reason, "target": target},
    )
    await db.commit()
    raise ValueError(reason)


async def ensure_not_emergency_stopped(
    db: AsyncSession, tenant_id: uuid.UUID, user_id: uuid.UUID
) -> None:
    state = await get_safety_state(db, tenant_id)
    if state.emergency_stop_engaged:
        await _refuse(
            db,
            tenant_id=tenant_id,
            user_id=user_id,
            target=None,
            reason=(
                "Red Team emergency stop is engaged for this tenant - all "
                "offensive-adjacent tools are blocked until a platform_owner clears it "
                "(POST /red-team/emergency-stop/clear)"
            ),
        )


async def ensure_target_authorized(
    db: AsyncSession, tenant_id: uuid.UUID, user_id: uuid.UUID, target: str
) -> AuthorizedTarget:
    row = (
        await db.execute(
            select(AuthorizedTarget).where(
                AuthorizedTarget.tenant_id == tenant_id,
                AuthorizedTarget.target == target,
                AuthorizedTarget.status == "active",
            )
        )
    ).scalar_one_or_none()
    if row is None:
        await _refuse(
            db,
            tenant_id=tenant_id,
            user_id=user_id,
            target=target,
            reason=(
                f"'{target}' has no active authorization record - Red Team tools refuse "
                "any target without an explicit, scoped AuthorizedTarget (POST "
                "/red-team/targets)"
            ),
        )
    now = datetime.now(UTC)
    if now < row.valid_from or now > row.valid_until:
        await _refuse(
            db,
            tenant_id=tenant_id,
            user_id=user_id,
            target=target,
            reason=(
                f"'{target}'s authorization window has expired or not yet started "
                f"(valid {row.valid_from.isoformat()} to {row.valid_until.isoformat()})"
            ),
        )
    return row


async def ensure_rate_limit_ok(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    user_id: uuid.UUID,
    target: str,
    max_actions_per_hour: int,
) -> None:
    key = f"redteam:ratelimit:{tenant_id}:{target}"
    async with _get_redis() as r:
        count = await r.incr(key)
        if count == 1:
            await r.expire(key, 3600)
    if count > max_actions_per_hour:
        await _refuse(
            db,
            tenant_id=tenant_id,
            user_id=user_id,
            target=target,
            reason=(
                f"Rate limit exceeded for '{target}': max {max_actions_per_hour} Red "
                "Team actions per hour, set by this target's own authorization record"
            ),
        )
