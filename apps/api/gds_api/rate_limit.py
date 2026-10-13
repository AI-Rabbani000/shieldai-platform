"""Small Redis INCR+EXPIRE rate limiter - no new third-party dependency (Redis is
already a first-class dependency via gds_api.memory), avoiding an unverified
compatibility/maintenance-risk package for what is a well-known ~20-line pattern.

Two flavors: ip_rate_limit (unauthenticated routes, keyed by client IP - protects
POST /auth/login against brute force) and tenant_rate_limit (authenticated routes,
keyed by tenant_id - protects POST /missions, which triggers real, metered Anthropic
API usage per call).
"""

from collections.abc import Awaitable, Callable

from fastapi import Depends, HTTPException, Request, status
from redis.asyncio import Redis

from gds_api.config import settings
from gds_api.security import CurrentUser, get_current_user


def _get_redis() -> Redis:
    # Fresh client per call, not a module-level singleton - same reasoning as
    # gds_api.memory._get_redis(): redis-py's connection pool binds to whichever event
    # loop first used it, which breaks across the test suite's asyncio.run()-per-test
    # pattern. Uvicorn only ever runs one loop, so this costs nothing there either.
    return Redis(host=settings.redis_host, port=settings.redis_port, decode_responses=True)


async def _check_and_increment(key: str, max_requests: int, window_seconds: int) -> None:
    async with _get_redis() as r:
        count = await r.incr(key)
        if count == 1:
            await r.expire(key, window_seconds)
        if count > max_requests:
            raise HTTPException(
                status.HTTP_429_TOO_MANY_REQUESTS,
                f"Rate limit exceeded: max {max_requests} requests per {window_seconds}s",
            )


def ip_rate_limit(
    key_prefix: str, *, max_requests: int, window_seconds: int
) -> Callable[[Request], Awaitable[None]]:
    async def _dependency(request: Request) -> None:
        client_host = request.client.host if request.client else "unknown"
        await _check_and_increment(
            f"ratelimit:{key_prefix}:{client_host}", max_requests, window_seconds
        )

    return _dependency


def tenant_rate_limit(
    key_prefix: str, *, max_requests: int, window_seconds: int
) -> Callable[[CurrentUser], Awaitable[None]]:
    async def _dependency(current_user: CurrentUser = Depends(get_current_user)) -> None:
        await _check_and_increment(
            f"ratelimit:{key_prefix}:{current_user.tenant_id}", max_requests, window_seconds
        )

    return _dependency
