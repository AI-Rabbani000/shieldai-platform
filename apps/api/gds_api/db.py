from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from gds_api.config import settings

# NullPool: every connection is opened fresh and closed immediately after use, rather than
# kept in a pool tied to whichever event loop created it. The test suite runs its fixture
# setup/teardown (each its own asyncio.run(), i.e. its own event loop) alongside Temporal
# activities (gds_api.workflows.activities, each opens its own session per call, and the
# worker process may in principle run activities across different loops/threads). A real,
# pooled connection created on one of those loops breaks when reused from another
# ("Event loop is closed") - confirmed by hitting exactly that failure with the default
# pool. Uvicorn only ever runs on a single loop, so this costs nothing there either way.
#
# Phase 5 tried splitting this into a second, pooled engine used only by get_db() (FastAPI
# HTTP routes), reasoning that uvicorn's single persistent event loop never crosses the
# hazard above. That reasoning held for the real running app, but not for this test suite:
# Starlette's TestClient does not guarantee one stable event loop across every request
# made through a given instance - a single test making two sequential calls (login, then
# a second endpoint) hit the identical "Event loop is closed" / asyncpg "another operation
# is in progress" failures the pooled engine reintroduced. Reverted rather than chase
# escalating workarounds around a test harness that doesn't guarantee the assumption a
# pooled get_db() needs. Revisit only alongside a different test-execution strategy (e.g.
# a real running server hit over HTTP instead of TestClient's in-process transport).
engine = create_async_engine(settings.postgres_async_dsn, poolclass=NullPool)
async_session_factory = async_sessionmaker(engine, expire_on_commit=False)


async def get_db() -> AsyncGenerator[AsyncSession]:
    async with async_session_factory() as session:
        yield session
