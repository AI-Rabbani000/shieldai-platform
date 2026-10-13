"""Shared Temporal client connection helper. Every FastAPI request that needs to start
or query a workflow (gds_api.missions) creates a client via this function; the worker
(gds_api.worker_main) connects separately since it runs in its own process."""

from temporalio.client import Client

from gds_api.config import settings

TASK_QUEUE = "gds-missions"


async def get_temporal_client() -> Client:
    return await Client.connect(f"{settings.temporal_host}:{settings.temporal_port}")
