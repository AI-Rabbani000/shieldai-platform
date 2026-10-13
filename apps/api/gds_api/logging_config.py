"""Structured JSON logging, shared by the FastAPI process (main.py) and the Temporal
worker process (worker_main.py) - both call configure_logging() once at startup.

request_id/tenant_id/user_id are bound via contextvars so every log line emitted while
handling a given request carries them automatically, without threading them through
every function call by hand.
"""

import logging
import uuid
from typing import Any

import structlog


def configure_logging() -> None:
    logging.basicConfig(format="%(message)s", level=logging.INFO)

    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(logging.INFO),
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str) -> Any:
    return structlog.get_logger(name)


def bind_request_context(
    *, request_id: str | None = None, tenant_id: str | None = None, user_id: str | None = None
) -> None:
    structlog.contextvars.bind_contextvars(
        request_id=request_id or str(uuid.uuid4()),
        **({"tenant_id": tenant_id} if tenant_id else {}),
        **({"user_id": user_id} if user_id else {}),
    )


def clear_request_context() -> None:
    structlog.contextvars.clear_contextvars()
