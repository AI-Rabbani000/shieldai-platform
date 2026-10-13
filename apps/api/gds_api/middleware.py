"""Request-scoped structured logging + HTTP metrics: one JSON log line per request
(method, path, status, latency), a request_id bound to every log line emitted while
handling it (via gds_api.logging_config's contextvars, echoed back as X-Request-ID for
client-side correlation), and a real Prometheus counter/histogram observation per
request (gds_api.metrics).
"""

import time
import uuid
from collections.abc import Awaitable, Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from gds_api.logging_config import bind_request_context, clear_request_context, get_logger
from gds_api.metrics import http_request_duration_seconds, http_requests_total

_log = get_logger("gds_api.request")


def _route_path(request: Request) -> str:
    # The matched route's template (e.g. "/missions/{mission_id}"), not the resolved
    # path with a real UUID in it - using the raw path as a metric label would create
    # unbounded cardinality (one Prometheus time series per mission ever created).
    route = request.scope.get("route")
    return str(route.path) if route is not None else request.url.path


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        request_id = str(uuid.uuid4())
        bind_request_context(request_id=request_id)
        start = time.perf_counter()
        try:
            response = await call_next(request)
        except Exception:
            _log.exception("request.failed", method=request.method, path=request.url.path)
            clear_request_context()
            raise

        duration_seconds = time.perf_counter() - start
        path_label = _route_path(request)
        http_requests_total.labels(
            method=request.method, path=path_label, status_code=str(response.status_code)
        ).inc()
        http_request_duration_seconds.labels(method=request.method, path=path_label).observe(
            duration_seconds
        )

        _log.info(
            "request.completed",
            method=request.method,
            path=request.url.path,
            status_code=response.status_code,
            latency_ms=round(duration_seconds * 1000, 2),
        )
        response.headers["X-Request-ID"] = request_id
        clear_request_context()
        return response
