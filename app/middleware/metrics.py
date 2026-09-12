"""
Prometheus metrics middleware.

Records request count, latency histogram, and active connections for
every HTTP request except the /metrics endpoint itself (to avoid
recursive counting).
"""

from __future__ import annotations

import time
from typing import Any

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

from app.utils.metrics import (
    active_connections,
    http_request_duration_seconds,
    http_requests_total,
)


class MetricsMiddleware(BaseHTTPMiddleware):
    """Middleware that collects Prometheus metrics for each request."""

    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        path = request.url.path

        # Skip metrics endpoint to avoid recursive counting
        if path == "/metrics":
            return await call_next(request)

        method = request.method
        start_time = time.time()
        active_connections.inc()

        try:
            response = await call_next(request)
            duration = time.time() - start_time

            http_requests_total.labels(
                method=method, endpoint=path, status=str(response.status_code)
            ).inc()
            http_request_duration_seconds.labels(method=method, endpoint=path).observe(
                duration
            )

            return response
        finally:
            active_connections.dec()