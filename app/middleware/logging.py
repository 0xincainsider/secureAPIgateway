"""
Logging middleware for structured request and response logging.

Provides request ID generation, timing, and structured JSON logging
for every HTTP request processed by the gateway.
"""

from __future__ import annotations

import time
import uuid
from typing import Any

from starlette.datastructures import Headers
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp

from app.utils.logger import get_logger, log_security_event

logger = get_logger(__name__)


class LoggingMiddleware(BaseHTTPMiddleware):
    """Middleware for structured request/response logging.

    Adds a unique request ID to each request, logs request details,
    measures response time, and logs the complete request lifecycle.
    """

    def __init__(self, app: ASGIApp) -> None:
        """Initialize the logging middleware."""
        super().__init__(app)

    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        """Process an incoming request with structured logging.

        Args:
            request: The incoming HTTP request.
            call_next: The next middleware or route handler.

        Returns:
            The HTTP response.
        """
        # Generate and attach request ID
        request_id = uuid.uuid4().hex[:16]
        request.state.request_id = request_id

        # Extract client IP considering proxies
        forwarded = request.headers.get("X-Forwarded-For")
        client_ip = (
            forwarded.split(",")[0].strip()
            if forwarded
            else (request.client.host if request.client else "unknown")
        )
        request.state.client_ip = client_ip

        # Start timing
        start_time = time.time()

        # Log incoming request
        logger.info(
            "Incoming request",
            extra={
                "request_id": request_id,
                "ip": client_ip,
                "endpoint": str(request.url.path),
                "method": request.method,
                "user_agent": request.headers.get("User-Agent", "unknown"),
            },
        )

        try:
            response = await call_next(request)
            duration_ms = int((time.time() - start_time) * 1000)

            # Log completed request
            logger.info(
                "Request completed",
                extra={
                    "request_id": request_id,
                    "ip": client_ip,
                    "endpoint": str(request.url.path),
                    "method": request.method,
                    "status_code": response.status_code,
                    "duration_ms": duration_ms,
                },
            )

            # Add request ID to response headers
            response.headers["X-Request-ID"] = request_id

            return response

        except Exception as exc:
            duration_ms = int((time.time() - start_time) * 1000)

            logger.error(
                "Request failed",
                extra={
                    "request_id": request_id,
                    "ip": client_ip,
                    "endpoint": str(request.url.path),
                    "method": request.method,
                    "duration_ms": duration_ms,
                    "error": str(exc),
                },
            )
            raise
