"""
Global rate limiting middleware.

Applies IP-based rate limiting (and user-based when a valid access
token is present) to every request, except a small allow-list of
administrative endpoints (health, metrics, docs).

Blocked requests receive HTTP 429 with an accurate Retry-After header.
Fail-open when Redis is unavailable or rate limiting is disabled.
"""

from __future__ import annotations

from typing import Any

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from app.core.dependencies import get_global_rate_limiter
from app.security.jwt import decode_token
from app.utils.logger import get_logger, log_security_event

logger = get_logger(__name__)

# Endpoints that are exempt from rate limiting
EXEMPT_PATHS = {
    "/health",
    "/metrics",
    "/api/v1/docs",
    "/api/v1/redoc",
    "/api/v1/openapi.json",
}


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Middleware that enforces global IP/user rate limits."""

    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        path = request.url.path

        if request.method == "OPTIONS" or path in EXEMPT_PATHS:
            return await call_next(request)

        rate_limiter = get_global_rate_limiter()
        if rate_limiter is None:
            return await call_next(request)

        client_ip = self._get_client_ip(request)
        user_id = self._extract_user_id(request)

        if user_id:
            is_allowed, limit_info = await rate_limiter.check_rate_limit(
                user_id=user_id
            )
        else:
            is_allowed, limit_info = await rate_limiter.check_rate_limit(ip=client_ip)

        if not is_allowed:
            log_security_event(
                logger,
                "rate_limit_exceeded",
                level=30,
                ip=client_ip,
                user_id=user_id,
                endpoint=path,
                method=request.method,
            )
            return JSONResponse(
                status_code=429,
                content={"detail": "Too many requests"},
                headers={"Retry-After": str(limit_info.get("retry_after", 60))},
            )

        return await call_next(request)

    @staticmethod
    def _get_client_ip(request: Request) -> str:
        """Extract client IP considering proxies."""
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return request.client.host if request.client else "unknown"

    @staticmethod
    def _extract_user_id(request: Request) -> str | None:
        """Extract the authenticated user ID from a Bearer token, if present.

        Stateless check (no DB access, no blacklist lookup) to avoid adding
        a round-trip on every request. Invalid/expired tokens fall back to
        IP-based limiting.
        """
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return None

        token = auth_header.split(" ", 1)[1]
        try:
            payload = decode_token(token)
            if payload.get("type") == "access" and payload.get("sub"):
                return payload["sub"]
        except Exception:
            return None
        return None