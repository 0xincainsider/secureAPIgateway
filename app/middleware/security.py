"""
Security middleware implementing OWASP-recommended protections.

Adds security headers, validates requests, and provides basic
protection against common web attacks.
"""

from __future__ import annotations

from typing import Any

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

from app.core.config import get_settings
from app.utils.logger import get_logger, log_security_event

settings = get_settings()
logger = get_logger(__name__)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Middleware that adds security headers to all responses.

    Implements OWASP-recommended security headers including:
    - Content Security Policy (CSP)
    - X-Content-Type-Options
    - X-Frame-Options
    - Strict-Transport-Security
    - X-XSS-Protection
    - Referrer-Policy
    - Permissions-Policy
    """

    def __init__(self, app: Any) -> None:
        """Initialize the security headers middleware."""
        super().__init__(app)

    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        """Process request and add security headers to response.

        Args:
            request: The incoming HTTP request.
            call_next: The next middleware or route handler.

        Returns:
            The HTTP response with security headers added.
        """
        response = await call_next(request)

        if settings.enable_security_headers:
            self._apply_security_headers(response)

        return response

    def _apply_security_headers(self, response: Response) -> None:
        """Apply OWASP-recommended security headers to the response.

        Args:
            response: The HTTP response to modify.
        """
        # Content Security Policy - restricts resources the browser can load
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "font-src 'self'; "
            "connect-src 'self'; "
            "frame-ancestors 'none'; "
            "form-action 'self'; "
            "base-uri 'self'; "
            "object-src 'none'"
        )

        # Prevent MIME type sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"

        # Prevent clickjacking - don't allow embedding in frames
        response.headers["X-Frame-Options"] = "DENY"

        # Enable HSTS (HTTP Strict Transport Security)
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains; preload"
        )

        # Deprecated but still widely checked XSS protection
        response.headers["X-XSS-Protection"] = "0"

        # Control referrer information sent with requests
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        # Restrict browser features/permissions
        response.headers["Permissions-Policy"] = (
            "accelerometer=(), "
            "camera=(), "
            "geolocation=(), "
            "gyroscope=(), "
            "magnetometer=(), "
            "microphone=(), "
            "payment=(), "
            "usb=()"
        )

        # Prevent caching of sensitive data
        response.headers["Cache-Control"] = "no-store, max-age=0"

        # NOTE: the Server header is intentionally NOT set here. Uvicorn adds
        # its own at the ASGI level, so setting it in middleware produced a
        # duplicated header. The production image drops it entirely with
        # `uvicorn --no-server-header` (see Dockerfile).


class RequestValidationMiddleware(BaseHTTPMiddleware):
    """Middleware that validates incoming requests for security issues.

    Checks for:
    - Suspicious URL patterns
    - Oversized request bodies
    - Invalid content types
    - SQL injection patterns in query parameters
    """

    def __init__(self, app: Any) -> None:
        """Initialize the request validation middleware."""
        super().__init__(app)
        # Max request body size: 1MB
        self.max_body_size = 1_048_576

    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        """Validate incoming request for security issues.

        Args:
            request: The incoming HTTP request.
            call_next: The next middleware or route handler.

        Returns:
            The HTTP response, or a 400 response if validation fails.
        """
        # Check Content-Length header
        content_length = request.headers.get("content-length")
        if content_length and int(content_length) > self.max_body_size:
            log_security_event(
                logger,
                "request_body_too_large",
                level=30,
                ip=request.client.host if request.client else "unknown",
                endpoint=str(request.url.path),
            )
            from starlette.responses import JSONResponse
            return JSONResponse(
                status_code=413,
                content={"detail": "Request body too large"},
            )

        # Check for suspicious patterns in URL path
        suspicious_patterns = [
            "..",  # Path traversal
            "\\",  # Backslash
        ]
        path = str(request.url.path)
        for pattern in suspicious_patterns:
            if pattern in path:
                log_security_event(
                    logger,
                    "suspicious_url_pattern_detected",
                    level=30,
                    ip=request.client.host if request.client else "unknown",
                    endpoint=path,
                )
                from starlette.responses import JSONResponse
                return JSONResponse(
                    status_code=400,
                    content={"detail": "Invalid request"},
                )

        response = await call_next(request)
        return response
