"""
Secure API Gateway - FastAPI Application Entry Point.

Initializes the application with security middleware, rate limiting,
structured logging, Prometheus metrics, and all API routes.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any

import redis.asyncio as aioredis
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app.api.v1.admin import router as admin_router
from app.api.v1.auth import router as auth_router
from app.core.config import get_settings
from app.core.dependencies import set_redis_client
from app.database.session import dispose_engine, get_engine
from app.middleware.logging import LoggingMiddleware
from app.middleware.metrics import MetricsMiddleware
from app.middleware.rate_limit import RateLimitMiddleware
from app.middleware.security import RequestValidationMiddleware, SecurityHeadersMiddleware
from app.models.user import User  # noqa: F401 - Register model for Alembic
from app.models.refresh_token import RefreshToken  # noqa: F401
from app.models.audit_log import AuditLog  # noqa: F401
from app.utils.logger import get_logger

settings = get_settings()
logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> Any:
    """Application lifecycle manager.

    Handles startup and shutdown events including:
    - Redis connection
    - Database connection pool (schema is managed by Alembic migrations)
    """
    logger.info(
        "Starting Secure API Gateway",
        extra={
            "version": settings.app_version,
            "environment": settings.app_env,
        },
    )

    # Initialize Redis connection
    redis_client = aioredis.from_url(
        settings.redis_url,
        decode_responses=True,
        socket_connect_timeout=5,
        socket_timeout=5,
        retry_on_timeout=True,
    )

    # Verify Redis connection
    try:
        await redis_client.ping()
        logger.info("Redis connection established")
    except Exception as exc:
        logger.warning(
            "Redis connection failed - rate limiting and token blacklist disabled",
            extra={"error": str(exc)},
        )

    # Set global Redis client for dependencies
    set_redis_client(redis_client)

    # Database schema is applied via Alembic migrations (see migrations/).
    # Run `alembic upgrade head` before starting the service (the Docker
    # entrypoint does this automatically).
    get_engine()

    yield

    # Shutdown: close connections
    logger.info("Shutting down Secure API Gateway")
    await redis_client.close()
    await dispose_engine()


# Create FastAPI application
app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="""
    Secure API Gateway with authentication, rate limiting,
    structured logging, observability, and OWASP security controls.

    ## Features
    * JWT-based authentication with refresh tokens
    * OAuth2 Password Flow (compatible with Swagger UI)
    * Rate limiting (IP and user-based) via global middleware
    * Role-based access control (superuser admin endpoints)
    * Structured JSON logging
    * Security audit trail
    * Prometheus metrics
    * OWASP security headers
    """,
    docs_url=f"{settings.api_v1_prefix}/docs",
    redoc_url=f"{settings.api_v1_prefix}/redoc",
    openapi_url=f"{settings.api_v1_prefix}/openapi.json",
    lifespan=lifespan,
    contact={
        "name": "Secure API Gateway Team",
        "url": "https://github.com/secure-api-gateway",
    },
    license_info={
        "name": "MIT",
    },
)

# ---------------------------------------------------------------------------
# Middleware setup.
#
# IMPORTANT: Starlette builds the middleware stack in REVERSE order of
# registration (the last middleware added is the outermost). The sequence
# below therefore lists middlewares from innermost to outermost, so the
# effective stack is:
#
#   CORS -> TrustedHost -> Metrics -> RateLimit -> Logging
#          -> RequestValidation -> SecurityHeaders -> app
#
# - CORS is outermost so preflight (OPTIONS) requests are handled first.
# - TrustedHost validates the Host header early (host-header injection).
# - Metrics is outside RateLimit so blocked requests are still counted.
# - RateLimit short-circuits with 429 before reaching the app.
# ---------------------------------------------------------------------------


# Security headers (innermost)
app.add_middleware(SecurityHeadersMiddleware)

# Request validation (SQL injection, path traversal, body size)
app.add_middleware(RequestValidationMiddleware)

# Structured request/response logging
app.add_middleware(LoggingMiddleware)

# Global rate limiting (IP- and user-based)
app.add_middleware(RateLimitMiddleware)

# Prometheus metrics
if settings.prometheus_enabled:
    app.add_middleware(MetricsMiddleware)

# Host header validation (uses ALLOWED_HOSTS)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.allowed_hosts_list)

# CORS (outermost)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=settings.cors_allow_credentials,
    allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
    allow_headers=[
        "Authorization",
        "Content-Type",
        "X-Request-ID",
        "X-Forwarded-For",
    ],
    expose_headers=["X-Request-ID"],
    max_age=3600,
)

# --- Prometheus Metrics Endpoint ---
if settings.prometheus_enabled:
    import os

    from prometheus_client import CollectorRegistry, generate_latest, multiprocess
    from starlette.responses import Response

    @app.get("/metrics", include_in_schema=False)
    async def metrics():
        """Prometheus metrics endpoint.

        Uses the multiprocess collector when `prometheus_multiproc_dir` is
        set (multi-worker deployments), merging metrics from every worker.
        Falls back to the default single-process registry otherwise.
        """
        if os.environ.get("prometheus_multiproc_dir"):
            registry = CollectorRegistry()
            multiprocess.MultiProcessCollector(registry)
            data = generate_latest(registry)
        else:
            data = generate_latest()
        return Response(content=data, media_type="text/plain")

    logger.info("Prometheus metrics enabled")

# --- Exception Handlers ---


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    """Handle HTTP exceptions with structured error responses."""
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail},
        headers=getattr(exc, "headers", None) or {},
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Handle unexpected exceptions without leaking sensitive information."""
    logger.error(
        "Unhandled exception",
        extra={
            "endpoint": str(request.url.path),
            "method": request.method,
            "error": str(exc),
        },
    )

    # Return generic error message (no stack traces in production)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "An internal error occurred"},
    )


# --- Health Check ---


@app.get(
    "/health",
    tags=["Health"],
    summary="Health check endpoint",
    description="Returns the health status of the API gateway.",
)
async def health_check():
    """Health check endpoint for monitoring and orchestration."""
    return {
        "status": "healthy",
        "version": settings.app_version,
        "environment": settings.app_env,
    }


# --- Include Routers ---

app.include_router(auth_router, prefix=settings.api_v1_prefix)
app.include_router(admin_router, prefix=settings.api_v1_prefix)