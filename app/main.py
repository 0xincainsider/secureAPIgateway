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
from sqlalchemy import select

from app.api.v1.auth import router as auth_router
from app.core.config import get_settings
from app.core.dependencies import set_redis_client
from app.database.session import Base, dispose_engine, get_engine, get_session_factory
from app.middleware.logging import LoggingMiddleware
from app.middleware.security import RequestValidationMiddleware, SecurityHeadersMiddleware
from app.models.user import User  # noqa: F401 - Register model for Alembic
from app.models.refresh_token import RefreshToken  # noqa: F401
from app.models.audit_log import AuditLog  # noqa: F401
from app.utils.logger import get_logger, log_security_event

settings = get_settings()
logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> Any:
    """Application lifecycle manager.

    Handles startup and shutdown events including:
    - Database connection pool initialization
    - Redis connection
    - Metrics setup
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

    # Create database tables (in production, use Alembic migrations)
    try:
        engine = get_engine()
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        logger.info("Database tables verified/created")
    except Exception as exc:
        logger.warning(
            "Database initialization issue - ensure PostgreSQL is available",
            extra={"error": str(exc)},
        )

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
    * Rate limiting (IP and user-based)
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

# --- Middleware Setup (order matters: first added = outermost) ---

# CORS middleware
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

# Security headers middleware
app.add_middleware(SecurityHeadersMiddleware)

# Request validation middleware (SQL injection, path traversal, etc.)
app.add_middleware(RequestValidationMiddleware)

# Structured logging middleware
app.add_middleware(LoggingMiddleware)

# --- Prometheus Metrics ---
if settings.prometheus_enabled:
    from prometheus_client import Counter, Gauge, Histogram, generate_latest
    from starlette.responses import Response

    # Define metrics
    http_requests_total = Counter(
        "http_requests_total",
        "Total HTTP requests",
        ["method", "endpoint", "status"],
    )
    http_request_duration_seconds = Histogram(
        "http_request_duration_seconds",
        "HTTP request duration in seconds",
        ["method", "endpoint"],
        buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
    )
    auth_login_success_total = Counter(
        "auth_login_success_total",
        "Total successful logins",
    )
    auth_login_failure_total = Counter(
        "auth_login_failure_total",
        "Total failed logins",
    )
    rate_limit_blocked_total = Counter(
        "rate_limit_blocked_total",
        "Total requests blocked by rate limiter",
    )
    active_connections = Gauge(
        "active_connections",
        "Number of active connections",
    )

    @app.middleware("http")
    async def metrics_middleware(request: Request, call_next: Any) -> Any:
        """Middleware that collects Prometheus metrics for each request."""
        import time

        method = request.method
        path = request.url.path

        # Skip metrics endpoint to avoid recursive counting
        if path == "/metrics":
            return await call_next(request)

        start_time = time.time()
        active_connections.inc()

        try:
            response = await call_next(request)
            duration = time.time() - start_time
            status_code = str(response.status_code)

            http_requests_total.labels(method=method, endpoint=path, status=status_code).inc()
            http_request_duration_seconds.labels(method=method, endpoint=path).observe(duration)

            return response
        except HTTPException as exc:
            duration = time.time() - start_time
            status_code = str(exc.status_code)

            http_requests_total.labels(method=method, endpoint=path, status=status_code).inc()
            http_request_duration_seconds.labels(method=method, endpoint=path).observe(duration)

            raise
        finally:
            active_connections.dec()

    @app.get("/metrics", include_in_schema=False)
    async def metrics():
        """Prometheus metrics endpoint."""
        return Response(content=generate_latest(), media_type="text/plain")

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
