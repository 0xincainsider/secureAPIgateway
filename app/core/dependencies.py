"""
FastAPI dependencies for dependency injection.

Provides reusable dependencies for authentication, authorization,
rate limiting, and database session management.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPBearer, OAuth2PasswordBearer
from jwt.exceptions import InvalidTokenError
from redis.asyncio import Redis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.database.session import get_session
from app.models.user import User
from app.security.jwt import decode_token
from app.security.rate_limiter import RateLimiter
from app.security.token_blacklist import TokenBlacklist
from app.utils.logger import get_logger

settings = get_settings()
logger = get_logger(__name__)

# OAuth2 password flow scheme for Swagger UI
oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl=f"{settings.api_v1_prefix}/auth/login",
)

# HTTP Bearer scheme for programmatic access
bearer_scheme = HTTPBearer(auto_error=False)

# Global singletons (set during app startup)
_redis: Redis | None = None
_rate_limiter: RateLimiter | None = None
_token_blacklist: TokenBlacklist | None = None


def set_redis_client(redis_client: Redis) -> None:
    """Set the global Redis client singleton.

    Called during application startup.
    """
    global _redis, _rate_limiter, _token_blacklist
    _redis = redis_client
    _rate_limiter = RateLimiter(redis_client)
    _token_blacklist = TokenBlacklist(redis_client)


def get_redis() -> Redis:
    """Dependency: Get the Redis client instance."""
    if _redis is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Redis connection not available",
        )
    return _redis


def get_rate_limiter() -> RateLimiter:
    """Dependency: Get the rate limiter instance."""
    if _rate_limiter is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Rate limiter not initialized",
        )
    return _rate_limiter


def get_token_blacklist() -> TokenBlacklist:
    """Dependency: Get the token blacklist instance."""
    if _token_blacklist is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Token blacklist not initialized",
        )
    return _token_blacklist


async def get_current_user(
    token: str = Depends(oauth2_scheme),
    session: AsyncSession = Depends(get_session),
    token_blacklist: TokenBlacklist = Depends(get_token_blacklist),
) -> User:
    """Dependency: Get the currently authenticated user from JWT.

    Args:
        token: The JWT access token from the Authorization header.
        session: The database session.
        token_blacklist: The token blacklist instance.

    Returns:
        The authenticated User object.

    Raises:
        HTTPException 401: If authentication fails.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = decode_token(token)
    except InvalidTokenError:
        raise credentials_exception

    # Verify it's an access token
    if payload.get("type") != "access":
        raise credentials_exception

    # Check if token is blacklisted
    jti = payload.get("jti")
    if jti and await token_blacklist.is_blacklisted(jti):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has been revoked",
        )

    user_id = payload.get("sub")
    if not user_id:
        raise credentials_exception

    try:
        user_uuid = UUID(user_id)
    except (ValueError, TypeError):
        raise credentials_exception

    result = await session.execute(
        select(User).where(User.id == user_uuid, User.is_active == True)
    )
    user = result.scalar_one_or_none()

    if user is None:
        raise credentials_exception

    return user


async def get_optional_user(
    request: Request,
    session: AsyncSession = Depends(get_session),
    token_blacklist: TokenBlacklist = Depends(get_token_blacklist),
) -> User | None:
    """Dependency: Get the current user if authenticated, None otherwise.

    Similar to get_current_user but does not raise if no valid token.
    Useful for endpoints that behave differently for authenticated users.
    """
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return None

    token = auth_header.split(" ", 1)[1]

    try:
        payload = decode_token(token)
        if payload.get("type") != "access":
            return None

        jti = payload.get("jti")
        if jti and await token_blacklist.is_blacklisted(jti):
            return None

        user_id = payload.get("sub")
        if not user_id:
            return None

        user_uuid = UUID(user_id)
        result = await session.execute(
            select(User).where(User.id == user_uuid, User.is_active == True)
        )
        return result.scalar_one_or_none()
    except Exception:
        return None
