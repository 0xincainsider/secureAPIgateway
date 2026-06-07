"""
Rate limiting implementation using Redis.

Provides IP-based and user-based rate limiting using a sliding window
counter pattern stored in Redis.
"""

from __future__ import annotations

import time
from typing import Optional

from redis.asyncio import Redis

from app.core.config import get_settings
from app.utils.logger import get_logger

settings = get_settings()
logger = get_logger(__name__)


class RateLimiter:
    """Rate limiter using Redis as the backend store.

    Implements a sliding window counter per key, allowing configuration
    of request limits per time window.
    """

    def __init__(self, redis_client: Redis) -> None:
        """Initialize the rate limiter.

        Args:
            redis_client: An async Redis client instance.
        """
        self.redis = redis_client
        self.default_limit = settings.rate_limit_default
        self.per_user_limit = settings.rate_limit_per_user
        self.window_seconds = settings.rate_limit_window_seconds

    def _build_ip_key(self, ip: str) -> str:
        """Build a Redis key for IP-based rate limiting."""
        return f"ratelimit:ip:{ip}"

    def _build_user_key(self, user_id: str) -> str:
        """Build a Redis key for user-based rate limiting."""
        return f"ratelimit:user:{user_id}"

    async def check_rate_limit(
        self,
        ip: str | None = None,
        user_id: str | None = None,
    ) -> tuple[bool, dict]:
        """Check if a request exceeds rate limits.

        Args:
            ip: The client IP address.
            user_id: The authenticated user ID.

        Returns:
            Tuple of (is_allowed, limit_info).
            limit_info contains: allowed, limit, remaining, reset_at, retry_after.
        """
        if not settings.enable_rate_limit:
            return True, {"allowed": True, "limit": 0, "remaining": 0, "reset_at": 0}

        if user_id:
            key = self._build_user_key(user_id)
            limit = self.per_user_limit
        elif ip:
            key = self._build_ip_key(ip)
            limit = self.default_limit
        else:
            return True, {"allowed": True, "limit": 0, "remaining": 0, "reset_at": 0}

        return await self._check_window(key, limit)

    async def _check_window(
        self,
        key: str,
        limit: int,
    ) -> tuple[bool, dict]:
        """Check rate limit using a fixed window counter.

        Uses Redis INCR with EXPIRE for atomic counter management.
        """
        now = int(time.time())
        window_start = now - (now % self.window_seconds)
        reset_at = window_start + self.window_seconds

        try:
            current_count = await self.redis.incr(key)

            # Set expiry on first increment if not already set
            if current_count == 1:
                await self.redis.expire(key, self.window_seconds * 2)

            remaining = max(0, limit - current_count)
            is_allowed = current_count <= limit

            if not is_allowed:
                logger.warning(
                    "Rate limit exceeded",
                    extra={
                        "key": key,
                        "current_count": current_count,
                        "limit": limit,
                        "reset_at": reset_at,
                    },
                )

            return is_allowed, {
                "allowed": is_allowed,
                "limit": limit,
                "remaining": remaining,
                "reset_at": reset_at,
                "retry_after": max(0, reset_at - now),
            }

        except Exception as exc:
            logger.error(
                "Rate limiter error",
                extra={"key": key, "error": str(exc)},
            )
            # Fail open - allow request if Redis is down
            return True, {
                "allowed": True,
                "limit": limit,
                "remaining": 1,
                "reset_at": 0,
            }
