"""
Rate limiting implementation using Redis.

Provides IP-based and user-based rate limiting using a fixed window
counter pattern stored in Redis. Each key is scoped to the current
window boundary, so counters reset exactly at the window start and the
reported reset_at / retry_after values are accurate.
"""

from __future__ import annotations

import time
from typing import Optional

from redis.asyncio import Redis

from app.core.config import get_settings
from app.utils.logger import get_logger
from app.utils.metrics import rate_limit_blocked_total

settings = get_settings()
logger = get_logger(__name__)


class RateLimiter:
    """Rate limiter using Redis as the backend store.

    Implements a fixed window counter per key, allowing configuration
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

    def _build_ip_key(self, ip: str, window_start: int) -> str:
        """Build a Redis key for IP-based rate limiting."""
        return f"ratelimit:ip:{ip}:{window_start}"

    def _build_user_key(self, user_id: str, window_start: int) -> str:
        """Build a Redis key for user-based rate limiting."""
        return f"ratelimit:user:{user_id}:{window_start}"

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

        now = int(time.time())
        window_start = now - (now % self.window_seconds)

        if user_id:
            key = self._build_user_key(user_id, window_start)
            limit = self.per_user_limit
        elif ip:
            key = self._build_ip_key(ip, window_start)
            limit = self.default_limit
        else:
            return True, {"allowed": True, "limit": 0, "remaining": 0, "reset_at": 0}

        return await self._check_window(key, limit, window_start, now)

    async def _check_window(
        self,
        key: str,
        limit: int,
        window_start: int,
        now: int,
    ) -> tuple[bool, dict]:
        """Check rate limit using a fixed window counter.

        The key already embeds the window boundary, so the counter is
        naturally scoped to the current window and resets when the
        window rolls over. TTL is one window (plus a small grace period)
        so stale keys are cleaned up shortly after the window ends.
        """
        reset_at = window_start + self.window_seconds

        try:
            current_count = await self.redis.incr(key)

            # Set expiry on first increment if not already set
            if current_count == 1:
                await self.redis.expire(key, self.window_seconds * 2)

            remaining = max(0, limit - current_count)
            is_allowed = current_count <= limit

            if not is_allowed:
                rate_limit_blocked_total.inc()
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
