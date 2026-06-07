"""
Token blacklist for managing revoked and blacklisted tokens.

Uses Redis to store blacklisted token identifiers (JTI) with
TTL matching the original token's remaining lifetime.
"""

from __future__ import annotations

import time

from redis.asyncio import Redis

from app.utils.logger import get_logger

logger = get_logger(__name__)


class TokenBlacklist:
    """Manages token revocation using Redis.

    Stores blacklisted JTI (JWT ID) values with TTL equal to
    the token's remaining lifespan.
    """

    def __init__(self, redis_client: Redis) -> None:
        """Initialize the token blacklist.

        Args:
            redis_client: An async Redis client instance.
        """
        self.redis = redis_client
        self._prefix = "blacklist:token:"

    def _build_key(self, jti: str) -> str:
        """Build a Redis key for a blacklisted token."""
        return f"{self._prefix}{jti}"

    async def blacklist_token(
        self,
        jti: str,
        expires_at: int | None = None,
    ) -> bool:
        """Add a token to the blacklist.

        Args:
            jti: The JWT ID of the token to blacklist.
            expires_at: Unix timestamp when the token expires.
                        If None, uses a default TTL.

        Returns:
            True if the token was blacklisted, False otherwise.
        """
        key = self._build_key(jti)

        if expires_at:
            ttl = max(1, expires_at - int(time.time()))
        else:
            ttl = 3600  # Default 1 hour fallback

        try:
            await self.redis.setex(key, ttl, "revoked")
            logger.info(
                "Token blacklisted",
                extra={"jti": jti[:8] + "...", "ttl_seconds": ttl},
            )
            return True
        except Exception as exc:
            logger.error(
                "Failed to blacklist token",
                extra={"jti": jti[:8] + "...", "error": str(exc)},
            )
            return False

    async def is_blacklisted(self, jti: str) -> bool:
        """Check if a token has been blacklisted.

        Args:
            jti: The JWT ID to check.

        Returns:
            True if the token is blacklisted, False otherwise.
        """
        key = self._build_key(jti)

        try:
            result = await self.redis.exists(key)
            return bool(result)
        except Exception as exc:
            logger.error(
                "Failed to check token blacklist",
                extra={"jti": jti[:8] + "...", "error": str(exc)},
            )
            return False

    async def remove_from_blacklist(self, jti: str) -> bool:
        """Remove a token from the blacklist.

        Args:
            jti: The JWT ID to remove.

        Returns:
            True if the token was removed, False otherwise.
        """
        key = self._build_key(jti)

        try:
            result = await self.redis.delete(key)
            return bool(result)
        except Exception as exc:
            logger.error(
                "Failed to remove token from blacklist",
                extra={"jti": jti[:8] + "...", "error": str(exc)},
            )
            return False
