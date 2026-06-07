"""
Core security utilities for password hashing and verification.

Uses bcrypt directly for secure password storage.
All configuration is loaded from environment variables.
"""

from __future__ import annotations

import bcrypt

from app.core.config import get_settings

settings = get_settings()


def hash_password(password: str) -> str:
    """Hash a password using bcrypt.

    Args:
        password: The plain-text password to hash.

    Returns:
        The hashed password string (includes salt).
    """
    salt = bcrypt.gensalt(rounds=settings.bcrypt_rounds)
    hashed = bcrypt.hashpw(
        password.encode("utf-8"),
        salt,
    )
    return hashed.decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plain-text password against its hash.

    Args:
        plain_password: The plain-text password to verify.
        hashed_password: The stored hashed password.

    Returns:
        True if the password matches, False otherwise.
    """
    try:
        return bcrypt.checkpw(
            plain_password.encode("utf-8"),
            hashed_password.encode("utf-8"),
        )
    except (ValueError, TypeError):
        return False
