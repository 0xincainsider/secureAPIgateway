"""
JWT token management for authentication.

Handles creation, verification, and decoding of access and refresh tokens
with support for JTI (JWT ID) for revocation tracking.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt
from jwt.exceptions import (
    ExpiredSignatureError,
    ImmatureSignatureError,
    InvalidAudienceError,
    InvalidIssuerError,
    InvalidSignatureError,
    InvalidTokenError,
)

from app.core.config import get_settings

settings = get_settings()


def create_access_token(
    subject: str | uuid.UUID,
    extra_claims: dict[str, Any] | None = None,
) -> tuple[str, int, str]:
    """Create a JWT access token.

    Args:
        subject: The token subject (typically user ID).
        extra_claims: Optional additional claims to include.

    Returns:
        Tuple of (encoded_token, expires_in_seconds, jti).
    """
    jti = uuid.uuid4().hex[:16]
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(minutes=settings.access_token_expire_minutes)
    expires_in = settings.access_token_expire_seconds

    payload: dict[str, Any] = {
        "sub": str(subject),
        "jti": jti,
        "iat": int(now.timestamp()),
        "exp": int(expires_at.timestamp()),
        "iss": settings.jwt_issuer,
        "aud": settings.jwt_audience,
        "type": "access",
    }

    if extra_claims:
        payload.update(extra_claims)

    token = jwt.encode(
        payload,
        settings.secret_key,
        algorithm=settings.jwt_algorithm,
    )

    return token, expires_in, jti


def create_refresh_token(
    subject: str | uuid.UUID,
) -> tuple[str, int, str]:
    """Create a JWT refresh token.

    Args:
        subject: The token subject (typically user ID).

    Returns:
        Tuple of (encoded_token, expires_in_seconds, jti).
    """
    jti = uuid.uuid4().hex[:16]
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(days=settings.refresh_token_expire_days)
    expires_in = settings.refresh_token_expire_seconds

    payload: dict[str, Any] = {
        "sub": str(subject),
        "jti": jti,
        "iat": int(now.timestamp()),
        "exp": int(expires_at.timestamp()),
        "iss": settings.jwt_issuer,
        "aud": settings.jwt_audience,
        "type": "refresh",
    }

    token = jwt.encode(
        payload,
        settings.secret_key,
        algorithm=settings.jwt_algorithm,
    )

    return token, expires_in, jti


def decode_token(token: str) -> dict[str, Any]:
    """Decode and validate a JWT token.

    Args:
        token: The JWT token string to decode.

    Returns:
        The decoded token payload.

    Raises:
        jwt.InvalidTokenError: If the token is invalid, expired, or tampered with.
    """
    try:
        payload = jwt.decode(
            token,
            settings.secret_key,
            algorithms=[settings.jwt_algorithm],
            audience=settings.jwt_audience,
            issuer=settings.jwt_issuer,
            options={
                "require": ["sub", "jti", "iat", "exp", "iss", "aud", "type"],
                "verify_exp": True,
            },
        )
        return payload
    except ExpiredSignatureError:
        raise InvalidTokenError("Token has expired")
    except InvalidAudienceError:
        raise InvalidTokenError("Invalid token audience")
    except InvalidIssuerError:
        raise InvalidTokenError("Invalid token issuer")
    except InvalidSignatureError:
        raise InvalidTokenError("Invalid token signature")
    except ImmatureSignatureError:
        raise InvalidTokenError("Token is not yet valid")
    except Exception:
        raise InvalidTokenError("Invalid token")


def get_token_type(token: str) -> str | None:
    """Extract the token type from a JWT without full validation.

    Args:
        token: The JWT token string.

    Returns:
        The token type claim or None if decoding fails.
    """
    try:
        payload = jwt.decode(
            token,
            options={"verify_signature": False},
        )
        return payload.get("type")
    except Exception:
        return None
