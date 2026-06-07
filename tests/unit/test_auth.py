"""
Unit tests for authentication components.

Tests password hashing, JWT token creation/validation,
schema validation, and security utilities in isolation.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import jwt as pyjwt
import pytest
from pydantic import ValidationError

from app.core.config import get_settings
from app.core.security import hash_password, verify_password
from app.schemas.auth import UserRegisterRequest
from app.security.jwt import (
    create_access_token,
    create_refresh_token,
    decode_token,
    get_token_type,
)

settings = get_settings()


# =============================================================================
# Password Hashing Tests
# =============================================================================


class TestPasswordHashing:
    """Tests for secure password hashing and verification."""

    def test_hash_password_returns_string(self):
        """Verify password hashing returns a non-empty string."""
        password = "TestPassword123!"
        hashed = hash_password(password)
        assert isinstance(hashed, str)
        assert len(hashed) > 0

    def test_hash_password_different_salts(self):
        """Verify each hash is unique due to salt."""
        password = "TestPassword123!"
        hash1 = hash_password(password)
        hash2 = hash_password(password)
        assert hash1 != hash2

    def test_verify_password_correct(self):
        """Verify correct password matches hash."""
        password = "TestPassword123!"
        hashed = hash_password(password)
        assert verify_password(password, hashed) is True

    def test_verify_password_incorrect(self):
        """Verify incorrect password does not match hash."""
        password = "TestPassword123!"
        wrong_password = "WrongPassword456!"
        hashed = hash_password(password)
        assert verify_password(wrong_password, hashed) is False

    def test_verify_password_empty_string(self):
        """Verify empty password does not match hash."""
        hashed = hash_password("TestPassword123!")
        assert verify_password("", hashed) is False


# =============================================================================
# JWT Token Tests
# =============================================================================


class TestJWTTokens:
    """Tests for JWT token creation, validation, and management."""

    def test_create_access_token_returns_valid_token(self):
        """Verify access token creation returns a valid JWT string."""
        user_id = uuid.uuid4()
        token, expires_in, jti = create_access_token(subject=user_id)

        assert isinstance(token, str)
        assert len(token.split(".")) == 3  # JWT has 3 parts
        assert expires_in == settings.access_token_expire_seconds
        assert isinstance(jti, str)
        assert len(jti) > 0

    def test_create_access_token_with_extra_claims(self):
        """Verify access token includes extra claims."""
        user_id = uuid.uuid4()
        extra = {"username": "testuser", "email": "test@example.com"}
        token, _, _ = create_access_token(subject=user_id, extra_claims=extra)

        payload = decode_token(token)
        assert payload["username"] == "testuser"
        assert payload["email"] == "test@example.com"

    def test_decode_valid_access_token(self):
        """Verify decoding a valid access token returns correct payload."""
        user_id = uuid.uuid4()
        token, _, _ = create_access_token(subject=user_id)

        payload = decode_token(token)
        assert payload["sub"] == str(user_id)
        assert payload["type"] == "access"
        assert payload["iss"] == settings.jwt_issuer
        assert payload["aud"] == settings.jwt_audience
        assert "jti" in payload
        assert "iat" in payload
        assert "exp" in payload

    def test_decode_token_rejects_expired_token(self):
        """Verify expired tokens are rejected."""
        user_id = uuid.uuid4()
        # Create an already-expired token
        now = datetime.now(timezone.utc)
        expired_payload = {
            "sub": str(user_id),
            "jti": uuid.uuid4().hex[:16],
            "iat": int((now - timedelta(hours=2)).timestamp()),
            "exp": int((now - timedelta(hours=1)).timestamp()),
            "iss": settings.jwt_issuer,
            "aud": settings.jwt_audience,
            "type": "access",
        }
        expired_token = pyjwt.encode(
            expired_payload,
            settings.secret_key,
            algorithm=settings.jwt_algorithm,
        )

        from jwt.exceptions import InvalidTokenError
        with pytest.raises(InvalidTokenError, match="Token has expired"):
            decode_token(expired_token)

    def test_decode_token_rejects_invalid_signature(self):
        """Verify tokens with invalid signatures are rejected."""
        user_id = uuid.uuid4()
        token, _, _ = create_access_token(subject=user_id)

        # Tamper with the token
        parts = token.split(".")
        tampered_token = f"{parts[0]}.{parts[1]}.invalidsignature"

        from jwt.exceptions import InvalidTokenError
        with pytest.raises(InvalidTokenError):
            decode_token(tampered_token)

    def test_create_refresh_token(self):
        """Verify refresh token creation."""
        user_id = uuid.uuid4()
        token, expires_in, jti = create_refresh_token(subject=user_id)

        assert isinstance(token, str)
        assert len(token.split(".")) == 3
        assert expires_in == settings.refresh_token_expire_seconds

        payload = decode_token(token)
        assert payload["type"] == "refresh"
        assert payload["sub"] == str(user_id)

    def test_get_token_type(self):
        """Verify token type extraction."""
        user_id = uuid.uuid4()

        access_token, _, _ = create_access_token(subject=user_id)
        assert get_token_type(access_token) == "access"

        refresh_token, _, _ = create_refresh_token(subject=user_id)
        assert get_token_type(refresh_token) == "refresh"

    def test_get_token_type_invalid(self):
        """Verify token type returns None for invalid tokens."""
        assert get_token_type("not-a-token") is None


# =============================================================================
# Schema Validation Tests
# =============================================================================


class TestSchemaValidation:
    """Tests for Pydantic schema validation."""

    def test_valid_registration_schema(self):
        """Verify valid registration data passes validation."""
        data = {
            "email": "newuser@example.com",
            "username": "newuser",
            "password": "StrongPass123!",
            "display_name": "New User",
        }
        schema = UserRegisterRequest(**data)
        assert schema.email == "newuser@example.com"
        assert schema.username == "newuser"
        assert schema.display_name == "New User"

    def test_weak_password_rejected(self):
        """Verify weak passwords are rejected by schema validation."""
        with pytest.raises(ValidationError):
            UserRegisterRequest(
                email="test@example.com",
                username="testuser",
                password="weak",  # Too short, no uppercase, no digit, no special char
            )

    def test_password_missing_uppercase_rejected(self):
        """Verify password without uppercase is rejected."""
        with pytest.raises(ValidationError):
            UserRegisterRequest(
                email="test@example.com",
                username="testuser",
                password="lowercaseonly123!",
            )

    def test_password_missing_digit_rejected(self):
        """Verify password without digit is rejected."""
        with pytest.raises(ValidationError):
            UserRegisterRequest(
                email="test@example.com",
                username="testuser",
                password="NoDigitsHere!",
            )

    def test_invalid_username_chars_rejected(self):
        """Verify username with invalid characters is rejected."""
        with pytest.raises(ValidationError):
            UserRegisterRequest(
                email="test@example.com",
                username="user name!",  # Contains space and !
                password="StrongPass123!",
            )

    def test_short_username_rejected(self):
        """Verify username shorter than 3 chars is rejected."""
        with pytest.raises(ValidationError):
            UserRegisterRequest(
                email="test@example.com",
                username="ab",  # Too short
                password="StrongPass123!",
            )

    def test_invalid_email_rejected(self):
        """Verify invalid email is rejected."""
        with pytest.raises(ValidationError):
            UserRegisterRequest(
                email="not-an-email",
                username="testuser",
                password="StrongPass123!",
            )
