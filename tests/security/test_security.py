"""
Security tests for the Secure API Gateway.

Tests authentication bypass protection, token security,
rate limiting, and authorization controls.
"""

from __future__ import annotations

import uuid
from unittest.mock import AsyncMock

import pytest
from httpx import AsyncClient

from app.security.jwt import create_access_token
from app.security.token_blacklist import TokenBlacklist


@pytest.mark.asyncio
class TestSecurityAuth:
    """Security tests for authentication and authorization."""

    async def test_access_without_token_is_rejected(self, async_client: AsyncClient):
        """Verify endpoints requiring auth reject unauthenticated requests."""
        protected_endpoints = [
            ("GET", "/api/v1/auth/me"),
            ("POST", "/api/v1/auth/logout"),
        ]

        for method, endpoint in protected_endpoints:
            if method == "GET":
                response = await async_client.get(endpoint)
            else:
                response = await async_client.post(endpoint, json={})

            assert response.status_code == 401, (
                f"Expected 401 for {method} {endpoint}, got {response.status_code}"
            )

    async def test_access_with_expired_token_is_rejected(
        self, async_client: AsyncClient
    ):
        """Verify expired tokens are rejected."""
        import jwt as pyjwt
        from datetime import datetime, timedelta, timezone
        from app.core.config import get_settings

        settings = get_settings()
        user_id = uuid.uuid4()

        # Create an expired token
        now = datetime.now(timezone.utc)
        payload = {
            "sub": str(user_id),
            "jti": uuid.uuid4().hex[:16],
            "iat": int((now - timedelta(hours=2)).timestamp()),
            "exp": int((now - timedelta(hours=1)).timestamp()),
            "iss": settings.jwt_issuer,
            "aud": settings.jwt_audience,
            "type": "access",
        }
        expired_token = pyjwt.encode(
            payload, settings.secret_key, algorithm=settings.jwt_algorithm
        )

        response = await async_client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {expired_token}"},
        )
        assert response.status_code == 401

    async def test_access_with_tampered_token_is_rejected(
        self, async_client: AsyncClient
    ):
        """Verify tampered tokens are rejected."""
        user_id = uuid.uuid4()
        token, _, _ = create_access_token(subject=user_id)

        # Tamper with token signature (simpler approach)
        parts = token.split(".")
        tampered_token = f"{parts[0]}.{parts[1]}.invalidsignature"

        response = await async_client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {tampered_token}"},
        )
        assert response.status_code == 401

    async def test_password_not_returned_in_responses(
        self, async_client: AsyncClient, auth_headers
    ):
        """Verify password hashes are never exposed in API responses."""
        # Register and check response
        response = await async_client.post(
            "/api/v1/auth/register",
            json={
                "email": "nopassword@example.com",
                "username": "nopassword_user",
                "password": "StrongPass123!",
            },
        )
        data = response.json()
        sensitive_fields = ["password", "hashed_password", "password_hash"]
        for field in sensitive_fields:
            assert field not in data, f"Sensitive field '{field}' exposed in response"

        # Check /auth/me
        response = await async_client.get(
            "/api/v1/auth/me", headers=auth_headers
        )
        data = response.json()
        for field in sensitive_fields:
            assert field not in data, f"Sensitive field '{field}' exposed in /auth/me"

    async def test_token_blacklist_prevents_reuse(
        self, async_client: AsyncClient, mock_redis, test_user
    ):
        """Verify blacklisted token cannot be used.

        Creates a token for a real user, verifies it works,
        blacklists it, then verifies it's rejected.
        """
        # Create a valid token for the test user
        token, _, jti = create_access_token(subject=test_user.id)
        headers = {"Authorization": f"Bearer {token}"}

        # Verify the token works initially
        response = await async_client.get("/api/v1/auth/me", headers=headers)
        assert response.status_code == 200, "Token should work before blacklisting"

        # Blacklist the token
        blacklist = TokenBlacklist(mock_redis)
        await blacklist.blacklist_token(jti)

        # Mark as blacklisted for the check
        mock_redis.exists = AsyncMock(return_value=True)

        # Verify the token is now rejected
        response = await async_client.get(
            "/api/v1/auth/me",
            headers=headers,
        )
        assert response.status_code == 401, "Token should be rejected after blacklisting"

    async def test_weak_password_rejected_at_registration(
        self, async_client: AsyncClient
    ):
        """Verify weak passwords are rejected during registration."""
        weak_passwords = [
            "short",  # Too short
            "nouppercase123!",  # No uppercase
            "NOLOWERCASE123!",  # No lowercase
            "NoDigitsHere!",  # No digits
            "NoSpecialChar123",  # No special char
        ]

        for password in weak_passwords:
            response = await async_client.post(
                "/api/v1/auth/register",
                json={
                    "email": f"weak_{password}@example.com",
                    "username": f"weak_user_{password[:5]}",
                    "password": password,
                },
            )
            assert response.status_code == 422, (
                f"Weak password '{password}' was accepted"
            )
