"""
Tests for gateway-level features introduced in the gap fixes:

- Global rate limiting middleware (429 + Retry-After)
- Role-based access control (superuser admin endpoints)
- Live Prometheus auth metrics
- Email verification flow
"""

from __future__ import annotations

import re
from unittest.mock import AsyncMock

import pytest
from httpx import AsyncClient

from app.core.config import get_settings

settings = get_settings()


@pytest.mark.asyncio
class TestGlobalRateLimiting:
    """Tests for the global rate limiting middleware."""

    async def test_rate_limit_applies_to_all_endpoints(
        self, async_client: AsyncClient, mock_redis
    ):
        """Verify that exceeding the IP limit on any endpoint returns 429."""
        # Simulate the counter exceeding the default IP limit
        mock_redis.incr = AsyncMock(return_value=settings.rate_limit_default + 1)

        response = await async_client.get("/api/v1/auth/me")

        assert response.status_code == 429
        assert response.json()["detail"] == "Too many requests"
        assert "Retry-After" in response.headers

    async def test_health_is_exempt_from_rate_limiting(
        self, async_client: AsyncClient, mock_redis
    ):
        """Verify the health endpoint is never rate limited."""
        mock_redis.incr = AsyncMock(return_value=settings.rate_limit_default + 1)

        response = await async_client.get("/health")

        assert response.status_code == 200


@pytest.mark.asyncio
class TestAdminRBAC:
    """Tests for role-based access control on admin endpoints."""

    async def test_admin_endpoint_rejects_normal_user(
        self, async_client: AsyncClient, auth_headers
    ):
        """Verify a normal (non-superuser) user gets 403 on admin endpoints."""
        response = await async_client.get("/api/v1/admin/users", headers=auth_headers)
        assert response.status_code == 403

    async def test_admin_endpoint_requires_auth(self, async_client: AsyncClient):
        """Verify admin endpoints reject unauthenticated requests."""
        response = await async_client.get("/api/v1/admin/users")
        assert response.status_code == 401

    async def test_admin_can_list_users(
        self, async_client: AsyncClient, admin_headers, test_user
    ):
        """Verify a superuser can list all users."""
        response = await async_client.get("/api/v1/admin/users", headers=admin_headers)
        assert response.status_code == 200
        data = response.json()
        assert any(user["username"] == "testuser" for user in data)
        assert any(user["username"] == "admin" for user in data)

    async def test_admin_can_list_audit_logs(
        self, async_client: AsyncClient, admin_headers
    ):
        """Verify a superuser can read the audit log trail."""
        response = await async_client.get(
            "/api/v1/admin/audit-logs", headers=admin_headers
        )
        assert response.status_code == 200
        assert isinstance(response.json(), list)


@pytest.mark.asyncio
class TestAuthMetrics:
    """Tests for live Prometheus authentication metrics."""

    async def test_login_failure_metric_increments(
        self, async_client: AsyncClient
    ):
        """Verify failed logins increment the auth_login_failure counter."""
        await async_client.post(
            "/api/v1/auth/login",
            data={"username": "nobody", "password": "WrongPass123!"},
        )

        response = await async_client.get("/metrics")
        assert response.status_code == 200
        match = re.search(r"auth_login_failure_total\s+([\d.]+)", response.text)
        assert match is not None
        assert float(match.group(1)) >= 1.0

    async def test_login_success_metric_increments(
        self, async_client: AsyncClient, test_user
    ):
        """Verify successful logins increment the auth_login_success counter."""
        await async_client.post(
            "/api/v1/auth/login",
            data={"username": "testuser", "password": "TestPass123!"},
        )

        response = await async_client.get("/metrics")
        assert response.status_code == 200
        match = re.search(r"auth_login_success_total\s+([\d.]+)", response.text)
        assert match is not None
        assert float(match.group(1)) >= 1.0


@pytest.mark.asyncio
class TestEmailVerification:
    """Tests for the email verification flow."""

    async def test_full_verification_flow(self, async_client: AsyncClient):
        """Verify register -> request verification -> verify -> confirmed."""
        # Register a new (unverified) user
        reg = await async_client.post(
            "/api/v1/auth/register",
            json={
                "email": "verify@example.com",
                "username": "verify_user",
                "password": "StrongPass123!",
            },
        )
        assert reg.status_code == 201
        assert reg.json()["is_verified"] is False

        # Login to get an access token
        login = await async_client.post(
            "/api/v1/auth/login",
            data={"username": "verify_user", "password": "StrongPass123!"},
        )
        assert login.status_code == 200
        access_token = login.json()["access_token"]
        headers = {"Authorization": f"Bearer {access_token}"}

        # Request verification (dev env returns the token in the response)
        req = await async_client.post(
            "/api/v1/auth/request-verification", headers=headers
        )
        assert req.status_code == 200
        body = req.json()
        assert "token" in body

        # Verify the email
        ver = await async_client.post(
            "/api/v1/auth/verify-email",
            json={"token": body["token"]},
        )
        assert ver.status_code == 200

        # Profile now reflects the verified status
        me = await async_client.get("/api/v1/auth/me", headers=headers)
        assert me.status_code == 200
        assert me.json()["is_verified"] is True

    async def test_verify_email_rejects_invalid_token(
        self, async_client: AsyncClient
    ):
        """Verify an invalid verification token is rejected."""
        response = await async_client.post(
            "/api/v1/auth/verify-email",
            json={"token": "not-a-valid-token"},
        )
        assert response.status_code == 401