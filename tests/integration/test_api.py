"""
Integration tests for the Secure API Gateway.

Tests the full request/response lifecycle including authentication
flows, error handling, and middleware behavior.
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
class TestAuthEndpoints:
    """Integration tests for authentication API endpoints."""

    async def test_register_user_success(self, async_client: AsyncClient):
        """Verify successful user registration returns 201."""
        response = await async_client.post(
            "/api/v1/auth/register",
            json={
                "email": "newuser@example.com",
                "username": "newuser",
                "password": "StrongPass123!",
                "display_name": "New User",
            },
        )
        assert response.status_code == 201
        data = response.json()
        assert data["email"] == "newuser@example.com"
        assert data["username"] == "newuser"
        assert "id" in data
        assert "password" not in data  # Password should never be returned

    async def test_register_duplicate_email(self, async_client: AsyncClient):
        """Verify registering with duplicate email returns 409."""
        # First registration
        await async_client.post(
            "/api/v1/auth/register",
            json={
                "email": "duplicate@example.com",
                "username": "user1",
                "password": "StrongPass123!",
            },
        )
        # Second registration with same email
        response = await async_client.post(
            "/api/v1/auth/register",
            json={
                "email": "duplicate@example.com",
                "username": "user2",
                "password": "StrongPass123!",
            },
        )
        assert response.status_code == 409

    async def test_login_success(self, async_client: AsyncClient, test_user):
        """Verify successful login returns tokens."""
        response = await async_client.post(
            "/api/v1/auth/login",
            data={"username": "testuser", "password": "TestPass123!"},
        )
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["token_type"] == "bearer"
        assert data["expires_in"] > 0

    async def test_login_invalid_credentials(self, async_client: AsyncClient):
        """Verify login with wrong password returns 401."""
        response = await async_client.post(
            "/api/v1/auth/login",
            data={"username": "testuser", "password": "WrongPassword123!"},
        )
        assert response.status_code == 401

    async def test_get_me_authenticated(self, async_client: AsyncClient, auth_headers):
        """Verify authenticated user can access /auth/me."""
        response = await async_client.get(
            "/api/v1/auth/me",
            headers=auth_headers,
        )
        assert response.status_code == 200
        data = response.json()
        assert data["email"] == "testuser@example.com"
        assert data["username"] == "testuser"

    async def test_get_me_unauthenticated(self, async_client: AsyncClient):
        """Verify unauthenticated request to /auth/me returns 401."""
        response = await async_client.get("/api/v1/auth/me")
        assert response.status_code == 401

    async def test_health_check(self, async_client: AsyncClient):
        """Verify health check endpoint works."""
        response = await async_client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
