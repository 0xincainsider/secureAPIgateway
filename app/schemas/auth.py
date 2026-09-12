"""
Pydantic schemas for authentication and user management.

Defines request/response models with strict validation to
prevent injection and data corruption.
"""

from __future__ import annotations

import re
from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, EmailStr, Field, field_validator


class UserRegisterRequest(BaseModel):
    """Schema for user registration request."""

    email: EmailStr = Field(..., description="User email address")
    username: str = Field(
        ...,
        min_length=3,
        max_length=50,
        description="Username (alphanumeric, 3-50 chars)",
        examples=["johndoe"],
    )
    password: str = Field(
        ...,
        min_length=8,
        max_length=128,
        description="Password (8-128 chars)",
    )
    display_name: str | None = Field(
        None,
        max_length=100,
        description="Optional display name",
    )

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        """Validate username allows only alphanumeric and underscore."""
        if not re.match(r"^[a-zA-Z0-9_]+$", v):
            raise ValueError(
                "Username must contain only letters, numbers, and underscores"
            )
        return v.lower()

    @field_validator("password")
    @classmethod
    def validate_password_strength(cls, v: str) -> str:
        """Enforce minimum password strength requirements."""
        if not re.search(r"[A-Z]", v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not re.search(r"[a-z]", v):
            raise ValueError("Password must contain at least one lowercase letter")
        if not re.search(r"\d", v):
            raise ValueError("Password must contain at least one digit")
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>_\-\[\]\\;'`~]", v):
            raise ValueError("Password must contain at least one special character")
        return v


class UserLoginRequest(BaseModel):
    """Schema for user login request."""

    username: str = Field(
        ...,
        description="Username or email",
        examples=["johndoe"],
    )
    password: str = Field(
        ...,
        min_length=1,
        description="User password",
    )


class TokenResponse(BaseModel):
    """Schema for token response after authentication."""

    access_token: str = Field(..., description="JWT access token")
    refresh_token: str = Field(..., description="Refresh token")
    token_type: str = Field("bearer", description="Token type")
    expires_in: int = Field(..., description="Access token TTL in seconds")


class TokenRefreshRequest(BaseModel):
    """Schema for token refresh request."""

    refresh_token: str = Field(..., description="Valid refresh token")


class VerifyEmailRequest(BaseModel):
    """Schema for email verification request."""

    token: str = Field(..., description="Email verification token")


class VerificationResponse(BaseModel):
    """Schema for the email verification request response.

    The verification token is only included in non-production
    environments for development convenience.
    """

    message: str = Field(..., description="Response message")
    token: str | None = Field(None, description="Verification token (dev only)")
    expires_in: int | None = Field(None, description="Token TTL in seconds")


class UserResponse(BaseModel):
    """Schema for user data in API responses."""

    id: UUID = Field(..., description="User unique identifier")
    email: str = Field(..., description="User email address")
    username: str = Field(..., description="Username")
    display_name: str | None = Field(None, description="Display name")
    is_active: bool = Field(..., description="Whether the account is active")
    is_verified: bool = Field(..., description="Whether the email is verified")
    created_at: datetime = Field(..., description="Account creation timestamp")

    model_config = {"from_attributes": True}


class MessageResponse(BaseModel):
    """Schema for simple message responses."""

    message: str = Field(..., description="Response message")


class AuditLogResponse(BaseModel):
    """Schema for audit log entries in API responses."""

    id: UUID = Field(..., description="Audit entry unique identifier")
    event_type: str = Field(..., description="Security event type")
    event_description: str = Field(..., description="Human-readable event description")
    severity: str = Field(..., description="Severity level (info/warning/critical)")
    ip_address: str | None = Field(None, description="Client IP address")
    user_agent: str | None = Field(None, description="Client user agent")
    endpoint: str | None = Field(None, description="Request endpoint")
    status_code: int | None = Field(None, description="HTTP status code")
    details: str | None = Field(None, description="Additional details")
    created_at: datetime = Field(..., description="Event timestamp")

    model_config = {"from_attributes": True}
