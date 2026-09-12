"""
Authentication API routes.

Implements the auth endpoints with rate limiting, audit logging,
and security controls built in.
"""

from __future__ import annotations

from fastapi import APIRouter, Body, Depends, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import (
    get_current_user,
    get_rate_limiter,
    get_redis,
    get_token_blacklist,
)
from app.database.session import get_session
from app.models.user import User
from app.schemas.auth import (
    MessageResponse,
    TokenRefreshRequest,
    TokenResponse,
    UserRegisterRequest,
    UserResponse,
    VerificationResponse,
    VerifyEmailRequest,
)
from app.security.rate_limiter import RateLimiter
from app.security.token_blacklist import TokenBlacklist
from app.services.auth_service import AuthService
from app.utils.logger import get_logger

router = APIRouter(prefix="/auth", tags=["Authentication"])
logger = get_logger(__name__)


async def _get_auth_service(
    request: Request,
    session: AsyncSession = Depends(get_session),
    redis_client: Redis = Depends(get_redis),
    rate_limiter: RateLimiter = Depends(get_rate_limiter),
    token_blacklist: TokenBlacklist = Depends(get_token_blacklist),
) -> AuthService:
    """Dependency factory for AuthService."""
    return AuthService(
        session=session,
        request=request,
        rate_limiter=rate_limiter,
        token_blacklist=token_blacklist,
        redis_client=redis_client,
    )


@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user",
    description="Create a new user account with email, username, and password.",
)
async def register(
    register_data: UserRegisterRequest,
    auth_service: AuthService = Depends(_get_auth_service),
) -> UserResponse:
    """Register a new user account."""
    return await auth_service.register(register_data)


@router.post(
    "/login",
    response_model=TokenResponse,
    summary="Authenticate and get tokens",
    description="Login with username/email and password to receive JWT tokens. Accepts both form-encoded (OAuth2) and JSON bodies.",
)
async def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    auth_service: AuthService = Depends(_get_auth_service),
) -> TokenResponse:
    """Authenticate user and return JWT tokens.

    Compatible with OAuth2 Password Flow (form-encoded) and JSON bodies.
    Rate limiting is enforced globally by the RateLimitMiddleware.
    """
    from app.schemas.auth import UserLoginRequest
    login_data = UserLoginRequest(
        username=form_data.username,
        password=form_data.password,
    )

    return await auth_service.login(login_data)


@router.post(
    "/refresh",
    response_model=TokenResponse,
    summary="Refresh authentication tokens",
    description="Use a valid refresh token to obtain new access and refresh tokens.",
)
async def refresh(
    refresh_data: TokenRefreshRequest,
    auth_service: AuthService = Depends(_get_auth_service),
) -> TokenResponse:
    """Refresh tokens using a valid refresh token."""
    return await auth_service.refresh_token(refresh_data.refresh_token)


@router.post(
    "/logout",
    response_model=MessageResponse,
    summary="Logout and revoke tokens",
    description="Revoke the current refresh token to logout.",
)
async def logout(
    current_user: User = Depends(get_current_user),
    auth_service: AuthService = Depends(_get_auth_service),
    refresh_token: str | None = Body(None, description="Optional refresh token to revoke"),
) -> dict:
    """Logout by revoking refresh tokens."""
    return await auth_service.logout(current_user, refresh_token)


@router.get(
    "/me",
    response_model=UserResponse,
    summary="Get current user profile",
    description="Return the profile of the currently authenticated user.",
)
async def get_me(
    current_user: User = Depends(get_current_user),
    auth_service: AuthService = Depends(_get_auth_service),
) -> UserResponse:
    """Get the current authenticated user's profile."""
    return await auth_service.get_current_user(current_user)


@router.post(
    "/request-verification",
    response_model=VerificationResponse,
    summary="Request email verification",
    description="Generate an email verification token. In development the token is returned; in production it is delivered by email.",
)
async def request_verification(
    current_user: User = Depends(get_current_user),
    auth_service: AuthService = Depends(_get_auth_service),
) -> dict:
    """Generate a verification token for the current user."""
    return await auth_service.request_verification(current_user)


@router.post(
    "/verify-email",
    response_model=MessageResponse,
    summary="Verify email address",
    description="Verify the current user's email address using a signed verification token.",
)
async def verify_email(
    verify_data: VerifyEmailRequest,
    auth_service: AuthService = Depends(_get_auth_service),
) -> dict:
    """Verify a user's email address."""
    return await auth_service.verify_email(verify_data.token)
