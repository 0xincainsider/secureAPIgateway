"""
Authentication service with business logic.

Handles user registration, login, token refresh, logout,
and user profile retrieval with proper security controls.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from uuid import UUID

from fastapi import HTTPException, Request, status
from redis.asyncio import Redis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.dependencies import get_rate_limiter, get_token_blacklist
from app.core.security import hash_password, verify_password
from app.models.audit_log import AuditLog
from app.models.refresh_token import RefreshToken
from app.models.user import User
from app.schemas.auth import (
    TokenRefreshRequest,
    TokenResponse,
    UserLoginRequest,
    UserRegisterRequest,
    UserResponse,
)
from app.security.jwt import (
    create_access_token,
    create_refresh_token,
    create_verification_token,
    decode_token,
)
from app.security.rate_limiter import RateLimiter
from app.security.token_blacklist import TokenBlacklist
from app.utils.logger import get_logger, log_security_event
from app.utils.metrics import auth_login_failure_total, auth_login_success_total, auth_register_total

settings = get_settings()
logger = get_logger(__name__)


class AuthService:
    """Service layer for authentication operations."""

    def __init__(
        self,
        session: AsyncSession,
        request: Request,
        rate_limiter: RateLimiter | None = None,
        token_blacklist: TokenBlacklist | None = None,
        redis_client: Redis | None = None,
    ) -> None:
        """Initialize the auth service.

        Args:
            session: Database session.
            request: FastAPI request object.
            rate_limiter: Optional rate limiter instance.
            token_blacklist: Optional token blacklist instance.
            redis_client: Optional Redis client instance.
        """
        self.session = session
        self.request = request
        self.rate_limiter = rate_limiter
        self.token_blacklist = token_blacklist
        self.redis = redis_client

    def _get_client_ip(self) -> str:
        """Extract client IP from request, considering proxies."""
        forwarded = self.request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return self.request.client.host if self.request.client else "unknown"

    def _get_user_agent(self) -> str:
        """Extract User-Agent from request headers."""
        return self.request.headers.get("User-Agent", "unknown")

    async def _audit_log(
        self,
        event_type: str,
        description: str,
        severity: str = "info",
        user_id: UUID | None = None,
        status_code: int | None = None,
        details: str | None = None,
    ) -> None:
        """Create an audit log entry."""
        audit_entry = AuditLog(
            user_id=user_id,
            event_type=event_type,
            event_description=description,
            severity=severity,
            ip_address=self._get_client_ip(),
            user_agent=self._get_user_agent(),
            endpoint=str(self.request.url.path),
            status_code=status_code,
            details=details,
        )
        self.session.add(audit_entry)

    async def register(self, register_data: UserRegisterRequest) -> UserResponse:
        """Register a new user.

        Args:
            register_data: Registration request data.

        Returns:
            UserResponse with created user details.

        Raises:
            HTTPException 409: If email or username already exists.
            HTTPException 400: If validation fails.
        """
        # Check for existing email
        existing_email = await self.session.execute(
            select(User).where(User.email == register_data.email)
        )
        if existing_email.scalar_one_or_none():
            # Use generic message to prevent user enumeration
            log_security_event(
                logger,
                "registration_failed_email_exists",
                level=30,  # WARNING
                ip=self._get_client_ip(),
                endpoint="/auth/register",
            )
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="A user with this email or username already exists",
            )

        # Check for existing username
        existing_username = await self.session.execute(
            select(User).where(User.username == register_data.username)
        )
        if existing_username.scalar_one_or_none():
            log_security_event(
                logger,
                "registration_failed_username_exists",
                level=30,
                ip=self._get_client_ip(),
                endpoint="/auth/register",
            )
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="A user with this email or username already exists",
            )

        # Create user
        hashed_pw = hash_password(register_data.password)
        user = User(
            email=register_data.email,
            username=register_data.username,
            hashed_password=hashed_pw,
            display_name=register_data.display_name or register_data.username,
        )

        self.session.add(user)
        await self.session.flush()

        # Audit log
        await self._audit_log(
            event_type="user_registered",
            description=f"User registered: {user.username}",
            severity="info",
            user_id=user.id,
            status_code=201,
        )

        log_security_event(
            logger,
            "user_registered",
            ip=self._get_client_ip(),
            user_id=str(user.id),
            endpoint="/auth/register",
            status_code=201,
        )
        auth_register_total.inc()

        return UserResponse.model_validate(user)

    async def login(self, login_data: UserLoginRequest) -> TokenResponse:
        """Authenticate a user and return tokens.

        Args:
            login_data: Login request data.

        Returns:
            TokenResponse with access and refresh tokens.

        Raises:
            HTTPException 401: If credentials are invalid.
        """
        # Find user by username or email
        stmt = select(User).where(
            (User.username == login_data.username) | (User.email == login_data.username)
        )
        result = await self.session.execute(stmt)
        user = result.scalar_one_or_none()

        if not user or not verify_password(login_data.password, user.hashed_password):
            # Generic error to prevent user enumeration
            log_security_event(
                logger,
                "login_failed",
                level=30,
                ip=self._get_client_ip(),
                endpoint="/auth/login",
            )
            await self._audit_log(
                event_type="login_failed",
                description=f"Failed login attempt for: {login_data.username}",
                severity="warning",
                status_code=401,
                details="Invalid credentials",
            )
            auth_login_failure_total.inc()
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid username/email or password",
                headers={"WWW-Authenticate": "Bearer"},
            )

        if not user.is_active:
            log_security_event(
                logger,
                "login_failed_inactive",
                level=30,
                ip=self._get_client_ip(),
                user_id=str(user.id),
                endpoint="/auth/login",
            )
            await self._audit_log(
                event_type="login_failed_inactive",
                description=f"Inactive account login attempt: {user.username}",
                severity="warning",
                user_id=user.id,
                status_code=401,
            )
            auth_login_failure_total.inc()
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Account is inactive",
            )

        # Generate tokens (no PII embedded in the JWT claims)
        access_token, expires_in, access_jti = create_access_token(subject=user.id)
        refresh_token_str, _, refresh_jti = create_refresh_token(subject=user.id)

        # Hash refresh token before storing
        token_hash = hashlib.sha256(refresh_token_str.encode()).hexdigest()

        # Store refresh token in database
        refresh_token_model = RefreshToken(
            user_id=user.id,
            token_hash=token_hash,
            jti=refresh_jti,
            device_info=self._get_user_agent(),
            ip_address=self._get_client_ip(),
            expires_at=datetime.now(timezone.utc).replace(tzinfo=None)
            + timedelta(days=settings.refresh_token_expire_days),
        )
        self.session.add(refresh_token_model)

        # Update last login
        user.last_login_at = datetime.now(timezone.utc)

        await self.session.flush()

        # Audit log
        await self._audit_log(
            event_type="login_success",
            description=f"User logged in: {user.username}",
            severity="info",
            user_id=user.id,
            status_code=200,
        )

        log_security_event(
            logger,
            "login_success",
            ip=self._get_client_ip(),
            user_id=str(user.id),
            endpoint="/auth/login",
            status_code=200,
        )
        auth_login_success_total.inc()

        return TokenResponse(
            access_token=access_token,
            refresh_token=refresh_token_str,
            token_type="bearer",
            expires_in=expires_in,
        )

    async def refresh_token(self, refresh_token_str: str) -> TokenResponse:
        """Issue new tokens using a valid refresh token.

        Args:
            refresh_token_str: The refresh token string.

        Returns:
            TokenResponse with new access and refresh tokens.

        Raises:
            HTTPException 401: If refresh token is invalid.
        """
        # Decode the refresh token (signed with the dedicated refresh secret)
        try:
            payload = decode_token(refresh_token_str, secret=settings.jwt_refresh_secret)
        except Exception:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token",
            )

        if payload.get("type") != "refresh":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token type",
            )

        # Check blacklist
        jti = payload.get("jti")
        if self.token_blacklist and jti:
            if await self.token_blacklist.is_blacklisted(jti):
                # Token has been revoked - revoke all tokens for this user
                user_id = payload.get("sub")
                if user_id:
                    await self._revoke_all_user_tokens(UUID(user_id))
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Refresh token has been revoked",
                )

        # Find the stored refresh token
        token_hash = hashlib.sha256(refresh_token_str.encode()).hexdigest()
        result = await self.session.execute(
            select(RefreshToken).where(
                RefreshToken.token_hash == token_hash,
                RefreshToken.is_revoked == False,
            )
        )
        stored_token = result.scalar_one_or_none()

        if not stored_token or stored_token.is_expired:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired refresh token",
            )

        # Revoke the old refresh token (token rotation)
        stored_token.revoke()

        # Get the user
        result = await self.session.execute(
            select(User).where(User.id == stored_token.user_id, User.is_active == True)
        )
        user = result.scalar_one_or_none()

        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found or inactive",
            )

        # Issue new tokens (no PII embedded in the JWT claims)
        access_token, expires_in, access_jti = create_access_token(subject=user.id)
        new_refresh_token, _, new_jti = create_refresh_token(subject=user.id)

        # Store new refresh token
        new_token_hash = hashlib.sha256(new_refresh_token.encode()).hexdigest()
        new_token_model = RefreshToken(
            user_id=user.id,
            token_hash=new_token_hash,
            jti=new_jti,
            device_info=self._get_user_agent(),
            ip_address=self._get_client_ip(),
            expires_at=datetime.now(timezone.utc).replace(tzinfo=None)
            + timedelta(days=settings.refresh_token_expire_days),
        )
        self.session.add(new_token_model)

        await self.session.flush()

        await self._audit_log(
            event_type="token_refreshed",
            description=f"Tokens refreshed for: {user.username}",
            severity="info",
            user_id=user.id,
            status_code=200,
        )

        return TokenResponse(
            access_token=access_token,
            refresh_token=new_refresh_token,
            token_type="bearer",
            expires_in=expires_in,
        )

    async def logout(self, user: User, refresh_token_str: str | None = None) -> dict:
        """Logout a user by revoking tokens.

        Args:
            user: The authenticated user.
            refresh_token_str: Optional specific refresh token to revoke.
                              If None, revokes all user refresh tokens.

        Returns:
            Dict with success message.
        """
        if refresh_token_str:
            # Revoke specific refresh token
            token_hash = hashlib.sha256(refresh_token_str.encode()).hexdigest()
            result = await self.session.execute(
                select(RefreshToken).where(
                    RefreshToken.token_hash == token_hash,
                    RefreshToken.user_id == user.id,
                )
            )
            stored_token = result.scalar_one_or_none()

            if stored_token:
                stored_token.revoke()
        else:
            # Revoke all refresh tokens for this user
            await self._revoke_all_user_tokens(user.id)

        await self.session.flush()

        await self._audit_log(
            event_type="user_logout",
            description=f"User logged out: {user.username}",
            severity="info",
            user_id=user.id,
            status_code=200,
        )

        log_security_event(
            logger,
            "logout_success",
            ip=self._get_client_ip(),
            user_id=str(user.id),
            endpoint="/auth/logout",
        )

        return {"message": "Successfully logged out"}

    async def get_current_user(self, user: User) -> UserResponse:
        """Get the current authenticated user's profile.

        Args:
            user: The authenticated user.

        Returns:
            UserResponse with user details.
        """
        return UserResponse.model_validate(user)

    async def request_verification(self, user: User) -> dict:
        """Generate an email verification token for a user.

        In a real deployment this token is delivered by email. In non-
        production environments the token is returned in the response so
        the flow can be exercised end-to-end.

        Args:
            user: The authenticated user requesting verification.

        Returns:
            Dict with the verification token (dev only) or a generic message.
        """
        verification_token, expires_in, _ = create_verification_token(subject=user.id)

        await self._audit_log(
            event_type="verification_requested",
            description=f"Verification email requested for: {user.username}",
            severity="info",
            user_id=user.id,
            status_code=200,
        )

        # Never return the token in production; deliver via email instead.
        if settings.app_env == "production":
            log_security_event(
                logger,
                "verification_email_sent",
                ip=self._get_client_ip(),
                user_id=str(user.id),
                endpoint="/auth/request-verification",
                status_code=200,
            )
            return {
                "message": "If the account is pending verification, a confirmation link has been sent.",
                "expires_in": expires_in,
            }

        return {
            "message": "Verification token generated (development only - in production it is emailed)",
            "token": verification_token,
            "expires_in": expires_in,
        }

    async def verify_email(self, token: str) -> dict:
        """Verify a user's email address using a signed verification token.

        Args:
            token: The verification token (JWT of type "verify").

        Returns:
            Dict with a success message.

        Raises:
            HTTPException 401: If the token is invalid or expired.
        """
        try:
            payload = decode_token(token)
        except Exception:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired verification token",
            )

        if payload.get("type") != "verify":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token type",
            )

        try:
            user_id = UUID(payload["sub"])
        except (KeyError, ValueError, TypeError):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid verification token",
            )

        result = await self.session.execute(
            select(User).where(User.id == user_id, User.is_active == True)
        )
        user = result.scalar_one_or_none()
        if user is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found or inactive",
            )

        if not user.is_verified:
            user.is_verified = True

        await self.session.flush()

        await self._audit_log(
            event_type="email_verified",
            description=f"Email verified for: {user.username}",
            severity="info",
            user_id=user.id,
            status_code=200,
        )

        log_security_event(
            logger,
            "email_verified",
            ip=self._get_client_ip(),
            user_id=str(user.id),
            endpoint="/auth/verify-email",
            status_code=200,
        )

        return {"message": "Email address verified successfully"}

    async def _revoke_all_user_tokens(self, user_id: UUID) -> None:
        """Revoke all active refresh tokens for a user.

        Args:
            user_id: The user's UUID.
        """
        result = await self.session.execute(
            select(RefreshToken).where(
                RefreshToken.user_id == user_id,
                RefreshToken.is_revoked == False,
            )
        )
        tokens = result.scalars().all()

        for token in tokens:
            token.revoke()

            # Also blacklist in Redis if available
            if self.token_blacklist:
                await self.token_blacklist.blacklist_token(token.jti)

        logger.info(
            "All user tokens revoked",
            extra={"user_id": str(user_id), "count": len(tokens)},
        )
