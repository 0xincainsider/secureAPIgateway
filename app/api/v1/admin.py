"""
Administration API routes.

Superuser-only endpoints for user and audit log management,
demonstrating role-based access control (RBAC) on top of JWT auth.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import get_current_superuser
from app.database.session import get_session
from app.models.audit_log import AuditLog
from app.models.user import User
from app.schemas.auth import AuditLogResponse, UserResponse

router = APIRouter(prefix="/admin", tags=["Administration"])


@router.get(
    "/users",
    response_model=list[UserResponse],
    summary="List all users",
    description="Return all registered users (superuser only).",
)
async def list_users(
    _admin: User = Depends(get_current_superuser),
    session: AsyncSession = Depends(get_session),
) -> list[UserResponse]:
    """List all users ordered by creation date."""
    result = await session.execute(select(User).order_by(User.created_at.desc()))
    return [UserResponse.model_validate(user) for user in result.scalars()]


@router.get(
    "/audit-logs",
    response_model=list[AuditLogResponse],
    summary="List audit logs",
    description="Return the latest security audit events (superuser only).",
)
async def list_audit_logs(
    _admin: User = Depends(get_current_superuser),
    session: AsyncSession = Depends(get_session),
    limit: int = 100,
) -> list[AuditLogResponse]:
    """List the most recent audit log entries."""
    result = await session.execute(
        select(AuditLog).order_by(AuditLog.created_at.desc()).limit(limit)
    )
    return [AuditLogResponse.model_validate(entry) for entry in result.scalars()]