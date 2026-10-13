"""Password hashing, JWT issuance/verification, and the current-user/permission
dependencies every protected route uses. No agent or route may bypass these — see
CLAUDE.md's "do not weaken authentication or bypass policy checks" rule.
"""

import hashlib
import secrets
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import bcrypt
import jwt
from fastapi import Depends, HTTPException, Request, Response, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from gds_api.config import settings
from gds_api.db import get_db
from gds_api.models import Role, User

ACCESS_COOKIE_NAME = "gds_access_token"
REFRESH_COOKIE_NAME = "gds_refresh_token"
JWT_ALGORITHM = "HS256"


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password: str, password_hash: str) -> bool:
    return bcrypt.checkpw(password.encode(), password_hash.encode())


def create_access_token(*, user_id: uuid.UUID, tenant_id: uuid.UUID) -> str:
    now = datetime.now(UTC)
    payload = {
        "sub": str(user_id),
        "tenant_id": str(tenant_id),
        "iat": now,
        "exp": now + timedelta(minutes=settings.jwt_access_token_minutes),
    }
    return jwt.encode(payload, settings.jwt_secret_key, algorithm=JWT_ALGORITHM)


def decode_access_token(token: str) -> dict[str, str]:
    try:
        payload = jwt.decode(token, settings.jwt_secret_key, algorithms=[JWT_ALGORITHM])
    except jwt.PyJWTError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or expired session") from exc
    return payload


def generate_refresh_token() -> str:
    return secrets.token_urlsafe(32)


def hash_refresh_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def set_auth_cookies(response: Response, *, access_token: str, refresh_token: str) -> None:
    response.set_cookie(
        ACCESS_COOKIE_NAME,
        access_token,
        max_age=settings.jwt_access_token_minutes * 60,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="lax",
        path="/",
    )
    response.set_cookie(
        REFRESH_COOKIE_NAME,
        refresh_token,
        max_age=settings.jwt_refresh_token_days * 24 * 60 * 60,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="lax",
        path="/",
    )


def clear_auth_cookies(response: Response) -> None:
    response.delete_cookie(ACCESS_COOKIE_NAME, path="/")
    response.delete_cookie(REFRESH_COOKIE_NAME, path="/")


@dataclass
class CurrentUser:
    user_id: uuid.UUID
    tenant_id: uuid.UUID
    email: str
    role_id: uuid.UUID
    role_name: str
    permissions: list[str]


async def get_current_user(request: Request, db: AsyncSession = Depends(get_db)) -> CurrentUser:
    token = request.cookies.get(ACCESS_COOKIE_NAME)
    if not token:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Not authenticated")
    payload = decode_access_token(token)

    # Role/permissions are loaded fresh on every request (not trusted from the JWT) so a
    # role change or deactivation takes effect immediately, not just after token expiry.
    user_id = uuid.UUID(payload["sub"])
    result = await db.execute(
        select(User, Role).join(Role, User.role_id == Role.id).where(User.id == user_id)
    )
    row = result.first()
    if row is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "User no longer exists")
    user, role = row
    if not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "User is deactivated")

    from gds_api.logging_config import bind_request_context  # local import avoids a cycle

    bind_request_context(tenant_id=str(user.tenant_id), user_id=str(user.id))

    return CurrentUser(
        user_id=user.id,
        tenant_id=user.tenant_id,
        email=user.email,
        role_id=role.id,
        role_name=role.name,
        permissions=list(role.permissions),
    )


def require_permission(
    permission: str,
) -> Callable[[CurrentUser, AsyncSession], Awaitable[CurrentUser]]:
    async def _dependency(
        current_user: CurrentUser = Depends(get_current_user),
        db: AsyncSession = Depends(get_db),
    ) -> CurrentUser:
        if permission not in current_user.permissions:
            from gds_api.audit import record_audit_event  # local import avoids a cycle

            await record_audit_event(
                db,
                tenant_id=current_user.tenant_id,
                user_id=current_user.user_id,
                action="rbac.permission_denied",
                detail={"required_permission": permission},
            )
            await db.commit()
            raise HTTPException(status.HTTP_403_FORBIDDEN, f"Missing permission: {permission}")
        return current_user

    return _dependency
