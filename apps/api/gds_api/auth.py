from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from gds_api.audit import record_audit_event
from gds_api.config import settings
from gds_api.db import get_db
from gds_api.models import Role, Tenant, User, UserSession
from gds_api.rate_limit import ip_rate_limit
from gds_api.schemas import LoginRequest, MeResponse, RegisterRequest, RoleOut, TenantOut
from gds_api.security import (
    hash_password,
    REFRESH_COOKIE_NAME,
    CurrentUser,
    clear_auth_cookies,
    create_access_token,
    generate_refresh_token,
    get_current_user,
    hash_refresh_token,
    set_auth_cookies,
    verify_password,
)

router = APIRouter(prefix="/auth", tags=["auth"])

# A named reference (not an inline Depends(...) call) so the test suite can override
# just this dependency via app.dependency_overrides - real login flows still get real
# rate limiting; gds_api.rate_limit itself is exercised directly and for real in
# tests/test_rate_limit.py, so overriding it here doesn't leave the feature untested,
# just decoupled from tests that only need to log in as a means to an end.
login_rate_limit = ip_rate_limit("login", max_requests=10, window_seconds=60)
# EDP-008 Part 8 API hardening audit finding: /refresh had no rate limit at all, unlike
# /login - low severity on its own (refresh tokens are unguessable 32-byte
# secrets.token_urlsafe values, not brute-forceable), but a real inconsistency worth
# closing for defense in depth at the same cost as /login's own limit.
refresh_rate_limit = ip_rate_limit("refresh", max_requests=10, window_seconds=60)


async def _issue_session(db: AsyncSession, response: Response, *, user: User) -> None:
    refresh_token = generate_refresh_token()
    db.add(
        UserSession(
            tenant_id=user.tenant_id,
            user_id=user.id,
            refresh_token_hash=hash_refresh_token(refresh_token),
            expires_at=datetime.now(UTC) + timedelta(days=settings.jwt_refresh_token_days),
        )
    )
    access_token = create_access_token(user_id=user.id, tenant_id=user.tenant_id)
    set_auth_cookies(response, access_token=access_token, refresh_token=refresh_token)



@router.post("/register", dependencies=[Depends(ip_rate_limit("register", max_requests=5, window_seconds=60))])
async def register(
    body: RegisterRequest, response: Response, db: AsyncSession = Depends(get_db)
) -> MeResponse:
    """Register a new organization and admin user."""
    import uuid
    from gds_api.seed_data import ROLE_PERMISSIONS

    # Check if email already exists
    result = await db.execute(select(User).where(User.email == body.email))
    if result.scalar_one_or_none():
        raise HTTPException(status.HTTP_409_CONFLICT, "Email already registered")

    # Create new tenant
    slug = (body.full_name or body.email.split("@")[0]).lower().replace(" ", "-")[:50]
    tenant = Tenant(id=uuid.uuid4(), name=body.full_name or body.email, slug=f"{slug}-{uuid.uuid4().hex[:6]}")
    db.add(tenant)
    await db.flush()

    # Create platform_owner role for this tenant
    role = Role(
        id=uuid.uuid4(),
        tenant_id=tenant.id,
        name="platform_owner",
        permissions=ROLE_PERMISSIONS["platform_owner"],
    )
    db.add(role)
    await db.flush()

    # Create admin user
    user = User(
        id=uuid.uuid4(),
        tenant_id=tenant.id,
        role_id=role.id,
        email=body.email,
        password_hash=hash_password(body.password),
        is_active=True,
    )
    db.add(user)
    await db.flush()

    await _issue_session(db, response, user=user)
    await record_audit_event(
        db, tenant_id=tenant.id, user_id=user.id, action="auth.register", detail={"email": body.email}
    )
    await db.commit()

    return MeResponse(
        user_id=user.id,
        email=user.email,
        tenant=TenantOut(id=tenant.id, name=tenant.name, slug=tenant.slug),
        role=RoleOut(id=role.id, name=role.name, permissions=list(role.permissions)),
    )


@router.post("/login", dependencies=[Depends(login_rate_limit)])
async def login(
    body: LoginRequest, response: Response, db: AsyncSession = Depends(get_db)
) -> MeResponse:
    result = await db.execute(
        select(User, Role).join(Role, User.role_id == Role.id).where(User.email == body.email)
    )
    row = result.first()
    password_ok = row is not None and verify_password(body.password, row[0].password_hash)

    if row is None or not row[0].is_active or not password_ok:
        tenant_id = row[0].tenant_id if row is not None else None
        await record_audit_event(
            db,
            tenant_id=tenant_id,
            user_id=row[0].id if row is not None else None,
            action="auth.login.failure",
            detail={"email": body.email},
        )
        await db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid email or password")

    user, role = row
    await _issue_session(db, response, user=user)
    await record_audit_event(
        db, tenant_id=user.tenant_id, user_id=user.id, action="auth.login.success", detail={}
    )
    await db.commit()

    tenant = await db.get(Tenant, user.tenant_id)
    if tenant is None:
        # The tenant_id FK constraint should make this unreachable; fail loudly rather
        # than silently (an assert here would vanish under python -O).
        raise HTTPException(
            status.HTTP_500_INTERNAL_SERVER_ERROR, "User references a tenant that no longer exists"
        )
    return MeResponse(
        user_id=user.id,
        email=user.email,
        tenant=TenantOut(id=tenant.id, name=tenant.name, slug=tenant.slug),
        role=RoleOut(id=role.id, name=role.name, permissions=list(role.permissions)),
    )


@router.post("/refresh", dependencies=[Depends(refresh_rate_limit)])
async def refresh(
    request: Request, response: Response, db: AsyncSession = Depends(get_db)
) -> dict[str, str]:
    token = request.cookies.get(REFRESH_COOKIE_NAME)
    if not token:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "No refresh session")

    token_hash = hash_refresh_token(token)
    result = await db.execute(
        select(UserSession).where(UserSession.refresh_token_hash == token_hash)
    )
    session = result.scalar_one_or_none()
    now = datetime.now(UTC)
    if session is None or session.revoked_at is not None or session.expires_at < now:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Refresh session invalid or expired")

    session.revoked_at = now  # rotate: this refresh token is single-use
    user = await db.get(User, session.user_id)
    if user is None or not user.is_active:
        await db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "User no longer active")

    await _issue_session(db, response, user=user)
    await db.commit()
    return {"status": "refreshed"}


@router.post("/logout")
async def logout(
    request: Request,
    response: Response,
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict[str, str]:
    token = request.cookies.get(REFRESH_COOKIE_NAME)
    if token:
        token_hash = hash_refresh_token(token)
        result = await db.execute(
            select(UserSession).where(UserSession.refresh_token_hash == token_hash)
        )
        session = result.scalar_one_or_none()
        if session is not None and session.revoked_at is None:
            session.revoked_at = datetime.now(UTC)

    await record_audit_event(
        db,
        tenant_id=current_user.tenant_id,
        user_id=current_user.user_id,
        action="auth.logout",
        detail={},
    )
    await db.commit()
    clear_auth_cookies(response)
    return {"status": "logged_out"}


@router.get("/me")
async def me(
    current_user: CurrentUser = Depends(get_current_user), db: AsyncSession = Depends(get_db)
) -> MeResponse:
    tenant = await db.get(Tenant, current_user.tenant_id)
    if tenant is None:
        raise HTTPException(
            status.HTTP_500_INTERNAL_SERVER_ERROR, "User references a tenant that no longer exists"
        )
    return MeResponse(
        user_id=current_user.user_id,
        email=current_user.email,
        tenant=TenantOut(id=tenant.id, name=tenant.name, slug=tenant.slug),
        role=RoleOut(
            id=current_user.role_id,
            name=current_user.role_name,
            permissions=current_user.permissions,
        ),
    )
