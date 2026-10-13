"""GDS OS SSO/SAML — Routes."""
from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from gds_api.db import get_db
from gds_api.security import CurrentUser
from gds_api.sso.provider import (
    IdentityProvider,
    SSOSession,
    create_provider,
    create_sso_session,
    generate_oidc_auth_url,
    generate_saml_request,
    parse_saml_response,
    revoke_session,
    test_provider,
    validate_session,
)

router = APIRouter(prefix="/sso", tags=["sso"])


class CreateProviderRequest(BaseModel):
    name: str
    provider_type: str
    issuer_url: str | None = None
    sso_url: str | None = None
    metadata_url: str | None = None
    client_id: str | None = None
    client_secret: str | None = None
    scopes: list[str] | None = None
    attribute_mapping: dict | None = None
    auto_provision: bool = True
    is_primary: bool = False


class SAMLCallbackRequest(BaseModel):
    saml_response: str
    relay_state: str | None = None


class OIDCCallbackRequest(BaseModel):
    code: str
    state: str
    redirect_uri: str


class InitSAMLRequest(BaseModel):
    provider_id: str
    acs_url: str = "https://api.globaldigitalstreams.com/sso/saml/callback"


class InitOIDCRequest(BaseModel):
    provider_id: str
    redirect_uri: str = "https://api.globaldigitalstreams.com/sso/oidc/callback"


class ValidateSessionRequest(BaseModel):
    session_token: str


@router.post("/providers", status_code=status.HTTP_201_CREATED)
async def create_sso_provider(body: CreateProviderRequest, db: AsyncSession = Depends(get_db), user: CurrentUser = Depends) -> dict:
    p = await create_provider(db, user.tenant_id, body.name, body.provider_type,
                              body.issuer_url, body.sso_url, body.metadata_url,
                              body.client_id, body.client_secret, body.scopes,
                              body.attribute_mapping, body.auto_provision, body.is_primary)
    await db.commit()
    return {"id": str(p.id), "name": p.name, "provider_type": p.provider_type,
            "test_passed": p.test_passed, "is_primary": p.is_primary}


@router.get("/providers")
async def list_providers(db: AsyncSession = Depends(get_db), user: CurrentUser = Depends) -> list[dict]:
    q = select(IdentityProvider).where(IdentityProvider.tenant_id == user.tenant_id).order_by(IdentityProvider.created_at.desc())
    result = await db.execute(q)
    return [
        {"id": str(p.id), "name": p.name, "provider_type": p.provider_type,
         "issuer_url": p.issuer_url, "sso_url": p.sso_url, "is_primary": p.is_primary,
         "auto_provision": p.auto_provision, "test_passed": p.test_passed,
         "last_tested": p.last_tested.isoformat() if p.last_tested else None,
         "users_synced": p.users_synced, "is_active": p.is_active,
         "error_message": p.error_message}
        for p in result.scalars().all()
    ]


@router.get("/providers/{provider_id}")
async def get_provider(provider_id: uuid.UUID, db: AsyncSession = Depends(get_db), user: CurrentUser = Depends) -> dict:
    q = select(IdentityProvider).where(IdentityProvider.id == provider_id, IdentityProvider.tenant_id == user.tenant_id)
    p = (await db.execute(q)).scalar_one_or_none()
    if not p:
        raise HTTPException(status_code=404, detail="Provider not found")
    return {"id": str(p.id), "name": p.name, "provider_type": p.provider_type,
            "issuer_url": p.issuer_url, "sso_url": p.sso_url, "metadata_url": p.metadata_url,
            "client_id": p.client_id, "client_secret_hint": p.client_secret_hint,
            "scopes": p.scopes, "attribute_mapping": p.attribute_mapping,
            "is_primary": p.is_primary, "auto_provision": p.auto_provision,
            "test_passed": p.test_passed, "last_tested": p.last_tested.isoformat() if p.last_tested else None,
            "last_sync": p.last_sync.isoformat() if p.last_sync else None, "users_synced": p.users_synced,
            "is_active": p.is_active, "error_message": p.error_message}


@router.post("/providers/{provider_id}/test")
async def test_sso_provider(provider_id: uuid.UUID, db: AsyncSession = Depends(get_db), user: CurrentUser = Depends) -> dict:
    result = await test_provider(db, user.tenant_id, provider_id)
    await db.commit()
    return result


@router.delete("/providers/{provider_id}")
async def delete_provider(provider_id: uuid.UUID, db: AsyncSession = Depends(get_db), user: CurrentUser = Depends) -> dict:
    q = select(IdentityProvider).where(IdentityProvider.id == provider_id, IdentityProvider.tenant_id == user.tenant_id)
    p = (await db.execute(q)).scalar_one_or_none()
    if not p:
        raise HTTPException(status_code=404, detail="Provider not found")
    p.is_active = False
    await db.commit()
    return {"id": str(provider_id), "status": "deactivated"}


@router.post("/saml/init")
async def init_saml(body: InitSAMLRequest, db: AsyncSession = Depends(get_db), user: CurrentUser = Depends) -> dict:
    q = select(IdentityProvider).where(IdentityProvider.id == uuid.UUID(body.provider_id), IdentityProvider.tenant_id == user.tenant_id)
    p = (await db.execute(q)).scalar_one_or_none()
    if not p:
        raise HTTPException(status_code=404, detail="Provider not found")
    saml_request = generate_saml_request(p.issuer_url or "", body.acs_url, "GDS OS")
    return {"saml_request": saml_request, "relay_state": str(body.provider_id),
            "sso_url": p.sso_url or p.issuer_url or ""}


@router.post("/saml/callback")
async def saml_callback(body: SAMLCallbackRequest, db: AsyncSession = Depends(get_db), user: CurrentUser = Depends) -> dict:
    provider_id = uuid.UUID(body.relay_state) if body.relay_state else None
    if not provider_id:
        raise HTTPException(status_code=400, detail="Missing relay_state")
    q = select(IdentityProvider).where(IdentityProvider.id == provider_id, IdentityProvider.tenant_id == user.tenant_id)
    p = (await db.execute(q)).scalar_one_or_none()
    if not p:
        raise HTTPException(status_code=404, detail="Provider not found")
    parsed = parse_saml_response(body.saml_response)
    if not parsed["valid"]:
        raise HTTPException(status_code=401, detail="Invalid SAML response")
    session = await create_sso_session(db, user.tenant_id, provider_id,
                                       parsed["name_id"], parsed.get("attributes", {}).get("name", ""),
                                       parsed["attributes"], "saml", mfa_verified=True)
    await db.commit()
    return {"session_token": session.session_token, "user_email": session.user_email,
            "expires_at": session.expires_at.isoformat() if session.expires_at else None}


@router.post("/oidc/init")
async def init_oidc(body: InitOIDCRequest, db: AsyncSession = Depends(get_db), user: CurrentUser = Depends) -> dict:
    q = select(IdentityProvider).where(IdentityProvider.id == uuid.UUID(body.provider_id), IdentityProvider.tenant_id == user.tenant_id)
    p = (await db.execute(q)).scalar_one_or_none()
    if not p:
        raise HTTPException(status_code=404, detail="Provider not found")
    if not p.sso_url:
        raise HTTPException(status_code=400, detail="No SSO URL configured for OIDC")
    auth_url = generate_oidc_auth_url(p.sso_url, p.client_id or "", body.redirect_uri,
                                       str(uuid.uuid4()), p.scopes or ["openid", "profile", "email"])
    return {"auth_url": auth_url, "state": str(uuid.uuid4())}


@router.post("/oidc/callback")
async def oidc_callback(body: OIDCCallbackRequest, db: AsyncSession = Depends(get_db), user: CurrentUser = Depends) -> dict:
    from gds_api.sso.provider import exchange_oidc_code, fetch_oidc_userinfo
    q = select(IdentityProvider).where(IdentityProvider.tenant_id == user.tenant_id, IdentityProvider.is_active == True)  # noqa: E712
    p = (await db.execute(q)).scalars().first()
    if not p or not p.issuer_url:
        raise HTTPException(status_code=400, detail="No OIDC provider configured")
    tokens = await exchange_oidc_code(p.issuer_url, body.code, p.client_id or "", "", body.redirect_uri)
    if "error" in tokens:
        raise HTTPException(status_code=401, detail=tokens["error"])
    userinfo = await fetch_oidc_userinfo(p.issuer_url, tokens.get("access_token", ""))
    session = await create_sso_session(db, user.tenant_id, p.id,
                                       userinfo.get("email", ""), userinfo.get("name", ""),
                                       userinfo, "oidc", mfa_verified=True)
    await db.commit()
    return {"session_token": session.session_token, "user_email": session.user_email,
            "expires_at": session.expires_at.isoformat() if session.expires_at else None}


@router.post("/validate")
async def validate_sso_session(body: ValidateSessionRequest, db: AsyncSession = Depends(get_db), user: CurrentUser = Depends) -> dict:
    return await validate_session(db, user.tenant_id, body.session_token)


@router.post("/logout")
async def sso_logout(body: ValidateSessionRequest, db: AsyncSession = Depends(get_db), user: CurrentUser = Depends) -> dict:
    success = await revoke_session(db, user.tenant_id, body.session_token)
    await db.commit()
    return {"revoked": success}


@router.get("/sessions")
async def list_sessions(db: AsyncSession = Depends(get_db), user: CurrentUser = Depends) -> list[dict]:
    q = select(SSOSession).where(SSOSession.tenant_id == user.tenant_id).order_by(SSOSession.started_at.desc()).limit(50)
    result = await db.execute(q)
    return [
        {"id": str(s.id), "user_email": s.user_email, "user_name": s.user_name,
         "auth_method": s.auth_method, "mfa_verified": s.mfa_verified,
         "started_at": s.started_at.isoformat() if s.started_at else None,
         "expires_at": s.expires_at.isoformat() if s.expires_at else None,
         "revoked": s.revoked, "ip_address": s.ip_address}
        for s in result.scalars().all()
    ]
