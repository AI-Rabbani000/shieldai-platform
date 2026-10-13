"""GDS OS SSO/SAML Integration — Enterprise Identity Provider.

Supports SAML 2.0, OIDC, and custom identity providers for enterprise SSO.
"""
from __future__ import annotations

import base64
import hashlib
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
from sqlalchemy import ForeignKey, String, Text, func
from sqlalchemy import Boolean, DateTime, Integer
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy import select

from gds_api.logging_config import get_logger
from gds_api.models import Base

logger = get_logger(__name__)

# ============================================================================
# MODELS
# ============================================================================


class IdentityProvider(Base):
    __tablename__ = "identity_providers"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"))
    name: Mapped[str] = mapped_column(String(200))
    provider_type: Mapped[str] = mapped_column(String(100))  # saml, oidc, azure_ad, okta, google, auth0
    issuer_url: Mapped[str | None] = mapped_column(String(500), default=None)
    sso_url: Mapped[str | None] = mapped_column(String(500), default=None)
    metadata_url: Mapped[str | None] = mapped_column(String(500), default=None)
    client_id: Mapped[str | None] = mapped_column(String(200), default=None)
    client_secret_hint: Mapped[str | None] = mapped_column(String(50), default=None)
    scopes: Mapped[list] = mapped_column(JSONB, default=list)
    attribute_mapping: Mapped[dict] = mapped_column(JSONB, default=dict)
    is_primary: Mapped[bool] = mapped_column(Boolean, default=False)
    auto_provision: Mapped[bool] = mapped_column(Boolean, default=True)
    default_role_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("roles.id"), default=None)
    test_passed: Mapped[bool] = mapped_column(Boolean, default=False)
    last_tested: Mapped[datetime | None] = mapped_column(DateTime, default=None)
    last_sync: Mapped[datetime | None] = mapped_column(DateTime, default=None)
    users_synced: Mapped[int] = mapped_column(Integer, default=0)
    error_message: Mapped[str | None] = mapped_column(Text, default=None)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())


class SSOSession(Base):
    __tablename__ = "sso_sessions"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"))
    provider_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("identity_providers.id"))
    user_email: Mapped[str] = mapped_column(String(200))
    user_name: Mapped[str | None] = mapped_column(String(200), default=None)
    user_attributes: Mapped[dict] = mapped_column(JSONB, default=dict)
    session_token: Mapped[str] = mapped_column(String(128))
    auth_method: Mapped[str] = mapped_column(String(100))  # saml, oidc, oauth
    mfa_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    started_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    expires_at: Mapped[datetime] = mapped_column(DateTime)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime, default=None)
    ip_address: Mapped[str | None] = mapped_column(String(45), default=None)
    user_agent: Mapped[str | None] = mapped_column(String(500), default=None)


class SSOAttributeMapping(Base):
    __tablename__ = "sso_attribute_mappings"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"))
    provider_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("identity_providers.id"))
    idp_attribute: Mapped[str] = mapped_column(String(200))
    local_field: Mapped[str] = mapped_column(String(200))  # email, full_name, role, department, groups
    is_required: Mapped[bool] = mapped_column(Boolean, default=False)
    default_value: Mapped[str | None] = mapped_column(String(200), default=None)


# ============================================================================
# SAML HELPERS
# ============================================================================

def generate_saml_request(issuer_url: str, acs_url: str, provider_name: str = "GDS OS") -> str:
    """Generate a SAML AuthnRequest (base64-encoded XML)."""
    request_id = f"id_{secrets.token_hex(16)}"
    timestamp = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    saml_xml = f"""<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="{request_id}"
    Version="2.0"
    IssueInstant="{timestamp}"
    ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
    AssertionConsumerServiceURL="{acs_url}">
    <saml:Issuer>{provider_name}</saml:Issuer>
    <samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" AllowCreate="true"/>
</samlp:AuthnRequest>"""
    return base64.b64encode(saml_xml.encode()).decode()


def parse_saml_response(response_xml: str) -> dict[str, Any]:
    """Parse a SAML response (simplified — extracts key attributes)."""
    # In production, use python3-saml or xmlsec for full SAML parsing + signature verification
    # This is a simplified parser for the attribute extraction
    import re
    result = {"attributes": {}, "name_id": None, "issuer": None, "valid": False}

    name_id_match = re.search(r"<saml:NameID[^>]*>([^<]+)</saml:NameID>", response_xml)
    if name_id_match:
        result["name_id"] = name_id_match.group(1)

    issuer_match = re.search(r'<saml:Issuer[^>]*>([^<]+)</saml:Issuer>', response_xml)
    if issuer_match:
        result["issuer"] = issuer_match.group(1)

    # Extract attributes
    attr_matches = re.findall(r'<saml:Attribute[^>]*Name="([^"]+)"[^>]*>(.*?)</saml:Attribute>', response_xml, re.DOTALL)
    for name, value_xml in attr_matches:
        value_match = re.search(r'<saml:AttributeValue[^>]*>([^<]*)</saml:AttributeValue>', value_xml)
        result["attributes"][name] = value_match.group(1) if value_match else ""

    result["valid"] = result["name_id"] is not None
    return result


# ============================================================================
# OIDC HELPERS
# ============================================================================

def generate_oidc_auth_url(authorize_url: str, client_id: str, redirect_uri: str, state: str, scopes: list[str]) -> str:
    """Generate an OIDC authorization URL."""
    scope_str = " ".join(scopes) if scopes else "openid profile email"
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scope_str,
        "state": state,
    }
    query = "&".join(f"{k}={v}" for k, v in params.items())
    return f"{authorize_url}?{query}"


async def exchange_oidc_code(
    token_url: str, code: str, client_id: str, client_secret: str,
    redirect_uri: str,
) -> dict[str, Any]:
    """Exchange an OIDC authorization code for tokens."""
    payload = {
        "grant_type": "authorization_code",
        "code": code,
        "client_id": client_id,
        "client_secret": client_secret,
        "redirect_uri": redirect_uri,
    }
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.post(token_url, data=payload)
        if resp.status_code == 200:
            return resp.json()
        return {"error": f"Token exchange failed: {resp.status_code}", "details": resp.text[:500]}


async def fetch_oidc_userinfo(userinfo_url: str, access_token: str) -> dict[str, Any]:
    """Fetch user info from OIDC userinfo endpoint."""
    headers = {"Authorization": f"Bearer {access_token}"}
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.get(userinfo_url, headers=headers)
        if resp.status_code == 200:
            return resp.json()
        return {"error": f"UserInfo fetch failed: {resp.status_code}"}


async def fetch_saml_metadata(metadata_url: str) -> dict[str, Any]:
    """Fetch and parse SAML metadata from IdP."""
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.get(metadata_url)
        if resp.status_code != 200:
            return {"error": f"Failed to fetch metadata: {resp.status_code}"}
        import re
        xml = resp.text
        result = {"entity_id": None, "sso_url": None, "slo_url": None, "cert": None}
        eid = re.search(r'entityID="([^"]+)"', xml)
        if eid:
            result["entity_id"] = eid.group(1)
        sso = re.search(r'Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"[^>]*Location="([^"]+)"', xml)
        if sso:
            result["sso_url"] = sso.group(1)
        elif not sso:
            sso = re.search(r'Location="([^"]+)"[^>]*Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"', xml)
            if sso:
                result["sso_url"] = sso.group(1)
        cert = re.search(r'<ds:X509Certificate>([^<]+)</ds:X509Certificate>', xml)
        if cert:
            result["cert"] = cert.group(1).strip()
        return result


# ============================================================================
# SESSION MANAGEMENT
# ============================================================================

def generate_session_token() -> str:
    """Generate a cryptographically secure session token."""
    return secrets.token_urlsafe(48)


async def create_sso_session(
    db: AsyncSession, tenant_id, provider_id, user_email, user_name,
    user_attributes, auth_method, mfa_verified=False,
    expires_hours=8, ip_address=None, user_agent=None,
) -> SSOSession:
    """Create an SSO session after successful authentication."""
    session = SSOSession(
        tenant_id=tenant_id, provider_id=provider_id,
        user_email=user_email, user_name=user_name,
        user_attributes=user_attributes,
        session_token=generate_session_token(),
        auth_method=auth_method, mfa_verified=mfa_verified,
        expires_at=datetime.now(UTC) + timedelta(hours=expires_hours),
        ip_address=ip_address, user_agent=user_agent,
    )
    db.add(session)
    await db.flush()
    return session


async def validate_session(db: AsyncSession, tenant_id, session_token: str) -> dict:
    """Validate an SSO session token."""
    q = select(SSOSession).where(
        SSOSession.tenant_id == tenant_id,
        SSOSession.session_token == session_token,
        SSOSession.revoked == False,  # noqa: E712
    )
    session = (await db.execute(q)).scalar_one_or_none()
    if not session:
        return {"valid": False, "reason": "Session not found"}
    if session.expires_at and session.expires_at < datetime.now(UTC):
        return {"valid": False, "reason": "Session expired"}
    return {
        "valid": True, "user_email": session.user_email,
        "user_name": session.user_name, "auth_method": session.auth_method,
        "mfa_verified": session.mfa_verified,
        "expires_at": session.expires_at.isoformat() if session.expires_at else None,
    }


async def revoke_session(db: AsyncSession, tenant_id, session_token: str) -> bool:
    """Revoke an SSO session."""
    q = select(SSOSession).where(
        SSOSession.tenant_id == tenant_id,
        SSOSession.session_token == session_token,
    )
    session = (await db.execute(q)).scalar_one_or_none()
    if not session:
        return False
    session.revoked = True
    session.revoked_at = datetime.now(UTC)
    await db.flush()
    return True


# ============================================================================
# PROVIDER MANAGEMENT
# ============================================================================

async def create_provider(
    db: AsyncSession, tenant_id, name: str, provider_type: str,
    issuer_url: str | None = None, sso_url: str | None = None,
    metadata_url: str | None = None, client_id: str | None = None,
    client_secret: str | None = None, scopes: list[str] | None = None,
    attribute_mapping: dict | None = None, auto_provision: bool = True,
    is_primary: bool = False,
) -> IdentityProvider:
    """Create a new identity provider configuration."""
    # If primary, unset other primaries
    if is_primary:
        q = select(IdentityProvider).where(
            IdentityProvider.tenant_id == tenant_id,
            IdentityProvider.is_primary == True,  # noqa: E712
        )
        existing = (await db.execute(q)).scalars().all()
        for p in existing:
            p.is_primary = False

    provider = IdentityProvider(
        tenant_id=tenant_id, name=name, provider_type=provider_type,
        issuer_url=issuer_url, sso_url=sso_url, metadata_url=metadata_url,
        client_id=client_id,
        client_secret_hint=f"***{client_secret[-4:]}" if client_secret else None,
        scopes=scopes or ["openid", "profile", "email"],
        attribute_mapping=attribute_mapping or {},
        auto_provision=auto_provision, is_primary=is_primary,
    )
    db.add(provider)
    await db.flush()

    # If metadata_url provided, auto-configure
    if metadata_url:
        try:
            meta = await fetch_saml_metadata(metadata_url)
            if meta.get("sso_url"):
                provider.sso_url = meta["sso_url"]
            if meta.get("entity_id") and not issuer_url:
                provider.issuer_url = meta["entity_id"]
            provider.test_passed = meta.get("sso_url") is not None
            provider.last_tested = datetime.now(UTC)
        except Exception as e:
            provider.error_message = f"Metadata fetch failed: {e}"
        await db.flush()

    return provider


async def test_provider(db: AsyncSession, tenant_id, provider_id) -> dict:
    """Test connectivity to an identity provider."""
    q = select(IdentityProvider).where(
        IdentityProvider.id == provider_id,
        IdentityProvider.tenant_id == tenant_id,
    )
    provider = (await db.execute(q)).scalar_one_or_none()
    if not provider:
        return {"error": "Provider not found"}

    if provider.metadata_url:
        meta = await fetch_saml_metadata(provider.metadata_url)
        provider.test_passed = meta.get("sso_url") is not None
        provider.last_tested = datetime.now(UTC)
        if meta.get("error"):
            provider.error_message = meta["error"]
        await db.flush()
        return {"test_passed": provider.test_passed, "metadata": meta}
    elif provider.issuer_url:
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(provider.issuer_url)
                provider.test_passed = resp.status_code < 400
                provider.last_tested = datetime.now(UTC)
                await db.flush()
                return {"test_passed": provider.test_passed, "status_code": resp.status_code}
        except Exception as e:
            provider.error_message = str(e)
            await db.flush()
            return {"test_passed": False, "error": str(e)}
    return {"test_passed": False, "error": "No issuer URL or metadata URL configured"}
