"""GDS OS Phase 4 — Marketplace & Partner Framework Models.

Enables a full security ecosystem: developers publish agents, tools, workflows,
playbooks, and dashboards; customers subscribe; revenue is shared with publishers;
partners earn commissions; certifications verify quality.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from decimal import Decimal

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, Numeric, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from gds_api.models import Base


# ============================================================================
# DEVELOPER & ORGANIZATION
# ============================================================================

class Developer(Base):
    __tablename__ = "marketplace_developers"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"))
    display_name: Mapped[str] = mapped_column(String(200))
    email: Mapped[str] = mapped_column(String(255), unique=True)
    developer_type: Mapped[str] = mapped_column(String(50), default="individual")  # individual, organization, partner
    organization_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("marketplace_developer_orgs.id"), default=None)
    website: Mapped[str | None] = mapped_column(String(500), default=None)
    bio: Mapped[str | None] = mapped_column(Text, default=None)
    tier: Mapped[str] = mapped_column(String(50), default="standard")  # standard, verified, premium
    apps_published: Mapped[int] = mapped_column(Integer, default=0)
    agents_published: Mapped[int] = mapped_column(Integer, default=0)
    total_installs: Mapped[int] = mapped_column(Integer, default=0)
    total_revenue_usd: Mapped[float] = mapped_column(default=0.0)
    reputation_score: Mapped[float] = mapped_column(default=50.0)
    verification_status: Mapped[str] = mapped_column(String(50), default="pending")  # pending, verified, rejected
    certifications: Mapped[list] = mapped_column(JSONB, default=list)
    joined_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    last_active: Mapped[datetime | None] = mapped_column(DateTime, default=None)


class DeveloperOrganization(Base):
    __tablename__ = "marketplace_developer_orgs"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"))
    name: Mapped[str] = mapped_column(String(200))
    display_name: Mapped[str | None] = mapped_column(String(200), default=None)
    org_type: Mapped[str] = mapped_column(String(50), default="company")  # company, partnership, sole_trader
    website: Mapped[str | None] = mapped_column(String(500), default=None)
    country: Mapped[str | None] = mapped_column(String(100), default=None)
    member_count: Mapped[int] = mapped_column(Integer, default=1)
    apps_published: Mapped[int] = mapped_column(Integer, default=0)
    total_installs: Mapped[int] = mapped_column(Integer, default=0)
    total_revenue_usd: Mapped[float] = mapped_column(default=0.0)
    partner_tier: Mapped[str] = mapped_column(String(50), default="none")  # none, silver, gold, platinum
    verified: Mapped[bool] = mapped_column(Boolean, default=False)
    certified: Mapped[bool] = mapped_column(Boolean, default=False)
    revenue_share_pct: Mapped[float] = mapped_column(default=70.0)  # publisher gets 70% by default
    joined_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())


# ============================================================================
# PUBLISHER
# ============================================================================

class MarketplacePublisher(Base):
    __tablename__ = "marketplace_publishers"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"))
    developer_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("marketplace_developers.id"))
    org_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("marketplace_developer_orgs.id"), default=None)
    display_name: Mapped[str] = mapped_column(String(200))
    publisher_type: Mapped[str] = mapped_column(String(50), default="individual")  # individual, organization
    profile_url: Mapped[str | None] = mapped_column(String(500), default=None)
    logo_url: Mapped[str | None] = mapped_column(String(500), default=None)
    total_apps: Mapped[int] = mapped_column(Integer, default=0)
    total_agents: Mapped[int] = mapped_column(Integer, default=0)
    total_installs: Mapped[int] = mapped_column(Integer, default=0)
    avg_rating: Mapped[float] = mapped_column(default=0.0)
    total_revenue_usd: Mapped[float] = mapped_column(default=0.0)
    revenue_share_pct: Mapped[float] = mapped_column(default=70.0)
    is_featured: Mapped[bool] = mapped_column(Boolean, default=False)
    security_badge: Mapped[bool] = mapped_column(Boolean, default=False)
    compliance_badge: Mapped[bool] = mapped_column(Boolean, default=False)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime, default=None)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())


# ============================================================================
# LISTINGS (Unified — covers apps, agents, plugins, workflows, playbooks, dashboards)
# ============================================================================

class MarketplaceListing(Base):
    __tablename__ = "marketplace_listings"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"))
    publisher_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("marketplace_publishers.id"))
    name: Mapped[str] = mapped_column(String(200))
    display_name: Mapped[str | None] = mapped_column(String(200), default=None)
    tagline: Mapped[str | None] = mapped_column(String(500), default=None)
    description: Mapped[str] = mapped_column(Text, default="")
    item_type: Mapped[str] = mapped_column(String(50))  # application, agent, plugin, workflow, playbook, dashboard
    category: Mapped[str] = mapped_column(String(100))  # cloud-security, vulnerability-mgmt, incident-response, compliance, etc.
    subcategory: Mapped[str | None] = mapped_column(String(100), default=None)
    tags: Mapped[list] = mapped_column(JSONB, default=list)
    version: Mapped[str] = mapped_column(String(50), default="1.0.0")
    min_gds_version: Mapped[str | None] = mapped_column(String(50), default=None)
    pricing_model: Mapped[str] = mapped_column(String(50), default="free")  # free, one_time, subscription, usage_based
    price_usd: Mapped[float] = mapped_column(default=0.0)
    price_monthly_usd: Mapped[float] = mapped_column(default=0.0)
    installs_count: Mapped[int] = mapped_column(Integer, default=0)
    active_installs: Mapped[int] = mapped_column(Integer, default=0)
    rating: Mapped[float] = mapped_column(default=0.0)
    reviews_count: Mapped[int] = mapped_column(Integer, default=0)
    screenshots: Mapped[list] = mapped_column(JSONB, default=list)
    logo_url: Mapped[str | None] = mapped_column(String(500), default=None)
    documentation_url: Mapped[str | None] = mapped_column(String(500), default=None)
    source_url: Mapped[str | None] = mapped_column(String(500), default=None)
    certification_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("marketplace_certifications.id"), default=None)
    is_certified: Mapped[bool] = mapped_column(Boolean, default=False)
    is_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    is_featured: Mapped[bool] = mapped_column(Boolean, default=False)
    is_open_source: Mapped[bool] = mapped_column(Boolean, default=False)
    sbom_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    supply_chain_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    security_score: Mapped[float] = mapped_column(default=0.0)
    status: Mapped[str] = mapped_column(String(50), default="draft")  # draft, pending_review, published, rejected, deprecated, removed
    published_at: Mapped[datetime | None] = mapped_column(DateTime, default=None)
    last_updated: Mapped[datetime | None] = mapped_column(DateTime, default=None)


# ============================================================================
# CERTIFICATION
# ============================================================================

class Certification(Base):
    __tablename__ = "marketplace_certifications"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"))
    listing_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("marketplace_listings.id"))
    publisher_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("marketplace_publishers.id"))
    item_name: Mapped[str] = mapped_column(String(200))
    certification_type: Mapped[str] = mapped_column(String(100))  # security, code_quality, performance, compliance, full
    security_score: Mapped[float] = mapped_column(default=0.0)
    code_quality_score: Mapped[float] = mapped_column(default=0.0)
    performance_score: Mapped[float] = mapped_column(default=0.0)
    compliance_score: Mapped[float] = mapped_column(default=0.0)
    sbom_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    supply_chain_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    malware_clean: Mapped[bool] = mapped_column(Boolean, default=False)
    dependency_audit_passed: Mapped[bool] = mapped_column(Boolean, default=False)
    api_compatibility_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    sandbox_tested: Mapped[bool] = mapped_column(Boolean, default=False)
    overall_score: Mapped[float] = mapped_column(default=0.0)
    grade: Mapped[str] = mapped_column(String(10), default="F")  # A, B, C, D, F
    issues_found: Mapped[int] = mapped_column(Integer, default=0)
    critical_issues: Mapped[int] = mapped_column(Integer, default=0)
    certified_at: Mapped[datetime | None] = mapped_column(DateTime, default=None)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime, default=None)
    reviewed_by: Mapped[str | None] = mapped_column(String(200), default=None)
    status: Mapped[str] = mapped_column(String(50), default="pending")  # pending, in_review, certified, failed, expired


# ============================================================================
# REVIEWS
# ============================================================================

class MarketplaceReview(Base):
    __tablename__ = "marketplace_reviews"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"))
    listing_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("marketplace_listings.id"))
    reviewer_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    reviewer_name: Mapped[str | None] = mapped_column(String(200), default=None)
    rating: Mapped[int] = mapped_column(Integer)  # 1-5
    title: Mapped[str] = mapped_column(String(200))
    body: Mapped[str] = mapped_column(Text, default="")
    use_case: Mapped[str | None] = mapped_column(String(500), default=None)
    pros: Mapped[list] = mapped_column(JSONB, default=list)
    cons: Mapped[list] = mapped_column(JSONB, default=list)
    helpful_votes: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())


# ============================================================================
# DOWNLOADS, SUBSCRIPTIONS & LICENSES
# ============================================================================

class MarketplaceDownload(Base):
    __tablename__ = "marketplace_downloads"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"))
    listing_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("marketplace_listings.id"))
    item_name: Mapped[str] = mapped_column(String(200))
    downloader_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    downloader_tenant: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"))
    version_downloaded: Mapped[str] = mapped_column(String(50), default="1.0.0")
    install_type: Mapped[str] = mapped_column(String(50), default="install")  # install, trial, update
    environment: Mapped[str] = mapped_column(String(50), default="production")
    ip_country: Mapped[str | None] = mapped_column(String(100), default=None)
    downloaded_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())


class MarketplaceSubscription(Base):
    __tablename__ = "marketplace_subscriptions"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"))
    subscriber_tenant: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"))
    listing_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("marketplace_listings.id"))
    item_name: Mapped[str] = mapped_column(String(200))
    publisher_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("marketplace_publishers.id"))
    plan_name: Mapped[str] = mapped_column(String(200))
    price_monthly_usd: Mapped[float] = mapped_column(default=0.0)
    billing_cycle: Mapped[str] = mapped_column(String(50), default="monthly")  # monthly, annual
    current_period_start: Mapped[datetime | None] = mapped_column(DateTime, default=None)
    current_period_end: Mapped[datetime | None] = mapped_column(DateTime, default=None)
    usage_this_period: Mapped[int] = mapped_column(Integer, default=0)
    usage_limit: Mapped[int] = mapped_column(Integer, default=0)  # 0 = unlimited
    cancel_at_period_end: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    status: Mapped[str] = mapped_column(String(50), default="active")  # active, cancelled, suspended, expired


class MarketplaceLicense(Base):
    __tablename__ = "marketplace_licenses"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"))
    listing_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("marketplace_listings.id"))
    item_name: Mapped[str] = mapped_column(String(200))
    licensee_tenant: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"))
    license_type: Mapped[str] = mapped_column(String(50), default="subscription")  # subscription, perpetual, trial, educational
    seats: Mapped[int] = mapped_column(Integer, default=1)
    price_paid_usd: Mapped[float] = mapped_column(default=0.0)
    billing_cycle: Mapped[str] = mapped_column(String(50), default="monthly")
    starts_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    expires_at: Mapped[datetime | None] = mapped_column(DateTime, default=None)
    auto_renew: Mapped[bool] = mapped_column(Boolean, default=True)
    usage_count: Mapped[int] = mapped_column(Integer, default=0)
    max_usage: Mapped[int] = mapped_column(Integer, default=0)  # 0 = unlimited
    status: Mapped[str] = mapped_column(String(50), default="active")


# ============================================================================
# REVENUE & BILLING
# ============================================================================

class RevenueShare(Base):
    __tablename__ = "marketplace_revenue_shares"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"))
    publisher_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("marketplace_publishers.id"))
    period_start: Mapped[datetime] = mapped_column(DateTime)
    period_end: Mapped[datetime] = mapped_column(DateTime)
    gross_revenue_usd: Mapped[float] = mapped_column(default=0.0)
    platform_fee_pct: Mapped[float] = mapped_column(default=30.0)
    platform_fee_usd: Mapped[float] = mapped_column(default=0.0)
    publisher_share_pct: Mapped[float] = mapped_column(default=70.0)
    publisher_payout_usd: Mapped[float] = mapped_column(default=0.0)
    installs_period: Mapped[int] = mapped_column(Integer, default=0)
    subscriptions_period: Mapped[int] = mapped_column(Integer, default=0)
    top_item: Mapped[str | None] = mapped_column(String(200), default=None)
    payment_method: Mapped[str | None] = mapped_column(String(100), default=None)
    paid_at: Mapped[datetime | None] = mapped_column(DateTime, default=None)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    status: Mapped[str] = mapped_column(String(50), default="pending")  # pending, paid, disputed


class MarketplaceInvoice(Base):
    __tablename__ = "marketplace_invoices"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"))
    subscriber_tenant: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"))
    publisher_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("marketplace_publishers.id"), default=None)
    line_items: Mapped[list] = mapped_column(JSONB, default=list)
    subtotal_usd: Mapped[float] = mapped_column(default=0.0)
    tax_usd: Mapped[float] = mapped_column(default=0.0)
    total_usd: Mapped[float] = mapped_column(default=0.0)
    currency: Mapped[str] = mapped_column(String(10), default="USD")
    due_date: Mapped[datetime | None] = mapped_column(DateTime, default=None)
    paid_at: Mapped[datetime | None] = mapped_column(DateTime, default=None)
    payment_method: Mapped[str | None] = mapped_column(String(100), default=None)
    invoice_number: Mapped[str] = mapped_column(String(100), unique=True)
    period_start: Mapped[datetime | None] = mapped_column(DateTime, default=None)
    period_end: Mapped[datetime | None] = mapped_column(DateTime, default=None)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    status: Mapped[str] = mapped_column(String(50), default="pending")  # pending, paid, overdue, cancelled


# ============================================================================
# PARTNER PROGRAM
# ============================================================================

class Partner(Base):
    __tablename__ = "marketplace_partners"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"))
    name: Mapped[str] = mapped_column(String(200))
    partner_type: Mapped[str] = mapped_column(String(50), default="reseller")  # reseller, technology, referral, mssp
    tier: Mapped[str] = mapped_column(String(50), default="registered")  # registered, silver, gold, platinum
    country: Mapped[str | None] = mapped_column(String(100), default=None)
    customers_referred: Mapped[int] = mapped_column(Integer, default=0)
    customers_active: Mapped[int] = mapped_column(Integer, default=0)
    mrr_attributed_usd: Mapped[float] = mapped_column(default=0.0)
    arr_attributed_usd: Mapped[float] = mapped_column(default=0.0)
    commission_pct: Mapped[float] = mapped_column(default=15.0)  # 15% default commission
    ytd_commission_usd: Mapped[float] = mapped_column(default=0.0)
    contact_email: Mapped[str] = mapped_column(String(255))
    white_label_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    joined_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    status: Mapped[str] = mapped_column(String(50), default="active")


class PartnerAgreement(Base):
    __tablename__ = "marketplace_partner_agreements"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"))
    partner_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("marketplace_partners.id"))
    agreement_type: Mapped[str] = mapped_column(String(100))  # reseller, referral, technology, mssp_white_label
    commission_model: Mapped[str] = mapped_column(String(100), default="percentage")  # percentage, flat_fee, tiered
    commission_pct: Mapped[float] = mapped_column(default=15.0)
    minimum_commitment_usd: Mapped[float] = mapped_column(default=0.0)
    contract_start: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    contract_end: Mapped[datetime | None] = mapped_column(DateTime, default=None)
    auto_renew: Mapped[bool] = mapped_column(Boolean, default=True)
    total_paid_usd: Mapped[float] = mapped_column(default=0.0)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    status: Mapped[str] = mapped_column(String(50), default="active")
