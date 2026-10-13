"""GDS OS Phase 4 — Marketplace & Partner API Routes."""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from gds_api.marketplace.models import (
    Developer, DeveloperOrganization, MarketplacePublisher,
    MarketplaceListing, Certification, MarketplaceReview,
    MarketplaceSubscription, MarketplaceLicense,
    RevenueShare, MarketplaceInvoice, Partner, PartnerAgreement,
)
from gds_api.marketplace.engine import (
    LISTING_CATEGORIES, PRICING_MODELS, PARTNER_TIERS,
    register_developer, verify_developer,
    publish_listing, approve_listing, reject_listing,
    run_certification, subscribe_to_listing, record_download,
    calculate_revenue_share, generate_invoice,
    register_partner, calculate_partner_commission, upgrade_partner_tier,
    get_marketplace_stats, get_publisher_analytics,
)
from gds_api.db import get_db
from gds_api.security import CurrentUser

router = APIRouter(prefix="/marketplace", tags=["marketplace"])


# ============================================================================
# SCHEMAS
# ============================================================================

class RegisterDeveloperRequest(BaseModel):
    display_name: str
    email: str
    developer_type: str = "individual"
    website: str = ""
    bio: str = ""

class PublishListingRequest(BaseModel):
    publisher_id: str
    name: str
    item_type: str  # application, agent, plugin, workflow, playbook, dashboard
    category: str
    description: str = ""
    tagline: str = ""
    tags: list[str] = []
    pricing_model: str = "free"
    price_usd: float = 0.0
    price_monthly_usd: float = 0.0
    version: str = "1.0.0"
    is_open_source: bool = False
    documentation_url: str = ""
    source_url: str = ""

class SubscribeRequest(BaseModel):
    listing_id: str
    subscriber_tenant_id: str
    plan_name: str = "standard"
    billing_cycle: str = "monthly"

class DownloadRequest(BaseModel):
    listing_id: str
    version: str = "1.0.0"
    install_type: str = "install"
    country: str = ""

class ReviewRequest(BaseModel):
    listing_id: str
    rating: int  # 1-5
    title: str
    body: str = ""
    use_case: str = ""
    pros: list[str] = []
    cons: list[str] = []

class RevenueShareRequest(BaseModel):
    publisher_id: str
    period_start: str
    period_end: str

class GenerateInvoiceRequest(BaseModel):
    subscriber_tenant_id: str
    publisher_id: str | None = None
    line_items: list[dict[str, Any]]
    period_start: str | None = None
    period_end: str | None = None

class RegisterPartnerRequest(BaseModel):
    name: str
    partner_type: str = "reseller"
    contact_email: str
    country: str = ""
    tier: str = "registered"

class CommissionRequest(BaseModel):
    partner_id: str
    revenue_usd: float

class UpgradePartnerRequest(BaseModel):
    new_tier: str


# ============================================================================
# DEVELOPER ROUTES
# ============================================================================

@router.post("/developers/register")
async def api_register_developer(
    req: RegisterDeveloperRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends,
) -> dict[str, Any]:
    return await register_developer(db, user.tenant_id, req.display_name, req.email, req.developer_type, req.website, req.bio)

@router.get("/developers")
async def list_developers(
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends,
    limit: int = 50,
) -> dict[str, Any]:
    stmt = (
        select(Developer)
        .where(Developer.tenant_id == user.tenant_id)
        .order_by(Developer.total_revenue_usd.desc())
        .limit(limit)
    )
    result = await db.execute(stmt)
    devs = result.scalars().all()
    return {"total": len(devs), "developers": [
        {"id": str(d.id), "name": d.display_name, "email": d.email,
         "type": d.developer_type, "tier": d.tier,
         "verification": d.verification_status,
         "apps_published": d.apps_published, "agents_published": d.agents_published,
         "total_installs": d.total_installs, "revenue_usd": d.total_revenue_usd,
         "reputation": d.reputation_score, "joined_at": d.joined_at.isoformat() if d.joined_at else None}
        for d in devs
    ]}

@router.post("/developers/{developer_id}/verify")
async def api_verify_developer(
    developer_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends,
) -> dict[str, Any]:
    try:
        return await verify_developer(db, developer_id, user.tenant_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


# ============================================================================
# LISTING ROUTES
# ============================================================================

@router.post("/listings")
async def api_publish_listing(
    req: PublishListingRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends,
) -> dict[str, Any]:
    try:
        return await publish_listing(
            db, user.tenant_id, uuid.UUID(req.publisher_id),
            req.name, req.item_type, req.category, req.description, req.tagline,
            req.tags, req.pricing_model, req.price_usd, req.price_monthly_usd,
            req.version, req.is_open_source, req.documentation_url, req.source_url,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.get("/listings")
async def list_listings(
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends,
    item_type: str | None = None,
    category: str | None = None,
    pricing_model: str | None = None,
    is_certified: bool | None = None,
    is_featured: bool | None = None,
    limit: int = 50,
    sort: str = "installs",  # installs, rating, newest, revenue
) -> dict[str, Any]:
    stmt = select(MarketplaceListing).where(
        MarketplaceListing.tenant_id == user.tenant_id,
        MarketplaceListing.status == "published",
    )
    if item_type:
        stmt = stmt.where(MarketplaceListing.item_type == item_type)
    if category:
        stmt = stmt.where(MarketplaceListing.category == category)
    if pricing_model:
        stmt = stmt.where(MarketplaceListing.pricing_model == pricing_model)
    if is_certified is not None:
        stmt = stmt.where(MarketplaceListing.is_certified == is_certified)
    if is_featured is not None:
        stmt = stmt.where(MarketplaceListing.is_featured == is_featured)

    sort_map = {
        "installs": MarketplaceListing.installs_count.desc(),
        "rating": MarketplaceListing.rating.desc(),
        "newest": MarketplaceListing.published_at.desc(),
        "revenue": MarketplaceListing.price_monthly_usd.desc(),
    }
    stmt = stmt.order_by(sort_map.get(sort, MarketplaceListing.installs_count.desc())).limit(limit)

    result = await db.execute(stmt)
    listings = result.scalars().all()
    return {"total": len(listings), "listings": [
        {"id": str(l.id), "name": l.display_name or l.name, "tagline": l.tagline,
         "type": l.item_type, "category": l.category, "tags": l.tags,
         "version": l.version, "pricing_model": l.pricing_model,
         "price_usd": l.price_usd, "price_monthly_usd": l.price_monthly_usd,
         "installs": l.installs_count, "rating": l.rating, "reviews": l.reviews_count,
         "is_certified": l.is_certified, "is_verified": l.is_verified,
         "is_featured": l.is_featured, "is_open_source": l.is_open_source,
         "security_score": l.security_score, "publisher_id": str(l.publisher_id),
         "published_at": l.published_at.isoformat() if l.published_at else None}
        for l in listings
    ]}

@router.get("/listings/{listing_id}")
async def get_listing(
    listing_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends,
) -> dict[str, Any]:
    stmt = select(MarketplaceListing).where(
        MarketplaceListing.id == listing_id,
        MarketplaceListing.tenant_id == user.tenant_id,
    )
    listing = (await db.execute(stmt)).scalar_one_or_none()
    if not listing:
        raise HTTPException(status_code=404, detail="Listing not found")
    return {
        "id": str(listing.id), "name": listing.display_name or listing.name,
        "tagline": listing.tagline, "description": listing.description,
        "type": listing.item_type, "category": listing.category, "tags": listing.tags,
        "version": listing.version, "pricing_model": listing.pricing_model,
        "price_usd": listing.price_usd, "price_monthly_usd": listing.price_monthly_usd,
        "installs": listing.installs_count, "active_installs": listing.active_installs,
        "rating": listing.rating, "reviews_count": listing.reviews_count,
        "is_certified": listing.is_certified, "is_verified": listing.is_verified,
        "is_featured": listing.is_featured, "is_open_source": listing.is_open_source,
        "sbom_verified": listing.sbom_verified, "supply_chain_verified": listing.supply_chain_verified,
        "security_score": listing.security_score, "status": listing.status,
        "documentation_url": listing.documentation_url, "source_url": listing.source_url,
        "publisher_id": str(listing.publisher_id),
        "published_at": listing.published_at.isoformat() if listing.published_at else None,
        "last_updated": listing.last_updated.isoformat() if listing.last_updated else None,
    }

@router.post("/listings/{listing_id}/approve")
async def api_approve_listing(
    listing_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends,
) -> dict[str, Any]:
    try:
        result = await approve_listing(db, listing_id, user.tenant_id)
        await db.commit()
        return result
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

@router.post("/listings/{listing_id}/reject")
async def api_reject_listing(
    listing_id: uuid.UUID,
    reason: str = "",
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends,
) -> dict[str, Any]:
    try:
        return await reject_listing(db, listing_id, user.tenant_id, reason)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


# ============================================================================
# CERTIFICATION ROUTES
# ============================================================================

@router.post("/listings/{listing_id}/certify")
async def api_certify_listing(
    listing_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends,
) -> dict[str, Any]:
    try:
        result = await run_certification(db, listing_id, user.tenant_id)
        await db.commit()
        return result
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

@router.get("/certifications")
async def list_certifications(
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends,
    limit: int = 20,
) -> dict[str, Any]:
    stmt = (
        select(Certification)
        .where(Certification.tenant_id == user.tenant_id)
        .order_by(Certification.certified_at.desc().nullslast())
        .limit(limit)
    )
    result = await db.execute(stmt)
    certs = result.scalars().all()
    return {"total": len(certs), "certifications": [
        {"id": str(c.id), "item_name": c.item_name, "type": c.certification_type,
         "security_score": c.security_score, "overall_score": c.overall_score,
         "grade": c.grade, "issues_found": c.issues_found,
         "sbom_verified": c.sbom_verified, "supply_chain_verified": c.supply_chain_verified,
         "malware_clean": c.malware_clean, "status": c.status,
         "certified_at": c.certified_at.isoformat() if c.certified_at else None,
         "expires_at": c.expires_at.isoformat() if c.expires_at else None}
        for c in certs
    ]}


# ============================================================================
# SUBSCRIPTION & DOWNLOAD ROUTES
# ============================================================================

@router.post("/subscribe")
async def api_subscribe(
    req: SubscribeRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends,
) -> dict[str, Any]:
    try:
        result = await subscribe_to_listing(
            db, user.tenant_id, uuid.UUID(req.listing_id),
            uuid.UUID(req.subscriber_tenant_id), req.plan_name, req.billing_cycle,
        )
        await db.commit()
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.post("/download")
async def api_download(
    req: DownloadRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends,
) -> dict[str, Any]:
    try:
        result = await record_download(
            db, user.tenant_id, uuid.UUID(req.listing_id),
            user.user_id, user.tenant_id, req.version, req.install_type, req.country,
        )
        await db.commit()
        return result
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

@router.get("/subscriptions")
async def list_subscriptions(
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends,
    limit: int = 50,
) -> dict[str, Any]:
    stmt = (
        select(MarketplaceSubscription)
        .where(MarketplaceSubscription.tenant_id == user.tenant_id)
        .order_by(MarketplaceSubscription.created_at.desc())
        .limit(limit)
    )
    result = await db.execute(stmt)
    subs = result.scalars().all()
    return {"total": len(subs), "subscriptions": [
        {"id": str(s.id), "item_name": s.item_name, "plan": s.plan_name,
         "price_monthly_usd": s.price_monthly_usd, "billing_cycle": s.billing_cycle,
         "status": s.status, "cancel_at_period_end": s.cancel_at_period_end,
         "period_start": s.current_period_start.isoformat() if s.current_period_start else None,
         "period_end": s.current_period_end.isoformat() if s.current_period_end else None}
        for s in subs
    ]}


# ============================================================================
# REVIEW ROUTES
# ============================================================================

@router.post("/reviews")
async def create_review(
    req: ReviewRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends,
) -> dict[str, Any]:
    if not 1 <= req.rating <= 5:
        raise HTTPException(status_code=400, detail="Rating must be 1-5")
    review = MarketplaceReview(
        tenant_id=user.tenant_id, listing_id=uuid.UUID(req.listing_id),
        reviewer_id=user.user_id, reviewer_name=user.full_name if hasattr(user, "full_name") else None,
        rating=req.rating, title=req.title, body=req.body,
        use_case=req.use_case or None, pros=req.pros, cons=req.cons,
    )
    db.add(review)
    await db.flush()

    # Update listing rating
    list_stmt = select(MarketplaceListing).where(MarketplaceListing.id == uuid.UUID(req.listing_id))
    listing = (await db.execute(list_stmt)).scalar_one_or_none()
    if listing:
        listing.reviews_count += 1
        # Recalculate average rating (simplified)
        listing.rating = round((listing.rating * (listing.reviews_count - 1) + req.rating) / listing.reviews_count, 1)

    await db.commit()
    return {"review_id": str(review.id), "rating": req.rating, "title": req.title}

@router.get("/listings/{listing_id}/reviews")
async def get_reviews(
    listing_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends,
    limit: int = 20,
) -> dict[str, Any]:
    stmt = (
        select(MarketplaceReview)
        .where(MarketplaceReview.listing_id == listing_id, MarketplaceReview.tenant_id == user.tenant_id)
        .order_by(MarketplaceReview.helpful_votes.desc(), MarketplaceReview.created_at.desc())
        .limit(limit)
    )
    result = await db.execute(stmt)
    reviews = result.scalars().all()
    return {"total": len(reviews), "reviews": [
        {"id": str(r.id), "rating": r.rating, "title": r.title, "body": r.body,
         "use_case": r.use_case, "pros": r.pros, "cons": r.cons,
         "helpful_votes": r.helpful_votes,
         "reviewer": r.reviewer_name, "created_at": r.created_at.isoformat() if r.created_at else None}
        for r in reviews
    ]}


# ============================================================================
# REVENUE & BILLING ROUTES
# ============================================================================

@router.post("/revenue-share")
async def api_revenue_share(
    req: RevenueShareRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends,
) -> dict[str, Any]:
    try:
        result = await calculate_revenue_share(
            db, uuid.UUID(req.publisher_id), user.tenant_id,
            datetime.fromisoformat(req.period_start), datetime.fromisoformat(req.period_end),
        )
        await db.commit()
        return result
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

@router.post("/invoices")
async def api_generate_invoice(
    req: GenerateInvoiceRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends,
) -> dict[str, Any]:
    return await generate_invoice(
        db, user.tenant_id, uuid.UUID(req.subscriber_tenant_id),
        uuid.UUID(req.publisher_id) if req.publisher_id else None, req.line_items,
        datetime.fromisoformat(req.period_start) if req.period_start else None,
        datetime.fromisoformat(req.period_end) if req.period_end else None,
    )

@router.get("/invoices")
async def list_invoices(
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends,
    limit: int = 20,
) -> dict[str, Any]:
    stmt = (
        select(MarketplaceInvoice)
        .where(MarketplaceInvoice.tenant_id == user.tenant_id)
        .order_by(MarketplaceInvoice.created_at.desc())
        .limit(limit)
    )
    result = await db.execute(stmt)
    invoices = result.scalars().all()
    return {"total": len(invoices), "invoices": [
        {"id": str(i.id), "invoice_number": i.invoice_number,
         "subtotal_usd": i.subtotal_usd, "total_usd": i.total_usd,
         "status": i.status,
         "due_date": i.due_date.isoformat() if i.due_date else None,
         "paid_at": i.paid_at.isoformat() if i.paid_at else None,
         "line_items": i.line_items}
        for i in invoices
    ]}


# ============================================================================
# PARTNER ROUTES
# ============================================================================

@router.post("/partners/register")
async def api_register_partner(
    req: RegisterPartnerRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends,
) -> dict[str, Any]:
    try:
        result = await register_partner(db, user.tenant_id, req.name, req.partner_type, req.contact_email, req.country, req.tier)
        await db.commit()
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.get("/partners")
async def list_partners(
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends,
    limit: int = 50,
) -> dict[str, Any]:
    stmt = (
        select(Partner)
        .where(Partner.tenant_id == user.tenant_id, Partner.status == "active")
        .order_by(Partner.arr_attributed_usd.desc())
        .limit(limit)
    )
    result = await db.execute(stmt)
    partners = result.scalars().all()
    return {"total": len(partners), "partners": [
        {"id": str(p.id), "name": p.name, "type": p.partner_type,
         "tier": p.tier, "country": p.country,
         "customers_referred": p.customers_referred, "customers_active": p.customers_active,
         "mrr_attributed": p.mrr_attributed_usd, "arr_attributed": p.arr_attributed_usd,
         "commission_pct": p.commission_pct, "ytd_commission": p.ytd_commission_usd,
         "white_label": p.white_label_enabled, "joined_at": p.joined_at.isoformat() if p.joined_at else None}
        for p in partners
    ]}

@router.post("/partners/{partner_id}/commission")
async def api_calc_commission(
    partner_id: uuid.UUID,
    req: CommissionRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends,
) -> dict[str, Any]:
    try:
        result = await calculate_partner_commission(db, partner_id, user.tenant_id, req.revenue_usd)
        await db.commit()
        return result
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

@router.post("/partners/{partner_id}/upgrade")
async def api_upgrade_partner(
    partner_id: uuid.UUID,
    req: UpgradePartnerRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends,
) -> dict[str, Any]:
    try:
        result = await upgrade_partner_tier(db, partner_id, user.tenant_id, req.new_tier)
        await db.commit()
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.get("/partners/tiers")
async def list_partner_tiers() -> dict[str, Any]:
    return {"tiers": PARTNER_TIERS}


# ============================================================================
# ANALYTICS & CATALOG ROUTES
# ============================================================================

@router.get("/stats")
async def api_marketplace_stats(
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends,
) -> dict[str, Any]:
    return await get_marketplace_stats(db, user.tenant_id)

@router.get("/publishers/{publisher_id}/analytics")
async def api_publisher_analytics(
    publisher_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends,
) -> dict[str, Any]:
    return await get_publisher_analytics(db, publisher_id, user.tenant_id)

@router.get("/categories")
async def list_categories() -> dict[str, Any]:
    return {"total": len(LISTING_CATEGORIES), "categories": LISTING_CATEGORIES}

@router.get("/pricing-models")
async def list_pricing_models() -> dict[str, Any]:
    return {"models": PRICING_MODELS}
