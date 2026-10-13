"""FastAPI router for billing endpoints — GBP (£)."""
import os
import stripe
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel
from typing import Optional

from gds_api.db import get_db
from gds_api.auth import get_current_user
from .service import (
    create_checkout_session,
    create_portal_session,
    get_subscription_status,
    cancel_subscription,
    list_invoices,
    handle_webhook_event,
)
from .models import Subscription

def _ensure_stripe():
    """Set stripe.api_key from environment."""
    import stripe
    key = os.getenv("STRIPE_SECRET_KEY", "")
    if key:
        stripe.api_key = key
    return bool(stripe.api_key)



router = APIRouter(prefix="/billing", tags=["billing"])

# stripe.api_key set per-request via _ensure_stripe()
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "")

PLANS = [
    {
        "tier": "starter",
        "name": "Starter",
        "price_monthly": 399,
        "price_annual": 3990,
        "currency": "GBP",
        "symbol": "£",
        "description": "Perfect for small teams getting started with autonomous security",
        "features": [
            "Cloud posture scan", "Basic findings dashboard", "1 cloud account",
            "In-app notifications", "Email support", "Daily scan schedule"
        ],
        "max_cloud_accounts": 1,
        "token_quota": 50000,
    },
    {
        "tier": "professional",
        "name": "Professional",
        "price_monthly": 1199,
        "price_annual": 11990,
        "currency": "GBP",
        "symbol": "£",
        "description": "For security teams managing multiple cloud environments",
        "features": [
            "Everything in Starter", "Multi-cloud (AWS/Azure/GCP)",
            "Threat intelligence feeds", "SSH network diagnostics",
            "Email + Slack alerts", "5 cloud accounts", "Scheduled missions",
            "API access", "Priority support"
        ],
        "max_cloud_accounts": 5,
        "token_quota": 200000,
    },
    {
        "tier": "enterprise",
        "name": "Enterprise",
        "price_monthly": 3999,
        "price_annual": 39990,
        "currency": "GBP",
        "symbol": "£",
        "description": "Full autonomous security operations for large enterprises and MSSPs",
        "features": [
            "Everything in Professional", "Red team operations",
            "Purple team collaboration", "Compliance automation (SOC2/ISO27001/PCI)",
            "Enterprise SSO (SAML/OIDC)", "Dedicated support engineer",
            "Custom agent workflows", "Unlimited cloud accounts",
            "On-premise deployment option", "SLA with credits"
        ],
        "max_cloud_accounts": 999,
        "token_quota": 1000000,
    },
]


class CheckoutRequest(BaseModel):
    plan_tier: str
    tenant_id: Optional[str] = None


class CancelRequest(BaseModel):
    immediate: bool = False


@router.get("/plans")
async def get_plans():
    """List available subscription plans (GBP)."""
    return {"plans": PLANS, "currency": "GBP", "symbol": "£"}


@router.post("/checkout")
async def checkout(
    req: CheckoutRequest,
    db: AsyncSession = Depends(get_db),
    user=Depends(get_current_user),
):
    """Create a Stripe Checkout Session."""
    if req.plan_tier not in ["starter", "professional", "enterprise"]:
        raise HTTPException(status_code=400, detail="Invalid plan tier")

    _ensure_stripe()
    if not stripe.api_key:
        raise HTTPException(status_code=503, detail="Stripe not configured. Contact admin.")

    try:
        result = await create_checkout_session(
            db=db,
            user_id=str(user.user_id if hasattr(user, "user_id") else user.id),
            email=getattr(user, "email", ""),
            plan_tier=req.plan_tier,
            tenant_id=str(getattr(user, "tenant_id", getattr(user, "tenant", req.tenant_id))),
        )
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except stripe.error.StripeError as e:
        raise HTTPException(status_code=502, detail=f"Stripe error: {str(e)}")
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Checkout error: {type(e).__name__}: {str(e)}")


@router.post("/portal")
async def portal(
    db: AsyncSession = Depends(get_db),
    user=Depends(get_current_user),
):
    """Create a Stripe Customer Portal session."""
    _ensure_stripe()
    if not stripe.api_key:
        raise HTTPException(status_code=503, detail="Stripe not configured. Contact admin.")
    try:
        result = await create_portal_session(db=db, user_id=str(user.user_id if hasattr(user, "user_id") else user.id))
        return result
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except stripe.error.StripeError as e:
        raise HTTPException(status_code=502, detail=f"Stripe error: {str(e)}")
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Checkout error: {type(e).__name__}: {str(e)}")


@router.get("/subscription")
async def subscription_status(
    db: AsyncSession = Depends(get_db),
    user=Depends(get_current_user),
):
    """Get current subscription status."""
    return await get_subscription_status(db=db, user_id=str(user.user_id if hasattr(user, "user_id") else user.id))


@router.post("/cancel")
async def cancel(
    req: CancelRequest,
    db: AsyncSession = Depends(get_db),
    user=Depends(get_current_user),
):
    """Cancel subscription."""
    _ensure_stripe()
    try:
        return await cancel_subscription(db=db, user_id=str(user.user_id if hasattr(user, "user_id") else user.id), immediate=req.immediate)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except stripe.error.StripeError as e:
        raise HTTPException(status_code=502, detail=f"Stripe error: {str(e)}")
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Cancel error: {type(e).__name__}: {str(e)}")


@router.get("/invoices")
async def invoices(
    db: AsyncSession = Depends(get_db),
    user=Depends(get_current_user),
):
    """List payment history."""
    return {"invoices": await list_invoices(db=db, user_id=str(user.user_id if hasattr(user, "user_id") else user.id))}


@router.post("/webhook")
async def webhook(request: Request, db: AsyncSession = Depends(get_db)):
    """Stripe webhook endpoint."""
    payload = await request.body()
    sig_header = request.headers.get("stripe-signature", "")

    if not STRIPE_WEBHOOK_SECRET:
        import json
        event = json.loads(payload)
    else:
        try:
            # Validate signature using Stripe's method
            stripe.Webhook.construct_event(
                payload, sig_header, STRIPE_WEBHOOK_SECRET
            )
            # Use raw JSON dict (not Stripe object) so .get() works in handlers
            import json
            event = json.loads(payload)
        except stripe.error.SignatureVerificationError:
            raise HTTPException(status_code=400, detail="Invalid webhook signature")
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Webhook error: {str(e)}")

    try:
        result = await handle_webhook_event(db=db, event=event)
        return {"received": True, "result": result}
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Webhook processing error: {type(e).__name__}: {str(e)}")
