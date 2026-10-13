"""Stripe API service layer — GBP billing."""
import os
import stripe
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from datetime import datetime

from .models import Subscription, PaymentHistory

def _ensure_stripe():
    """Set stripe.api_key from environment — called before every Stripe operation."""
    import stripe
    key = os.getenv("STRIPE_SECRET_KEY", "")
    if key:
        stripe.api_key = key
    return bool(stripe.api_key)



# Configure Stripe
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "")
APP_DOMAIN = os.getenv("APP_DOMAIN", "https://app.globaldigitalsecurity.io")

# Plan to Stripe Price mapping — GBP (£)
PLAN_PRICES = {
    "starter": {"monthly": os.getenv("STRIPE_PRICE_STARTER_MONTHLY", ""), "amount": 399},
    "professional": {"monthly": os.getenv("STRIPE_PRICE_PROFESSIONAL_MONTHLY", ""), "amount": 1199},
    "enterprise": {"monthly": os.getenv("STRIPE_PRICE_ENTERPRISE_MONTHLY", ""), "amount": 3999},
}


async def create_checkout_session(
    db: AsyncSession,
    user_id: str,
    email: str,
    plan_tier: str,
    tenant_id: str = None,
) -> dict:
    """Create a Stripe Checkout Session for subscription signup."""
    price_id = PLAN_PRICES.get(plan_tier, {}).get("monthly", "")
    if not price_id:
        raise ValueError(f"No Stripe Price ID configured for plan: {plan_tier}. Run setup first.")

    existing_sub = await db.execute(
        select(Subscription).where(Subscription.user_id == user_id)
    )
    existing = existing_sub.scalar_one_or_none()

    if existing and existing.stripe_customer_id:
        customer = stripe.Customer.retrieve(existing.stripe_customer_id)
    else:
        customer = stripe.Customer.create(email=email)

    session = stripe.checkout.Session.create(
        customer=customer.id,
        payment_method_types=["card"],
        line_items=[{"price": price_id, "quantity": 1}],
        mode="subscription",
        success_url=f"{APP_DOMAIN}/billing?status=success&session_id={{CHECKOUT_SESSION_ID}}",
        cancel_url=f"{APP_DOMAIN}/billing?status=cancelled",
        client_reference_id=str(user_id),
        metadata={
            "user_id": str(user_id),
            "plan_tier": plan_tier,
            "tenant_id": str(tenant_id) if tenant_id else "",
        },
    )

    if existing:
        existing.stripe_customer_id = customer.id
        existing.plan_tier = plan_tier
        existing.status = "trialing"
    else:
        sub = Subscription(
            user_id=user_id,
            tenant_id=tenant_id,
            stripe_customer_id=customer.id,
            plan_tier=plan_tier,
            status="trialing",
            monthly_amount_gbp=PLAN_PRICES[plan_tier]["amount"],
        )
        db.add(sub)

    await db.commit()
    return {"checkout_url": session.url, "session_id": session.id}


async def create_portal_session(db: AsyncSession, user_id: str) -> dict:
    """Create a Stripe Customer Portal session."""
    result = await db.execute(
        select(Subscription).where(Subscription.user_id == user_id)
    )
    sub = result.scalar_one_or_none()
    if not sub or not sub.stripe_customer_id:
        raise ValueError("No active subscription found for this user.")

    portal = stripe.billing_portal.Session.create(
        customer=sub.stripe_customer_id,
        return_url=f"{APP_DOMAIN}/billing",
    )
    return {"portal_url": portal.url}


async def get_subscription_status(db: AsyncSession, user_id: str) -> dict:
    """Get current subscription status for a user."""
    result = await db.execute(
        select(Subscription).where(Subscription.user_id == user_id)
    )
    sub = result.scalar_one_or_none()

    if not sub:
        return {"status": "none", "plan": None, "message": "No subscription found"}

    stripe_data = {}
    if sub.stripe_subscription_id and stripe.api_key:
        try:
            stripe_sub = stripe.Subscription.retrieve(sub.stripe_subscription_id)
            sub.status = stripe_sub.status
            sub.current_period_start = datetime.fromtimestamp(stripe_sub.current_period_start)
            sub.current_period_end = datetime.fromtimestamp(stripe_sub.current_period_end)
            sub.cancel_at_period_end = stripe_sub.cancel_at_period_end
            await db.commit()
            stripe_data = {
                "stripe_status": stripe_sub.status,
                "current_period_end": sub.current_period_end.isoformat() if sub.current_period_end else None,
                "cancel_at_period_end": sub.cancel_at_period_end,
            }
        except Exception as e:
            stripe_data = {"sync_error": str(e)}

    return {
        "status": sub.status,
        "plan": sub.plan_tier,
        "monthly_amount_gbp": sub.monthly_amount_gbp,
        "stripe_customer_id": sub.stripe_customer_id,
        "stripe_subscription_id": sub.stripe_subscription_id,
        **stripe_data,
    }


async def cancel_subscription(db: AsyncSession, user_id: str, immediate: bool = False) -> dict:
    """Cancel a subscription."""
    result = await db.execute(
        select(Subscription).where(Subscription.user_id == user_id)
    )
    sub = result.scalar_one_or_none()
    if not sub or not sub.stripe_subscription_id:
        raise ValueError("No active subscription found.")

    if immediate:
        stripe.Subscription.delete(sub.stripe_subscription_id)
        sub.status = "canceled"
        sub.canceled_at = datetime.utcnow()
    else:
        stripe.Subscription.modify(
            sub.stripe_subscription_id,
            cancel_at_period_end=True,
        )
        sub.cancel_at_period_end = True

    await db.commit()
    return {"status": sub.status, "cancel_at_period_end": sub.cancel_at_period_end}


async def list_invoices(db: AsyncSession, user_id: str, limit: int = 10) -> list:
    """List payment history for a user."""
    result = await db.execute(
        select(PaymentHistory)
        .where(PaymentHistory.user_id == user_id)
        .order_by(PaymentHistory.created_at.desc())
        .limit(limit)
    )
    invoices = result.scalars().all()
    return [
        {
            "id": str(inv.id),
            "amount_paid": inv.amount_paid,
            "currency": inv.currency,
            "status": inv.status,
            "invoice_url": inv.invoice_url,
            "invoice_pdf_url": inv.invoice_pdf_url,
            "paid_at": inv.paid_at.isoformat() if inv.paid_at else None,
            "description": inv.description,
        }
        for inv in invoices
    ]


async def handle_webhook_event(db: AsyncSession, event: dict) -> dict:
    """Process a Stripe webhook event."""
    event_type = event["type"]
    data = event["data"]["object"]

    if event_type == "checkout.session.completed":
        return await _handle_checkout_completed(db, data)
    elif event_type == "customer.subscription.updated":
        return await _handle_subscription_updated(db, data)
    elif event_type == "customer.subscription.deleted":
        return await _handle_subscription_deleted(db, data)
    elif event_type == "invoice.payment_succeeded":
        return await _handle_payment_succeeded(db, data)
    elif event_type == "invoice.payment_failed":
        return await _handle_payment_failed(db, data)
    else:
        return {"processed": False, "event_type": event_type, "message": "Unhandled event type"}


async def _handle_checkout_completed(db: AsyncSession, data: dict) -> dict:
    user_id = data.get("metadata", {}).get("user_id")
    plan_tier = data.get("metadata", {}).get("plan_tier", "starter")
    stripe_customer_id = data.get("customer")
    stripe_subscription_id = data.get("subscription")

    if not user_id:
        return {"processed": False, "reason": "No user_id in metadata"}

    result = await db.execute(
        select(Subscription).where(Subscription.user_id == user_id)
    )
    sub = result.scalar_one_or_none()

    if sub:
        sub.stripe_customer_id = stripe_customer_id
        sub.stripe_subscription_id = stripe_subscription_id
        sub.status = "active"
        sub.plan_tier = plan_tier
        sub.monthly_amount_gbp = PLAN_PRICES.get(plan_tier, {}).get("amount", 0)
    else:
        sub = Subscription(
            user_id=user_id,
            stripe_customer_id=stripe_customer_id,
            stripe_subscription_id=stripe_subscription_id,
            status="active",
            plan_tier=plan_tier,
            monthly_amount_gbp=PLAN_PRICES.get(plan_tier, {}).get("amount", 0),
        )
        db.add(sub)

    await db.commit()
    return {"processed": True, "user_id": user_id, "status": "active", "plan": plan_tier}


async def _handle_subscription_updated(db: AsyncSession, data: dict) -> dict:
    stripe_sub_id = data.get("id")
    result = await db.execute(
        select(Subscription).where(Subscription.stripe_subscription_id == stripe_sub_id)
    )
    sub = result.scalar_one_or_none()

    if sub:
        sub.status = data.get("status", sub.status)
        if data.get("current_period_start"):
            sub.current_period_start = datetime.fromtimestamp(data["current_period_start"])
        if data.get("current_period_end"):
            sub.current_period_end = datetime.fromtimestamp(data["current_period_end"])
        sub.cancel_at_period_end = data.get("cancel_at_period_end", False)
        await db.commit()
        return {"processed": True, "subscription_id": stripe_sub_id, "status": sub.status}

    return {"processed": False, "reason": "Subscription not found"}


async def _handle_subscription_deleted(db: AsyncSession, data: dict) -> dict:
    stripe_sub_id = data.get("id")
    result = await db.execute(
        select(Subscription).where(Subscription.stripe_subscription_id == stripe_sub_id)
    )
    sub = result.scalar_one_or_none()

    if sub:
        sub.status = "canceled"
        sub.canceled_at = datetime.utcnow()
        await db.commit()
        return {"processed": True, "subscription_id": stripe_sub_id, "status": "canceled"}

    return {"processed": False, "reason": "Subscription not found"}


async def _handle_payment_succeeded(db: AsyncSession, data: dict) -> dict:
    stripe_customer_id = data.get("customer")
    amount_paid = data.get("amount_paid", 0) / 100  # Stripe uses pence for GBP
    invoice_url = data.get("hosted_invoice_url")
    invoice_pdf = data.get("invoice_pdf")

    result = await db.execute(
        select(Subscription).where(Subscription.stripe_customer_id == stripe_customer_id)
    )
    sub = result.scalar_one_or_none()

    payment = PaymentHistory(
        subscription_id=sub.id if sub else None,
        user_id=sub.user_id if sub else None,
        stripe_invoice_id=data.get("id"),
        amount_paid=amount_paid,
        currency=data.get("currency", "gbp"),
        status="paid",
        invoice_url=invoice_url,
        invoice_pdf_url=invoice_pdf,
        description=data.get("description"),
        paid_at=datetime.utcnow(),
    )
    db.add(payment)
    await db.commit()

    return {"processed": True, "amount": amount_paid, "currency": "gbp", "status": "paid"}


async def _handle_payment_failed(db: AsyncSession, data: dict) -> dict:
    stripe_customer_id = data.get("customer")

    result = await db.execute(
        select(Subscription).where(Subscription.stripe_customer_id == stripe_customer_id)
    )
    sub = result.scalar_one_or_none()

    payment = PaymentHistory(
        subscription_id=sub.id if sub else None,
        user_id=sub.user_id if sub else None,
        stripe_invoice_id=data.get("id"),
        amount_paid=0,
        currency=data.get("currency", "gbp"),
        status="failed",
        description=data.get("description"),
        failure_reason="Payment failed",
        created_at=datetime.utcnow(),
    )
    db.add(payment)

    if sub:
        sub.status = "past_due"
        await db.commit()

    return {"processed": True, "status": "failed", "currency": "gbp"}
