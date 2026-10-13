"""Database models for billing and subscriptions."""
import uuid
from datetime import datetime
from sqlalchemy import Column, String, DateTime, Float, Integer, Boolean, Text, ForeignKey
from sqlalchemy.dialects.postgresql import UUID, JSONB
from gds_api.models import Base


class Subscription(Base):
    __tablename__ = "billing_subscriptions"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("tenants.id"), nullable=True)

    stripe_customer_id = Column(String(255), nullable=True)
    stripe_subscription_id = Column(String(255), nullable=True)
    stripe_price_id = Column(String(255), nullable=True)

    plan_tier = Column(String(50), nullable=False, default="starter")
    status = Column(String(50), nullable=False, default="none")
    # none, trialing, active, past_due, canceled, unpaid, incomplete

    current_period_start = Column(DateTime, nullable=True)
    current_period_end = Column(DateTime, nullable=True)
    cancel_at_period_end = Column(Boolean, default=False)
    canceled_at = Column(DateTime, nullable=True)

    quantity = Column(Integer, default=1)
    monthly_amount_gbp = Column(Float, default=0.0)

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class PaymentHistory(Base):
    __tablename__ = "billing_payments"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    subscription_id = Column(UUID(as_uuid=True), ForeignKey("billing_subscriptions.id"), nullable=True)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)

    stripe_invoice_id = Column(String(255), nullable=True)
    stripe_charge_id = Column(String(255), nullable=True)

    amount_paid = Column(Float, default=0.0)
    currency = Column(String(10), default="usd")
    status = Column(String(50), nullable=False, default="pending")
    # pending, paid, failed, refunded

    invoice_url = Column(Text, nullable=True)
    invoice_pdf_url = Column(Text, nullable=True)
    receipt_url = Column(Text, nullable=True)

    description = Column(Text, nullable=True)
    failure_reason = Column(Text, nullable=True)

    paid_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class UsageRecord(Base):
    """Track metered usage for usage-based billing add-ons."""
    __tablename__ = "billing_usage"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("tenants.id"), nullable=True)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)

    usage_type = Column(String(100), nullable=False)
    # api_calls, scans, cloud_accounts, tokens, agents

    quantity = Column(Integer, default=0)
    period_start = Column(DateTime, nullable=False)
    period_end = Column(DateTime, nullable=False)

    metadata_json = Column(JSONB, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
