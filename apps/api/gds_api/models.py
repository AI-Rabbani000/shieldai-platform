"""SQLAlchemy models for the Phase 2 Core Platform domain: tenancy, auth, RBAC, audit,
policy, approvals, evidence, and notifications.

Every tenant-owned table carries tenant_id, per CLAUDE.md's tenant-isolation principle,
even though exactly one tenant is seeded today (see docs/adr/0001-foundation-decisions.md
and scripts/seed.py) — this is what makes it real multi-tenancy scaffolding rather than a
single-tenant assumption baked into the schema.
"""

import uuid
from datetime import datetime
from decimal import Decimal

from sqlalchemy import DateTime, ForeignKey, Index, Numeric, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.sql import func


class Base(DeclarativeBase):
    # Every Mapped[datetime] column is timezone-aware by default. Without this, Postgres
    # columns come out as TIMESTAMP WITHOUT TIME ZONE, and inserting the tz-aware
    # datetime.now(UTC) values this codebase uses everywhere fails at the driver level.
    type_annotation_map = {datetime: DateTime(timezone=True)}


def _uuid_pk() -> Mapped[uuid.UUID]:
    return mapped_column(primary_key=True, default=uuid.uuid4)


class Tenant(Base):
    __tablename__ = "tenants"

    id: Mapped[uuid.UUID] = _uuid_pk()
    name: Mapped[str] = mapped_column(String(200))
    slug: Mapped[str] = mapped_column(String(100), unique=True)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())


class Role(Base):
    __tablename__ = "roles"

    id: Mapped[uuid.UUID] = _uuid_pk()
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"))
    name: Mapped[str] = mapped_column(String(100))
    # e.g. ["audit:read", "evidence:write", "approvals:decide"]
    permissions: Mapped[list[str]] = mapped_column(JSONB, default=list)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = _uuid_pk()
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"))
    role_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("roles.id"))
    email: Mapped[str] = mapped_column(String(320), unique=True)
    password_hash: Mapped[str] = mapped_column(String(200))
    is_active: Mapped[bool] = mapped_column(default=True)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())


class UserSession(Base):
    """A rotating refresh-token session. Named UserSession (not Session) to avoid
    colliding with sqlalchemy.orm.Session / AsyncSession."""

    __tablename__ = "user_sessions"

    id: Mapped[uuid.UUID] = _uuid_pk()
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"))
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    # SHA-256 of the refresh token, never the token itself — a DB read can't be replayed.
    refresh_token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    expires_at: Mapped[datetime]
    revoked_at: Mapped[datetime | None] = mapped_column(default=None)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())


class AuditEvent(Base):
    """Append-only. No update/delete path is exposed anywhere in the API on purpose."""

    __tablename__ = "audit_events"

    id: Mapped[uuid.UUID] = _uuid_pk()
    tenant_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("tenants.id"), default=None)
    user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"), default=None)
    action: Mapped[str] = mapped_column(String(100))
    detail: Mapped[dict[str, object]] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())


class Policy(Base):
    """Deterministic risk_class -> decision rule. See gds_api.policy.evaluate_policy."""

    __tablename__ = "policies"

    id: Mapped[uuid.UUID] = _uuid_pk()
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"))
    risk_class: Mapped[str] = mapped_column(String(50))
    requires_approval: Mapped[bool]
    min_role: Mapped[str] = mapped_column(String(100))
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())


class Approval(Base):
    __tablename__ = "approvals"

    id: Mapped[uuid.UUID] = _uuid_pk()
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"))
    requested_by_user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    risk_class: Mapped[str] = mapped_column(String(50))
    action_description: Mapped[str] = mapped_column(String(500))
    status: Mapped[str] = mapped_column(String(20), default="pending")  # pending|approved|rejected
    decided_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id"), default=None
    )
    decided_at: Mapped[datetime | None] = mapped_column(default=None)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())


class Evidence(Base):
    __tablename__ = "evidence"

    id: Mapped[uuid.UUID] = _uuid_pk()
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"))
    # Generic tag until Findings/Incidents exist (Phase 4/5) to attach real evidence to.
    subject_type: Mapped[str] = mapped_column(String(100))
    subject_id: Mapped[str | None] = mapped_column(String(200), default=None)
    storage_key: Mapped[str] = mapped_column(String(500))
    sha256: Mapped[str] = mapped_column(String(64))
    content_type: Mapped[str] = mapped_column(String(100))
    size_bytes: Mapped[int]
    created_by_user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())


class Notification(Base):
    __tablename__ = "notifications"

    id: Mapped[uuid.UUID] = _uuid_pk()
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"))
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    type: Mapped[str] = mapped_column(String(100))
    message: Mapped[str] = mapped_column(String(500))
    read_at: Mapped[datetime | None] = mapped_column(default=None)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())


class ConversationThread(Base):
    """Phase 10.3: a real multi-turn chat thread. Deliberately holds no messages of its
    own - each turn is a real Mission row (see Mission.conversation_thread_id below).
    This reverses docs/adr/0005 section 3's original "no separate conversational-thread
    model" decision; see docs/adr/0010 for why that reversal is legitimate now (Phase
    10.1 gave missions real adaptive behavior to back a real chat experience with,
    which didn't exist when ADR 0005 was written)."""

    __tablename__ = "conversation_threads"

    id: Mapped[uuid.UUID] = _uuid_pk()
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"))
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    agent_name: Mapped[str | None] = mapped_column(String(100), default=None)
    title: Mapped[str] = mapped_column(String(200))
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    last_message_at: Mapped[datetime] = mapped_column(server_default=func.now())


class Mission(Base):
    """A Rabbani AI Core mission. Phase 3 has no Phase 4+ specialist agents to hand tasks
    to, so a mission's tasks route through gds_api.tool_gateway's real tools instead of
    fabricated department agents - see docs/BUILD-STATUS.md Phase 3 detail.

    Phase 10.3: a chat turn is also a real Mission - conversation_thread_id links it to
    its ConversationThread when the mission originated from a chat message rather than a
    direct mission creation. objective becomes the user's chat message; report becomes
    the assistant's reply; tasks are the visible tool-call sub-steps - all for free from
    existing Mission/MissionTask rendering, no parallel message schema needed."""

    __tablename__ = "missions"

    id: Mapped[uuid.UUID] = _uuid_pk()
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"))
    requested_by_user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    objective: Mapped[str] = mapped_column(Text)
    # planning|awaiting_approval|running|completed|failed|cancelled - see
    # docs/architecture/mission-workflow-lifecycle.md. Phase 15 made "running" and
    # "failed" real (previously never assigned by any code path) and added "cancelled"
    # (previously only WorkflowRun.status tracked cancellation, never Mission itself).
    # "awaiting_approval" remains reserved/unused at the mission level - approval-waiting
    # is tracked per-MissionTask, not mission-wide.
    status: Mapped[str] = mapped_column(String(30), default="planning")
    risk_class: Mapped[str | None] = mapped_column(String(50), default=None)
    report: Mapped[str | None] = mapped_column(Text, default=None)
    conversation_thread_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("conversation_threads.id"), default=None
    )
    # Phase 20 (Continuation Prompt 7), Part 7: one of the 23 values in
    # gds_api.mission_taxonomy.MISSION_TYPES, or None for a legacy/unclassified
    # mission (every Mission created before this column existed, and any future
    # mission that genuinely isn't a Purple Workforce security mission - e.g. a
    # plain chat turn). Nullable, not defaulted, so existing rows are honestly
    # "unclassified" rather than silently backfilled to a guessed type. See
    # gds_api.mission_taxonomy.validate_mission_type_eligibility for the real,
    # fail-closed eligibility checks run before a mission of a sensitive type
    # (e.g. penetration_test, auto_fix) is allowed to be created.
    mission_type: Mapped[str | None] = mapped_column(String(50), default=None)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    completed_at: Mapped[datetime | None] = mapped_column(default=None)
    cancelled_at: Mapped[datetime | None] = mapped_column(default=None)


class MissionTask(Base):
    __tablename__ = "mission_tasks"

    id: Mapped[uuid.UUID] = _uuid_pk()
    mission_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("missions.id"))
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"))
    sequence: Mapped[int]
    description: Mapped[str] = mapped_column(String(500))
    tool_name: Mapped[str | None] = mapped_column(String(100), default=None)
    # A validated key into gds_api.agents.registry.AGENT_REGISTRY, not a real FK - same
    # pattern tool_name already uses against tool_gateway.TOOL_REGISTRY. Null means
    # Rabbani AI Core handles the task directly (Phase 3 behavior, unchanged).
    agent_name: Mapped[str | None] = mapped_column(String(100), default=None)
    risk_class: Mapped[str | None] = mapped_column(String(50), default=None)
    # pending|awaiting_approval|running|completed|failed|denied
    status: Mapped[str] = mapped_column(String(30), default="pending")
    approval_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("approvals.id"), default=None)
    result: Mapped[dict[str, object]] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())


class WorkflowRun(Base):
    """Phase 15: extended from a create-once/cancel-only row into a genuinely synced
    mirror of Mission's real lifecycle - see docs/architecture/mission-workflow-lifecycle.md
    for the full status model and docs/adr/0013 for why. mission_id keeps its pre-existing
    UNIQUE constraint (real 1:1 Mission:WorkflowRun cardinality, unchanged)."""

    __tablename__ = "workflow_runs"

    id: Mapped[uuid.UUID] = _uuid_pk()
    mission_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("missions.id"), unique=True)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"))
    # Phase 15: nullable - only set when the mission is a real chat turn (mirrors
    # Mission.conversation_thread_id). Lets the Workflows page and API answer "is this a
    # chat-created workflow" without a join back through Mission for every list row.
    conversation_thread_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("conversation_threads.id"), default=None
    )
    temporal_workflow_id: Mapped[str] = mapped_column(String(200))
    temporal_run_id: Mapped[str] = mapped_column(String(200))
    # running|completed|failed|canceled|orphaned - see
    # docs/architecture/mission-workflow-lifecycle.md. "canceled" (single-L) is the
    # pre-existing spelling, kept for API compatibility.
    status: Mapped[str] = mapped_column(String(30), default="running")
    # A short, human-readable description of what's happening right now (e.g.
    # "executing:check_platform_health", "awaiting_approval:<task_id>") - deliberately a
    # single descriptive string rather than separate current_agent_id/current_step_id
    # columns, since that detail is already derivable via a MissionTask join when needed
    # and this avoids syncing 3 columns for every progress tick. See ADR 0013.
    current_stage: Mapped[str | None] = mapped_column(String(200), default=None)
    # Schema exists for forward compatibility but is NOT populated with real data this
    # phase - always 0 today. Temporal's default activity retries happen transparently
    # inside a single workflow.execute_activity() call; observing them accurately would
    # need real per-attempt introspection (activity heartbeats or a worker interceptor),
    # which was judged out of scope for this phase - see ADR 0013's "Alternatives
    # rejected". Exposed via the API/frontend honestly as "0" today, not hidden, so nothing
    # implies retry tracking works that doesn't yet.
    retry_count: Mapped[int] = mapped_column(default=0, server_default="0")
    last_progress_at: Mapped[datetime | None] = mapped_column(default=None)
    started_at: Mapped[datetime] = mapped_column(server_default=func.now())
    completed_at: Mapped[datetime | None] = mapped_column(default=None)
    failed_at: Mapped[datetime | None] = mapped_column(default=None)
    cancelled_at: Mapped[datetime | None] = mapped_column(default=None)
    # Deliberately a short, truncated, non-traceback string - never raw exception content
    # (which could include internal paths, query text, or other sensitive detail).
    failure_message_safe: Mapped[str | None] = mapped_column(String(500), default=None)
    # null = never checked by the reconciler; otherwise CONSISTENT|DRIFTED|ORPHANED|
    # STALLED|MISSING_TEMPORAL_EXECUTION|DUPLICATED - see
    # docs/architecture/workflow-reconciliation.md.
    reconciliation_state: Mapped[str | None] = mapped_column(String(30), default=None)
    reconciled_at: Mapped[datetime | None] = mapped_column(default=None)
    # Optimistic-concurrency counter, incremented on every status-affecting update - lets
    # the reconciler detect "this row changed since I last read it" before repairing.
    status_version: Mapped[int] = mapped_column(default=0, server_default="0")

    # Phase 15: the reconciliation service and the Workflows page both filter/sort by
    # tenant + status (e.g. "every RUNNING workflow for this tenant, is any stalled?").
    __table_args__ = (Index("ix_workflow_runs_tenant_status", "tenant_id", "status"),)


class KnowledgeDocument(Base):
    """Postgres side of semantic memory - the source text/metadata. The embedding vector
    itself lives in Qdrant (collection gds_knowledge), pointed at by qdrant_point_id.

    Phase 20 (Continuation Prompt 7 / EDP-007), Part 13: document_type/source_mission_id
    are additive - "manual" (the default) is every pre-existing document's unchanged
    real meaning (human- or add_knowledge-tool-created); the 4 real lesson types in
    gds_api.mission_memory.LessonType are this sub-phase's new vocabulary, written only
    by gds_api.tool_gateway.record_mission_lesson. No new retrieval mechanism was
    needed - a Lesson is retrieved by the exact same real search_knowledge() semantic
    query every mission's own planning prompt already runs (Phase 10.2)."""

    __tablename__ = "knowledge_documents"

    id: Mapped[uuid.UUID] = _uuid_pk()
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"))
    title: Mapped[str] = mapped_column(String(300))
    content: Mapped[str] = mapped_column(Text)
    qdrant_point_id: Mapped[uuid.UUID] = mapped_column(unique=True)
    created_by_user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    document_type: Mapped[str] = mapped_column(String(30), default="manual")
    source_mission_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("missions.id"), default=None
    )
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())


class CostRecord(Base):
    """Real token counts and latency from every model_router call, never estimated."""

    __tablename__ = "cost_records"

    id: Mapped[uuid.UUID] = _uuid_pk()
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"))
    mission_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("missions.id"), default=None)
    provider: Mapped[str] = mapped_column(String(50))
    model: Mapped[str] = mapped_column(String(100))
    input_tokens: Mapped[int]
    output_tokens: Mapped[int]
    cost_usd: Mapped[Decimal] = mapped_column(Numeric(12, 6))
    latency_ms: Mapped[float]
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())


class Finding(Base):
    """A detection produced by a Phase 5 Defensive Agent's tool (check_cisa_kev,
    search_osv_vulnerabilities, check_threat_indicator) against a real, free, keyless
    feed. severity is the raw severity reported by the source; risk_class is set by
    triage_finding's deterministic rules (same no-agent-self-authorizes philosophy as
    gds_api.policy.evaluate_policy) and is what actually gates escalation.

    Phase 20 (Continuation Prompt 7), Part 9: status now uses the real 15-state
    lifecycle in gds_api.finding_lifecycle.FindingStatus (migrated from the prior
    4-state new|triaged|escalated|closed vocabulary by migration
    e1f4a2b9c8d0_phase_20_finding_lifecycle - see
    gds_api.finding_lifecycle.LEGACY_STATUS_MIGRATION for the exact mapping and its
    reasoning). Every status change must go through
    gds_api.finding_lifecycle.validate_finding_transition() first - no direct
    assignment. approval_id reuses the existing Approval table (not a duplicate
    string field) for "approval state"; remediation_state/retest_state are
    deliberately not separate fields - gds_api.finding_lifecycle.FindingStatus's
    own remediation_planned/remediation_in_progress/awaiting_retest/retest_failed/
    remediated values already encode them without duplication."""

    __tablename__ = "findings"

    id: Mapped[uuid.UUID] = _uuid_pk()
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"))
    source: Mapped[str] = mapped_column(String(50))
    external_id: Mapped[str | None] = mapped_column(String(200), default=None)
    title: Mapped[str] = mapped_column(String(300))
    description: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(50))
    risk_class: Mapped[str | None] = mapped_column(String(50), default=None)
    # One of gds_api.finding_lifecycle.FINDING_STATUSES (15 values).
    status: Mapped[str] = mapped_column(String(30), default="observed")
    raw_data: Mapped[dict[str, object]] = mapped_column(JSONB, default=dict)
    # --- Part 9 enrichment/prioritisation/closure fields, all additive -----------
    confidence: Mapped[str | None] = mapped_column(String(20), default=None)  # low|medium|high
    business_impact: Mapped[str | None] = mapped_column(Text, default=None)
    cve: Mapped[str | None] = mapped_column(String(30), default=None)
    cvss: Mapped[float | None] = mapped_column(default=None)
    epss: Mapped[float | None] = mapped_column(default=None)
    kev_listed: Mapped[bool] = mapped_column(default=False)
    # reachable|unreachable|unknown - real analysis is Part 10's job; this field
    # exists now so Part 10 has somewhere real to write its result.
    reachability: Mapped[str | None] = mapped_column(String(20), default=None)
    exploitability: Mapped[str | None] = mapped_column(String(20), default=None)
    exposure: Mapped[str | None] = mapped_column(String(20), default=None)  # internal|external
    attack_path: Mapped[str | None] = mapped_column(Text, default=None)
    detection_coverage: Mapped[str | None] = mapped_column(String(20), default=None)
    recommended_remediation: Mapped[str | None] = mapped_column(Text, default=None)
    # Soft reference (agent stable_key or a real user id string), matching this
    # codebase's established MissionTask.agent_name pattern - not a FK, so a
    # renamed/removed agent never breaks a historical finding's readability.
    owner: Mapped[str | None] = mapped_column(String(100), default=None)
    sla_due_at: Mapped[datetime | None] = mapped_column(default=None)
    approval_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("approvals.id"), default=None)
    # List of Evidence.id (as str) proving closure - never a Finding marked
    # remediated/closed without something real backing it.
    closure_evidence: Mapped[list[str]] = mapped_column(JSONB, default=list)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(server_default=func.now(), onupdate=func.now())


class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[uuid.UUID] = _uuid_pk()
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"))
    title: Mapped[str] = mapped_column(String(300))
    summary: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(50))
    # open|investigating|resolved
    status: Mapped[str] = mapped_column(String(30), default="open")
    report: Mapped[str | None] = mapped_column(Text, default=None)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    resolved_at: Mapped[datetime | None] = mapped_column(default=None)


class IncidentFinding(Base):
    """Join table: which Findings were escalated into a given Incident."""

    __tablename__ = "incident_findings"

    incident_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("incidents.id"), primary_key=True)
    finding_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("findings.id"), primary_key=True)


class AuthorizedTarget(Base):
    """Phase 8: an explicit, time-bounded authorization record for the Red Team Agent's
    reconnaissance tools - deliberately a separate, stronger table from Watchlist (Phase
    5/7's lighter "check this against a feed" authorization), since offensive-adjacent
    actions need scope description, an accountable human authorizer, and a real expiry,
    not just a value on a list. See docs/adr/0007-phase-8-red-team-safety-boundary.md."""

    __tablename__ = "authorized_targets"

    id: Mapped[uuid.UUID] = _uuid_pk()
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"))
    target: Mapped[str] = mapped_column(String(300))
    target_type: Mapped[str] = mapped_column(String(20))  # domain|url|ip
    scope_description: Mapped[str] = mapped_column(Text)
    authorized_by_user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    valid_from: Mapped[datetime] = mapped_column(server_default=func.now())
    valid_until: Mapped[datetime]
    max_actions_per_hour: Mapped[int] = mapped_column(default=10)
    status: Mapped[str] = mapped_column(String(20), default="active")  # active|revoked
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    revoked_at: Mapped[datetime | None] = mapped_column(default=None)


class RedTeamSafetyState(Base):
    """Phase 8: a real, per-tenant emergency-stop kill switch. One row per tenant
    (tenant_id is the primary key, not a separate uuid) - checked first, before target
    authorization or rate limiting, by every real offensive-adjacent tool."""

    __tablename__ = "red_team_safety_state"

    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"), primary_key=True)
    emergency_stop_engaged: Mapped[bool] = mapped_column(default=False)
    engaged_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id"), default=None
    )
    engaged_at: Mapped[datetime | None] = mapped_column(default=None)


class Engagement(Base):
    """Phase 20 (Continuation Prompt 7 / EDP-007), Part 11: a formal, written
    penetration-test engagement layered on top of the existing AuthorizedTarget/
    redteam_safety boundary - never replacing it (every real recon action a linked
    Engagement runs still passes through gds_api.redteam_safety's exact 3 checks per
    target). An Engagement adds what a bare AuthorizedTarget alone doesn't carry:
    rules of engagement, an explicit allowed/prohibited technique list, an exclusion
    list, and a formal planned -> authorized -> in_progress -> completed/aborted
    lifecycle (gds_api.engagement.EngagementStatus), scoped 1:1 to one real
    `penetration_test`-typed Mission. See docs/reviews/phase-20-purple-workforce-pre-build-audit.md
    section 26 item 4 for why this is a new table referencing AuthorizedTarget
    rather than replacing it."""

    __tablename__ = "engagements"

    id: Mapped[uuid.UUID] = _uuid_pk()
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"))
    mission_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("missions.id"), unique=True)
    name: Mapped[str] = mapped_column(String(200))
    rules_of_engagement: Mapped[str] = mapped_column(Text)
    # Real, fixed technique names from gds_api.engagement.KNOWN_TECHNIQUES - the
    # honest, narrow set coordinate_pentest_engagement actually knows how to run
    # today, not a fabricated full MITRE ATT&CK technique catalogue.
    allowed_techniques: Mapped[list[str]] = mapped_column(JSONB, default=list)
    prohibited_techniques: Mapped[list[str]] = mapped_column(JSONB, default=list)
    exclusion_list: Mapped[list[str]] = mapped_column(JSONB, default=list)
    status: Mapped[str] = mapped_column(String(20), default="planned")
    authorized_by_user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    report_summary: Mapped[str | None] = mapped_column(Text, default=None)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    started_at: Mapped[datetime | None] = mapped_column(default=None)
    completed_at: Mapped[datetime | None] = mapped_column(default=None)


class EngagementTarget(Base):
    """Join table: which real AuthorizedTargets are in scope for a given Engagement.
    Deliberately many-to-many (not a single target_id on Engagement) - a real
    engagement commonly spans more than one authorized target."""

    __tablename__ = "engagement_targets"

    engagement_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("engagements.id"), primary_key=True)
    authorized_target_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("authorized_targets.id"), primary_key=True
    )


class Watchlist(Base):
    """A tenant-scoped entry the Defensive Agents check real external feeds against
    (gds_api.seed_data.WATCHLIST_SEED is what scripts/seed.py writes here) - real,
    tenant-configurable data, not a hardcoded list in tool code."""

    __tablename__ = "watchlist_entries"

    id: Mapped[uuid.UUID] = _uuid_pk()
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"))
    kind: Mapped[str] = mapped_column(String(20))  # cve|package|ioc
    value: Mapped[str] = mapped_column(String(200))
    ecosystem: Mapped[str | None] = mapped_column(String(50), default=None)  # for kind="package"
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())


class CapabilityRequestRecord(Base):
    """Phase 16: a durable record of one real request to invoke a Capability
    (gds_api.capabilities.catalog.CAPABILITY_REGISTRY - a code-defined, immutable
    catalogue, not a table - see docs/adr/0015). capability_key/requesting_agent_id are
    soft references into that code-defined catalogue and AGENT_REGISTRY respectively -
    same pattern MissionTask.tool_name/agent_name already use against
    TOOL_REGISTRY/AGENT_REGISTRY, not real FKs, since neither registry is a DB table."""

    __tablename__ = "capability_requests"

    id: Mapped[uuid.UUID] = _uuid_pk()
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"))
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    mission_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("missions.id"))
    workflow_run_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("workflow_runs.id"), default=None
    )
    conversation_thread_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("conversation_threads.id"), default=None
    )
    requesting_agent_id: Mapped[str | None] = mapped_column(String(100), default=None)
    supervising_agent_id: Mapped[str | None] = mapped_column(String(100), default=None)
    capability_key: Mapped[str] = mapped_column(String(100))
    requested_tool_id: Mapped[str | None] = mapped_column(String(100), default=None)
    target_type: Mapped[str | None] = mapped_column(String(20), default=None)
    target_reference: Mapped[str | None] = mapped_column(String(300), default=None)
    target_scope: Mapped[str | None] = mapped_column(Text, default=None)
    purpose: Mapped[str] = mapped_column(Text)
    # Secret-redacted before storage - see capabilities/broker.py's redact_secrets().
    # Never the raw untrusted payload.
    requested_parameters_safe: Mapped[dict[str, object]] = mapped_column(JSONB, default=dict)
    idempotency_key: Mapped[str | None] = mapped_column(String(200), default=None)
    model_provider: Mapped[str | None] = mapped_column(String(50), default=None)
    model_name: Mapped[str | None] = mapped_column(String(100), default=None)
    parent_request_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("capability_requests.id"), default=None
    )
    requested_at: Mapped[datetime] = mapped_column(server_default=func.now())

    __table_args__ = (
        Index("ix_capability_requests_tenant_mission", "tenant_id", "mission_id"),
        Index(
            "ix_capability_requests_idempotency",
            "tenant_id",
            "capability_key",
            "idempotency_key",
            unique=True,
        ),
    )


class CapabilityDecisionRecord(Base):
    """Phase 16: one immutable decision snapshot for a CapabilityRequestRecord - 1:many,
    not 1:1: Part I's execution-time re-check (gds_api.capabilities.broker.
    reevaluate_capability_request) re-evaluates the SAME real proposed request (the
    idempotency-key-bearing one a human's Approval is bound to) as time-sensitive state
    changes, producing a NEW decision row each time rather than a new request - per Part
    Q's "do not update old decisions to conceal history". gds_api.capabilities.broker
    never UPDATEs a decided row's decision/authoritative_risk_class/safe_denial_message
    after creation - only executed_at/execution_status are ever set later, once, when
    the Tool Gateway actually consumes an ALLOW decision."""

    __tablename__ = "capability_decisions"

    id: Mapped[uuid.UUID] = _uuid_pk()
    request_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("capability_requests.id"))
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"))
    # ALLOW|DENY|REQUIRE_APPROVAL|BLOCKED_DEPENDENCY|BLOCKED_AUTHORIZATION|
    # BLOCKED_EMERGENCY_STOP|RATE_LIMITED|EXPIRED|DISABLED
    decision: Mapped[str] = mapped_column(String(30))
    capability_key: Mapped[str] = mapped_column(String(100))
    capability_version: Mapped[str] = mapped_column(String(20))
    authoritative_risk_class: Mapped[str] = mapped_column(String(10))
    evaluated_tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"))
    evaluated_user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    evaluated_agent_id: Mapped[str | None] = mapped_column(String(100), default=None)
    evaluated_mission_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("missions.id"))
    evaluated_workflow_run_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("workflow_runs.id"), default=None
    )
    evaluated_target: Mapped[str | None] = mapped_column(String(300), default=None)
    approval_required: Mapped[bool] = mapped_column(default=False)
    approval_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("approvals.id"), default=None)
    target_authorisation_required: Mapped[bool] = mapped_column(default=False)
    target_authorisation_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("authorized_targets.id"), default=None
    )
    # Real check outcomes, safe to expose to the requesting tenant (no cross-tenant/
    # secret detail) - "connector: healthy", "rate_limit: 3/20", etc.
    connector_checks: Mapped[dict[str, object]] = mapped_column(JSONB, default=dict)
    credential_checks: Mapped[dict[str, object]] = mapped_column(JSONB, default=dict)
    emergency_stop_check: Mapped[dict[str, object]] = mapped_column(JSONB, default=dict)
    rate_limit_check: Mapped[dict[str, object]] = mapped_column(JSONB, default=dict)
    policy_checks: Mapped[dict[str, object]] = mapped_column(JSONB, default=dict)
    denial_code: Mapped[str | None] = mapped_column(String(50), default=None)
    safe_denial_message: Mapped[str | None] = mapped_column(Text, default=None)
    # The full internal trace (every check, its input, its result, timing) - NEVER
    # returned by a non-admin API response, only via the admin decisions endpoint.
    decision_trace: Mapped[dict[str, object]] = mapped_column(JSONB, default=dict)
    policy_version: Mapped[str] = mapped_column(String(20), default="1.0.0")
    decided_at: Mapped[datetime] = mapped_column(server_default=func.now())
    expires_at: Mapped[datetime | None] = mapped_column(default=None)
    executed_at: Mapped[datetime | None] = mapped_column(default=None)
    # None|pending|executed|failed - "executed" is set exactly once by the Tool Gateway,
    # a real reuse-prevention guard (Part I: "do not assume a previously allowed
    # decision remains safe indefinitely" / "a matching, non-expired decision").
    execution_status: Mapped[str | None] = mapped_column(String(20), default=None)

    __table_args__ = (
        Index("ix_capability_decisions_tenant_status", "tenant_id", "decision"),
        Index("ix_capability_decisions_mission", "evaluated_mission_id"),
        Index("ix_capability_decisions_request", "request_id"),
    )


class CapabilityState(Base):
    """Phase 16, Part C / ADR 0015: the ONE property of a CapabilityDefinition a real
    administrator may change at runtime without a code deploy - whether it is currently
    disabled for a tenant. Every other property (risk_class, approval/target-auth/
    emergency-stop requirements, allowed teams, etc.) stays immutable in
    gds_api.capabilities.catalog. This table can only ever narrow what the code-defined
    default already allows, never widen it - a missing row always means "use the code
    default," never "assume enabled." See gds_api.capabilities.broker's real
    enforcement of this rule."""

    __tablename__ = "capability_state"

    capability_key: Mapped[str] = mapped_column(String(100), primary_key=True)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"), primary_key=True)
    disabled: Mapped[bool] = mapped_column(default=False)
    disabled_reason: Mapped[str | None] = mapped_column(Text, default=None)
    disabled_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id"), default=None
    )
    updated_at: Mapped[datetime] = mapped_column(server_default=func.now(), onupdate=func.now())


class Repository(Base):
    """Phase 17 (Continuation Prompt 4), Part 2: a repository as a real managed object.
    Registering a repository never clones or mutates anything by itself - it only
    records real facts about a real, already-existing local path (`working_directory`)
    for the LOCAL provider (the only operational one this phase - see
    gds_api.repository.providers). No repository operation may run against
    `working_directory` directly; every real operation happens inside an isolated
    git worktree under a Workspace - see gds_api.repository.workspace_manager and
    docs/adr/0016-repository-workspace-architecture.md."""

    __tablename__ = "repositories"

    id: Mapped[uuid.UUID] = _uuid_pk()
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"))
    display_name: Mapped[str] = mapped_column(String(200))
    owner_user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    # local|github|gitlab|azure_devops|bitbucket - see RepositoryProviderType.
    provider: Mapped[str] = mapped_column(String(30))
    # private|public
    visibility: Mapped[str] = mapped_column(String(20), default="private")
    default_branch: Mapped[str] = mapped_column(String(200), default="main")
    # The primary clone's real, queried-on-demand checked-out branch - refreshed by
    # gds_api.repository.providers.LocalRepositoryProvider.refresh_status, not kept
    # continuously in sync (this row is a cache of a real fact, not a live mirror).
    current_branch: Mapped[str | None] = mapped_column(String(200), default=None)
    remote_url: Mapped[str | None] = mapped_column(String(500), default=None)
    # A symbolic reference to a credential store entry - mirrors
    # AgentManifest.required_credentials's real-but-honestly-unused-today pattern
    # (Phase 14). No credential resolution exists this phase; every real operational
    # repository is LOCAL and needs no credential at all.
    credential_reference: Mapped[str | None] = mapped_column(String(200), default=None)
    working_directory: Mapped[str] = mapped_column(String(1000))
    # REGISTERED|AVAILABLE|UNAVAILABLE|ARCHIVED|BROKEN
    status: Mapped[str] = mapped_column(String(20), default="REGISTERED")
    status_detail: Mapped[str | None] = mapped_column(Text, default=None)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(server_default=func.now(), onupdate=func.now())

    __table_args__ = (Index("ix_repositories_tenant_status", "tenant_id", "status"),)


class RepositoryPolicy(Base):
    """Phase 17, Part 4 (fields extended to real enforcement in Phase 18): real,
    per-repository policy - 1:1 with Repository. ENFORCED fields:
    readable/searchable/worktree_creation/delete_worktree_allowed/allowed_agents/
    allowed_capabilities/forbidden_paths/allowed_paths/approval_requirement (Phase 17),
    plus commit_allowed (checked directly by
    gds_api.engineering.orchestrator.commit_session - defaults to False, a real,
    deliberate secure-by-default gate an operator must explicitly opt each repository
    into) and maximum_changed_files/maximum_changed_lines (checked by
    gds_api.engineering.review_engine.run_review - a real FAIL finding over the limit)
    as of Phase 18. allowed_branches/protected_branches remain real and stored but NOT
    enforced - every workspace always opens the repository's own current/default branch
    (no caller-chosen-branch capability exists), so there is no real caller-controlled
    branch choice yet for them to govern. branch_creation/patch_creation/push_allowed/
    pull_request_allowed/required_tests/review_requirement/rollback_requirement remain
    real, stored, and API-editable with no real enforcement path yet - review always
    runs regardless of review_requirement, there is no push/PR/rollback capability yet,
    and required_tests is not read by the Review Engine's real tool-availability checks.
    Storing every field now (rather than adding them in a later phase) means each future
    capability inherits real policy data instead of a schema migration - never claimed
    as "enforced" until it actually is."""

    __tablename__ = "repository_policies"

    repository_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("repositories.id"), primary_key=True
    )
    readable: Mapped[bool] = mapped_column(default=True)
    searchable: Mapped[bool] = mapped_column(default=True)
    branch_creation: Mapped[bool] = mapped_column(default=False)
    worktree_creation: Mapped[bool] = mapped_column(default=True)
    patch_creation: Mapped[bool] = mapped_column(default=False)
    commit_allowed: Mapped[bool] = mapped_column(default=False)
    push_allowed: Mapped[bool] = mapped_column(default=False)
    pull_request_allowed: Mapped[bool] = mapped_column(default=False)
    delete_worktree_allowed: Mapped[bool] = mapped_column(default=True)
    # Empty list = no restriction beyond the Secure Capability Broker's own real
    # allow-list check (gds_api.capabilities.broker) - these lists can only ever narrow
    # further, never grant something the broker itself would otherwise deny.
    allowed_agents: Mapped[list[str]] = mapped_column(JSONB, default=list)
    allowed_capabilities: Mapped[list[str]] = mapped_column(JSONB, default=list)
    allowed_branches: Mapped[list[str]] = mapped_column(JSONB, default=list)
    protected_branches: Mapped[list[str]] = mapped_column(JSONB, default=list)
    forbidden_paths: Mapped[list[str]] = mapped_column(JSONB, default=list)
    allowed_paths: Mapped[list[str]] = mapped_column(JSONB, default=list)
    maximum_changed_files: Mapped[int] = mapped_column(default=25)
    maximum_changed_lines: Mapped[int] = mapped_column(default=1000)
    required_tests: Mapped[bool] = mapped_column(default=False)
    review_requirement: Mapped[bool] = mapped_column(default=False)
    approval_requirement: Mapped[bool] = mapped_column(default=False)
    rollback_requirement: Mapped[bool] = mapped_column(default=False)
    updated_at: Mapped[datetime] = mapped_column(server_default=func.now(), onupdate=func.now())


class WorkspacePolicy(Base):
    """Phase 17, Part 2: the second, distinct per-repository policy Part 2 names
    separately from RepositoryPolicy - governs workspace/worktree lifecycle limits
    rather than what a capability may do inside one. 1:1 with Repository."""

    __tablename__ = "workspace_policies"

    repository_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("repositories.id"), primary_key=True
    )
    default_ttl_seconds: Mapped[int] = mapped_column(default=1800)
    maximum_ttl_seconds: Mapped[int] = mapped_column(default=7200)
    maximum_concurrent_workspaces: Mapped[int] = mapped_column(default=5)
    allow_heartbeat_extension: Mapped[bool] = mapped_column(default=True)
    auto_cleanup_on_expire: Mapped[bool] = mapped_column(default=True)
    updated_at: Mapped[datetime] = mapped_column(server_default=func.now(), onupdate=func.now())


class Workspace(Base):
    """Phase 17, Part 5: one real, isolated `git worktree` session over exactly one
    Repository. Never the primary repository's own working_directory - see
    gds_api.repository.worktree_manager. capability_decision_id records the ONE
    CapabilityDecisionRecord (a real `repository.read`) that caused this workspace to be
    created; later capability requests against the same repository within the same
    mission reuse this workspace by id rather than creating a new one - see
    gds_api.repository.workspace_manager.resolve_or_create_workspace."""

    __tablename__ = "workspaces"

    id: Mapped[uuid.UUID] = _uuid_pk()
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"))
    mission_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("missions.id"))
    workflow_run_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("workflow_runs.id"), default=None
    )
    capability_decision_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("capability_decisions.id"), default=None
    )
    repository_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("repositories.id"))
    # None = Rabbani-direct, matching gds_api.capabilities.broker's own real
    # requesting_agent_id convention - every real repository capability this phase is
    # Rabbani-direct only (see gds_api.capabilities.catalog's repository.* entries).
    agent_id: Mapped[str | None] = mapped_column(String(100), default=None)
    provider: Mapped[str] = mapped_column(String(30))
    workspace_path: Mapped[str] = mapped_column(String(1000))
    temporary_directory: Mapped[str] = mapped_column(String(1000))
    # ALLOCATED|READY|ACTIVE|LOCKED|EXPIRED|DESTROYED|FAILED
    state: Mapped[str] = mapped_column(String(20), default="ALLOCATED")
    failure_reason: Mapped[str | None] = mapped_column(Text, default=None)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    last_heartbeat_at: Mapped[datetime] = mapped_column(server_default=func.now())
    expires_at: Mapped[datetime] = mapped_column()
    destroyed_at: Mapped[datetime | None] = mapped_column(default=None)

    __table_args__ = (
        Index("ix_workspaces_tenant_state", "tenant_id", "state"),
        Index("ix_workspaces_repository", "repository_id"),
        Index("ix_workspaces_mission", "mission_id"),
        Index("ix_workspaces_expires", "state", "expires_at"),
    )


class EngineeringSession(Base):
    """Phase 18 (Continuation Prompt 5): one real, persisted AI engineering execution -
    a provider (Claude Code CLI subprocess or OpenAI Codex Responses API) doing real work
    inside an already-open Workspace's worktree (Phase 17), never the primary repository.
    A session's own Mission carries the real broker/audit context (matching Workspace's
    own precedent) - `gds_api.engineering.orchestrator` drives the Mission's real status
    lifecycle (planning -> running -> completed/failed) so the existing
    `/missions/{id}/stream` SSE endpoint's `mission_finished` termination fires naturally,
    no parallel lifecycle or endpoint needed.

    Status machine: PENDING -> RUNNING -> AWAITING_REVIEW -> (AWAITING_APPROVAL ->)
    APPROVED -> COMMITTING -> COMPLETED, with FAILED/CANCELLED/REJECTED reachable from
    any non-terminal state. AWAITING_APPROVAL is only entered when the real Review
    Engine's sensitive-area/risk finding requires it (Part 10) - most sessions go
    AWAITING_REVIEW -> APPROVED directly."""

    __tablename__ = "engineering_sessions"

    id: Mapped[uuid.UUID] = _uuid_pk()
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"))
    mission_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("missions.id"))
    workflow_run_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("workflow_runs.id"), default=None
    )
    repository_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("repositories.id"))
    workspace_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("workspaces.id"))
    capability_decision_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("capability_decisions.id"), default=None
    )
    # claude|openai - gds_api.engineering.providers.PROVIDER_REGISTRY's real keys.
    provider: Mapped[str] = mapped_column(String(30))
    requested_by_user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    agent_id: Mapped[str | None] = mapped_column(String(100), default=None)
    objective: Mapped[str] = mapped_column(Text)
    prompt_version: Mapped[str] = mapped_column(String(20), default="1.0.0")
    compiled_prompt: Mapped[str] = mapped_column(Text)
    # PENDING|RUNNING|AWAITING_REVIEW|AWAITING_APPROVAL|APPROVED|REJECTED|COMMITTING|
    # COMPLETED|FAILED|CANCELLED
    status: Mapped[str] = mapped_column(String(30), default="PENDING")
    # The real claude CLI's own --resume session id, or the OpenAI response id - whatever
    # a real provider needs to resume THIS session, never a fabricated placeholder.
    provider_session_id: Mapped[str | None] = mapped_column(String(200), default=None)
    external_pid: Mapped[int | None] = mapped_column(default=None)
    # Capped in the executor (see _MAX_LOG_CHARS) before ever being persisted - never an
    # unbounded real subprocess/API transcript.
    stdout_log: Mapped[str | None] = mapped_column(Text, default=None)
    stderr_log: Mapped[str | None] = mapped_column(Text, default=None)
    exit_code: Mapped[int | None] = mapped_column(default=None)
    reasoning_summary: Mapped[str | None] = mapped_column(Text, default=None)
    patch_summary: Mapped[dict[str, object]] = mapped_column(JSONB, default=dict)
    # PASS|WARNING|FAIL|None (not yet reviewed)
    review_result: Mapped[str | None] = mapped_column(String(20), default=None)
    review_findings: Mapped[list[dict[str, object]]] = mapped_column(JSONB, default=list)
    sensitive_area_hit: Mapped[bool] = mapped_column(default=False)
    approval_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("approvals.id"), default=None)
    # The real CapabilityRequestRecord id from the engineering.commit evaluation - must
    # be reused (never re-evaluated as a new request) once a human approves, per Phase
    # 16's own established "re-evaluate the SAME request" precedent
    # (capabilities/broker.py's reevaluate_capability_request).
    commit_request_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("capability_requests.id"), default=None
    )
    commit_hash: Mapped[str | None] = mapped_column(String(64), default=None)
    input_tokens: Mapped[int] = mapped_column(default=0)
    output_tokens: Mapped[int] = mapped_column(default=0)
    cost_usd: Mapped[Decimal] = mapped_column(Numeric(12, 6), default=Decimal("0"))
    failure_reason: Mapped[str | None] = mapped_column(Text, default=None)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    started_at: Mapped[datetime | None] = mapped_column(default=None)
    completed_at: Mapped[datetime | None] = mapped_column(default=None)

    __table_args__ = (
        Index("ix_engineering_sessions_tenant_status", "tenant_id", "status"),
        Index("ix_engineering_sessions_mission", "mission_id"),
        Index("ix_engineering_sessions_repository", "repository_id"),
        Index("ix_engineering_sessions_workspace", "workspace_id"),
    )


class MissionPlan(Base):
    """Phase 19 (Continuation Prompt 6): the real, structured decomposition of one real
    Mission into a dependency-ordered graph of EngineeringTask nodes. 1:1 with Mission
    (mirroring EngineeringSession's own precedent) - a mission that goes through the
    multi-agent path gets exactly one real MissionPlan, never more.

    mission_memory is real, structured, shared, READ-ONLY context every task's prompt
    is compiled with (Part 6) - only gds_api.engineering.mission_orchestrator ever
    writes to it (appending a completed task's real summary), never an individual
    task's own provider session - "agents may read shared context, agents may never
    overwrite another agent's work" is enforced structurally by which real code path
    has write access, not by convention alone."""

    __tablename__ = "mission_plans"

    id: Mapped[uuid.UUID] = _uuid_pk()
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"))
    mission_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("missions.id"), unique=True)
    repository_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("repositories.id"))
    requested_by_user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    # Phase 20 (Continuation Prompt 7), Part 10: set only when this MissionPlan was
    # created by auto_fix_finding (gds_api.tool_gateway) to remediate a real
    # Finding - None for every other MissionPlan (a real, direct engineering
    # mission has no finding to remediate). Lets merge_coordinator.commit_mission
    # advance the finding's real lifecycle (remediation_in_progress ->
    # awaiting_retest) at the exact moment its fix is genuinely committed, without
    # a second, parallel "which finding is this for" tracking mechanism.
    finding_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("findings.id"), default=None)
    objective: Mapped[str] = mapped_column(Text)
    # low|medium|high - a real, LLM-produced estimate (never fabricated as a constant).
    complexity: Mapped[str | None] = mapped_column(String(20), default=None)
    affected_systems: Mapped[list[str]] = mapped_column(JSONB, default=list)
    execution_strategy: Mapped[str | None] = mapped_column(Text, default=None)
    # PLANNING|READY|EXECUTING|MERGING|REVIEWING|AWAITING_APPROVAL|COMPLETED|FAILED|
    # CANCELLED
    status: Mapped[str] = mapped_column(String(30), default="PLANNING")
    max_concurrency: Mapped[int] = mapped_column(default=3)
    mission_memory: Mapped[dict[str, object]] = mapped_column(JSONB, default=dict)
    # The one real, dedicated Workspace the Merge Coordinator merges every real task
    # branch into - never one of the per-task workspaces themselves.
    integration_workspace_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("workspaces.id"), default=None
    )
    integration_branch: Mapped[str | None] = mapped_column(String(200), default=None)
    conflict_report: Mapped[dict[str, object]] = mapped_column(JSONB, default=dict)
    merged_review_result: Mapped[str | None] = mapped_column(String(20), default=None)
    merged_review_findings: Mapped[list[dict[str, object]]] = mapped_column(JSONB, default=list)
    approval_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("approvals.id"), default=None)
    commit_request_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("capability_requests.id"), default=None
    )
    commit_hash: Mapped[str | None] = mapped_column(String(64), default=None)
    failure_reason: Mapped[str | None] = mapped_column(Text, default=None)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    planned_at: Mapped[datetime | None] = mapped_column(default=None)
    completed_at: Mapped[datetime | None] = mapped_column(default=None)

    __table_args__ = (
        Index("ix_mission_plans_tenant_status", "tenant_id", "status"),
        Index("ix_mission_plans_repository", "repository_id"),
    )


class EngineeringTask(Base):
    """Phase 19: one real node in a MissionPlan's task graph. Executes through Phase
    18's exact real AIProvider/prompt-compiler/patch-extractor/review-engine pipeline
    (engineering_session_id, once started) - a specialist "agent" is a real prompt/scope
    profile (specialist_role), never a third code-writing mechanism alongside Claude
    Code/OpenAI Codex (ADR 0029). Always its own real Workspace on its own real named
    branch (branch_name) - "no workspace sharing" (Part 4) is a real, structural fact:
    every task gets a fresh real git worktree, never reused across tasks."""

    __tablename__ = "engineering_tasks"

    id: Mapped[uuid.UUID] = _uuid_pk()
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"))
    mission_plan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("mission_plans.id"))
    repository_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("repositories.id"))
    # Short, real, unique-within-plan slug (e.g. "backend-1") - the real identity
    # depends_on references use, never a raw UUID a mission-planning LLM call would have
    # to fabricate correctly.
    task_key: Mapped[str] = mapped_column(String(100))
    title: Mapped[str] = mapped_column(String(300))
    description: Mapped[str] = mapped_column(Text)
    specialist_role: Mapped[str] = mapped_column(String(50))
    provider: Mapped[str] = mapped_column(String(30))
    depends_on: Mapped[list[str]] = mapped_column(JSONB, default=list)
    required_capabilities: Mapped[list[str]] = mapped_column(JSONB, default=list)
    output_contract: Mapped[str | None] = mapped_column(Text, default=None)
    # PENDING|READY|RUNNING|AWAITING_REVIEW|COMPLETED|FAILED|CANCELLED|BLOCKED
    status: Mapped[str] = mapped_column(String(30), default="PENDING")
    risk_estimate: Mapped[str] = mapped_column(String(20), default="low")
    duration_estimate_seconds: Mapped[int | None] = mapped_column(default=None)
    workspace_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("workspaces.id"), default=None
    )
    branch_name: Mapped[str | None] = mapped_column(String(200), default=None)
    engineering_session_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("engineering_sessions.id"), default=None
    )
    patch_summary: Mapped[dict[str, object]] = mapped_column(JSONB, default=dict)
    review_result: Mapped[str | None] = mapped_column(String(20), default=None)
    review_findings: Mapped[list[dict[str, object]]] = mapped_column(JSONB, default=list)
    input_tokens: Mapped[int] = mapped_column(default=0)
    output_tokens: Mapped[int] = mapped_column(default=0)
    cost_usd: Mapped[Decimal] = mapped_column(Numeric(12, 6), default=Decimal("0"))
    failure_reason: Mapped[str | None] = mapped_column(Text, default=None)
    retry_count: Mapped[int] = mapped_column(default=0)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    started_at: Mapped[datetime | None] = mapped_column(default=None)
    completed_at: Mapped[datetime | None] = mapped_column(default=None)

    __table_args__ = (
        Index("ix_engineering_tasks_plan", "mission_plan_id"),
        Index("ix_engineering_tasks_tenant_status", "tenant_id", "status"),
        Index("ix_engineering_tasks_plan_key", "mission_plan_id", "task_key", unique=True),
    )


class MissionMessage(Base):
    """Phase 19, Part 7: real, structured, fully-audited inter-agent messaging - "no
    free-form hidden communication" is a real, structural fact: every real message is a
    real row here, visible on the mission timeline, never an out-of-band channel between
    two provider sessions (which cannot actually talk to each other directly - neither
    Claude Code nor OpenAI Codex supports being interrupted mid-session by another real
    session). task_id is the real sender (None = the Mission Orchestrator itself);
    related_task_id is which task a question/answer is really about, when relevant."""

    __tablename__ = "mission_messages"

    id: Mapped[uuid.UUID] = _uuid_pk()
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"))
    mission_plan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("mission_plans.id"))
    task_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("engineering_tasks.id"), default=None
    )
    related_task_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("engineering_tasks.id"), default=None
    )
    # question|answer|dependency_complete|need_review|need_clarification|risk_raised|
    # blocked|complete
    message_type: Mapped[str] = mapped_column(String(30))
    content: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())

    __table_args__ = (Index("ix_mission_messages_plan", "mission_plan_id"),)


class PurpleMissionMessage(Base):
    """Phase 20 (Continuation Prompt 7), Part 8: real, structured, persisted,
    fully-audited Purple Workforce inter-agent messaging - the same "no hidden
    inter-agent communication" principle as Phase 19's MissionMessage, but scoped to
    the general Mission/MissionTask system (gds_api.mission_taxonomy's 23 Purple
    mission types) rather than Phase 19's engineering-specific MissionPlan/
    EngineeringTask system. Deliberately a new table, not a generalisation of
    MissionMessage: the two reference genuinely different foreign keys
    (Mission/MissionTask here vs. MissionPlan/EngineeringTask there) for genuinely
    different mission kinds, and forcing one schema to serve both would mean either
    a dual-nullable-FK table (ambiguous which FK pair is "real" for a given row) or
    diluting Phase 19's already-real, already-tested engineering message semantics.
    See ADR 0032.

    sender_agent/recipient_agent are soft references (plain strings, matching
    MissionTask.agent_name's existing pattern), not foreign keys into
    AGENT_REGISTRY - an agent removed/renamed in a future registry edit must never
    break a historical message's readability. recipient_agent is nullable: several
    message types (e.g. finding_created, safety_stop) are broadcast/inform-only,
    not directed at one specific recipient."""

    __tablename__ = "purple_mission_messages"

    id: Mapped[uuid.UUID] = _uuid_pk()
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"))
    mission_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("missions.id"))
    task_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("mission_tasks.id"), default=None)
    related_task_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("mission_tasks.id"), default=None
    )
    # One of gds_api.purple_messages.PURPLE_MESSAGE_TYPES (28 values) - validated at
    # insert time by record_purple_message(), not a DB CHECK constraint (matches
    # this codebase's existing status-vocabulary pattern of app-level validation).
    message_type: Mapped[str] = mapped_column(String(50))
    sender_agent: Mapped[str | None] = mapped_column(String(100), default=None)
    recipient_agent: Mapped[str | None] = mapped_column(String(100), default=None)
    # info|warning|critical - how this message should be surfaced/prioritised on a
    # mission timeline. Not a risk_class (that's the finding/capability's own
    # concern) - purely a display/triage signal for the message itself.
    classification: Mapped[str] = mapped_column(String(20), default="info")
    content: Mapped[str] = mapped_column(Text)
    # Structured, operationally useful payload (e.g. {"finding_id": "...", "cve":
    # "..."}) - never raw model chain-of-thought, per Prompt 7 Part 8's explicit
    # rule to store only decisions/evidence/outcomes.
    payload: Mapped[dict[str, object]] = mapped_column(JSONB, default=dict)
    # List of Evidence.id (as str) this message references, if any.
    evidence_references: Mapped[list[str]] = mapped_column(JSONB, default=list)
    # Groups a related sequence of messages across agents/tasks (e.g. a
    # finding_created -> approval_requested -> approval_resolved -> retest_passed
    # chain about the same underlying finding) - independent of task_id, since a
    # correlated sequence often spans more than one task or agent.
    correlation_id: Mapped[uuid.UUID | None] = mapped_column(default=None)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())

    __table_args__ = (
        Index("ix_purple_mission_messages_mission", "mission_id"),
        Index("ix_purple_mission_messages_correlation", "correlation_id"),
    )


class CloudEnvironment(Base):
    """EDP-009 Part 1, Section 2: an authorised organisational cloud scope (an AWS
    Organisation/Account, an Azure Management Group/Subscription, a GCP
    Organisation/Project, a Kubernetes cluster, etc.) - the provider-neutral core
    plus provider-specific detail lives in `environment_metadata`, per this Part's
    own instruction not to force every provider into an identical hierarchy where
    their real structures differ. `provider` is a soft reference into
    gds_api.cloud.providers.CLOUD_PROVIDER_REGISTRY (same soft-reference pattern
    MissionTask.tool_name uses against TOOL_REGISTRY), not a foreign key, since that
    registry is code-defined, not a table (ADR 0012/0015 precedent).

    This Part's own pre-build audit (docs/reviews/phase-22-cloud-foundation-pre-build-audit.md)
    found no existing model plays the "authorised target" role AuthorizedTarget plays
    for Red Team - CloudEnvironment IS that role for cloud capabilities
    (`requires_target_authorisation`-gated capabilities can check this row's own
    `status`/`enabled` state directly, deliberately not forced through
    AuthorizedTarget's domain/url/ip-shaped target_type)."""

    __tablename__ = "cloud_environments"

    id: Mapped[uuid.UUID] = _uuid_pk()
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"))
    provider: Mapped[str] = mapped_column(String(30))
    name: Mapped[str] = mapped_column(String(200))
    native_id: Mapped[str] = mapped_column(String(300))
    # organisation|account|subscription|project|resource_group|management_group|
    # folder|cluster|namespace - validated at insert time against the real per-provider
    # environment types Section 2 documents, not a DB CHECK constraint (matches this
    # codebase's existing status-vocabulary pattern of app-level validation).
    environment_type: Mapped[str] = mapped_column(String(50))
    parent_environment_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("cloud_environments.id"), default=None
    )
    # Real, human-readable breadcrumb (e.g. "Org > OU > Account") - derived from real
    # discovered hierarchy, never fabricated ahead of a real discovery job confirming it.
    organisational_path: Mapped[str | None] = mapped_column(Text, default=None)
    # registered|active|disabled|error
    status: Mapped[str] = mapped_column(String(20), default="registered")
    connection_profile_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("cloud_connection_profiles.id"), default=None
    )
    # never_run|queued|running|partially_completed|completed|failed
    discovery_status: Mapped[str] = mapped_column(String(30), default="never_run")
    last_successful_discovery_at: Mapped[datetime | None] = mapped_column(default=None)
    last_attempted_discovery_at: Mapped[datetime | None] = mapped_column(default=None)
    last_failure_detail: Mapped[str | None] = mapped_column(Text, default=None)
    # Real counts, refreshed after every completed/partially_completed discovery job -
    # never estimated or fabricated ahead of a real discovery.
    asset_count: Mapped[int] = mapped_column(default=0)
    region_count: Mapped[int] = mapped_column(default=0)
    # Section 18's own explicit rule: "If graph synchronization fails... mark
    # graph freshness accurately... do not claim the graph is current." Real,
    # honest defaults - never_synced until gds_api.cloud.graph actually runs a
    # real sync for this environment, error if that real sync fails.
    graph_sync_status: Mapped[str] = mapped_column(String(30), default="never_synced")
    graph_last_synced_at: Mapped[datetime | None] = mapped_column(default=None)
    created_by_user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    tags: Mapped[dict[str, object]] = mapped_column(JSONB, default=dict)
    classification: Mapped[str | None] = mapped_column(String(50), default=None)
    description: Mapped[str | None] = mapped_column(Text, default=None)
    enabled: Mapped[bool] = mapped_column(default=True)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(server_default=func.now(), onupdate=func.now())

    __table_args__ = (
        Index("ix_cloud_environments_tenant_provider", "tenant_id", "provider"),
        Index("ix_cloud_environments_parent", "parent_environment_id"),
    )


class CloudConnectionProfile(Base):
    """EDP-009 Part 1, Section 3-4: a governed description of HOW this platform is
    authorised to connect to a real CloudEnvironment, without ever storing a raw
    secret value in this row. `credential_reference` is an opaque pointer, mirroring
    the exact same real-but-honestly-narrow precedent `Repository.credential_reference`
    already established (Phase 17) - no secret-resolution/vault integration exists
    yet; a real production deployment resolves this reference through its own real
    deployment-managed secret store (see docs/guides/security-guide.md's "no
    secrets-manager integration" disclosed limitation), never through a column on
    this table. See docs/adr/0050-provider-neutral-cloud-foundation.md."""

    __tablename__ = "cloud_connection_profiles"

    id: Mapped[uuid.UUID] = _uuid_pk()
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"))
    environment_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("cloud_environments.id"))
    provider: Mapped[str] = mapped_column(String(30))
    # assume_role|external_id_sts|short_lived_sts_credentials|service_principal|
    # managed_identity|workload_identity_federation|service_account_impersonation|
    # short_lived_credentials|service_account_or_workload_identity_reference|
    # restricted_kubeconfig_secret_reference - matches
    # CloudProviderDefinition.supported_authentication_mechanisms per provider.
    authentication_type: Mapped[str] = mapped_column(String(60))
    # Opaque reference only - NEVER a raw secret value. See the class docstring.
    credential_reference: Mapped[str | None] = mapped_column(String(300), default=None)
    role_or_principal_reference: Mapped[str | None] = mapped_column(String(300), default=None)
    external_id: Mapped[str | None] = mapped_column(String(200), default=None)
    permission_scope: Mapped[str | None] = mapped_column(Text, default=None)
    read_only: Mapped[bool] = mapped_column(default=True)
    # never_validated|valid|invalid|expired|error
    validation_status: Mapped[str] = mapped_column(String(20), default="never_validated")
    last_validated_at: Mapped[datetime | None] = mapped_column(default=None)
    expiry_at: Mapped[datetime | None] = mapped_column(default=None)
    # not_tracked|current|due_for_rotation|expired - honestly not_tracked by default
    # since no real rotation automation exists this Part.
    rotation_state: Mapped[str] = mapped_column(String(30), default="not_tracked")
    created_by_user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    enabled: Mapped[bool] = mapped_column(default=True)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(server_default=func.now(), onupdate=func.now())

    __table_args__ = (Index("ix_cloud_connection_profiles_tenant", "tenant_id"),)


class CloudConnectionValidation(Base):
    """EDP-009 Part 1, Section 5: a real, durable record of one real read-only
    connection-test attempt - never a destructive test, never a cloud-configuration
    mutation. Kept as its own append-only table (not just fields on
    CloudConnectionProfile) because Section 5 requires a real per-attempt audit
    trail (attempt time, completion time, sanitised error, correlation ID) distinct
    from the profile's own current `validation_status` summary field."""

    __tablename__ = "cloud_connection_validations"

    id: Mapped[uuid.UUID] = _uuid_pk()
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"))
    connection_profile_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("cloud_connection_profiles.id")
    )
    provider_identity: Mapped[str | None] = mapped_column(String(300), default=None)
    scope_identity: Mapped[str | None] = mapped_column(String(300), default=None)
    # success|failure|error
    status: Mapped[str] = mapped_column(String(20))
    attempted_at: Mapped[datetime] = mapped_column(server_default=func.now())
    completed_at: Mapped[datetime | None] = mapped_column(default=None)
    # Sanitized - never a raw provider SDK exception (which can embed request
    # metadata) - see gds_api.cloud.connections' real sanitisation helper.
    sanitized_error: Mapped[str | None] = mapped_column(Text, default=None)
    capability_availability: Mapped[dict[str, object]] = mapped_column(JSONB, default=dict)
    latency_ms: Mapped[float | None] = mapped_column(default=None)
    actor_user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    correlation_id: Mapped[uuid.UUID] = mapped_column(default=uuid.uuid4)
    evidence_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("evidence.id"), default=None)

    __table_args__ = (
        Index("ix_cloud_connection_validations_profile", "connection_profile_id"),
    )


class CloudDiscoveryJob(Base):
    """EDP-009 Part 1, Section 6: a real, durable discovery-job record. Reuses the
    existing Mission/Capability Broker pipeline rather than a bespoke parallel job
    system (Section 6's own instruction: "Discovery jobs must use existing workflow
    and worker infrastructure where appropriate") - `mission_id` links to a real
    Mission of type `cloud_security_assessment` (already a real value in the 23-value
    MissionType enum, previously unused - see mission_taxonomy.py's new eligibility
    branch), and the actual discovery work runs as the real
    `cloud.discover_environment` capability via `tool_gateway._discover_cloud_environment`
    - never a second execution path around the Capability Broker.

    This sub-phase's own honest limitation: no real adapter exists yet for any
    provider (see ADR 0050), so every real job created this sub-phase will
    genuinely reach `failed` with a disclosed "no adapter available" reason - the
    full queued->running->partially_completed/completed state vocabulary exists
    now for later sub-phases' real adapters to actually use, not fabricated
    progress this sub-phase can't produce."""

    __tablename__ = "cloud_discovery_jobs"

    id: Mapped[uuid.UUID] = _uuid_pk()
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"))
    environment_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("cloud_environments.id"))
    provider: Mapped[str] = mapped_column(String(30))
    # Nullable: a job is now created as soon as a real CloudEnvironment is found
    # (Section 49 - every failure mode gets a real, durable, honestly `failed`
    # job, never a bare unrecorded error), and an environment with no connection
    # profile configured yet is itself one of those honest failure modes.
    connection_profile_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("cloud_connection_profiles.id"), default=None
    )
    # Real, requested discovery scope - e.g. {"native_id": "o-abc123"} - never
    # fabricated ahead of what was actually requested.
    requested_scope: Mapped[dict[str, object]] = mapped_column(JSONB, default=dict)
    discovery_categories: Mapped[list[str]] = mapped_column(JSONB, default=list)
    regions: Mapped[list[str]] = mapped_column(JSONB, default=list)
    initiated_by_user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    mission_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("missions.id"), default=None)
    workflow_run_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("workflow_runs.id"), default=None
    )
    # queued|starting|running|partially_completed|completed|failed|cancelled|timed_out
    status: Mapped[str] = mapped_column(String(30), default="queued")
    started_at: Mapped[datetime | None] = mapped_column(default=None)
    completed_at: Mapped[datetime | None] = mapped_column(default=None)
    assets_discovered: Mapped[int] = mapped_column(default=0)
    assets_updated: Mapped[int] = mapped_column(default=0)
    assets_unchanged: Mapped[int] = mapped_column(default=0)
    assets_marked_absent: Mapped[int] = mapped_column(default=0)
    relationships_discovered: Mapped[int] = mapped_column(default=0)
    errors: Mapped[list[str]] = mapped_column(JSONB, default=list)
    warnings: Mapped[list[str]] = mapped_column(JSONB, default=list)
    rate_limit_state: Mapped[dict[str, object]] = mapped_column(JSONB, default=dict)
    evidence_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("evidence.id"), default=None)
    correlation_id: Mapped[uuid.UUID] = mapped_column(default=uuid.uuid4)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(server_default=func.now(), onupdate=func.now())

    __table_args__ = (
        Index("ix_cloud_discovery_jobs_environment", "environment_id"),
        Index("ix_cloud_discovery_jobs_tenant_status", "tenant_id", "status"),
    )


class CloudAsset(Base):
    """EDP-009 Part 1, Sections 12-14: the provider-neutral, persisted asset
    record - the real destination `ProviderAdapter.discover_assets()` results
    (gds_api.cloud.schemas.NormalizedCloudAsset, an adapter-facing dataclass)
    are upserted into by gds_api.cloud.assets.upsert_asset(), never a second,
    parallel storage path.

    Two distinct category fields, deliberately not one (Section 12 vs 13):
    `provider_category` is the real, already-tested value each adapter itself
    emits (e.g. AWS's `ec2_instance`, GCP's `compute_instance`) - Section 1's
    own per-provider vocabulary, unchanged since Sections 8-11. `normalized_category`
    is Section 13's cross-provider taxonomy value (e.g. `virtual_machine`),
    computed once at persistence time via gds_api.cloud.taxonomy.taxonomy_category_for
    - never re-derived ad hoc elsewhere, and never `unknown_or_provider_specific`
    by silent omission (Section 13's own explicit rule).

    `raw_metadata` is redacted and size-bounded before persistence
    (gds_api.cloud.assets._bounded_metadata) - Section 14's own explicit
    requirement ("No unrestricted arbitrary payload growth... No credentials...
    No secret values") - the adapter's own job is only to report what the
    provider said (see NormalizedCloudAsset's own docstring); this model's job
    is to store only a safe, bounded version of that."""

    __tablename__ = "cloud_assets"

    id: Mapped[uuid.UUID] = _uuid_pk()
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"))
    environment_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("cloud_environments.id"))
    provider: Mapped[str] = mapped_column(String(30))
    native_id: Mapped[str] = mapped_column(String(1000))
    native_resource_type: Mapped[str] = mapped_column(String(200))
    provider_category: Mapped[str] = mapped_column(String(100))
    normalized_category: Mapped[str] = mapped_column(String(100))
    name: Mapped[str] = mapped_column(String(500))
    display_name: Mapped[str | None] = mapped_column(String(500), default=None)
    region_or_location: Mapped[str | None] = mapped_column(String(100), default=None)
    availability_zone: Mapped[str | None] = mapped_column(String(100), default=None)
    parent_asset_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("cloud_assets.id"), default=None
    )
    account_or_subscription_or_project: Mapped[str | None] = mapped_column(
        String(300), default=None
    )
    resource_group_or_org_path: Mapped[str | None] = mapped_column(Text, default=None)
    # unknown|running|stopped|available|deleted|error|... - real, provider-reported
    # lifecycle text, never normalized into a fabricated shared vocabulary Section
    # 12 doesn't itself define.
    lifecycle_state: Mapped[str | None] = mapped_column(String(100), default=None)
    created_at_provider: Mapped[datetime | None] = mapped_column(default=None)
    first_seen_at: Mapped[datetime] = mapped_column(server_default=func.now())
    last_seen_at: Mapped[datetime] = mapped_column(server_default=func.now())
    last_changed_at: Mapped[datetime] = mapped_column(server_default=func.now())
    discovery_job_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("cloud_discovery_jobs.id"), default=None
    )
    # Reserved for Section 16 (Inventory Snapshots, a later sub-phase of this same
    # Part) - nullable and unused until that sub-phase's own real snapshot model
    # exists, never a forward reference to something not yet built.
    inventory_snapshot_id: Mapped[uuid.UUID | None] = mapped_column(default=None)
    tags: Mapped[dict[str, str]] = mapped_column(JSONB, default=dict)
    internet_exposure_known: Mapped[bool | None] = mapped_column(default=None)
    managed_service: Mapped[bool | None] = mapped_column(default=None)
    raw_metadata: Mapped[dict[str, object]] = mapped_column(JSONB, default=dict)
    schema_version: Mapped[int] = mapped_column(default=1)
    # fresh|stale|unknown - real, computed from last_seen_at vs the environment's
    # own discovery cadence at read time (gds_api.cloud.assets), never stored as a
    # value that could silently drift from the truth.
    freshness_state: Mapped[str] = mapped_column(String(20), default="fresh")
    # Section 17's own real vocabulary, graduated rather than a bare present/
    # absent boolean: unknown|present|absent_current_run|confirmed_absent|
    # inaccessible|provider_not_found. "unknown" (not "absent") is this column's
    # own honest default: an asset that has never been re-scanned is not yet
    # known to be gone (Section 17's explicit "not observed is not always
    # deleted" rule), so a freshly-discovered asset must never default to a
    # value that would misrepresent it as confirmed absent. See
    # gds_api/cloud/changes.py for the real state-transition logic.
    absence_state: Mapped[str] = mapped_column(String(40), default="unknown")
    evidence_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("evidence.id"), default=None)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(server_default=func.now(), onupdate=func.now())

    __table_args__ = (
        Index("ix_cloud_assets_tenant_environment", "tenant_id", "environment_id"),
        Index("ix_cloud_assets_tenant_category", "tenant_id", "normalized_category"),
        Index(
            "ux_cloud_assets_environment_native_id",
            "environment_id",
            "provider",
            "native_id",
            unique=True,
        ),
    )


class CloudAssetRelationship(Base):
    """EDP-009 Part 1, Section 15: a real, direct-or-derived relationship between
    two persisted CloudAsset rows. Every relationship this Part's four real
    adapters (Sections 8-11) currently produce is direct (`is_direct=True`,
    `derivation_rule=None`) - sourced straight from a real provider API response
    field, never inferred from shared tags or region alone (Section 15's own
    explicit rule). The derived-relationship path (`is_direct=False` plus a real
    `derivation_rule` string explaining it) is real schema support for a later
    sub-phase's own derived-relationship logic (e.g. the Cloud Asset Graph,
    Section 18), not exercised by any adapter yet."""

    __tablename__ = "cloud_asset_relationships"

    id: Mapped[uuid.UUID] = _uuid_pk()
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"))
    source_asset_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("cloud_assets.id"))
    target_asset_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("cloud_assets.id"))
    # CONTAINS|BELONGS_TO|LOCATED_IN|ATTACHED_TO|CONNECTED_TO|ROUTES_TO|EXPOSED_BY|
    # PROTECTED_BY|USES|ASSUMES|CAN_ACCESS|ENCRYPTED_BY|LOGS_TO|MONITORED_BY|
    # DEPLOYED_FROM|RUNS_ON|LOAD_BALANCES|RESOLVES_TO|MEMBER_OF|PEERS_WITH -
    # Section 15's own real vocabulary, matches gds_api.cloud.schemas.
    # NormalizedCloudRelationship.relationship_type exactly.
    relationship_type: Mapped[str] = mapped_column(String(30))
    provider_native_source: Mapped[str | None] = mapped_column(Text, default=None)
    discovery_job_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("cloud_discovery_jobs.id"), default=None
    )
    first_seen_at: Mapped[datetime] = mapped_column(server_default=func.now())
    last_seen_at: Mapped[datetime] = mapped_column(server_default=func.now())
    # direct|derived - matches NormalizedCloudRelationship.is_direct's own real
    # distinction, never presented identically once persisted (Section 15's rule).
    confidence_basis: Mapped[str] = mapped_column(String(20), default="direct")
    is_direct: Mapped[bool] = mapped_column(default=True)
    derivation_rule: Mapped[str | None] = mapped_column(Text, default=None)
    relationship_metadata: Mapped[dict[str, object]] = mapped_column(JSONB, default=dict)
    evidence_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("evidence.id"), default=None)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(server_default=func.now(), onupdate=func.now())

    __table_args__ = (
        Index("ix_cloud_asset_relationships_tenant_source", "tenant_id", "source_asset_id"),
        Index("ix_cloud_asset_relationships_tenant_target", "tenant_id", "target_asset_id"),
        Index(
            "ux_cloud_asset_relationships_unique",
            "source_asset_id",
            "target_asset_id",
            "relationship_type",
            unique=True,
        ),
    )


class CloudInventorySnapshot(Base):
    """EDP-009 Part 1, Section 16: a real, point-in-time summary record created
    once per completed/failed discovery job - a "versioned current-state record"
    strategy (the section's own third documented option), not a full
    materialized copy of every asset: `CloudAsset` itself is already the
    single, always-current source of truth (real upsert semantics, Section 12),
    so duplicating every asset's full data into a snapshot row on every
    discovery run would be real, unbounded storage growth for no real benefit
    this Part's own scope needs. What a snapshot adds is what `CloudAsset`
    alone cannot answer after the fact: what did coverage/counts/completeness
    look like for this specific historical run."""

    __tablename__ = "cloud_inventory_snapshots"

    id: Mapped[uuid.UUID] = _uuid_pk()
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"))
    environment_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("cloud_environments.id"))
    provider: Mapped[str] = mapped_column(String(30))
    discovery_job_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("cloud_discovery_jobs.id"))
    started_at: Mapped[datetime] = mapped_column()
    completed_at: Mapped[datetime | None] = mapped_column(default=None)
    # completed|partially_completed|failed - mirrors the real CloudDiscoveryJob.status
    # this snapshot summarizes, never a fabricated "completed" for a job that failed.
    status: Mapped[str] = mapped_column(String(30))
    # Real per-normalized_category counts computed from CloudAsset rows actually
    # touched by this discovery_job_id - e.g. {"virtual_machine": 12, "network": 3}.
    resource_counts_by_category: Mapped[dict[str, int]] = mapped_column(JSONB, default=dict)
    relationship_count: Mapped[int] = mapped_column(default=0)
    regions_covered: Mapped[list[str]] = mapped_column(JSONB, default=list)
    # Section 16's own required field - real category/region scopes this run's
    # own adapter-level warnings named, never fabricated ahead of what the
    # adapter actually logged.
    failed_scopes: Mapped[list[str]] = mapped_column(JSONB, default=list)
    warnings: Mapped[list[str]] = mapped_column(JSONB, default=list)
    # complete|partial|unknown - real, honest completeness signal, distinct from
    # `status` (a job can be `completed` in the workflow sense while its own
    # underlying coverage is only `partial` - Section 27's own future concern,
    # this field is the real data that later sub-phase reads, not fabricated
    # ahead of it).
    completeness_status: Mapped[str] = mapped_column(String(20), default="unknown")
    previous_snapshot_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("cloud_inventory_snapshots.id"), default=None
    )
    # Real counts of CloudAssetChangeEvent rows this same discovery_job_id
    # produced - {"added": 3, "updated": 1, "absent": 0, ...}.
    change_summary: Mapped[dict[str, int]] = mapped_column(JSONB, default=dict)
    evidence_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("evidence.id"), default=None)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())

    __table_args__ = (
        Index("ix_cloud_inventory_snapshots_tenant_environment", "tenant_id", "environment_id"),
        Index("ix_cloud_inventory_snapshots_discovery_job", "discovery_job_id"),
    )


class CloudAssetChangeEvent(Base):
    """EDP-009 Part 1, Section 17: a real, individual change event - one row per
    real, detected change, produced by gds_api.cloud.changes at the end of a
    successful discovery run. Never a derived/re-computed view - a durable,
    queryable record real enough to back a real Change Feed (Section 21's own
    later UI requirement)."""

    __tablename__ = "cloud_asset_change_events"

    id: Mapped[uuid.UUID] = _uuid_pk()
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"))
    environment_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("cloud_environments.id"))
    asset_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("cloud_assets.id"))
    discovery_job_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("cloud_discovery_jobs.id"), default=None
    )
    # asset_added|asset_updated|asset_absent_current_run|asset_confirmed_absent|
    # asset_reappeared|relationship_added|relationship_removed|tag_changed|
    # region_changed|exposure_changed|lifecycle_state_changed - Section 17's own
    # real vocabulary.
    change_type: Mapped[str] = mapped_column(String(40))
    # Real before/after values for the specific field this event is about (e.g.
    # {"lifecycle_state": "pending"} / {"lifecycle_state": "running"}) - empty
    # for change types that aren't a single-field transition (e.g. asset_added).
    previous_value: Mapped[dict[str, object]] = mapped_column(JSONB, default=dict)
    new_value: Mapped[dict[str, object]] = mapped_column(JSONB, default=dict)
    detected_at: Mapped[datetime] = mapped_column(server_default=func.now())

    __table_args__ = (
        Index("ix_cloud_asset_change_events_tenant_environment", "tenant_id", "environment_id"),
        Index("ix_cloud_asset_change_events_asset", "asset_id"),
        Index("ix_cloud_asset_change_events_discovery_job", "discovery_job_id"),
    )


class CloudPostureEvaluationRun(Base):
    """EDP-009 Part 2, Section 18: one governed cloud posture evaluation run -
    mirrors CloudDiscoveryJob's own synchronous-within-one-request execution model
    (ADR 0051 Decision D7) rather than a Temporal MissionWorkflow, since policy
    evaluation is deterministic rule-matching against already-persisted inventory,
    never an LLM reasoning loop. A partially completed run must never be described
    as completed (Section 18's own explicit rule) - see
    gds_api.cloud.posture.evaluation for the real execution logic that maintains
    this."""

    __tablename__ = "cloud_posture_evaluation_runs"

    id: Mapped[uuid.UUID] = _uuid_pk()
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"))
    environment_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("cloud_environments.id"))
    provider: Mapped[str] = mapped_column(String(30))
    inventory_snapshot_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("cloud_inventory_snapshots.id"), default=None
    )
    mission_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("missions.id"), default=None)
    workflow_run_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("workflow_runs.id"), default=None
    )
    # Empty list means "every enabled, applicable policy" - Section 18's own
    # "requested policy scope".
    requested_policy_ids: Mapped[list[str]] = mapped_column(JSONB, default=list)
    requested_benchmark_ids: Mapped[list[str]] = mapped_column(JSONB, default=list)
    initiated_by_user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    started_at: Mapped[datetime | None] = mapped_column(default=None)
    completed_at: Mapped[datetime | None] = mapped_column(default=None)
    # queued|starting|running|partially_completed|completed|failed|cancelled|
    # timed_out - Section 18's own real vocabulary.
    status: Mapped[str] = mapped_column(String(30), default="queued")
    assets_considered: Mapped[int] = mapped_column(default=0)
    policies_considered: Mapped[int] = mapped_column(default=0)
    evaluations_attempted: Mapped[int] = mapped_column(default=0)
    passed_count: Mapped[int] = mapped_column(default=0)
    failed_count: Mapped[int] = mapped_column(default=0)
    not_applicable_count: Mapped[int] = mapped_column(default=0)
    unsupported_count: Mapped[int] = mapped_column(default=0)
    skipped_count: Mapped[int] = mapped_column(default=0)
    error_count: Mapped[int] = mapped_column(default=0)
    indeterminate_count: Mapped[int] = mapped_column(default=0)
    findings_created: Mapped[int] = mapped_column(default=0)
    findings_updated: Mapped[int] = mapped_column(default=0)
    findings_resolved: Mapped[int] = mapped_column(default=0)
    findings_unchanged: Mapped[int] = mapped_column(default=0)
    warnings: Mapped[list[str]] = mapped_column(JSONB, default=list)
    errors: Mapped[list[str]] = mapped_column(JSONB, default=list)
    evidence_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("evidence.id"), default=None)
    correlation_id: Mapped[uuid.UUID] = mapped_column(default=uuid.uuid4)
    # A short, code-defined version string for the evaluator framework
    # (gds_api.cloud.posture.evaluator.EVALUATOR_VERSION) - bumped only on a real
    # behavioural change to the Applicability Engine or evaluator contract.
    evaluator_version: Mapped[str] = mapped_column(String(20))
    # A real sha256 fingerprint of every registered policy's (policy_id, version)
    # pair at the moment this run executed
    # (gds_api.cloud.posture.registry.policy_registry_fingerprint()) - Section 18's
    # own "policy-registry version", computed rather than hand-maintained since
    # POLICY_REGISTRY has no single version counter of its own.
    policy_registry_fingerprint: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(server_default=func.now(), onupdate=func.now())

    __table_args__ = (
        Index(
            "ix_cloud_posture_evaluation_runs_tenant_environment",
            "tenant_id",
            "environment_id",
        ),
        Index("ix_cloud_posture_evaluation_runs_tenant_status", "tenant_id", "status"),
    )


class CloudPolicyEvaluation(Base):
    """EDP-009 Part 2, Section 19: one persisted, immutable evaluation record - the
    full history of every real policy evaluation ever run, never overwritten.
    policy_id/policy_version soft-reference
    gds_api.cloud.posture.registry.POLICY_REGISTRY (never a foreign key - the
    registry is code-defined, per ADR 0051 Decision D2), the same pattern
    CloudAsset.provider soft-references CLOUD_PROVIDER_REGISTRY."""

    __tablename__ = "cloud_policy_evaluations"

    id: Mapped[uuid.UUID] = _uuid_pk()
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"))
    evaluation_run_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("cloud_posture_evaluation_runs.id")
    )
    environment_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("cloud_environments.id"))
    # Null for an ENVIRONMENT_LEVEL policy - there is no single target resource.
    asset_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("cloud_assets.id"), default=None
    )
    policy_id: Mapped[str] = mapped_column(String(200))
    policy_version: Mapped[int] = mapped_column()
    # pass|fail|not_applicable|unsupported|skipped|error|indeterminate - Section 9's
    # own strict 7-value taxonomy (gds_api.cloud.posture.taxonomy.EvaluationResult).
    result: Mapped[str] = mapped_column(String(20))
    # critical|high|medium|low|informational - denormalized from the policy
    # definition at evaluation time so historical severity survives a future policy
    # severity change (Section 3's own "preserve the policy version used for each
    # finding" rule extended to severity).
    severity: Mapped[str] = mapped_column(String(20))
    # applicable|not_applicable|unsupported|skipped|blocked_by_missing_data -
    # gds_api.cloud.posture.taxonomy.ApplicabilityState.
    applicability_state: Mapped[str] = mapped_column(String(30))
    applicability_reason: Mapped[str] = mapped_column(Text)
    # Bounded structured evidence facts (Section 19/25) - real size bound applied
    # by gds_api.cloud.posture.evaluation before persistence, mirroring
    # gds_api.cloud.assets._bounded_metadata's own approach for
    # CloudAsset.raw_metadata.
    facts: Mapped[dict[str, object]] = mapped_column(JSONB, default=dict)
    explanation: Mapped[str] = mapped_column(Text)
    evaluation_time: Mapped[datetime] = mapped_column(server_default=func.now())
    duration_ms: Mapped[float | None] = mapped_column(default=None)
    evaluator_version: Mapped[str] = mapped_column(String(20))
    # complete|partial|missing - Section 10's own "required-data state".
    data_state: Mapped[str] = mapped_column(String(20), default="complete")
    snapshot_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("cloud_inventory_snapshots.id"), default=None
    )
    error_category: Mapped[str | None] = mapped_column(String(100), default=None)
    # Populated once Finding correlation exists (a later sub-phase) - always null
    # until then, schema-ready rather than added as an afterthought migration.
    finding_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("findings.id"), default=None)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())

    __table_args__ = (
        Index(
            "ix_cloud_policy_evaluations_tenant_environment", "tenant_id", "environment_id"
        ),
        Index("ix_cloud_policy_evaluations_run", "evaluation_run_id"),
        Index("ix_cloud_policy_evaluations_asset", "asset_id"),
        Index("ix_cloud_policy_evaluations_policy", "policy_id"),
    )


class CloudFindingContext(Base):
    """EDP-009 Part 2, Section 21: cloud-specific linkage for a real platform
    Finding row - additive, 1:1 via finding_id, never a second finding type
    Executive/Purple Command can't understand (ADR 0051 Decision D6). Finding
    itself (source="cspm") carries title/description/severity/risk_class/status/
    recommended_remediation - this table only adds what a cloud finding needs that
    the generic Finding model doesn't have a place for.

    Deduplication (Section 22) is enforced by a real database unique index (see
    migration - a Postgres expression index on
    (tenant_id, environment_id, policy_id, COALESCE(cloud_asset_id, <nil-uuid>)),
    since cloud_asset_id is nullable for an environment-level policy and Postgres
    unique indexes treat every NULL as distinct) - never application logic alone."""

    __tablename__ = "cloud_finding_contexts"

    id: Mapped[uuid.UUID] = _uuid_pk()
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"))
    finding_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("findings.id"), unique=True)
    cloud_environment_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("cloud_environments.id"))
    # Null for an ENVIRONMENT_LEVEL policy - there is no single target resource.
    cloud_asset_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("cloud_assets.id"), default=None
    )
    provider: Mapped[str] = mapped_column(String(30))
    policy_id: Mapped[str] = mapped_column(String(200))
    policy_version: Mapped[int] = mapped_column()
    first_detected_at: Mapped[datetime] = mapped_column(server_default=func.now())
    last_detected_at: Mapped[datetime] = mapped_column(server_default=func.now())
    last_evaluated_at: Mapped[datetime] = mapped_column(server_default=func.now())
    last_evaluation_run_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("cloud_posture_evaluation_runs.id"), default=None
    )
    last_evaluation_record_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("cloud_policy_evaluations.id"), default=None
    )
    # When the Finding most recently reached remediated/closed - null while open,
    # re-set on every fresh resolution (Section 23's own "record the evaluation
    # that caused resolution", satisfied jointly with last_evaluation_record_id).
    resolution_time: Mapped[datetime | None] = mapped_column(default=None)
    # A real, sanitized Evidence row (Section 25 - never raw provider payloads,
    # never credentials/secrets) created once at first detection, mirroring the
    # Part 1 evidence_id nullable-FK-per-row pattern rather than the legacy
    # subject_type/subject_id tag.
    evidence_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("evidence.id"), default=None)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(server_default=func.now(), onupdate=func.now())

    __table_args__ = (
        Index(
            "ix_cloud_finding_contexts_tenant_environment", "tenant_id", "cloud_environment_id"
        ),
        Index("ix_cloud_finding_contexts_asset", "cloud_asset_id"),
        Index("ix_cloud_finding_contexts_policy", "policy_id"),
    )


class CloudFindingStatusHistory(Base):
    """EDP-009 Part 2, Section 24: an append-only record of every real Finding
    status transition a CSPM evaluation ever drove - one row per single-hop
    transition (matching gds_api.finding_lifecycle.validate_finding_transition's
    own single-hop contract), never a bare summary of start/end state. The
    current status field on Finding itself is never the only record of how it got
    there."""

    __tablename__ = "cloud_finding_status_history"

    id: Mapped[uuid.UUID] = _uuid_pk()
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"))
    finding_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("findings.id"))
    previous_status: Mapped[str] = mapped_column(String(30))
    new_status: Mapped[str] = mapped_column(String(30))
    reason: Mapped[str | None] = mapped_column(Text, default=None)
    evaluation_run_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("cloud_posture_evaluation_runs.id"), default=None
    )
    evaluation_record_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("cloud_policy_evaluations.id"), default=None
    )
    # Null for every transition this sub-phase's own automatic CSPM correlation
    # drives - there is no human actor yet (suppression/accepted-risk, a later
    # sub-phase, is the first real human-governed transition this table will
    # ever record a real actor for).
    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"), default=None)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())

    __table_args__ = (Index("ix_cloud_finding_status_history_finding", "finding_id"),)


class CloudFindingSuppression(Base):
    """EDP-009 Part 2, Section 28: governed cloud finding suppression - a genuinely
    new concept in this codebase (the pre-implementation audit found no prior
    suppression/waiver/accepted-risk model anywhere). Reuses the existing
    `Approval`/`Policy` (risk_class -> requires_approval) tables directly via
    `gds_api.policy.evaluate_policy` - the same governed mechanism `Finding.approval_id`
    already relies on - rather than inventing a second approval mechanism.

    Suppression never deletes the Finding and never alters `CloudPolicyEvaluation`
    history (Section 28's own explicit rule) - it is a real, separate, auditable
    row that operational views check for, not a mutation of the finding itself.
    The one exception: `suppression_type == "accepted_risk"` also drives
    `Finding.status` to `accepted_risk` (gds_api.cloud.posture.suppression's own
    real, additional transition), since that specific status already exists in
    the platform's real 15-state lifecycle and is the correct place to record it."""

    __tablename__ = "cloud_finding_suppressions"

    id: Mapped[uuid.UUID] = _uuid_pk()
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"))
    finding_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("findings.id"))
    # false_positive|compensating_control|temporary_exception|accepted_risk|
    # test_environment|not_applicable_override - Section 28's own real vocabulary.
    suppression_type: Mapped[str] = mapped_column(String(40))
    reason: Mapped[str] = mapped_column(Text)
    requested_by_user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    # Populated only when the finding's own risk_class/severity requires approval
    # per the existing Policy rules (gds_api.policy.evaluate_policy) - null means
    # this suppression never needed one (a real, low/medium-risk finding).
    approval_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("approvals.id"), default=None)
    start_time: Mapped[datetime] = mapped_column(server_default=func.now())
    expiry_time: Mapped[datetime | None] = mapped_column(default=None)
    # pending_approval|active|rejected|expired - recomputed at read time from the
    # linked Approval's real current status and expiry_time
    # (gds_api.cloud.posture.suppression._refresh_suppression_status) rather than
    # trusted as a value that could silently drift from the truth.
    status: Mapped[str] = mapped_column(String(20), default="pending_approval")
    review_date: Mapped[datetime | None] = mapped_column(default=None)
    evidence_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("evidence.id"), default=None)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(server_default=func.now(), onupdate=func.now())

    __table_args__ = (
        Index("ix_cloud_finding_suppressions_finding", "finding_id"),
        Index("ix_cloud_finding_suppressions_tenant_status", "tenant_id", "status"),
    )
