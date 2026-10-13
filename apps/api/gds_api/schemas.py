"""Pydantic request/response schemas for the Phase 2 Core Platform API."""

import uuid
from datetime import datetime
from decimal import Decimal

from pydantic import BaseModel, EmailStr


class RegisterRequest(BaseModel):
    email: str
    password: str
    full_name: str | None = None


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class TenantOut(BaseModel):
    id: uuid.UUID
    name: str
    slug: str


class RoleOut(BaseModel):
    id: uuid.UUID
    name: str
    permissions: list[str]


class MeResponse(BaseModel):
    user_id: uuid.UUID
    email: str
    tenant: TenantOut
    role: RoleOut


class AuditEventOut(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID | None
    user_id: uuid.UUID | None
    action: str
    detail: dict[str, object]
    created_at: datetime


class PolicyEvaluateRequest(BaseModel):
    risk_class: str
    action_description: str


class PolicyEvaluateResponse(BaseModel):
    decision: str  # "allow" | "require_approval" | "deny"
    approval_id: uuid.UUID | None = None


class ApprovalOut(BaseModel):
    id: uuid.UUID
    risk_class: str
    action_description: str
    status: str
    requested_by_user_id: uuid.UUID
    decided_by_user_id: uuid.UUID | None
    created_at: datetime
    decided_at: datetime | None


class ApprovalDecisionRequest(BaseModel):
    decision: str  # "approved" | "rejected"


class EvidenceOut(BaseModel):
    id: uuid.UUID
    subject_type: str
    subject_id: str | None
    sha256: str
    content_type: str
    size_bytes: int
    created_at: datetime
    download_url: str | None = None


class NotificationOut(BaseModel):
    id: uuid.UUID
    type: str
    message: str
    read_at: datetime | None
    created_at: datetime


class MissionCreateRequest(BaseModel):
    objective: str
    # Phase 20 (Continuation Prompt 7), Part 7: one of gds_api.mission_taxonomy's 23
    # Purple mission types, or None for an unclassified/legacy-style mission.
    mission_type: str | None = None


class MissionTaskOut(BaseModel):
    id: uuid.UUID
    sequence: int
    description: str
    tool_name: str | None
    agent_name: str | None
    risk_class: str | None
    status: str
    approval_id: uuid.UUID | None
    result: dict[str, object]


class AgentOut(BaseModel):
    id: uuid.UUID
    name: str
    stable_key: str
    display_name: str
    description: str
    tool_names: list[str]
    team: str
    department: str
    status: str
    version: str
    implementation_class: str
    supervisor_agent_id: str | None
    risk_ceiling: str
    supported_mission_types: list[str]
    allowed_capability_ids: list[str]
    required_connector_ids: list[str]
    required_credentials: list[str]
    memory_scopes: list[str]
    approval_policy: str
    target_authorisation_required: bool
    supports_streaming: bool
    supports_iterative_reasoning: bool
    supports_parallel_execution: bool
    created_at: str
    updated_at: str
    # Phase 20 (Continuation Prompt 7): Unified Purple Cybersecurity Workforce
    # taxonomy fields - see docs/architecture/unified-purple-workforce.md.
    # workforce/purple_role_id are None for the 5 Foundation agents (out of
    # taxonomy scope) and for any agent not yet mapped.
    workforce: str | None
    purple_role_id: str | None
    purple_role_name: str | None
    operational_domain: str
    mission_role: str
    objectives: list[str]
    five_verb_contract: list[str]
    knowledge_domains: list[str]
    skills: list[str]
    approval_requirements: list[str]
    evidence_requirements: list[str]
    input_contracts: list[str]
    output_contracts: list[str]
    collaboration_contracts: list[str]
    repository_permissions: list[str]
    workspace_permissions: list[str]
    health_checks: list[str]
    degraded_reason: str
    planned_reason: str
    owner: str
    documentation_reference: str


class PlannedAgentOut(BaseModel):
    id: uuid.UUID
    name: str
    stable_key: str
    display_name: str
    description: str
    team: str
    department: str
    status: str
    reason: str
    required_connector_ids: list[str]
    created_at: str
    updated_at: str
    # Phase 20 (Continuation Prompt 7): same taxonomy fields as AgentOut, minus the
    # ones that only make sense for an agent with real tools/capabilities.
    workforce: str | None
    purple_role_id: str | None
    purple_role_name: str | None
    operational_domain: str
    mission_role: str
    objectives: list[str]
    knowledge_domains: list[str]
    skills: list[str]
    collaboration_contracts: list[str]
    owner: str
    documentation_reference: str


class AgentActivityOut(BaseModel):
    """Phase 12.2: one real currently-running MissionTask assigned to an agent - not a
    synthetic "busy" flag. An agent can appear more than once if it's genuinely running a
    task in more than one concurrent mission at once."""

    agent_name: str
    mission_id: uuid.UUID
    task_id: uuid.UUID
    description: str


class MissionOut(BaseModel):
    id: uuid.UUID
    objective: str
    status: str
    risk_class: str | None
    report: str | None
    mission_type: str | None = None
    created_at: datetime
    completed_at: datetime | None
    # Phase 21 (Continuation Prompt 8 / EDP-008), Part 2: real since Mission gained
    # this column (chat-turn missions only) - null for a mission created directly
    # (e.g. POST /missions with just an objective), never fabricated. Lets the Mission
    # Workspace's Chat panel know whether a real conversation thread exists to embed.
    conversation_thread_id: uuid.UUID | None = None
    tasks: list[MissionTaskOut] = []


class PurpleMissionMessageOut(BaseModel):
    """Phase 20 (Continuation Prompt 7 / EDP-007), Part 14: the real read-side
    contract for Part 8's write-only PurpleMissionMessage table - the timeline a
    future Co-Pilot surface (Part 15) renders."""

    id: uuid.UUID
    mission_id: uuid.UUID
    task_id: uuid.UUID | None
    related_task_id: uuid.UUID | None
    message_type: str
    sender_agent: str | None
    recipient_agent: str | None
    classification: str
    content: str
    payload: dict[str, object]
    evidence_references: list[str]
    correlation_id: uuid.UUID | None
    created_at: datetime


class ConversationCreateRequest(BaseModel):
    title: str
    agent_name: str | None = None


class ConversationMessageRequest(BaseModel):
    message: str


class ConversationThreadOut(BaseModel):
    id: uuid.UUID
    title: str
    agent_name: str | None
    created_at: datetime
    last_message_at: datetime


class ConversationDetailOut(BaseModel):
    thread: ConversationThreadOut
    turns: list[MissionOut] = []


class FindingOut(BaseModel):
    id: uuid.UUID
    source: str
    external_id: str | None
    title: str
    description: str
    severity: str
    risk_class: str | None
    status: str
    created_at: datetime
    # Phase 20 (Continuation Prompt 7), Part 9: real lifecycle enrichment/closure
    # fields - see gds_api.finding_lifecycle. Read-only here; state changes are
    # tool/capability-broker-gated (triage_finding/enrich_finding/
    # prioritise_finding/validate_finding), never a raw REST write.
    confidence: str | None = None
    business_impact: str | None = None
    cve: str | None = None
    cvss: float | None = None
    epss: float | None = None
    kev_listed: bool = False
    reachability: str | None = None
    exploitability: str | None = None
    exposure: str | None = None
    owner: str | None = None
    updated_at: datetime


class IncidentOut(BaseModel):
    id: uuid.UUID
    title: str
    summary: str
    severity: str
    status: str
    report: str | None
    created_at: datetime
    resolved_at: datetime | None
    finding_count: int


class KnowledgeDocumentOut(BaseModel):
    id: uuid.UUID
    title: str
    content: str
    created_at: datetime
    # Phase 20 (Continuation Prompt 7 / EDP-007), Part 13: "manual" for every
    # pre-existing document; one of gds_api.mission_memory.LessonType for a real
    # per-mission lesson.
    document_type: str
    source_mission_id: uuid.UUID | None


class KnowledgeCreateRequest(BaseModel):
    title: str
    content: str


class KnowledgeSearchResultOut(BaseModel):
    id: uuid.UUID
    title: str
    content: str
    score: float | None


class WorkflowRunOut(BaseModel):
    id: uuid.UUID
    mission_id: uuid.UUID
    mission_objective: str
    # Phase 15: the real Mission.status alongside WorkflowRun's own - lets a client
    # cross-check the two without a second request; see
    # docs/architecture/mission-workflow-lifecycle.md for how they relate.
    mission_status: str
    conversation_thread_id: uuid.UUID | None
    temporal_workflow_id: str
    temporal_run_id: str
    status: str
    current_stage: str | None
    retry_count: int
    started_at: datetime
    last_progress_at: datetime | None
    completed_at: datetime | None
    failed_at: datetime | None
    cancelled_at: datetime | None
    failure_message_safe: str | None
    reconciliation_state: str | None
    can_cancel: bool
    is_live: bool
    # Live Temporal-side status, fetched on demand (GET /workflows/{id} only) - None on
    # the list endpoint, which deliberately avoids one Temporal round-trip per row.
    temporal_status: str | None = None


class WorkflowReconciliationFindingOut(BaseModel):
    workflow_run_id: uuid.UUID
    mission_id: uuid.UUID
    issue: str
    detail: str
    repaired: bool


class WorkflowReconciliationReportOut(BaseModel):
    dry_run: bool
    checked_count: int
    findings: list[WorkflowReconciliationFindingOut]


class BuildGuideSectionOut(BaseModel):
    id: str
    label: str
    status: str  # complete|incomplete|warning|failed|optional
    detail: str


class BuildGuideStatusOut(BaseModel):
    sections: list[BuildGuideSectionOut]


class WorkingMemoryEntryOut(BaseModel):
    mission_id: uuid.UUID
    ttl_seconds: int


class AgentToolEdgeOut(BaseModel):
    """Phase 12.3: a real, honest co-occurrence count - agent_name and tool_name have
    both really appeared on the same real mission(s) mission_count times. Neo4j has no
    direct Agent-[:USED]->Tool edge (they only connect via a shared Mission), so this is
    a real Cypher aggregation over that shared structure, not a fabricated direct edge."""

    agent_name: str
    tool_name: str
    mission_count: int


class RelationshipGraphOut(BaseModel):
    edges: list[AgentToolEdgeOut]


class RelationshipMemoryOut(BaseModel):
    mission_nodes: int
    tool_nodes: int
    agent_nodes: int
    executed_edges: int
    handled_by_edges: int


class FindingCorrelationOut(BaseModel):
    """Phase 20 (Continuation Prompt 7 / EDP-007), Part 12: the real, honest
    correlation chain for one Finding - attack path/detection are real text
    properties already on the Finding itself (Part 9), never fabricated
    separate entities; remediation/commit/retest are real Neo4j nodes/edges
    written at the exact real state-transition points
    (tool_gateway._auto_fix_finding, merge_coordinator.commit_mission) that
    already produce them. Every field is None/False until the real event it
    represents has actually happened - never backfilled or guessed."""

    finding_id: uuid.UUID
    finding_title: str
    finding_status: str
    attack_path: str | None
    detection_coverage: str | None
    mission_plan_id: uuid.UUID | None
    remediation_objective: str | None
    commit_hash: str | None
    retest_requested: bool


class MemoryOverviewOut(BaseModel):
    working_memory: list[WorkingMemoryEntryOut]
    relationship_memory: RelationshipMemoryOut
    knowledge_document_count: int


class MissionMemoryOut(BaseModel):
    """Phase 21 (Continuation Prompt 8 / EDP-008), Part 2: the Mission Memory panel's
    real data - working_memory is this mission's own real Redis-backed scratch state
    (None once it has expired/was never set), lessons_created is every real
    KnowledgeDocument this mission itself produced via record_mission_lesson (Part 13).
    Deliberately does NOT claim to show "lessons used"/semantic-match confidence during
    this mission's own planning - search_knowledge() results are consumed live inside
    the reasoning loop's prompt and never persisted anywhere queryable after the fact,
    so there is no real data source for that - see docs/adr/0044."""

    working_memory: WorkingMemoryEntryOut | None
    lessons_created: list[KnowledgeDocumentOut]


class AuthorizedTargetCreateRequest(BaseModel):
    target: str
    target_type: str  # domain|url|ip
    scope_description: str
    valid_until: datetime
    max_actions_per_hour: int = 10


class AuthorizedTargetOut(BaseModel):
    id: uuid.UUID
    target: str
    target_type: str
    scope_description: str
    authorized_by_user_id: uuid.UUID
    valid_from: datetime
    valid_until: datetime
    max_actions_per_hour: int
    status: str
    created_at: datetime
    revoked_at: datetime | None


class RedTeamStatusOut(BaseModel):
    emergency_stop_engaged: bool
    engaged_by_user_id: uuid.UUID | None
    engaged_at: datetime | None
    active_target_count: int


# ---- Phase 20 (Continuation Prompt 7 / EDP-007), Part 11: Pentest Engagements -----


class EngagementCreateRequest(BaseModel):
    mission_id: uuid.UUID
    name: str
    rules_of_engagement: str
    target_ids: list[uuid.UUID]
    allowed_techniques: list[str] = []
    prohibited_techniques: list[str] = []
    exclusion_list: list[str] = []


class EngagementOut(BaseModel):
    id: uuid.UUID
    mission_id: uuid.UUID
    name: str
    rules_of_engagement: str
    allowed_techniques: list[str]
    prohibited_techniques: list[str]
    exclusion_list: list[str]
    status: str
    authorized_by_user_id: uuid.UUID
    report_summary: str | None
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None
    target_ids: list[uuid.UUID]


# ---- Phase 16 (Continuation Prompt 3): Secure Capability Broker -------------------


class CapabilityOut(BaseModel):
    id: uuid.UUID
    stable_key: str
    display_name: str
    description: str
    category: str
    risk_class: str
    side_effect_type: str
    status: str
    version: str
    target_types: list[str]
    allowed_team_types: list[str]
    allowed_agent_ids: list[str]
    required_connector_ids: list[str]
    requires_mission: bool
    requires_workflow_run: bool
    requires_human_approval: bool
    requires_target_authorisation: bool
    requires_emergency_stop_clear: bool
    evidence_required: bool
    audit_level: str
    # The code-defined default, and the real, tenant-scoped result after applying any
    # CapabilityState row (which can only narrow this, never widen it - ADR 0015).
    enabled: bool
    effective_enabled: bool


class CapabilityCategoryOut(BaseModel):
    category: str
    count: int


class AgentCapabilityDenialOut(BaseModel):
    capability_key: str
    reason: str


class AgentCapabilitiesOut(BaseModel):
    agent_id: str
    risk_ceiling: str
    allowed_capabilities: list[CapabilityOut]
    denied_capabilities: list[AgentCapabilityDenialOut]


class CapabilityRequestCreateRequest(BaseModel):
    mission_id: uuid.UUID
    capability_key: str
    requested_tool_id: str | None = None
    requesting_agent_id: str | None = None
    target_type: str | None = None
    target_reference: str | None = None
    target_scope: str | None = None
    purpose: str
    requested_parameters: dict[str, object] = {}
    idempotency_key: str | None = None


class CapabilityRequestOut(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    mission_id: uuid.UUID
    workflow_run_id: uuid.UUID | None
    requesting_agent_id: str | None
    capability_key: str
    requested_tool_id: str | None
    target_type: str | None
    target_reference: str | None
    purpose: str
    requested_parameters_safe: dict[str, object]
    idempotency_key: str | None
    requested_at: datetime


class CapabilityDecisionOut(BaseModel):
    id: uuid.UUID
    request_id: uuid.UUID
    decision: str
    capability_key: str
    capability_version: str
    authoritative_risk_class: str
    approval_required: bool
    approval_id: uuid.UUID | None
    target_authorisation_required: bool
    target_authorisation_id: uuid.UUID | None
    denial_code: str | None
    safe_denial_message: str | None
    policy_version: str
    decided_at: datetime
    expires_at: datetime | None
    executed_at: datetime | None
    execution_status: str | None


class CapabilityDecisionAdminOut(CapabilityDecisionOut):
    # Internal-only: full check-by-check evaluation trace. Never returned by any
    # non-admin endpoint - see gds_api.capabilities_api.
    decision_trace: dict[str, object]
    tenant_id: uuid.UUID


class CapabilityRequestWithDecisionOut(BaseModel):
    request: CapabilityRequestOut
    decision: CapabilityDecisionOut | None


class CapabilityStateOut(BaseModel):
    capability_key: str
    tenant_id: uuid.UUID
    disabled: bool
    disabled_reason: str | None
    updated_at: datetime


class CapabilityStatePatchRequest(BaseModel):
    disabled: bool
    reason: str | None = None


class CapabilityPolicyVersionOut(BaseModel):
    policy_version: str


# ---- Phase 17 (Continuation Prompt 4): Repository / Workspace ---------------------


class RepositoryCreateRequest(BaseModel):
    display_name: str
    provider: str = "local"
    working_directory: str
    visibility: str = "private"
    remote_url: str | None = None
    credential_reference: str | None = None


class RepositoryOut(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    display_name: str
    owner_user_id: uuid.UUID
    provider: str
    visibility: str
    default_branch: str
    current_branch: str | None
    remote_url: str | None
    credential_reference: str | None
    working_directory: str
    status: str
    status_detail: str | None
    created_at: datetime
    updated_at: datetime


class RepositoryPolicyOut(BaseModel):
    repository_id: uuid.UUID
    readable: bool
    searchable: bool
    branch_creation: bool
    worktree_creation: bool
    patch_creation: bool
    commit_allowed: bool
    push_allowed: bool
    pull_request_allowed: bool
    delete_worktree_allowed: bool
    allowed_agents: list[str]
    allowed_capabilities: list[str]
    allowed_branches: list[str]
    protected_branches: list[str]
    forbidden_paths: list[str]
    allowed_paths: list[str]
    maximum_changed_files: int
    maximum_changed_lines: int
    required_tests: bool
    review_requirement: bool
    approval_requirement: bool
    rollback_requirement: bool
    updated_at: datetime


class RepositoryPolicyPatchRequest(BaseModel):
    readable: bool | None = None
    searchable: bool | None = None
    branch_creation: bool | None = None
    worktree_creation: bool | None = None
    patch_creation: bool | None = None
    commit_allowed: bool | None = None
    push_allowed: bool | None = None
    pull_request_allowed: bool | None = None
    delete_worktree_allowed: bool | None = None
    allowed_agents: list[str] | None = None
    allowed_capabilities: list[str] | None = None
    allowed_branches: list[str] | None = None
    protected_branches: list[str] | None = None
    forbidden_paths: list[str] | None = None
    allowed_paths: list[str] | None = None
    maximum_changed_files: int | None = None
    maximum_changed_lines: int | None = None
    required_tests: bool | None = None
    review_requirement: bool | None = None
    approval_requirement: bool | None = None
    rollback_requirement: bool | None = None


class WorkspacePolicyOut(BaseModel):
    repository_id: uuid.UUID
    default_ttl_seconds: int
    maximum_ttl_seconds: int
    maximum_concurrent_workspaces: int
    allow_heartbeat_extension: bool
    auto_cleanup_on_expire: bool
    updated_at: datetime


class WorkspacePolicyPatchRequest(BaseModel):
    default_ttl_seconds: int | None = None
    maximum_ttl_seconds: int | None = None
    maximum_concurrent_workspaces: int | None = None
    allow_heartbeat_extension: bool | None = None
    auto_cleanup_on_expire: bool | None = None


class WorkspaceOut(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    mission_id: uuid.UUID
    workflow_run_id: uuid.UUID | None
    capability_decision_id: uuid.UUID | None
    repository_id: uuid.UUID
    agent_id: str | None
    provider: str
    workspace_path: str
    temporary_directory: str
    state: str
    failure_reason: str | None
    created_at: datetime
    last_heartbeat_at: datetime
    expires_at: datetime
    destroyed_at: datetime | None


class WorkspaceCleanupReportOut(BaseModel):
    """EDP-008 Part 8 API hardening audit finding: POST /workspaces/cleanup had no
    response_model, so OpenAPI showed a bare untyped object. Mirrors
    gds_api.repository.workspace_manager.CleanupReport's real fields exactly."""

    expired_destroyed: list[str]
    orphans_removed: list[str]
    marked_failed: list[str]


class RepositoryExecuteCapabilityRequest(BaseModel):
    parameters: dict[str, object] = {}
    purpose: str = "Repository browsing via API"


class RepositoryExecuteCapabilityResponse(BaseModel):
    decision: str
    capability_key: str
    request_id: uuid.UUID
    output: dict[str, object] | None
    safe_message: str | None


class EngineeringSessionCreateRequest(BaseModel):
    repository_id: uuid.UUID
    provider: str
    objective: str
    developer_instructions: str | None = None


class EngineeringSessionOut(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    mission_id: uuid.UUID
    workflow_run_id: uuid.UUID | None
    repository_id: uuid.UUID
    workspace_id: uuid.UUID
    capability_decision_id: uuid.UUID | None
    provider: str
    requested_by_user_id: uuid.UUID
    agent_id: str | None
    objective: str
    prompt_version: str
    status: str
    provider_session_id: str | None
    exit_code: int | None
    reasoning_summary: str | None
    patch_summary: dict[str, object]
    review_result: str | None
    review_findings: list[dict[str, object]]
    sensitive_area_hit: bool
    approval_id: uuid.UUID | None
    commit_hash: str | None
    input_tokens: int
    output_tokens: int
    cost_usd: Decimal
    failure_reason: str | None
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None


class EngineeringSessionExecuteResponse(BaseModel):
    decision: str
    capability_key: str
    request_id: uuid.UUID
    output: dict[str, object] | None
    safe_message: str | None


class EngineeringRecoveryReportOut(BaseModel):
    stale_running_failed: list[str]
    rejected_approvals_marked: list[str]


class MissionPlanCreateRequest(BaseModel):
    repository_id: uuid.UUID
    objective: str
    max_concurrency: int = 3


class MissionPlanOut(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    mission_id: uuid.UUID
    repository_id: uuid.UUID
    requested_by_user_id: uuid.UUID
    objective: str
    complexity: str | None
    affected_systems: list[str]
    execution_strategy: str | None
    status: str
    max_concurrency: int
    mission_memory: dict[str, object]
    integration_workspace_id: uuid.UUID | None
    integration_branch: str | None
    conflict_report: dict[str, object]
    merged_review_result: str | None
    merged_review_findings: list[dict[str, object]]
    approval_id: uuid.UUID | None
    commit_request_id: uuid.UUID | None
    commit_hash: str | None
    failure_reason: str | None
    created_at: datetime
    planned_at: datetime | None
    completed_at: datetime | None


class EngineeringTaskOut(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    mission_plan_id: uuid.UUID
    repository_id: uuid.UUID
    task_key: str
    title: str
    description: str
    specialist_role: str
    provider: str
    depends_on: list[str]
    required_capabilities: list[str]
    output_contract: str | None
    status: str
    risk_estimate: str
    duration_estimate_seconds: int | None
    workspace_id: uuid.UUID | None
    branch_name: str | None
    engineering_session_id: uuid.UUID | None
    patch_summary: dict[str, object]
    review_result: str | None
    review_findings: list[dict[str, object]]
    input_tokens: int
    output_tokens: int
    cost_usd: Decimal
    failure_reason: str | None
    retry_count: int
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None


class MissionPlanExecuteResponse(BaseModel):
    decision: str
    capability_key: str
    request_id: uuid.UUID
    output: dict[str, object] | None
    safe_message: str | None


class MissionMessageOut(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    mission_plan_id: uuid.UUID
    task_id: uuid.UUID | None
    related_task_id: uuid.UUID | None
    message_type: str
    content: str
    created_at: datetime


# ---- EDP-009 Part 1: Multi-Cloud Foundation -----------------------------------


class CloudProviderOut(BaseModel):
    provider_id: str
    display_name: str
    status: str
    supported_authentication_mechanisms: tuple[str, ...]
    supported_discovery_scopes: tuple[str, ...]
    supported_resource_categories: tuple[str, ...]
    regional: bool
    adapter_available: bool
    connection_test_capability: bool
    inventory_capability: bool
    known_limitations: tuple[str, ...]


class CloudEnvironmentCreateRequest(BaseModel):
    provider: str
    name: str
    native_id: str
    environment_type: str
    parent_environment_id: uuid.UUID | None = None
    classification: str | None = None
    description: str | None = None
    tags: dict[str, object] = {}


class CloudEnvironmentOut(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    provider: str
    name: str
    native_id: str
    environment_type: str
    parent_environment_id: uuid.UUID | None
    organisational_path: str | None
    status: str
    connection_profile_id: uuid.UUID | None
    discovery_status: str
    last_successful_discovery_at: datetime | None
    last_attempted_discovery_at: datetime | None
    last_failure_detail: str | None
    asset_count: int
    region_count: int
    graph_sync_status: str
    graph_last_synced_at: datetime | None
    created_by_user_id: uuid.UUID
    tags: dict[str, object]
    classification: str | None
    description: str | None
    enabled: bool
    created_at: datetime
    updated_at: datetime


class CloudConnectionProfileCreateRequest(BaseModel):
    environment_id: uuid.UUID
    provider: str
    authentication_type: str
    credential_reference: str | None = None
    role_or_principal_reference: str | None = None
    external_id: str | None = None
    permission_scope: str | None = None
    read_only: bool = True


class CloudConnectionProfileOut(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    environment_id: uuid.UUID
    provider: str
    authentication_type: str
    # Deliberately included - this is always an opaque reference, never a secret
    # value (see CloudConnectionProfile's own docstring). Never add a raw-secret
    # field to this schema.
    credential_reference: str | None
    role_or_principal_reference: str | None
    external_id: str | None
    permission_scope: str | None
    read_only: bool
    validation_status: str
    last_validated_at: datetime | None
    expiry_at: datetime | None
    rotation_state: str
    created_by_user_id: uuid.UUID
    enabled: bool
    created_at: datetime
    updated_at: datetime


class CloudConnectionValidationOut(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    connection_profile_id: uuid.UUID
    provider_identity: str | None
    scope_identity: str | None
    status: str
    attempted_at: datetime
    completed_at: datetime | None
    sanitized_error: str | None
    capability_availability: dict[str, object]
    latency_ms: float | None
    actor_user_id: uuid.UUID
    correlation_id: uuid.UUID
    evidence_id: uuid.UUID | None


class CloudDiscoveryJobStartRequest(BaseModel):
    environment_id: uuid.UUID
    discovery_categories: list[str] = []


class CloudDiscoveryJobOut(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    environment_id: uuid.UUID
    provider: str
    connection_profile_id: uuid.UUID | None
    requested_scope: dict[str, object]
    discovery_categories: list[str]
    regions: list[str]
    initiated_by_user_id: uuid.UUID
    mission_id: uuid.UUID | None
    workflow_run_id: uuid.UUID | None
    status: str
    started_at: datetime | None
    completed_at: datetime | None
    assets_discovered: int
    assets_updated: int
    assets_unchanged: int
    assets_marked_absent: int
    relationships_discovered: int
    errors: list[str]
    warnings: list[str]
    rate_limit_state: dict[str, object]
    evidence_id: uuid.UUID | None
    correlation_id: uuid.UUID
    created_at: datetime
    updated_at: datetime


class CloudAssetOut(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    environment_id: uuid.UUID
    provider: str
    native_id: str
    native_resource_type: str
    provider_category: str
    normalized_category: str
    name: str
    display_name: str | None
    region_or_location: str | None
    availability_zone: str | None
    parent_asset_id: uuid.UUID | None
    account_or_subscription_or_project: str | None
    resource_group_or_org_path: str | None
    lifecycle_state: str | None
    created_at_provider: datetime | None
    first_seen_at: datetime
    last_seen_at: datetime
    last_changed_at: datetime
    discovery_job_id: uuid.UUID | None
    tags: dict[str, str]
    internet_exposure_known: bool | None
    managed_service: bool | None
    raw_metadata: dict[str, object]
    schema_version: int
    freshness_state: str
    absence_state: str
    evidence_id: uuid.UUID | None
    created_at: datetime
    updated_at: datetime


class CloudAssetRelationshipOut(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    source_asset_id: uuid.UUID
    target_asset_id: uuid.UUID
    relationship_type: str
    discovery_job_id: uuid.UUID | None
    first_seen_at: datetime
    last_seen_at: datetime
    confidence_basis: str
    is_direct: bool
    derivation_rule: str | None
    relationship_metadata: dict[str, object]
    evidence_id: uuid.UUID | None
    created_at: datetime
    updated_at: datetime


class CloudInventorySnapshotOut(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    environment_id: uuid.UUID
    provider: str
    discovery_job_id: uuid.UUID
    started_at: datetime
    completed_at: datetime | None
    status: str
    resource_counts_by_category: dict[str, int]
    relationship_count: int
    regions_covered: list[str]
    failed_scopes: list[str]
    warnings: list[str]
    completeness_status: str
    previous_snapshot_id: uuid.UUID | None
    change_summary: dict[str, int]
    evidence_id: uuid.UUID | None
    created_at: datetime


class CloudAssetChangeEventOut(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    environment_id: uuid.UUID
    asset_id: uuid.UUID
    discovery_job_id: uuid.UUID | None
    change_type: str
    previous_value: dict[str, object]
    new_value: dict[str, object]
    detected_at: datetime


class CloudGraphSubgraphOut(BaseModel):
    nodes: list[dict[str, object]]
    edges: list[dict[str, object]]
    truncated: bool


# ---- EDP-009 Part 2: CSPM (Sections 1-31, 54) -----------------------------------


class CloudRemediationGuidanceOut(BaseModel):
    objective: str
    provider_specific_guidance: str
    validation_guidance: str
    rollback_considerations: str
    required_approval_class: str
    documentation_references: tuple[str, ...]


class CloudPolicyOut(BaseModel):
    policy_id: str
    version: int
    name: str
    description: str
    provider: str
    severity: str
    security_domain: str
    policy_family: str
    evaluation_type: str
    environment_types: tuple[str, ...]
    asset_categories: tuple[str, ...]
    native_resource_types: tuple[str, ...]
    required_fields: tuple[str, ...]
    required_relationships: tuple[str, ...]
    evidence_fields: tuple[str, ...]
    remediation_guidance: CloudRemediationGuidanceOut | None
    tags: tuple[str, ...]
    enabled: bool
    experimental: bool
    deprecated: bool
    replacement_policy_id: str | None
    documentation_reference: str | None
    authoritative_source_reference: str | None
    data_quality_requirements: tuple[str, ...]
    unsupported_conditions: tuple[str, ...]
    skip_conditions: tuple[str, ...]


class CloudBenchmarkCoverageOut(BaseModel):
    benchmark_id: str
    coverage_state: str
    mapped_control_count: int
    directly_covered_control_count: int
    partially_covered_control_count: int
    supporting_covered_control_count: int
    related_covered_control_count: int
    mapped_policy_count: int
    enabled_mapped_policy_count: int


class CloudBenchmarkOut(BaseModel):
    benchmark_id: str
    name: str
    version: str
    provider: str
    publisher: str
    description: str
    documentation_reference: str | None
    licensing_note: str | None
    coverage: CloudBenchmarkCoverageOut


class CloudPostureEvaluationRunOut(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    environment_id: uuid.UUID
    provider: str
    inventory_snapshot_id: uuid.UUID | None
    mission_id: uuid.UUID | None
    workflow_run_id: uuid.UUID | None
    requested_policy_ids: list[str]
    requested_benchmark_ids: list[str]
    initiated_by_user_id: uuid.UUID
    started_at: datetime | None
    completed_at: datetime | None
    status: str
    assets_considered: int
    policies_considered: int
    evaluations_attempted: int
    passed_count: int
    failed_count: int
    not_applicable_count: int
    unsupported_count: int
    skipped_count: int
    error_count: int
    indeterminate_count: int
    findings_created: int
    findings_updated: int
    findings_resolved: int
    findings_unchanged: int
    warnings: list[str]
    errors: list[str]
    evidence_id: uuid.UUID | None
    correlation_id: uuid.UUID
    evaluator_version: str
    policy_registry_fingerprint: str
    created_at: datetime
    updated_at: datetime


class CloudPostureEvaluationStartRequest(BaseModel):
    environment_id: uuid.UUID
    policy_ids: list[str] = []


class CloudPolicyEvaluationOut(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    evaluation_run_id: uuid.UUID
    environment_id: uuid.UUID
    asset_id: uuid.UUID | None
    policy_id: str
    policy_version: int
    result: str
    severity: str
    applicability_state: str
    applicability_reason: str
    facts: dict[str, object]
    explanation: str
    evaluation_time: datetime
    duration_ms: float | None
    evaluator_version: str
    data_state: str
    snapshot_id: uuid.UUID | None
    error_category: str | None
    finding_id: uuid.UUID | None
    created_at: datetime


class CloudFindingOut(BaseModel):
    """The real join of platform `Finding` + cloud-specific `CloudFindingContext`
    (Section 21) - never a second, disconnected finding shape."""

    id: uuid.UUID
    tenant_id: uuid.UUID
    title: str
    description: str
    severity: str
    risk_class: str | None
    status: str
    recommended_remediation: str | None
    created_at: datetime
    updated_at: datetime
    cloud_environment_id: uuid.UUID
    cloud_asset_id: uuid.UUID | None
    provider: str
    policy_id: str
    policy_version: int
    first_detected_at: datetime
    last_detected_at: datetime
    last_evaluated_at: datetime
    last_evaluation_run_id: uuid.UUID | None
    last_evaluation_record_id: uuid.UUID | None
    resolution_time: datetime | None
    evidence_id: uuid.UUID | None


class CloudFindingStatusHistoryOut(BaseModel):
    id: uuid.UUID
    finding_id: uuid.UUID
    previous_status: str
    new_status: str
    reason: str | None
    evaluation_run_id: uuid.UUID | None
    evaluation_record_id: uuid.UUID | None
    actor_user_id: uuid.UUID | None
    created_at: datetime


class CloudFindingSuppressionOut(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    finding_id: uuid.UUID
    suppression_type: str
    reason: str
    requested_by_user_id: uuid.UUID
    approval_id: uuid.UUID | None
    start_time: datetime
    expiry_time: datetime | None
    status: str
    review_date: datetime | None
    evidence_id: uuid.UUID | None
    created_at: datetime
    updated_at: datetime


class CloudFindingSuppressionRequest(BaseModel):
    suppression_type: str
    reason: str
    expiry_time: datetime | None = None
    review_date: datetime | None = None


class CloudEnvironmentCoverageOut(BaseModel):
    environment_id: uuid.UUID
    provider: str
    policies_applicable_by_provider: int
    has_been_evaluated: bool
    last_evaluation_run_id: uuid.UUID | None
    policies_considered: int
    evaluations_attempted: int
    passed_count: int
    failed_count: int
    not_applicable_count: int
    unsupported_count: int
    skipped_count: int
    error_count: int
    indeterminate_count: int
    findings_created: int
    findings_resolved: int


class CloudRegistryCoverageOut(BaseModel):
    total_policies: int
    enabled_policies: int
    disabled_policies: int
    experimental_policies: int
    deprecated_policies: int
    policies_by_provider: dict[str, int]
    total_benchmarks: int
    benchmark_mapped_control_counts: dict[str, int]
