"""Phase 16 (Continuation Prompt 3): the authoritative Capability catalogue - one real
entry per real gds_api.tool_gateway.TOOL_REGISTRY tool, plus a handful of PLANNED/
DISABLED future capabilities named after Part B's own examples, defined but never
executable. See docs/architecture/capability-domain-model.md and
docs/security/capability-risk-model.md for the full reasoning.

allowed_team_types is set from the REAL current agent ownership in
gds_api.agents.registry.AGENT_REGISTRY (cross-checked directly, not assumed) - each
capability may only be requested by an agent on the team that actually owns its backing
tool today, or (for the two tools no agent owns - get_current_time, purge_mission_memory)
only via a direct Rabbani-orchestrated request with no agent attached at all
(allowed_team_types=(), allowed_agent_ids=()). This is the real fix for the Phase 16
audit's finding 1 - "Rabbani-direct" execution previously had zero allow-list check;
now a capability with a non-empty team/agent scope can never be reached that way.

requires_human_approval preserves this platform's EXISTING real approval behavior
exactly - it is a direct carry-over of whether the backing tool's OLD risk_class was
high/critical (True) or low/medium (False), per gds_api.seed_data.POLICY_RULES, NOT
auto-derived from the new, richer RiskClass. This guarantees the migration cannot
silently remove an approval gate that exists today - see ADR 0014's "risk model"
section for the full reasoning on why RiskClass and requires_human_approval are two
independent decisions here, not one derived from the other.
"""

from gds_api.agents.manifest import Team
from gds_api.capabilities.definitions import (
    CapabilityDefinition,
    CapabilityStatus,
    RiskClass,
    SideEffectType,
)

CAPABILITY_REGISTRY: dict[str, CapabilityDefinition] = {
    # ---- Rabbani-direct only (no agent owns these two tools today) -----------------
    "platform.get_time": CapabilityDefinition(
        stable_key="platform.get_time",
        display_name="Get Current Time",
        description="Returns the current UTC time. No side effects.",
        category="platform",
        risk_class=RiskClass.R0,
        side_effect_type=SideEffectType.NONE,
        required_tool_ids=("get_current_time",),
    ),
    "memory.purge": CapabilityDefinition(
        stable_key="memory.purge",
        display_name="Purge Mission Memory",
        description="Clears a mission's Redis working-memory state. Destructive.",
        category="memory",
        risk_class=RiskClass.R3,
        side_effect_type=SideEffectType.DESTRUCTIVE,
        required_tool_ids=("purge_mission_memory",),
        requires_human_approval=True,
    ),
    # ---- Foundation team --------------------------------------------------------------
    "knowledge.search": CapabilityDefinition(
        stable_key="knowledge.search",
        display_name="Search Knowledge Base",
        description="Real semantic search over the tenant's knowledge base (Qdrant).",
        category="knowledge",
        risk_class=RiskClass.R0,
        side_effect_type=SideEffectType.NONE,
        required_tool_ids=("search_knowledge",),
        allowed_team_types=(Team.FOUNDATION,),
    ),
    "knowledge.write_candidate": CapabilityDefinition(
        stable_key="knowledge.write_candidate",
        display_name="Add Knowledge Document",
        description="Adds a document (title + content) to the tenant's knowledge base.",
        category="knowledge",
        risk_class=RiskClass.R2,
        side_effect_type=SideEffectType.WRITE_INTERNAL,
        required_tool_ids=("add_knowledge",),
        allowed_team_types=(Team.FOUNDATION,),
    ),
    # Phase 20 (Continuation Prompt 7 / EDP-007), Part 13: Memory/Learning
    # Integration. A real, distinct capability from knowledge.write_candidate - a
    # mission-triggered lesson, not a caller-supplied document - but reuses the exact
    # same add_knowledge_document/search_knowledge machinery underneath, so no second
    # knowledge-write path exists.
    "knowledge.record_lesson": CapabilityDefinition(
        stable_key="knowledge.record_lesson",
        display_name="Record Mission Lesson",
        description=(
            "Records a decision, failed approach, successful technique, or reusable "
            "playbook from a real mission as a real, semantically-retrievable "
            "knowledge document."
        ),
        category="knowledge",
        risk_class=RiskClass.R1,
        side_effect_type=SideEffectType.WRITE_INTERNAL,
        required_tool_ids=("record_mission_lesson",),
        allowed_team_types=(Team.FOUNDATION,),
    ),
    "platform.metrics.read": CapabilityDefinition(
        stable_key="platform.metrics.read",
        display_name="Read Platform Metrics",
        description="Real aggregate stats over LLM cost records or mission activity.",
        category="platform",
        risk_class=RiskClass.R0,
        side_effect_type=SideEffectType.NONE,
        required_tool_ids=("query_platform_metrics",),
        allowed_team_types=(Team.FOUNDATION,),
    ),
    "approvals.list_pending": CapabilityDefinition(
        stable_key="approvals.list_pending",
        display_name="List Pending Approvals",
        description="Lists the tenant's real approvals still awaiting a human decision.",
        category="platform",
        risk_class=RiskClass.R0,
        side_effect_type=SideEffectType.NONE,
        required_tool_ids=("list_pending_approvals",),
        allowed_team_types=(Team.FOUNDATION,),
    ),
    "platform.health.read": CapabilityDefinition(
        stable_key="platform.health.read",
        display_name="Check Platform Health",
        description="Real connectivity check against every infrastructure service.",
        category="platform",
        risk_class=RiskClass.R0,
        side_effect_type=SideEffectType.NONE,
        required_tool_ids=("check_platform_health",),
        allowed_team_types=(Team.FOUNDATION,),
    ),
    "mission.list_recent": CapabilityDefinition(
        stable_key="mission.list_recent",
        display_name="List Recent Missions",
        description="Lists the tenant's most recently completed real missions.",
        category="platform",
        risk_class=RiskClass.R0,
        side_effect_type=SideEffectType.NONE,
        required_tool_ids=("list_recent_missions",),
        allowed_team_types=(Team.FOUNDATION,),
    ),
    # ---- Blue team ----------------------------------------------------------------
    "threat_intel.lookup_cve": CapabilityDefinition(
        stable_key="threat_intel.lookup_cve",
        display_name="Look Up CISA KEV",
        description="Checks the real CISA KEV feed against this tenant's watchlist.",
        category="threat_intelligence",
        risk_class=RiskClass.R3,
        side_effect_type=SideEffectType.READ_EXTERNAL,
        required_tool_ids=("check_cisa_kev",),
        allowed_team_types=(Team.BLUE,),
        requires_human_approval=True,
        allows_network=True,
    ),
    "vulnerability.lookup": CapabilityDefinition(
        stable_key="vulnerability.lookup",
        display_name="Search OSV Vulnerabilities",
        description="Real OSV.dev query for known vulnerabilities in a package+ecosystem.",
        category="vulnerability",
        risk_class=RiskClass.R3,
        side_effect_type=SideEffectType.READ_EXTERNAL,
        required_tool_ids=("search_osv_vulnerabilities",),
        allowed_team_types=(Team.BLUE,),
        requires_human_approval=True,
        allows_network=True,
    ),
    "threat_intel.lookup_ioc": CapabilityDefinition(
        stable_key="threat_intel.lookup_ioc",
        display_name="Check Threat Indicator",
        description="Checks a URL/host against abuse.ch URLhaus's real online-URL feed.",
        category="threat_intelligence",
        risk_class=RiskClass.R3,
        side_effect_type=SideEffectType.READ_EXTERNAL,
        required_tool_ids=("check_threat_indicator",),
        allowed_team_types=(Team.BLUE,),
        requires_human_approval=True,
        allows_network=True,
    ),
    "finding.triage": CapabilityDefinition(
        stable_key="finding.triage",
        display_name="Triage Findings",
        description="Deterministic severity->risk_class mapping over new findings.",
        category="findings",
        risk_class=RiskClass.R1,
        side_effect_type=SideEffectType.WRITE_INTERNAL,
        required_tool_ids=("triage_finding",),
        allowed_team_types=(Team.BLUE,),
    ),
    "finding.list_open": CapabilityDefinition(
        stable_key="finding.list_open",
        display_name="List Open Findings",
        description="Lists this tenant's real findings still open (new or triaged).",
        category="findings",
        risk_class=RiskClass.R0,
        side_effect_type=SideEffectType.NONE,
        required_tool_ids=("list_open_findings",),
        allowed_team_types=(Team.BLUE,),
    ),
    "finding.enrich": CapabilityDefinition(
        stable_key="finding.enrich",
        display_name="Enrich Finding",
        description=(
            "Phase 20, Part 9: real CVE/CVSS/EPSS/KEV enrichment for a triaged finding "
            "via FIRST.org and CISA KEV."
        ),
        category="findings",
        risk_class=RiskClass.R1,
        side_effect_type=SideEffectType.WRITE_INTERNAL,
        required_tool_ids=("enrich_finding",),
        allows_network=True,
        allowed_team_types=(Team.BLUE,),
    ),
    "finding.prioritise": CapabilityDefinition(
        stable_key="finding.prioritise",
        display_name="Prioritise Finding",
        description=(
            "Phase 20, Part 9: real, deterministic priority scoring for an enriched finding."
        ),
        category="findings",
        risk_class=RiskClass.R0,
        side_effect_type=SideEffectType.WRITE_INTERNAL,
        required_tool_ids=("prioritise_finding",),
        allowed_team_types=(Team.BLUE,),
    ),
    "finding.validate": CapabilityDefinition(
        stable_key="finding.validate",
        display_name="Validate or Reject Finding",
        description=(
            "Phase 20, Part 9: independent validation/rejection of a finding awaiting "
            "validation - the Validation and Retest Agent's first real capability."
        ),
        category="findings",
        risk_class=RiskClass.R2,
        side_effect_type=SideEffectType.WRITE_INTERNAL,
        required_tool_ids=("validate_finding",),
        allowed_team_types=(Team.BLUE,),
    ),
    "incident.create": CapabilityDefinition(
        stable_key="incident.create",
        display_name="Create Incident From Findings",
        description="Escalates triaged high/critical findings into a real incident.",
        category="incidents",
        risk_class=RiskClass.R2,
        side_effect_type=SideEffectType.WRITE_INTERNAL,
        required_tool_ids=("create_incident_from_findings",),
        allowed_team_types=(Team.BLUE,),
    ),
    "incident.list_open": CapabilityDefinition(
        stable_key="incident.list_open",
        display_name="List Open Incidents",
        description="Lists this tenant's real incidents still open or under investigation.",
        category="incidents",
        risk_class=RiskClass.R0,
        side_effect_type=SideEffectType.NONE,
        required_tool_ids=("list_open_incidents",),
        allowed_team_types=(Team.BLUE,),
    ),
    "compliance.review_architecture": CapabilityDefinition(
        stable_key="compliance.review_architecture",
        display_name="Review Platform Architecture",
        description="Real internal review of this tenant's policy rules and role structure.",
        category="compliance",
        risk_class=RiskClass.R0,
        side_effect_type=SideEffectType.NONE,
        required_tool_ids=("review_platform_architecture",),
        allowed_team_types=(Team.BLUE,),
    ),
    "compliance.review_identity": CapabilityDefinition(
        stable_key="compliance.review_identity",
        display_name="Review Identity Posture",
        description="Real internal review of this tenant's users/roles/broad permissions.",
        category="compliance",
        risk_class=RiskClass.R0,
        side_effect_type=SideEffectType.NONE,
        required_tool_ids=("review_identity_posture",),
        allowed_team_types=(Team.BLUE,),
    ),
    "network.check_domain_security": CapabilityDefinition(
        stable_key="network.check_domain_security",
        display_name="Check Domain Security",
        description="Real, passive TLS certificate check against a Watchlist-authorized domain.",
        category="network",
        risk_class=RiskClass.R2,
        side_effect_type=SideEffectType.READ_EXTERNAL,
        required_tool_ids=("check_domain_security",),
        allowed_team_types=(Team.BLUE,),
        allows_network=True,
    ),
    "network.check_url_headers": CapabilityDefinition(
        stable_key="network.check_url_headers",
        display_name="Check URL Security Headers",
        description="Real, passive HTTP security-header check against a Watchlist-authorized URL.",
        category="network",
        risk_class=RiskClass.R2,
        side_effect_type=SideEffectType.READ_EXTERNAL,
        required_tool_ids=("check_url_security_headers",),
        allowed_team_types=(Team.BLUE,),
        allows_network=True,
    ),
    "compliance.review_posture": CapabilityDefinition(
        stable_key="compliance.review_posture",
        display_name="Review Compliance Posture",
        description="Real, honest review of this platform's actual control implementation.",
        category="compliance",
        risk_class=RiskClass.R0,
        side_effect_type=SideEffectType.NONE,
        required_tool_ids=("review_compliance_posture",),
        allowed_team_types=(Team.BLUE,),
    ),
    "risk.calculate_exposure": CapabilityDefinition(
        stable_key="risk.calculate_exposure",
        display_name="Calculate Risk Exposure",
        description="Real, deterministic weighted risk score over open findings/incidents.",
        category="risk",
        risk_class=RiskClass.R0,
        side_effect_type=SideEffectType.NONE,
        required_tool_ids=("calculate_risk_exposure",),
        allowed_team_types=(Team.BLUE,),
    ),
    "evidence.verify_integrity": CapabilityDefinition(
        stable_key="evidence.verify_integrity",
        display_name="Verify Evidence Integrity",
        description="Re-downloads stored evidence from MinIO and recomputes its SHA-256.",
        category="evidence",
        risk_class=RiskClass.R0,
        side_effect_type=SideEffectType.NONE,
        required_tool_ids=("verify_evidence_integrity",),
        allowed_team_types=(Team.BLUE,),
    ),
    "vulnerability.scan_dependencies": CapabilityDefinition(
        stable_key="vulnerability.scan_dependencies",
        display_name="Scan Own Dependencies",
        description="Real SCA via OSV.dev against this codebase's own dependency manifests.",
        category="vulnerability",
        risk_class=RiskClass.R3,
        side_effect_type=SideEffectType.READ_EXTERNAL,
        required_tool_ids=("scan_own_dependencies",),
        allowed_team_types=(Team.BLUE,),
        requires_human_approval=True,
        allows_network=True,
    ),
    "threat_intel.lookup_malware_hash": CapabilityDefinition(
        stable_key="threat_intel.lookup_malware_hash",
        display_name="Check Malware Hash",
        description="Checks a file hash against abuse.ch MalwareBazaar's real recent-samples feed.",
        category="threat_intelligence",
        risk_class=RiskClass.R3,
        side_effect_type=SideEffectType.READ_EXTERNAL,
        required_tool_ids=("check_malware_hash",),
        allowed_team_types=(Team.BLUE,),
        requires_human_approval=True,
        allows_network=True,
    ),
    # ---- Red team -------------------------------------------------------------------
    "red_team.recon_passive": CapabilityDefinition(
        stable_key="red_team.recon_passive",
        display_name="Passive DNS Reconnaissance",
        description="Real DNS A-record resolution against an explicitly authorized target only.",
        category="red_team",
        risk_class=RiskClass.R4,
        side_effect_type=SideEffectType.OFFENSIVE,
        required_tool_ids=("recon_dns_enumeration",),
        target_types=("domain", "ip"),
        allowed_team_types=(Team.RED,),
        requires_human_approval=True,
        requires_target_authorisation=True,
        requires_emergency_stop_clear=True,
        allows_network=True,
        audit_level="elevated",
    ),
    "red_team.recon_active": CapabilityDefinition(
        stable_key="red_team.recon_active",
        display_name="Lightweight-Active Port Reconnaissance",
        description=(
            "Real TCP connect check against 10 well-known ports on an explicitly "
            "authorized target only - not a full port sweep, not exploitation."
        ),
        category="red_team",
        risk_class=RiskClass.R4,
        side_effect_type=SideEffectType.OFFENSIVE,
        required_tool_ids=("recon_port_scan",),
        target_types=("domain", "ip"),
        allowed_team_types=(Team.RED,),
        requires_human_approval=True,
        requires_target_authorisation=True,
        requires_emergency_stop_clear=True,
        allows_network=True,
        audit_level="elevated",
    ),
    "red_team.assess_attack_surface": CapabilityDefinition(
        stable_key="red_team.assess_attack_surface",
        display_name="Combined Attack Surface Assessment",
        description=(
            "Real combined DNS/port/TLS reconnaissance summary against an explicitly "
            "authorized target only."
        ),
        category="red_team",
        risk_class=RiskClass.R4,
        side_effect_type=SideEffectType.OFFENSIVE,
        required_tool_ids=("assess_attack_surface",),
        target_types=("domain", "ip"),
        allowed_team_types=(Team.RED,),
        requires_human_approval=True,
        requires_target_authorisation=True,
        requires_emergency_stop_clear=True,
        allows_network=True,
        audit_level="elevated",
    ),
    # Phase 20 (Continuation Prompt 7 / EDP-007), Part 11: coordinates the 3
    # red_team.* capabilities above across every target in a real Engagement.
    # gds_api.capabilities.validation._check_red_team_safety_coupling requires every
    # OPERATIONAL red_team capability to carry all three of requires_target_
    # authorisation/requires_emergency_stop_clear/requires_human_approval - a real,
    # platform-wide invariant this capability must not be exempted from. The broker's
    # own target_reference check (a single target) authorises the one real target the
    # requesting caller names at request time (one of the Engagement's own real,
    # already-validated targets - see redteam.create_engagement); it is a necessary
    # precondition, not the whole story - the tool itself additionally re-validates
    # every actual target it processes, one at a time, via the exact same
    # gds_api.redteam_safety.ensure_target_authorized check, so a multi-target
    # Engagement is never less safe than a single-target one.
    "red_team.coordinate_pentest_engagement": CapabilityDefinition(
        stable_key="red_team.coordinate_pentest_engagement",
        display_name="Coordinate Pentest Engagement",
        description=(
            "Real, coordinated DNS/port/TLS reconnaissance across every authorized "
            "target in scope for a real, human-authorized Engagement."
        ),
        category="red_team",
        risk_class=RiskClass.R4,
        side_effect_type=SideEffectType.OFFENSIVE,
        required_tool_ids=("coordinate_pentest_engagement",),
        target_types=("domain", "ip"),
        allowed_team_types=(Team.RED,),
        requires_human_approval=True,
        requires_target_authorisation=True,
        requires_emergency_stop_clear=True,
        allows_network=True,
        audit_level="elevated",
    ),
    # ---- PLANNED / DISABLED - defined per Part B's own examples, never executable ---
    # (no backing tool exists in TOOL_REGISTRY for any of these - required_tool_ids=()
    # is a real, structural guarantee they can never resolve to an executable tool, not
    # just a status flag - see capabilities/validation.py's
    # _check_planned_disabled_capabilities_have_no_tools.)
    "cloud.read_posture": CapabilityDefinition(
        stable_key="cloud.read_posture",
        display_name="Read Cloud Posture",
        description=(
            "Would review real cloud posture (IAM, storage, network exposure) - not "
            "possible without a real read-only cloud credential. Mirrors the Cloud "
            "Security agent's own Planned status (docs/architecture/agent-registry.md)."
        ),
        category="cloud",
        risk_class=RiskClass.R1,
        side_effect_type=SideEffectType.READ_EXTERNAL,
        required_tool_ids=(),
        status=CapabilityStatus.PLANNED,
        allowed_team_types=(Team.BLUE,),
        required_connector_ids=("aws_readonly", "azure_readonly", "gcp_readonly"),
        allows_network=True,
        enabled=False,
    ),
    "cloud.apply_remediation": CapabilityDefinition(
        stable_key="cloud.apply_remediation",
        display_name="Apply Cloud Remediation",
        description="Would apply a real cloud configuration change. Not implemented.",
        category="cloud",
        risk_class=RiskClass.R3,
        side_effect_type=SideEffectType.WRITE_EXTERNAL,
        required_tool_ids=(),
        status=CapabilityStatus.PLANNED,
        allowed_team_types=(Team.BLUE,),
        required_connector_ids=("aws_readonly", "azure_readonly", "gcp_readonly"),
        requires_human_approval=True,
        requires_sandbox=True,
        allows_network=True,
        enabled=False,
    ),
    # EDP-009 Part 1: real, operational, but deliberately narrow - inventory
    # discovery only, never posture/security assessment (that's `cloud.read_posture`
    # above, still PLANNED - CSPM assessment is explicitly out of scope this Part,
    # Section 48). Real today even though every provider adapter is honestly
    # NOT_YET_IMPLEMENTED/unverified in this environment (ADR 0050) - the capability
    # itself, the Mission/Broker/audit/evidence plumbing around it, and its honest
    # "no adapter available" failure path are all real and tested; only the actual
    # provider SDK calls are pending later sub-phases' real credentials.
    #
    # Deliberately Rabbani-direct only (both allow-lists empty), mirroring
    # repository_api.py's own real "browse repository" capabilities
    # (requesting_agent_id=None) - Sections 21/26 want a human-triggered "Start
    # authorised discovery" UI action in the Cloud Security Workspace, and the
    # broker's own agent-allow-list step (13) enforces an exclusive choice: a
    # capability is either Rabbani-direct only or agent-only, never both. The
    # dedicated Cloud Security Coordinator/Inventory Analyst agents (Section 32,
    # a later sub-phase) will need their own decision about whether to reuse this
    # capability or add a separate agent-scoped one - not resolved here.
    "cloud.discover_environment": CapabilityDefinition(
        stable_key="cloud.discover_environment",
        display_name="Discover Cloud Environment",
        description=(
            "Real, read-only cloud asset/relationship discovery for one registered, "
            "authorised CloudEnvironment - inventory only, never a posture or "
            "compliance assessment, never a configuration change."
        ),
        category="cloud",
        risk_class=RiskClass.R2,
        side_effect_type=SideEffectType.READ_EXTERNAL,
        required_tool_ids=("discover_cloud_environment",),
        allows_network=True,
        evidence_required=True,
        audit_level="elevated",
    ),
    # EDP-009 Part 2: the CSPM assessment layer promised (but not built) by Part 1's
    # comment above - deliberately a NEW, distinctly-named capability rather than
    # promoting `cloud.read_posture` (still PLANNED above): that placeholder
    # describes a *live credentialed* posture read ("not possible without a real
    # read-only cloud credential"), while this evaluates already-persisted
    # inventory deterministically - no cloud provider call at all, so
    # SideEffectType.WRITE_INTERNAL (not READ_EXTERNAL, unlike discovery above) and
    # allows_network=False are both real, deliberate distinctions from
    # `cloud.discover_environment`. Same Rabbani-direct-only shape as discovery,
    # for the same reason (a human-triggered "Run posture evaluation" UI action).
    "cloud.posture.evaluate_environment": CapabilityDefinition(
        stable_key="cloud.posture.evaluate_environment",
        display_name="Evaluate Cloud Posture",
        description=(
            "Real, deterministic policy evaluation against one registered "
            "CloudEnvironment's already-persisted asset inventory - never a live "
            "cloud call, never an LLM compliance decision, never a configuration "
            "change."
        ),
        category="cloud",
        risk_class=RiskClass.R2,
        side_effect_type=SideEffectType.WRITE_INTERNAL,
        required_tool_ids=("evaluate_cloud_posture",),
        allows_network=False,
        evidence_required=True,
        audit_level="elevated",
    ),
    # ---- Phase 17 (Continuation Prompt 4): 10 real, read-only repository -----------
    # capabilities, one per real tool_gateway tool - Rabbani-direct only
    # (allowed_team_types=(), allowed_agent_ids=()), matching platform.get_time/
    # memory.purge's precedent: no real agent's tool_names/allowed_capability_ids
    # names any of these yet (this phase explicitly prepares the repository operating
    # layer for a future Codex/Claude Code agent, per the build prompt's own mission
    # statement - it does not build that agent). R0 (repository.read - creates a real,
    # isolated Workspace, a genuine but non-destructive internal side effect) or, for
    # the 9 pure read operations against an already-open Workspace, R0 with no
    # additional side effect. None require human approval - real, low-risk reads
    # against an isolated worktree, never the primary repository.
    "repository.read": CapabilityDefinition(
        stable_key="repository.read",
        display_name="Open Repository",
        description=(
            "Resolves or creates a real, isolated git worktree Workspace for a "
            "registered repository and reports its real status."
        ),
        category="repository",
        risk_class=RiskClass.R1,
        side_effect_type=SideEffectType.WRITE_INTERNAL,
        required_tool_ids=("read_repository",),
    ),
    "repository.search": CapabilityDefinition(
        stable_key="repository.search",
        display_name="Search Repository",
        description="Real, read-only full-text search across a repository's tracked files.",
        category="repository",
        risk_class=RiskClass.R0,
        side_effect_type=SideEffectType.NONE,
        required_tool_ids=("search_repository",),
    ),
    "repository.list_files": CapabilityDefinition(
        stable_key="repository.list_files",
        display_name="List Repository Files",
        description="Real, read-only listing of a repository's tracked files.",
        category="repository",
        risk_class=RiskClass.R0,
        side_effect_type=SideEffectType.NONE,
        required_tool_ids=("list_repository_files",),
    ),
    "repository.read_file": CapabilityDefinition(
        stable_key="repository.read_file",
        display_name="Read Repository File",
        description="Real, read-only read of one tracked file's content at a given ref.",
        category="repository",
        risk_class=RiskClass.R0,
        side_effect_type=SideEffectType.NONE,
        required_tool_ids=("read_repository_file",),
    ),
    "repository.list_branches": CapabilityDefinition(
        stable_key="repository.list_branches",
        display_name="List Repository Branches",
        description="Real, read-only listing of a repository's real branches.",
        category="repository",
        risk_class=RiskClass.R0,
        side_effect_type=SideEffectType.NONE,
        required_tool_ids=("list_repository_branches",),
    ),
    "repository.list_tags": CapabilityDefinition(
        stable_key="repository.list_tags",
        display_name="List Repository Tags",
        description="Real, read-only listing of a repository's real tags.",
        category="repository",
        risk_class=RiskClass.R0,
        side_effect_type=SideEffectType.NONE,
        required_tool_ids=("list_repository_tags",),
    ),
    "repository.repository_metadata": CapabilityDefinition(
        stable_key="repository.repository_metadata",
        display_name="Repository Metadata",
        description="Real, comprehensive repository facts - branches, HEAD, commit/file counts.",
        category="repository",
        risk_class=RiskClass.R0,
        side_effect_type=SideEffectType.NONE,
        required_tool_ids=("get_repository_metadata",),
    ),
    "repository.history": CapabilityDefinition(
        stable_key="repository.history",
        display_name="Repository History",
        description="Real, read-only `git log` - commit hash/author/date/message, no diffs.",
        category="repository",
        risk_class=RiskClass.R0,
        side_effect_type=SideEffectType.NONE,
        required_tool_ids=("get_repository_history",),
    ),
    "repository.diff_between_refs": CapabilityDefinition(
        stable_key="repository.diff_between_refs",
        display_name="Diff Repository Refs",
        description=(
            "Real, read-only diff between two real refs, with real stats. No patch application."
        ),
        category="repository",
        risk_class=RiskClass.R0,
        side_effect_type=SideEffectType.NONE,
        required_tool_ids=("diff_repository_refs",),
    ),
    "repository.list_worktrees": CapabilityDefinition(
        stable_key="repository.list_worktrees",
        display_name="List Repository Worktrees",
        description=(
            "Real `git worktree list`, cross-referenced with this platform's own Workspace rows."
        ),
        category="repository",
        risk_class=RiskClass.R0,
        side_effect_type=SideEffectType.NONE,
        required_tool_ids=("list_repository_worktrees",),
    ),
    "repository.write": CapabilityDefinition(
        stable_key="repository.write",
        display_name="Write Repository File",
        description=(
            "Superseded by Phase 18's real engineering.execute_session/engineering.commit "
            "capabilities below, which give the same real effect (a governed, workspace- "
            "scoped write, gated by real review + mandatory approval before any commit) "
            "through the AI Engineering Execution Platform rather than a raw single-file "
            "write primitive. Remains PLANNED/DISABLED - no backing tool exists for a "
            "bare 'write one file' capability outside that governed pipeline."
        ),
        category="repository",
        risk_class=RiskClass.R3,
        side_effect_type=SideEffectType.WRITE_EXTERNAL,
        required_tool_ids=(),
        status=CapabilityStatus.DISABLED,
        requires_human_approval=True,
        requires_sandbox=True,
        independent_validation_required=True,
        enabled=False,
    ),
    # ---- Phase 18 (Continuation Prompt 5): AI Engineering Execution Platform --------
    # Real, operational (unlike repository.write above): opening a session only ever
    # writes inside an already-isolated Workspace (Phase 17) - a genuine but internal,
    # non-repository-affecting side effect (WRITE_INTERNAL, R1), auto-ALLOW. Committing
    # is a real, external, repository-affecting action (WRITE_EXTERNAL, R3) and its
    # backing tool's legacy risk_class="high" makes it ALWAYS require real human
    # approval via the existing Policy/Approval mechanism - see ADR 0024 for why this
    # phase does not attempt Part 10's finer-grained "only sensitive changes need
    # approval" and instead gates every real commit uniformly (strictly more
    # conservative, never less safe).
    "engineering.execute_session": CapabilityDefinition(
        stable_key="engineering.execute_session",
        display_name="Start Engineering Session",
        description=(
            "Starts a real AI engineering session (Claude Code or OpenAI Codex) inside "
            "an isolated Workspace - the provider may read/create/edit files only "
            "within that Workspace's own worktree, never the primary repository, and "
            "nothing is committed by this capability alone."
        ),
        category="engineering",
        risk_class=RiskClass.R1,
        side_effect_type=SideEffectType.WRITE_INTERNAL,
        required_tool_ids=("start_engineering_session",),
    ),
    "engineering.commit": CapabilityDefinition(
        stable_key="engineering.commit",
        display_name="Commit Engineering Session",
        description=(
            "Real `git add`/`git commit` (never push) of an already-reviewed engineering "
            "session's real, workspace-scoped changes - always requires human approval."
        ),
        category="engineering",
        risk_class=RiskClass.R3,
        side_effect_type=SideEffectType.WRITE_EXTERNAL,
        required_tool_ids=("commit_engineering_session",),
        requires_human_approval=True,
    ),
    # ---- Phase 19 (Continuation Prompt 6): Multi-Agent Engineering System ----------
    # Same real split as Phase 18's own two engineering.* capabilities (ADR 0024):
    # planning + parallel execution is a real, auto-ALLOW internal side effect (every
    # actual write happens inside per-task isolated Workspaces, never the primary
    # repository); the one real repository-affecting action - the final, merged,
    # mission-level commit - always requires human approval, uniformly.
    "engineering.plan_mission": CapabilityDefinition(
        stable_key="engineering.plan_mission",
        display_name="Plan and Execute Engineering Mission",
        description=(
            "Decomposes a real objective into a real, dependency-ordered task graph and "
            "runs it as real, parallel specialist engineering sessions, each inside its "
            "own isolated Workspace - never the primary repository, nothing committed "
            "by this capability alone."
        ),
        category="engineering",
        risk_class=RiskClass.R1,
        side_effect_type=SideEffectType.WRITE_INTERNAL,
        required_tool_ids=("start_mission_plan",),
    ),
    "engineering.commit_mission": CapabilityDefinition(
        stable_key="engineering.commit_mission",
        display_name="Commit Merged Engineering Mission",
        description=(
            "Real `git add`/`git commit` (never push) of an already-merged, already-"
            "reviewed multi-agent mission's real integration branch - always requires "
            "human approval."
        ),
        category="engineering",
        risk_class=RiskClass.R3,
        side_effect_type=SideEffectType.WRITE_EXTERNAL,
        required_tool_ids=("commit_mission_plan",),
        requires_human_approval=True,
    ),
    # ---- Phase 20 (Continuation Prompt 7), Part 10: Vulnerability-to-Auto-Fix ------
    # A real, distinct capability from engineering.plan_mission - a Finding-triggered
    # remediation, not a caller-supplied objective - but reuses the exact same
    # create_mission_plan/execute_mission_plan machinery underneath, so this
    # capability itself is deliberately low-risk (creates a plan + starts execution,
    # every write still confined to isolated Workspaces). The one real
    # repository-affecting action - the eventual mission commit - stays gated by the
    # existing engineering.commit_mission capability's own always-required approval;
    # this capability is not a second commit path.
    "remediation.auto_fix_finding": CapabilityDefinition(
        stable_key="remediation.auto_fix_finding",
        display_name="Auto-Fix a Validated Finding",
        description=(
            "Routes a real, validated Finding into the governed multi-agent "
            "engineering write path to produce an approval-gated fix - no second "
            "write path."
        ),
        category="remediation",
        risk_class=RiskClass.R2,
        side_effect_type=SideEffectType.WRITE_INTERNAL,
        required_tool_ids=("auto_fix_finding",),
        allowed_team_types=(Team.BLUE,),
    ),
    "shell.run_allowlisted": CapabilityDefinition(
        stable_key="shell.run_allowlisted",
        display_name="Run Allow-Listed Shell Command",
        description=(
            "Would run a real, narrowly allow-listed shell command in a sandbox. "
            "Explicitly out of scope this phase - no sandbox exists yet. No backing tool."
        ),
        category="shell",
        risk_class=RiskClass.R4,
        side_effect_type=SideEffectType.WRITE_EXTERNAL,
        required_tool_ids=(),
        status=CapabilityStatus.DISABLED,
        requires_human_approval=True,
        requires_sandbox=True,
        independent_validation_required=True,
        enabled=False,
    ),
    "shell.run_unrestricted": CapabilityDefinition(
        stable_key="shell.run_unrestricted",
        display_name="Unrestricted Shell Access",
        description="Prohibited. Never implemented, never enabled, at any future phase.",
        category="shell",
        risk_class=RiskClass.R5,
        side_effect_type=SideEffectType.WRITE_EXTERNAL,
        required_tool_ids=(),
        status=CapabilityStatus.DISABLED,
        enabled=False,
    ),

    # --- Priority 2: Extended Security Tools ---
    "security_tools.sast_scan": CapabilityDefinition(
        stable_key="security_tools.sast_scan",
        display_name="Run SAST Scan (Semgrep)",
        description="Run Semgrep static analysis on source code to identify security issues.",
        category="application_security",
        risk_class=RiskClass.R2,
        side_effect_type=SideEffectType.READ_EXTERNAL,
        required_tool_ids=("sast_scan",),
        allowed_team_types=(Team.BLUE, Team.RED),
    ),
    "security_tools.dast_scan": CapabilityDefinition(
        stable_key="security_tools.dast_scan",
        display_name="Run DAST Scan (Nuclei)",
        description="Run Nuclei dynamic web scanning for OWASP Top 10 vulnerabilities.",
        category="application_security",
        risk_class=RiskClass.R3,
        side_effect_type=SideEffectType.READ_EXTERNAL,
        required_tool_ids=("dast_scan",),
        allowed_team_types=(Team.RED,),
        requires_target_authorisation=True,
    ),
    "security_tools.container_scan": CapabilityDefinition(
        stable_key="security_tools.container_scan",
        display_name="Run Container Scan (Trivy)",
        description="Run Trivy container image vulnerability and secret scanning.",
        category="container_security",
        risk_class=RiskClass.R2,
        side_effect_type=SideEffectType.READ_EXTERNAL,
        required_tool_ids=("container_scan",),
        allowed_team_types=(Team.BLUE,),
    ),
    "security_tools.iac_scan": CapabilityDefinition(
        stable_key="security_tools.iac_scan",
        display_name="Run IaC Scan (Checkov)",
        description="Run Checkov IaC scanning for Terraform/CloudFormation/K8s misconfigurations.",
        category="infrastructure_security",
        risk_class=RiskClass.R2,
        side_effect_type=SideEffectType.READ_EXTERNAL,
        required_tool_ids=("iac_scan",),
        allowed_team_types=(Team.BLUE,),
    ),
    "security_tools.generate_sbom": CapabilityDefinition(
        stable_key="security_tools.generate_sbom",
        display_name="Generate SBOM",
        description="Generate a Software Bill of Materials in CycloneDX or SPDX format.",
        category="supply_chain",
        risk_class=RiskClass.R1,
        side_effect_type=SideEffectType.NONE,
        required_tool_ids=("generate_sbom",),
        allowed_team_types=(Team.BLUE,),
    ),
    "security_tools.darkweb_check": CapabilityDefinition(
        stable_key="security_tools.darkweb_check",
        display_name="Check Credential Leaks (HIBP)",
        description="Check email addresses against HaveIBeenPwned for credential leaks.",
        category="threat_intelligence",
        risk_class=RiskClass.R3,
        side_effect_type=SideEffectType.READ_EXTERNAL,
        required_tool_ids=("check_credential_leaks",),
        allowed_team_types=(Team.BLUE,),
    ),
    "security_tools.identity_threats": CapabilityDefinition(
        stable_key="security_tools.identity_threats",
        display_name="Detect Identity Threats",
        description="Detect impossible travel, off-hours access, and behavioral anomalies.",
        category="identity_security",
        risk_class=RiskClass.R1,
        side_effect_type=SideEffectType.NONE,
        required_tool_ids=("detect_identity_threats",),
        allowed_team_types=(Team.BLUE,),
    ),
}

# Part I: the real reverse lookup gds_api.workflows.activities uses to find the one
# OPERATIONAL capability that governs a given real tool_gateway.TOOL_REGISTRY tool -
# built from the catalogue itself (never a second, hand-maintained mapping that could
# drift from it), and only ever containing entries validation.py's own
# _check_every_real_tool_has_exactly_one_capability has already confirmed are 1:1.
TOOL_TO_CAPABILITY_KEY: dict[str, str] = {
    tool_id: capability.stable_key
    for capability in CAPABILITY_REGISTRY.values()
    if capability.status == CapabilityStatus.OPERATIONAL
    for tool_id in capability.required_tool_ids
}
