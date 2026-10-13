"""Phase 20 (Continuation Prompt 7 / EDP-007), ADR 0031: the one authoritative,
versioned, machine-readable taxonomy of the twenty Unified Purple Cybersecurity
Workforce roles.

This table is deliberately separate from AGENT_REGISTRY/PLANNED_AGENTS
(gds_api.agents.registry): a *role* (e.g. "Incident Response and DFIR") is a fixed
point in the taxonomy, while an *agent manifest* is a real, running (or planned)
implementation that realizes zero or more roles. Some roles are realized by more
than one existing agent manifest working together (see each role's `realized_by`
below and docs/architecture/purple-workforce-agent-migration.md for the full
reasoning) - this table still has to be the single, unambiguous list of the twenty
roles regardless of how many manifests implement each one.

Foundation-team agents (knowledge_memory, data_intelligence, automation_workflow,
platform_operations, executive_advisor) are platform-introspection agents, not
security-domain roles, and are deliberately NOT part of this taxonomy - see the
pre-build audit's "Summary for Part 2 planning" for why this scope line was drawn
explicitly rather than assumed.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class PurpleRole:
    role_id: str
    number: int
    name: str
    operational_domain: str
    mission_role: str
    # Stable keys of the AGENT_REGISTRY/PLANNED_AGENTS manifest(s) that realize this
    # role today. Never empty - a role with no current manifest still gets one real
    # (if PLANNED) manifest created for it in this phase, per Prompt 7 Part 3's "map
    # every existing agent into one authoritative final role" plus "do not blindly
    # delete existing agents" - net-new roles get a net-new manifest rather than
    # being left unrepresented in AGENT_REGISTRY/PLANNED_AGENTS.
    realized_by: tuple[str, ...]


PURPLE_TAXONOMY_VERSION = "1.0.0"

PURPLE_ROLES: tuple[PurpleRole, ...] = (
    PurpleRole(
        role_id="purple-01",
        number=1,
        name="Purple Security Command Agent",
        operational_domain="Mission Coordination",
        mission_role=(
            "Coordinates operational cybersecurity missions beneath Rabbani AI Core; "
            "translates the Master Orchestrator's mission into a Purple execution "
            "graph, selects specialist agents, tracks dependencies, consolidates "
            "findings, enforces scope, triggers approvals. Subordinate to Rabbani AI "
            "Core - never a competing master authority."
        ),
        realized_by=("purple_security_command",),
    ),
    PurpleRole(
        role_id="purple-02",
        number=2,
        name="SOC Detection and Triage Agent",
        operational_domain="Security Operations",
        mission_role=(
            "Alert ingestion, event normalisation, correlation, severity "
            "classification, false-positive reduction, incident creation, "
            "escalation, queue prioritisation."
        ),
        realized_by=("blue_team",),
    ),
    PurpleRole(
        role_id="purple-03",
        number=3,
        name="Incident Response and DFIR Agent",
        operational_domain="Incident Response",
        mission_role=(
            "Incident investigation, evidence acquisition, chain of custody, "
            "timeline reconstruction, root-cause analysis, containment/eradication "
            "planning, recovery validation, lessons learned."
        ),
        realized_by=("incident_response", "digital_forensics"),
    ),
    PurpleRole(
        role_id="purple-04",
        number=4,
        name="Threat Hunting Agent",
        operational_domain="Threat Hunting",
        mission_role=(
            "Hypothesis-driven and IOC-based threat hunting across indicators and "
            "known-malicious hashes; hunt-to-detection conversion, hunt reporting."
        ),
        realized_by=("threat_hunting", "malware_analysis"),
    ),
    PurpleRole(
        role_id="purple-05",
        number=5,
        name="Threat Intelligence Agent",
        operational_domain="Threat Intelligence",
        mission_role=(
            "Threat-feed ingestion (CISA KEV), IOC/CVE enrichment, intelligence-led "
            "mission recommendations."
        ),
        realized_by=("threat_intelligence",),
    ),
    PurpleRole(
        role_id="purple-06",
        number=6,
        name="Vulnerability and Exposure Management Agent",
        operational_domain="Vulnerability Management",
        mission_role=(
            "Vulnerability ingestion (OSV.dev), finding normalisation/dedup, "
            "exposure and prioritisation, remediation SLA tracking, retest "
            "scheduling, closure evidence, continuous exposure monitoring. Core "
            "mandate of the Agentic OS."
        ),
        realized_by=("vulnerability_management",),
    ),
    PurpleRole(
        role_id="purple-07",
        number=7,
        name="Penetration Testing Coordinator Agent",
        operational_domain="Penetration Testing",
        mission_role=(
            "Engagement creation, written-authorisation validation, scope/ROE/"
            "testing-window management, test-plan generation, specialist "
            "assignment, human pre-execution approval, safety monitoring, emergency "
            "stop, final penetration-test reporting."
        ),
        realized_by=("penetration_testing_coordinator",),
    ),
    PurpleRole(
        role_id="purple-08",
        number=8,
        name="External Attack Surface and Reconnaissance Agent",
        operational_domain="Attack Surface Management",
        mission_role=(
            "Domain/subdomain/IP/port/service discovery, technology fingerprinting, "
            "passive and approved lightweight-active reconnaissance, attack-surface "
            "change monitoring - all target-, time- and rate-governed."
        ),
        realized_by=("red_team",),
    ),
    PurpleRole(
        role_id="purple-09",
        number=9,
        name="Network Penetration Testing Agent",
        operational_domain="Network Security Testing",
        mission_role=(
            "Network enumeration, service validation, misconfiguration testing, "
            "safe vulnerability validation within explicit authorised scope; "
            "controlled exploitation only after separate approval (not yet built)."
        ),
        realized_by=("network_security",),
    ),
    PurpleRole(
        role_id="purple-10",
        number=10,
        name="Web Application and API Penetration Testing Agent",
        operational_domain="Application Security Testing",
        mission_role=(
            "OWASP Web/API Top 10 testing, authN/authZ testing, session management "
            "review, evidence-backed findings, retesting after remediation."
        ),
        realized_by=("api_application_security",),
    ),
    PurpleRole(
        role_id="purple-11",
        number=11,
        name="Cloud, Container and Kubernetes Security Agent",
        operational_domain="Cloud Security",
        mission_role=(
            "AWS/Azure/GCP posture assessment, IAM/CIEM review, container/"
            "Kubernetes posture, cloud attack paths and remediation."
        ),
        realized_by=(
            "cloud_security",
            "cloud_security_coordinator",
            "aws_inventory_analyst",
            "azure_inventory_analyst",
            "gcp_inventory_analyst",
            "kubernetes_inventory_analyst",
            "cloud_asset_correlation_analyst",
            # EDP-009 Part 2, Section 52: the seven CSPM specialist roles.
            "cloud_posture_coordinator",
            "aws_posture_analyst",
            "azure_posture_analyst",
            "gcp_posture_analyst",
            "kubernetes_posture_analyst",
            "cloud_compliance_mapping_analyst",
            "cloud_finding_review_analyst",
        ),
    ),
    PurpleRole(
        role_id="purple-12",
        number=12,
        name="Identity and Zero-Trust Security Agent",
        operational_domain="Identity Security",
        mission_role=(
            "Excessive-privilege and dormant-account detection, MFA coverage, "
            "identity remediation recommendations, zero-trust control validation."
        ),
        realized_by=("identity_access_management",),
    ),
    PurpleRole(
        role_id="purple-13",
        number=13,
        name="Detection Engineering Agent",
        operational_domain="Detection Engineering",
        mission_role=(
            "Sigma/YARA rule generation, SIEM/EDR content, ATT&CK coverage mapping, "
            "detection-gap analysis, threat-hunt-to-detection conversion."
        ),
        realized_by=("detection_engineering",),
    ),
    PurpleRole(
        role_id="purple-14",
        number=14,
        name="Adversary Emulation and Breach Simulation Agent",
        operational_domain="Adversary Emulation",
        mission_role=(
            "ATT&CK-aligned simulations, threat-actor emulation, kill-chain "
            "modelling, detection-control validation; non-destructive by default."
        ),
        realized_by=("adversary_emulation",),
    ),
    PurpleRole(
        role_id="purple-15",
        number=15,
        name="AI and LLM Security Testing Agent",
        operational_domain="AI/LLM Security",
        mission_role=(
            "Prompt-injection testing, RAG poisoning, tool abuse, excessive agency, "
            "MCP/connector security, agent-identity spoofing, approval-boundary "
            "validation - may assess GDS Security OS itself only in isolated, "
            "explicitly authorised test environments."
        ),
        realized_by=("ai_llm_security_testing",),
    ),
    PurpleRole(
        role_id="purple-16",
        number=16,
        name="Application and Software Supply-Chain Security Agent",
        operational_domain="Supply Chain Security",
        mission_role=(
            "SCA/dependency analysis, secrets detection, SBOM analysis, CI/CD and "
            "repository-protection review, software supply-chain findings."
        ),
        realized_by=("devsecops",),
    ),
    PurpleRole(
        role_id="purple-17",
        number=17,
        name="Defensive Remediation and Auto-Fix Agent",
        operational_domain="Remediation Engineering",
        mission_role=(
            "Remediation planning and governed code/config changes via the "
            "existing Repository Registry -> Workspace Manager -> Secure "
            "Capability Broker -> AIProvider -> Review Engine -> Human Approval -> "
            "Local Commit path. No second write path."
        ),
        realized_by=("defensive_remediation_autofix",),
    ),
    PurpleRole(
        role_id="purple-18",
        number=18,
        name="Validation and Retest Agent",
        operational_domain="Validation and Assurance",
        mission_role=(
            "Independently validates findings, retests remediation, confirms "
            "attack paths closed, rejects weak/unsupported findings, produces "
            "closure evidence. A finding is never closed merely because a patch "
            "exists."
        ),
        realized_by=("validation_retest",),
    ),
    PurpleRole(
        role_id="purple-19",
        number=19,
        name="Governance, Risk, Compliance and Evidence Agent",
        operational_domain="Governance, Risk and Compliance",
        mission_role=(
            "Risk-register management, control mapping, compliance evidence, "
            "policy review, exception tracking, audit packages, approval history, "
            "chain-of-custody support."
        ),
        realized_by=("security_architecture", "compliance_grc", "risk_business_intelligence"),
    ),
    PurpleRole(
        role_id="purple-20",
        number=20,
        name="Security Documentation and Executive Reporting Agent",
        operational_domain="Security Reporting",
        mission_role=(
            "Vulnerability/pentest/incident/threat-hunt/remediation/retest/"
            "compliance reports, executive summaries, board-ready risk narratives, "
            "evidence indexes - derived only from real findings, evidence and "
            "mission records."
        ),
        realized_by=("security_documentation_reporting",),
    ),
)

PURPLE_ROLE_BY_ID: dict[str, PurpleRole] = {role.role_id: role for role in PURPLE_ROLES}

assert len(PURPLE_ROLES) == 20, "The Purple Workforce taxonomy must define exactly twenty roles"
