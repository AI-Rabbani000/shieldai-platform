"""The five Phase 4 Foundation Agents (real internal platform state), the five Phase 5
Defensive Agents (real, free, keyless external feeds: CISA KEV, OSV.dev, abuse.ch
URLhaus - per agents/README.md and the session-log decision in docs/BUILD-STATUS.md to
prioritize agents backed by credentials/feeds actually available), and nine of Phase 7's
ten Extended Security Agents (real internal platform data or real, free, keyless
external checks - see docs/adr/0006-phase-7-extended-agents-scope.md for how each one
was made real without fabricating an integration this project doesn't have credentials
for). Cloud Security is the one Phase 7 agent still Planned - real cloud posture
scanning genuinely needs AWS/Azure/GCP credentials, which aren't configured; see
apps/web/lib/agents-registry.ts. Phase 8 adds the Red Team Agent - real but strictly
passive/lightweight-active reconnaissance only, gated by gds_api.redteam_safety's real
authorization/kill-switch/rate-limit boundary and always "critical" risk (always
human-approved) - see docs/adr/0007-phase-8-red-team-safety-boundary.md.
"""

from gds_api.agents.manifest import (
    AgentManifest,
    AgentStatus,
    PlannedAgentManifest,
    RiskCeiling,
    Team,
)

AGENT_REGISTRY: dict[str, AgentManifest] = {
    "knowledge_memory": AgentManifest(
        name="knowledge_memory",
        display_name="Knowledge & Memory Agent",
        description=(
            "Maintains the tenant's knowledge base: ingests new documents and retrieves "
            "relevant ones via real semantic search. Phase 20, Part 13: also records "
            "real per-mission lessons (decisions, failed approaches, successful "
            "techniques, reusable playbooks) - automatically retrievable by every "
            "future mission's own planning prompt via that same real semantic search."
        ),
        system_prompt=(
            "You are the Knowledge & Memory Agent for GDS Security OS. You maintain the "
            "tenant's knowledge base - ingesting documents and retrieving relevant ones "
            "by real semantic search, and recording real lessons from completed "
            "missions. Be precise about what you actually found or stored."
        ),
        tool_names=("search_knowledge", "add_knowledge", "record_mission_lesson"),
        team=Team.FOUNDATION,
        department="Knowledge & Memory",
        risk_ceiling=RiskCeiling.R2,
        memory_scopes=("relationship", "semantic"),
        allowed_capability_ids=(
            "knowledge.search",
            "knowledge.write_candidate",
            "knowledge.record_lesson",
        ),
    ),
    "data_intelligence": AgentManifest(
        name="data_intelligence",
        display_name="Data Intelligence Agent",
        description=(
            "Analyzes real platform data - LLM cost records and mission activity - and "
            "reports factual metrics."
        ),
        system_prompt=(
            "You are the Data Intelligence Agent for GDS Security OS. You analyze real "
            "platform data (cost records, mission activity) and report factual metrics. "
            "Never estimate or invent a number that wasn't actually returned to you."
        ),
        tool_names=("query_platform_metrics",),
        team=Team.FOUNDATION,
        department="Data Intelligence",
        risk_ceiling=RiskCeiling.R1,
        allowed_capability_ids=("platform.metrics.read",),
    ),
    "automation_workflow": AgentManifest(
        name="automation_workflow",
        display_name="Automation & Workflow Agent",
        description=(
            "Monitors operational backlog - pending approvals awaiting a human decision "
            "- and surfaces it clearly."
        ),
        system_prompt=(
            "You are the Automation & Workflow Agent for GDS Security OS. You monitor "
            "the tenant's operational backlog, especially approvals still awaiting a "
            "human decision, and report it clearly and honestly."
        ),
        tool_names=("list_pending_approvals",),
        team=Team.FOUNDATION,
        department="Automation & Workflow",
        risk_ceiling=RiskCeiling.R1,
        allowed_capability_ids=("approvals.list_pending",),
    ),
    "platform_operations": AgentManifest(
        name="platform_operations",
        display_name="Platform Operations Agent",
        description=(
            "Checks the real health of every infrastructure service and reports the "
            "platform's operational status."
        ),
        system_prompt=(
            "You are the Platform Operations Agent for GDS Security OS. You check the "
            "real health of every infrastructure service (Postgres, Redis, Neo4j, "
            "Qdrant, Temporal, NATS, MinIO) and report the platform's operational status "
            "honestly - never claim a service is healthy without checking it."
        ),
        tool_names=("check_platform_health",),
        team=Team.FOUNDATION,
        department="Platform Operations",
        risk_ceiling=RiskCeiling.R1,
        allowed_capability_ids=("platform.health.read",),
    ),
    "executive_advisor": AgentManifest(
        name="executive_advisor",
        display_name="Executive Advisor Agent",
        description=(
            "Summarizes recent real mission activity for leadership - what was done, "
            "what risk it carried, and the real outcome."
        ),
        system_prompt=(
            "You are the Executive Advisor Agent for GDS Security OS. You summarize "
            "recent mission activity for leadership: what was done, what risk it "
            "carried, and the real outcome - never embellished, never speculative."
        ),
        tool_names=("list_recent_missions",),
        team=Team.FOUNDATION,
        department="Executive Advisory",
        risk_ceiling=RiskCeiling.R1,
        allowed_capability_ids=("mission.list_recent",),
    ),
    "threat_intelligence": AgentManifest(
        name="threat_intelligence",
        display_name="Threat Intelligence Agent",
        description=(
            "Checks the real CISA Known Exploited Vulnerabilities feed against this "
            "tenant's watchlist and records real findings for matches."
        ),
        system_prompt=(
            "You are the Threat Intelligence Agent for GDS Security OS. You check the "
            "real CISA KEV feed against this tenant's watchlist and report only what the "
            "feed actually returned - never invent a CVE or a match that wasn't real."
        ),
        tool_names=("check_cisa_kev",),
        team=Team.BLUE,
        department="Threat Intelligence",
        risk_ceiling=RiskCeiling.R3,
        allowed_capability_ids=("threat_intel.lookup_cve",),
        workforce="purple-cybersecurity-workforce",
        purple_role_id="purple-05",
        purple_role_name="Threat Intelligence Agent",
        operational_domain="Threat Intelligence",
        mission_role=(
            "CVE/KEV intelligence enrichment against the real CISA Known Exploited "
            "Vulnerabilities feed."
        ),
        objectives=(
            "Cross-reference the tenant's CVE watchlist against the live CISA KEV catalog",
        ),
        knowledge_domains=("CVE intelligence", "CISA KEV", "exploit intelligence"),
        skills=("feed cross-referencing", "watchlist-driven enrichment"),
        approval_requirements=("threat_intel.lookup_cve requires human approval (R3)",),
        evidence_requirements=("Finding.raw_data retains the raw KEV catalog entry",),
        input_contracts=("tenant Watchlist rows with kind='cve'",),
        output_contracts=(
            "Finding(source='cisa_kev'), severity=critical if actively "
            "ransomware-exploited else high",
        ),
        collaboration_contracts=("vulnerability_management", "threat_hunting"),
        repository_permissions=("none",),
        workspace_permissions=("none",),
        health_checks=("check_cisa_kev call succeeds against the live CISA KEV feed",),
        owner="Purple Security Command / Rabbani AI Core",
        documentation_reference="docs/architecture/unified-purple-workforce.md#purple-05",
    ),
    "vulnerability_management": AgentManifest(
        name="vulnerability_management",
        display_name="Vulnerability Management Agent",
        description=(
            "Queries the real OSV.dev database for known vulnerabilities affecting a "
            "given package and ecosystem, and records real findings for matches."
        ),
        system_prompt=(
            "You are the Vulnerability Management Agent for GDS Security OS. You query "
            "the real OSV.dev vulnerability database for a specific package and "
            "ecosystem, enrich real CVE findings with real CVSS/EPSS/KEV data, and "
            "compute a real, deterministic priority score - report only what these "
            "real sources actually returned."
        ),
        tool_names=("search_osv_vulnerabilities", "enrich_finding", "prioritise_finding"),
        team=Team.BLUE,
        department="Vulnerability Management",
        risk_ceiling=RiskCeiling.R3,
        allowed_capability_ids=(
            "vulnerability.lookup",
            "finding.enrich",
            "finding.prioritise",
        ),
        workforce="purple-cybersecurity-workforce",
        purple_role_id="purple-06",
        purple_role_name="Vulnerability and Exposure Management Agent",
        operational_domain="Vulnerability Management",
        mission_role=(
            "Core Agentic OS mandate: package-vulnerability ingestion via real OSV.dev lookups, "
            "real CVE/CVSS/EPSS/KEV enrichment (Phase 20, Part 9), real deterministic "
            "prioritisation, finding dedup and triage handoff. Reachability/exposure analysis "
            "and SLA/exception tracking are honestly not yet built - see "
            "docs/reviews/phase-20-purple-workforce-pre-build-audit.md section 9."
        ),
        objectives=(
            "Query real OSV.dev for a given package/ecosystem",
            "Record real, deduplicated Finding rows for genuine matches",
            "Enrich a real CVE finding with real CVSS/EPSS/KEV data",
            "Compute a real, deterministic priority score for an enriched finding",
        ),
        knowledge_domains=("vulnerability management", "CVE/OSV data", "CVSS", "EPSS", "CISA KEV"),
        skills=(
            "package vulnerability lookup",
            "finding dedup",
            "CVE enrichment",
            "prioritisation",
        ),
        approval_requirements=("vulnerability.lookup requires human approval (R3)",),
        evidence_requirements=("Finding.raw_data retains the raw OSV.dev match",),
        input_contracts=("package name + ecosystem supplied by the requesting mission",),
        output_contracts=(
            "Finding(source='osv') rows, deduplicated on (source, external_id)",
            "Finding.cvss/epss/kev_listed populated for real CVE findings",
        ),
        collaboration_contracts=(
            "threat_intelligence",
            "devsecops",
            "defensive_remediation_autofix",
            "validation_retest",
        ),
        repository_permissions=("none",),
        workspace_permissions=("none",),
        health_checks=(
            "search_osv_vulnerabilities call succeeds against the live OSV.dev API",
            "enrich_finding call succeeds against the live FIRST.org EPSS API and CISA KEV feed",
        ),
        degraded_reason=(
            "Real OSV.dev-backed lookup, Finding creation, real CVSS/EPSS/KEV enrichment "
            "(Phase 20, Part 9), and deterministic prioritisation are operational; "
            "reachability analysis, exposure analysis and SLA/exception tracking are planned "
            "for a later Phase 20 sub-phase (Part 10), not yet implemented."
        ),
        owner="Purple Security Command / Rabbani AI Core",
        documentation_reference="docs/architecture/unified-purple-workforce.md#purple-06",
    ),
    "threat_hunting": AgentManifest(
        name="threat_hunting",
        display_name="Threat Hunting Agent",
        description=(
            "Checks a URL or host against abuse.ch URLhaus's real online-malicious-URL "
            "feed and records a real finding if it's known-malicious."
        ),
        system_prompt=(
            "You are the Threat Hunting Agent for GDS Security OS. You check a specific "
            "URL or host against the real abuse.ch URLhaus feed and report the real "
            "result - a clean result is a valid, honest outcome, not a failure."
        ),
        tool_names=("check_threat_indicator",),
        team=Team.BLUE,
        department="Threat Hunting",
        risk_ceiling=RiskCeiling.R3,
        allowed_capability_ids=("threat_intel.lookup_ioc",),
        workforce="purple-cybersecurity-workforce",
        purple_role_id="purple-04",
        purple_role_name="Threat Hunting Agent",
        operational_domain="Threat Hunting",
        mission_role=(
            "IOC hunting against a real abuse.ch URLhaus feed; hunt-to-detection reporting."
        ),
        objectives=("Check a specific URL/host against real known-malicious indicators",),
        knowledge_domains=("IOC hunting", "MITRE ATT&CK"),
        skills=("indicator lookup", "hunt reporting"),
        approval_requirements=("threat_intel.lookup_ioc requires human approval (R3)",),
        evidence_requirements=("Finding.raw_data retains the matched feed entry",),
        input_contracts=("indicator (url|host) supplied by the requesting mission",),
        output_contracts=("Finding(source='urlhaus') on match, honest clean result otherwise",),
        collaboration_contracts=("malware_analysis", "threat_intelligence", "blue_team"),
        repository_permissions=("none",),
        workspace_permissions=("none",),
        health_checks=("check_threat_indicator call succeeds against the live URLhaus feed",),
        owner="Purple Security Command / Rabbani AI Core",
        documentation_reference="docs/architecture/unified-purple-workforce.md#purple-04",
    ),
    "blue_team": AgentManifest(
        name="blue_team",
        display_name="Blue Team Agent",
        description=(
            "Triages new findings using deterministic severity rules and monitors the "
            "tenant's open-findings backlog."
        ),
        system_prompt=(
            "You are the Blue Team Agent for GDS Security OS. You triage newly detected "
            "findings using deterministic rules (never self-authorizing an escalation "
            "decision) and report the tenant's real open-findings backlog honestly."
        ),
        tool_names=("triage_finding", "list_open_findings"),
        team=Team.BLUE,
        department="Security Operations",
        risk_ceiling=RiskCeiling.R1,
        allowed_capability_ids=("finding.triage", "finding.list_open"),
        workforce="purple-cybersecurity-workforce",
        purple_role_id="purple-02",
        purple_role_name="SOC Detection and Triage Agent",
        operational_domain="Security Operations",
        mission_role="Alert triage, severity classification, escalation, queue prioritisation.",
        objectives=(
            "Deterministic severity-to-risk_class triage of new findings",
            "Surface the tenant's real open-findings backlog",
        ),
        knowledge_domains=(
            "alert triage",
            "severity classification",
            "MITRE ATT&CK (mapping context)",
        ),
        skills=("deterministic finding triage", "backlog prioritisation"),
        approval_requirements=(),
        evidence_requirements=("Finding.raw_data preserved from source feed",),
        input_contracts=("Finding rows with status='new'",),
        output_contracts=("Finding.risk_class set, Finding.status advanced",),
        collaboration_contracts=("incident_response", "risk_business_intelligence"),
        repository_permissions=("none",),
        workspace_permissions=("none",),
        health_checks=("triage_finding call succeeds against a real Finding row",),
        owner="Purple Security Command / Rabbani AI Core",
        documentation_reference="docs/architecture/unified-purple-workforce.md#purple-02",
    ),
    "incident_response": AgentManifest(
        name="incident_response",
        display_name="Incident Response Agent",
        description=(
            "Escalates triaged high/critical findings into a real incident and monitors "
            "the tenant's open-incidents backlog."
        ),
        system_prompt=(
            "You are the Incident Response Agent for GDS Security OS. You escalate "
            "triaged high/critical findings into a real incident and report the tenant's "
            "real open-incidents backlog - never claim an incident exists that wasn't "
            "actually created."
        ),
        tool_names=("create_incident_from_findings", "list_open_incidents"),
        team=Team.BLUE,
        department="Incident Response",
        risk_ceiling=RiskCeiling.R2,
        allowed_capability_ids=("incident.create", "incident.list_open"),
        workforce="purple-cybersecurity-workforce",
        purple_role_id="purple-03",
        purple_role_name="Incident Response and DFIR Agent",
        operational_domain="Incident Response",
        mission_role=(
            "Escalates triaged findings into real incidents and tracks the open-incident backlog."
        ),
        objectives=(
            "Escalate triaged high/critical findings into a real Incident",
            "Report the tenant's real open-incidents backlog",
        ),
        knowledge_domains=("incident response", "NIST SP 800-61"),
        skills=("finding-to-incident escalation", "incident backlog monitoring"),
        approval_requirements=(),
        evidence_requirements=("IncidentFinding linkage preserved for every escalated finding",),
        input_contracts=("Finding rows with status='triaged', risk_class in (high, critical)",),
        output_contracts=("Incident row created, IncidentFinding join rows written",),
        collaboration_contracts=(
            "blue_team",
            "digital_forensics",
            "security_documentation_reporting",
        ),
        repository_permissions=("none",),
        workspace_permissions=("none",),
        health_checks=("create_incident_from_findings succeeds against real triaged findings",),
        owner="Purple Security Command / Rabbani AI Core",
        documentation_reference="docs/architecture/unified-purple-workforce.md#purple-03",
    ),
    "security_architecture": AgentManifest(
        name="security_architecture",
        display_name="Security Architecture Agent",
        description=(
            "Reviews this tenant's real policy rules and role/permission structure and "
            "reports the actual architecture, not a generic template."
        ),
        system_prompt=(
            "You are the Security Architecture Agent for GDS Security OS. You review "
            "this tenant's real policy rules and role/permission structure and report "
            "the actual architecture - never invent a control that isn't really "
            "configured."
        ),
        tool_names=("review_platform_architecture",),
        team=Team.BLUE,
        department="Security Architecture",
        risk_ceiling=RiskCeiling.R1,
        allowed_capability_ids=("compliance.review_architecture",),
        workforce="purple-cybersecurity-workforce",
        purple_role_id="purple-19",
        purple_role_name="Governance, Risk, Compliance and Evidence Agent",
        operational_domain="Governance, Risk and Compliance",
        mission_role="Reviews this tenant's real policy rules and role/permission architecture.",
        objectives=("Report the real, actually-configured policy/role architecture",),
        knowledge_domains=("security architecture review", "control mapping"),
        skills=("policy/role architecture review",),
        approval_requirements=(),
        evidence_requirements=("Policy/Role query results preserved as reported",),
        input_contracts=("tenant Policy and Role tables",),
        output_contracts=("real architecture facts, never a fabricated control",),
        collaboration_contracts=("compliance_grc", "risk_business_intelligence"),
        repository_permissions=("none",),
        workspace_permissions=("none",),
        health_checks=("review_platform_architecture call succeeds against real tenant data",),
        owner="Purple Security Command / Rabbani AI Core",
        documentation_reference="docs/architecture/unified-purple-workforce.md#purple-19",
    ),
    "identity_access_management": AgentManifest(
        name="identity_access_management",
        display_name="Identity and Access Management Agent",
        description=(
            "Reviews this platform's real user/role data and flags roles holding broad permissions."
        ),
        system_prompt=(
            "You are the Identity and Access Management Agent for GDS Security OS. You "
            "review this platform's real user and role data (its own JWT-based auth - "
            "no external IdP is configured) and report real facts about permission "
            "breadth, never a fabricated MFA/SSO posture."
        ),
        tool_names=("review_identity_posture",),
        team=Team.BLUE,
        department="Identity and Access Management",
        risk_ceiling=RiskCeiling.R1,
        allowed_capability_ids=("compliance.review_identity",),
        workforce="purple-cybersecurity-workforce",
        purple_role_id="purple-12",
        purple_role_name="Identity and Zero-Trust Security Agent",
        operational_domain="Identity Security",
        mission_role=(
            "Reviews this platform's own real User/Role data and flags broad-permission roles."
        ),
        objectives=("Report real user/role counts and flag roles with broad permissions",),
        knowledge_domains=("identity and access management", "least privilege"),
        skills=("permission-breadth review",),
        approval_requirements=(),
        evidence_requirements=("User/Role query results preserved as reported",),
        input_contracts=("this platform's own User/Role tables",),
        output_contracts=(
            "real facts only; mfa_enforced honestly reported as False (no external IdP)",
        ),
        collaboration_contracts=("security_architecture", "compliance_grc"),
        repository_permissions=("none",),
        workspace_permissions=("none",),
        health_checks=("review_identity_posture call succeeds against real platform data",),
        degraded_reason=(
            "Reviews this platform's own JWT-based auth only - no external IdP/SSO/MFA "
            "integration exists to review; zero-trust control validation beyond permission "
            "breadth is planned for a later Phase 20 sub-phase."
        ),
        owner="Purple Security Command / Rabbani AI Core",
        documentation_reference="docs/architecture/unified-purple-workforce.md#purple-12",
    ),
    "network_security": AgentManifest(
        name="network_security",
        display_name="Network Security Agent",
        description=(
            "Runs a real, passive TLS certificate check against a tenant-authorized domain."
        ),
        system_prompt=(
            "You are the Network Security Agent for GDS Security OS. You run a real, "
            "passive TLS certificate check against a domain this tenant has explicitly "
            "authorized on its Watchlist - refuse any other target and report the real "
            "certificate expiry and issuer."
        ),
        tool_names=("check_domain_security",),
        team=Team.BLUE,
        department="Network Security",
        risk_ceiling=RiskCeiling.R2,
        allowed_capability_ids=("network.check_domain_security",),
        workforce="purple-cybersecurity-workforce",
        purple_role_id="purple-09",
        purple_role_name="Network Penetration Testing Agent",
        operational_domain="Network Security Testing",
        mission_role="Real, passive TLS certificate check against a tenant-authorized domain.",
        objectives=("Report real TLS certificate expiry/issuer for an authorized domain",),
        knowledge_domains=("TLS/certificate validation",),
        skills=("passive TLS probing",),
        approval_requirements=(),
        evidence_requirements=("raw certificate fields preserved as reported",),
        input_contracts=("domain present on the tenant's Watchlist",),
        output_contracts=("real certificate issuer/expiry, refuses any non-authorized target",),
        collaboration_contracts=(
            "red_team",
            "api_application_security",
            "penetration_testing_coordinator",
        ),
        repository_permissions=("none",),
        workspace_permissions=("none",),
        health_checks=("check_domain_security call succeeds against a real authorized domain",),
        degraded_reason=(
            "Passive TLS certificate probing only. Network enumeration, service validation, "
            "misconfiguration testing and controlled exploitation (Prompt 7 Part 3, Agent 09) "
            "require new ADR-gated tooling per docs/adr/0007 - not yet built."
        ),
        owner="Purple Security Command / Rabbani AI Core",
        documentation_reference="docs/architecture/unified-purple-workforce.md#purple-09",
    ),
    "api_application_security": AgentManifest(
        name="api_application_security",
        display_name="API and Application Security Agent",
        description=(
            "Runs a real, passive HTTP security-header check against a tenant-authorized URL."
        ),
        system_prompt=(
            "You are the API and Application Security Agent for GDS Security OS. You "
            "run a real, passive HTTP security-header check against a URL this tenant "
            "has explicitly authorized on its Watchlist - refuse any other target and "
            "report which real security headers are present or missing."
        ),
        tool_names=("check_url_security_headers",),
        team=Team.BLUE,
        department="API and Application Security",
        risk_ceiling=RiskCeiling.R2,
        allowed_capability_ids=("network.check_url_headers",),
        workforce="purple-cybersecurity-workforce",
        purple_role_id="purple-10",
        purple_role_name="Web Application and API Penetration Testing Agent",
        operational_domain="Application Security Testing",
        mission_role="Real, passive HTTP security-header check against a tenant-authorized URL.",
        objectives=("Report which real security headers are present/missing on an authorized URL",),
        knowledge_domains=("OWASP Web Top 10 (header-hardening subset)",),
        skills=("passive HTTP header inspection",),
        approval_requirements=(),
        evidence_requirements=("raw header presence/absence preserved as reported",),
        input_contracts=("URL present on the tenant's Watchlist",),
        output_contracts=("real header findings, refuses any non-authorized target",),
        collaboration_contracts=(
            "network_security",
            "devsecops",
            "penetration_testing_coordinator",
        ),
        repository_permissions=("none",),
        workspace_permissions=("none",),
        health_checks=("check_url_security_headers call succeeds against a real authorized URL",),
        degraded_reason=(
            "Passive HTTP security-header check only - explicitly not a DAST/exploitation tool. "
            "OWASP Web/API Top 10 testing, authN/authZ testing, BOLA/BFLA validation, and "
            "approved fuzzing (Prompt 7 Part 3, Agent 10) require new tooling - not yet built."
        ),
        owner="Purple Security Command / Rabbani AI Core",
        documentation_reference="docs/architecture/unified-purple-workforce.md#purple-10",
    ),
    "compliance_grc": AgentManifest(
        name="compliance_grc",
        display_name="Compliance and GRC Agent",
        description=(
            "Reviews this platform's real, honest control implementation - no "
            "fabricated framework mapping."
        ),
        system_prompt=(
            "You are the Compliance and GRC Agent for GDS Security OS. You report this "
            "platform's real control implementation honestly, including real gaps (e.g. "
            "no MFA) - never invent a compliance score or framework certification that "
            "doesn't exist."
        ),
        tool_names=("review_compliance_posture",),
        team=Team.BLUE,
        department="Compliance and GRC",
        risk_ceiling=RiskCeiling.R1,
        allowed_capability_ids=("compliance.review_posture",),
        workforce="purple-cybersecurity-workforce",
        purple_role_id="purple-19",
        purple_role_name="Governance, Risk, Compliance and Evidence Agent",
        operational_domain="Governance, Risk and Compliance",
        mission_role=(
            "Reports this platform's real, honest control implementation - no "
            "fabricated framework mapping."
        ),
        objectives=("Report real policy-count/approval-gating facts and real gaps (e.g. no MFA)",),
        knowledge_domains=("GRC", "ISO/IEC 27001 (context only, no mapping engine yet)"),
        skills=("policy posture review",),
        approval_requirements=(),
        evidence_requirements=("Policy query results preserved as reported",),
        input_contracts=("tenant Policy table",),
        output_contracts=("real facts only, never an invented compliance score/certification",),
        collaboration_contracts=("security_architecture", "risk_business_intelligence"),
        repository_permissions=("none",),
        workspace_permissions=("none",),
        health_checks=("review_compliance_posture call succeeds against real tenant data",),
        degraded_reason=(
            "No SOC2/ISO27001/NIST/PCI-DSS/HIPAA control-framework mapping exists yet; this is a "
            "real self-report of policy counts and approval-gating, not a framework mapping engine."
        ),
        owner="Purple Security Command / Rabbani AI Core",
        documentation_reference="docs/architecture/unified-purple-workforce.md#purple-19",
    ),
    "risk_business_intelligence": AgentManifest(
        name="risk_business_intelligence",
        display_name="Risk and Business Intelligence Agent",
        description=(
            "Calculates a real, deterministic risk-exposure score from this tenant's "
            "actual open findings and incidents."
        ),
        system_prompt=(
            "You are the Risk and Business Intelligence Agent for GDS Security OS. You "
            "calculate a real, deterministic risk-exposure score from this tenant's "
            "actual open findings/incidents and explain the real formula - never "
            "present an estimate as if it were more precise than it is."
        ),
        tool_names=("calculate_risk_exposure",),
        team=Team.BLUE,
        department="Risk and Business Intelligence",
        risk_ceiling=RiskCeiling.R1,
        allowed_capability_ids=("risk.calculate_exposure",),
        workforce="purple-cybersecurity-workforce",
        purple_role_id="purple-19",
        purple_role_name="Governance, Risk, Compliance and Evidence Agent",
        operational_domain="Governance, Risk and Compliance",
        mission_role=(
            "Deterministic, real risk-exposure scoring from actual open findings/incidents."
        ),
        objectives=("Calculate and explain a real, formula-transparent risk-exposure score",),
        knowledge_domains=("risk quantification",),
        skills=("deterministic risk scoring",),
        approval_requirements=(),
        evidence_requirements=("open Finding/Incident counts preserved as scored",),
        input_contracts=("tenant's real open Finding/Incident rows",),
        output_contracts=("weighted score with its formula disclosed, never false precision",),
        collaboration_contracts=("blue_team", "security_architecture", "compliance_grc"),
        repository_permissions=("none",),
        workspace_permissions=("none",),
        health_checks=("calculate_risk_exposure call succeeds against real tenant data",),
        owner="Purple Security Command / Rabbani AI Core",
        documentation_reference="docs/architecture/unified-purple-workforce.md#purple-19",
    ),
    "digital_forensics": AgentManifest(
        name="digital_forensics",
        display_name="Digital Forensics Agent",
        description=(
            "Verifies real chain-of-custody integrity by re-downloading stored evidence "
            "and recomputing its hash."
        ),
        system_prompt=(
            "You are the Digital Forensics Agent for GDS Security OS. You verify real "
            "chain-of-custody integrity by re-downloading stored evidence from MinIO and "
            "recomputing its SHA-256 against the recorded hash - report exactly what "
            "matched or didn't, never assume integrity without checking."
        ),
        tool_names=("verify_evidence_integrity",),
        team=Team.BLUE,
        department="Digital Forensics",
        risk_ceiling=RiskCeiling.R1,
        allowed_capability_ids=("evidence.verify_integrity",),
        workforce="purple-cybersecurity-workforce",
        purple_role_id="purple-03",
        purple_role_name="Incident Response and DFIR Agent",
        operational_domain="Incident Response",
        mission_role=(
            "Verifies chain-of-custody integrity of stored evidence via real hash re-computation."
        ),
        objectives=("Re-verify stored evidence integrity against its recorded SHA-256 hash",),
        knowledge_domains=("digital forensics", "chain of custody"),
        skills=("evidence hash verification",),
        approval_requirements=(),
        evidence_requirements=("Evidence.content_hash preserved and independently re-verifiable",),
        input_contracts=("Evidence rows stored in MinIO",),
        output_contracts=("intact: bool per evidence item, no mutation of the evidence itself",),
        collaboration_contracts=("incident_response", "validation_retest"),
        repository_permissions=("none",),
        workspace_permissions=("none",),
        health_checks=("verify_evidence_integrity succeeds against a real stored Evidence row",),
        owner="Purple Security Command / Rabbani AI Core",
        documentation_reference="docs/architecture/unified-purple-workforce.md#purple-03",
    ),
    "devsecops": AgentManifest(
        name="devsecops",
        display_name="DevSecOps Agent",
        description=(
            "Runs real SCA via OSV.dev against this codebase's own real Python/npm "
            "dependency manifests."
        ),
        system_prompt=(
            "You are the DevSecOps Agent for GDS Security OS. You run real dependency "
            "vulnerability scanning (via OSV.dev) against this codebase's own real "
            "pyproject.toml/package.json manifests - report only real matches, never a "
            "fabricated CI/CD pipeline status this project doesn't have."
        ),
        tool_names=("scan_own_dependencies",),
        team=Team.BLUE,
        department="DevSecOps",
        risk_ceiling=RiskCeiling.R3,
        allowed_capability_ids=("vulnerability.scan_dependencies",),
        workforce="purple-cybersecurity-workforce",
        purple_role_id="purple-16",
        purple_role_name="Application and Software Supply-Chain Security Agent",
        operational_domain="Supply Chain Security",
        mission_role=(
            "Real SCA via OSV.dev against this codebase's own real Python/npm dependency manifests."
        ),
        objectives=("Scan real declared dependencies for known vulnerabilities via OSV.dev",),
        knowledge_domains=("software composition analysis", "supply chain security"),
        skills=("dependency vulnerability scanning",),
        approval_requirements=("vulnerability.scan_dependencies requires human approval (R3)",),
        evidence_requirements=("Finding.raw_data retains the raw OSV.dev match",),
        input_contracts=("this repo's own pyproject.toml/package.json",),
        output_contracts=("Finding(source='osv') rows for this repo's own dependencies",),
        collaboration_contracts=("vulnerability_management", "defensive_remediation_autofix"),
        repository_permissions=("read-only: this repo's own manifest files",),
        workspace_permissions=("none",),
        health_checks=("scan_own_dependencies call succeeds against the live OSV.dev API",),
        degraded_reason=(
            "SCA is scoped to this repo's own manifests only - no tenant-repository SCA wired "
            "up yet. No SBOM generation (CycloneDX/SPDX), no secrets detection, no CI/CD security "
            "review exist yet."
        ),
        owner="Purple Security Command / Rabbani AI Core",
        documentation_reference="docs/architecture/unified-purple-workforce.md#purple-16",
    ),
    "malware_analysis": AgentManifest(
        name="malware_analysis",
        display_name="Malware Analysis Agent",
        description=(
            "Checks a file hash against abuse.ch MalwareBazaar's real recent-samples feed."
        ),
        system_prompt=(
            "You are the Malware Analysis Agent for GDS Security OS. You check a file "
            "hash against abuse.ch MalwareBazaar's real recent-samples feed - a clean "
            "result is a valid, honest outcome (it only covers recent samples, not the "
            "full historical database), never claim a sandboxed detonation this project "
            "doesn't have."
        ),
        tool_names=("check_malware_hash",),
        team=Team.BLUE,
        department="Malware Analysis",
        risk_ceiling=RiskCeiling.R3,
        allowed_capability_ids=("threat_intel.lookup_malware_hash",),
        workforce="purple-cybersecurity-workforce",
        purple_role_id="purple-04",
        purple_role_name="Threat Hunting Agent",
        operational_domain="Threat Hunting",
        mission_role=(
            "Hash-based IOC hunting against a real abuse.ch MalwareBazaar recent-samples feed."
        ),
        objectives=("Check a file hash against real recent known-malware samples",),
        knowledge_domains=("malware IOC hunting",),
        skills=("hash lookup", "hunt reporting"),
        approval_requirements=("threat_intel.lookup_malware_hash requires human approval (R3)",),
        evidence_requirements=("Finding.raw_data retains the matched feed entry",),
        input_contracts=("file hash supplied by the requesting mission",),
        output_contracts=(
            "Finding(source='malwarebazaar') on match, honest clean result otherwise",
        ),
        collaboration_contracts=("threat_hunting", "threat_intelligence"),
        repository_permissions=("none",),
        workspace_permissions=("none",),
        health_checks=("check_malware_hash call succeeds against the live MalwareBazaar feed",),
        owner="Purple Security Command / Rabbani AI Core",
        documentation_reference="docs/architecture/unified-purple-workforce.md#purple-04",
    ),
    "red_team": AgentManifest(
        name="red_team",
        display_name="Red Team Agent",
        description=(
            "Runs real, passive/lightweight-active reconnaissance (DNS resolution, a "
            "narrow well-known-port TCP connect check, TLS certificate probing) against "
            "explicitly authorized targets only - never exploitation."
        ),
        system_prompt=(
            "You are the Red Team Agent for GDS Security OS. You run REAL but strictly "
            "passive or lightweight-active reconnaissance - DNS A-record resolution, a "
            "narrow well-known-port TCP connect check, and TLS certificate probing - "
            "and nothing more. You never attempt exploitation, credential attacks, "
            "denial of service, or any destructive action. Every tool call you make is "
            "already gated by gds_api.redteam_safety (emergency stop, explicit target "
            "authorization, rate limiting) before it reaches you, and every one of your "
            "tools is 'critical' risk - a human always approves it first. Report "
            "findings honestly and factually; an unauthorized-target refusal is the "
            "safety boundary working correctly, not a failure to explain away."
        ),
        tool_names=("recon_dns_enumeration", "recon_port_scan", "assess_attack_surface"),
        team=Team.RED,
        department="Offensive Security",
        risk_ceiling=RiskCeiling.R4,
        target_authorisation_required=True,
        allowed_capability_ids=(
            "red_team.recon_passive",
            "red_team.recon_active",
            "red_team.assess_attack_surface",
        ),
        workforce="purple-cybersecurity-workforce",
        purple_role_id="purple-08",
        purple_role_name="External Attack Surface and Reconnaissance Agent",
        operational_domain="Attack Surface Management",
        mission_role=(
            "Real, strictly passive/lightweight-active DNS, port and TLS reconnaissance "
            "against explicitly authorised targets only - gated end-to-end by "
            "gds_api.redteam_safety. No exploitation, no credential attacks, no DoS."
        ),
        objectives=(
            "DNS A-record enumeration against an authorised target",
            "Well-known-port TCP connect check against an authorised target",
            "Passive attack-surface/TLS assessment against an authorised target",
        ),
        knowledge_domains=("reconnaissance", "DNS", "TLS", "MITRE ATT&CK (recon tactics)"),
        skills=("DNS enumeration", "port scanning", "TLS probing"),
        approval_requirements=(
            "human approval always required (R4/critical)",
            "explicit AuthorizedTarget required before any tool call",
            "emergency-stop must be clear",
        ),
        evidence_requirements=(
            "raw DNS/port/TLS probe results preserved verbatim, refusals audited too",
        ),
        input_contracts=("target string matching an active, unexpired AuthorizedTarget row",),
        output_contracts=("computed (not model-invented) DNS/port/TLS summary",),
        collaboration_contracts=(
            "penetration_testing_coordinator",
            "network_security",
            "api_application_security",
        ),
        repository_permissions=("none",),
        workspace_permissions=("none",),
        health_checks=(
            "redteam_safety 3-check boundary (emergency-stop, target-auth, rate-limit) passes",
        ),
        degraded_reason=(
            "Real recon tools only (DNS/port/TLS). Any expansion toward broader external "
            "attack-surface management (subdomain enumeration, certificate-transparency search, "
            "shadow-IT discovery) requires its own ADR per docs/adr/0007 before being built."
        ),
        owner="Purple Security Command / Rabbani AI Core",
        documentation_reference="docs/architecture/unified-purple-workforce.md#purple-08",
    ),
    # Phase 20, Part 9: promoted from PLANNED_AGENTS to a real AgentManifest - its
    # first real capability (validate_finding) now exists. Status is DEGRADED, not
    # OPERATIONAL: independent finding validation/rejection is real, but retest
    # execution (confirming a remediation actually closed an attack path) is still
    # Part 10 work, so this agent's own name ("...and Retest") is only half-real
    # today - degraded_reason discloses the gap honestly rather than claiming full
    # operational status for half a role.
    "validation_retest": AgentManifest(
        name="validation_retest",
        display_name="Validation and Retest Agent",
        description=(
            "Independently validates or rejects findings awaiting validation - never "
            "trusting a patch's existence alone. Real retest execution is not yet built."
        ),
        system_prompt=(
            "You are the Validation and Retest Agent for GDS Security OS. You "
            "independently validate or reject findings awaiting validation, with a "
            "real, stated reason for every decision - you never self-authorize a "
            "validation the way the finding's own source agent could, and you never "
            "mark a finding closed merely because a patch or commit exists."
        ),
        tool_names=("validate_finding",),
        team=Team.BLUE,
        department="Validation and Assurance",
        risk_ceiling=RiskCeiling.R2,
        status=AgentStatus.DEGRADED,
        allowed_capability_ids=("finding.validate",),
        workforce="purple-cybersecurity-workforce",
        purple_role_id="purple-18",
        purple_role_name="Validation and Retest Agent",
        operational_domain="Validation and Assurance",
        mission_role=(
            "Independently validates findings and rejects weak/unsupported ones (real, "
            "Phase 20 Part 9). Retesting remediation and confirming attack-path closure "
            "is Part 10 work, not yet built."
        ),
        objectives=(
            "Independently validate or reject a finding awaiting validation, with a "
            "real, documented reason",
        ),
        knowledge_domains=("independent validation", "retest methodology"),
        skills=("finding validation/rejection",),
        approval_requirements=(),
        evidence_requirements=("Finding.raw_data and enrichment fields reviewed before deciding",),
        input_contracts=("Finding rows with status='awaiting_validation'",),
        output_contracts=("Finding.status set to validated|rejected with a real reason recorded",),
        collaboration_contracts=(
            "vulnerability_management",
            "defensive_remediation_autofix",
            "digital_forensics",
        ),
        repository_permissions=("none",),
        workspace_permissions=("none",),
        health_checks=(
            "validate_finding call succeeds against a real awaiting_validation Finding",
        ),
        degraded_reason=(
            "Independent finding validation/rejection is real and operational (Phase 20, "
            "Part 9). Real retest execution (confirming a remediation actually closed the "
            "underlying issue) is Part 10 work, not yet built - this agent's own name is "
            "only half-real today, disclosed here rather than claimed as complete."
        ),
        owner="Purple Security Command / Rabbani AI Core",
        documentation_reference="docs/architecture/unified-purple-workforce.md#purple-18",
    ),
    # Phase 20, Part 10: promoted from PLANNED_AGENTS to a real AgentManifest -
    # auto_fix_finding is its first real capability. Status is DEGRADED, not
    # OPERATIONAL: it can trigger a real, governed remediation mission for a
    # validated finding, but the underlying Phase 18/19 write path's own real
    # commit is a background, asynchronous process this agent doesn't itself
    # wait on or guarantee completes - degraded_reason discloses this honestly.
    "defensive_remediation_autofix": AgentManifest(
        name="defensive_remediation_autofix",
        display_name="Defensive Remediation and Auto-Fix Agent",
        description=(
            "Routes a real, validated Finding into the existing, real, operational "
            "governed engineering write path (Repository Registry -> Workspace "
            "Manager -> Secure Capability Broker -> AIProvider -> Review Engine -> "
            "Human Approval -> Local Commit) to produce an approval-gated fix."
        ),
        system_prompt=(
            "You are the Defensive Remediation and Auto-Fix Agent for GDS Security "
            "OS. You route a real, validated finding into the existing governed "
            "engineering write path to produce a real, approval-gated fix - you "
            "never bypass human approval, and you never claim a fix is complete "
            "until its real commit actually lands."
        ),
        tool_names=("auto_fix_finding",),
        team=Team.BLUE,
        department="Remediation Engineering",
        risk_ceiling=RiskCeiling.R2,
        status=AgentStatus.DEGRADED,
        allowed_capability_ids=("remediation.auto_fix_finding",),
        workforce="purple-cybersecurity-workforce",
        purple_role_id="purple-17",
        purple_role_name="Defensive Remediation and Auto-Fix Agent",
        operational_domain="Remediation Engineering",
        mission_role=(
            "Real, operational trigger (Phase 20, Part 10) into the existing Phase "
            "18/19 governed engineering write path for a validated finding. Does "
            "not itself wait for or guarantee the resulting mission's real commit -"
            " that remains a real, separately-approved, asynchronous process."
        ),
        objectives=("Route a validated finding into a real, governed remediation mission",),
        knowledge_domains=("secure remediation", "governed code change management"),
        skills=("finding-to-remediation-mission routing",),
        approval_requirements=(
            "the resulting mission's eventual commit requires human approval "
            "(engineering.commit_mission, unchanged from Phase 18/19)",
        ),
        evidence_requirements=(
            "MissionPlan.finding_id links the remediation mission to its finding",
        ),
        input_contracts=("Finding rows with status='validated'",),
        output_contracts=(
            "Finding.status set to remediation_planned, a real MissionPlan created "
            "and linked via finding_id",
        ),
        collaboration_contracts=("vulnerability_management", "validation_retest", "devsecops"),
        repository_permissions=(
            "write: only inside an isolated Workspace, never the primary repo",
        ),
        workspace_permissions=("creates one via the existing Workspace Manager",),
        health_checks=("auto_fix_finding call succeeds against a real validated Finding",),
        degraded_reason=(
            "Real trigger into the governed engineering write path is operational "
            "(Phase 20, Part 10). The eventual mission's own execution/commit is a "
            "real, separate, asynchronous, human-approved process this agent does "
            "not itself await or guarantee - disclosed here rather than claiming "
            "end-to-end completion this agent alone doesn't control."
        ),
        owner="Purple Security Command / Rabbani AI Core",
        documentation_reference="docs/architecture/unified-purple-workforce.md#purple-17",
    ),
    # Phase 20, Part 11: promoted from PLANNED_AGENTS to a real AgentManifest -
    # coordinate_pentest_engagement is its first real capability. Status is
    # DEGRADED, not OPERATIONAL: it coordinates real DNS/port/TLS reconnaissance
    # (the same 3 primitives the Red Team Agent's own tools use) across a real,
    # human-authorized Engagement, but performs no exploitation, no attack-path
    # validation, and creates no Finding rows yet - degraded_reason discloses this
    # honestly rather than claiming the full "Penetration Testing Coordinator" name.
    "penetration_testing_coordinator": AgentManifest(
        name="penetration_testing_coordinator",
        display_name="Penetration Testing Coordinator Agent",
        description=(
            "Coordinates real DNS/port/TLS reconnaissance across every authorized "
            "target in scope for a real, written, human-authorized Engagement "
            "(gds_api.models.Engagement) - rules of engagement, an allowed/"
            "prohibited technique list, and an exclusion list, layered on top of "
            "the existing AuthorizedTarget/redteam_safety boundary."
        ),
        system_prompt=(
            "You are the Penetration Testing Coordinator Agent for GDS Security "
            "OS. You coordinate real reconnaissance across a real, human-"
            "authorized Engagement's in-scope targets, strictly honoring its "
            "rules of engagement, allowed/prohibited techniques, and exclusion "
            "list - you never run a technique the engagement prohibits, and you "
            "never touch a target outside its explicit scope."
        ),
        tool_names=("coordinate_pentest_engagement",),
        team=Team.RED,
        department="Penetration Testing",
        risk_ceiling=RiskCeiling.R4,
        status=AgentStatus.DEGRADED,
        target_authorisation_required=True,
        allowed_capability_ids=("red_team.coordinate_pentest_engagement",),
        workforce="purple-cybersecurity-workforce",
        purple_role_id="purple-07",
        purple_role_name="Penetration Testing Coordinator Agent",
        operational_domain="Penetration Testing",
        mission_role=(
            "Real, operational coordinator (Phase 20, Part 11) of the existing 3 "
            "Red Team recon primitives across a real Engagement's in-scope "
            "targets. Does not itself generate Findings, assess exploitability, "
            "or perform any technique beyond real DNS/port/TLS reconnaissance."
        ),
        objectives=(
            "Run a real, human-authorized Engagement's in-scope reconnaissance, "
            "honoring its rules of engagement",
        ),
        knowledge_domains=("penetration test coordination", "rules of engagement"),
        skills=("multi-target recon coordination", "engagement lifecycle management"),
        approval_requirements=(
            "coordinate_pentest_engagement always requires human approval (R4), "
            "same as the 3 underlying red_team.* recon capabilities",
        ),
        evidence_requirements=(
            "Engagement.report_summary and the real per-target recon results "
            "recorded as PurpleMissionMessage rows",
        ),
        input_contracts=("Engagement rows with status='authorized'",),
        output_contracts=(
            "Engagement.status set to in_progress then completed, with a real, "
            "computed report_summary",
        ),
        collaboration_contracts=("red_team", "network_security", "api_application_security"),
        repository_permissions=("none",),
        workspace_permissions=("none",),
        health_checks=(
            "coordinate_pentest_engagement call succeeds against a real authorized Engagement",
        ),
        degraded_reason=(
            "Real, coordinated multi-target DNS/port/TLS reconnaissance under a real "
            "Engagement's rules of engagement is operational (Phase 20, Part 11). "
            "Test-plan generation, specialist assignment beyond this one agent, "
            "attack-path validation, and automated Finding creation from recon "
            "results are honestly not yet built - disclosed here rather than "
            "claiming the full 'coordinator' scope this agent's name implies."
        ),
        owner="Purple Security Command / Rabbani AI Core",
        documentation_reference="docs/architecture/unified-purple-workforce.md#purple-07",
    ),
}

# Phase 14: the authoritative record of agents that are real in taxonomy/intent but
# have no backend implementation. Previously this existed ONLY as a frontend-only
# TypeScript array (apps/web/lib/agents-registry.ts) with no backend record at all -
# a split source of truth flagged in docs/reviews/phase-14-current-state-audit.md.
# GET /agents/planned now serves this; the frontend fetches it instead of hardcoding
# its own copy.
PLANNED_AGENTS: dict[str, PlannedAgentManifest] = {
    "cloud_security": PlannedAgentManifest(
        name="cloud_security",
        display_name="Cloud Security Agent",
        description=(
            "Would review real cloud posture (IAM, storage, network exposure) against "
            "a connected AWS/Azure/GCP account - not yet possible without a real "
            "read-only cloud credential."
        ),
        team=Team.BLUE,
        department="Cloud Security",
        reason=(
            "Still Planned - real cloud posture scanning needs a real AWS/Azure/GCP "
            "read-only credential, which isn't configured. Every other agent through "
            "Phase 8 found a real, credential-free path; this one genuinely can't."
        ),
        required_connector_ids=("aws_readonly", "azure_readonly", "gcp_readonly"),
        workforce="purple-cybersecurity-workforce",
        purple_role_id="purple-11",
        purple_role_name="Cloud, Container and Kubernetes Security Agent",
        operational_domain="Cloud Security",
        mission_role=(
            "Would review real cloud posture (IAM, storage, network exposure) against a "
            "connected AWS/Azure/GCP account - not yet possible without a real read-only "
            "cloud credential. No Kubernetes-specific code exists yet either."
        ),
        objectives=(
            "Real cloud posture assessment once a real read-only credential is configured",
        ),
        knowledge_domains=("cloud security posture management", "CIS Benchmarks", "CSA CCM"),
        skills=(),
        collaboration_contracts=("penetration_testing_coordinator", "identity_access_management"),
        owner="Purple Security Command / Rabbani AI Core",
        documentation_reference="docs/architecture/unified-purple-workforce.md#purple-11",
    ),
    # EDP-009 Part 1, Section 32 (Cloud Agent Foundation): the minimum specialist
    # roster the section names, registered here rather than in AGENT_REGISTRY. This
    # is a genuinely different real gap than the "cloud_security" entry above (which
    # is blocked on missing live credentials for POSTURE assessment - out of scope
    # for Part 1 anyway, per Section 48). Discovery/inventory itself does NOT need a
    # live credential to be real - the `cloud.discover_environment` capability
    # already runs today (ADR 0050), returning honest 0-asset results without one.
    # The real blocker is structural: capabilities/catalog.py's own comment on
    # `cloud.discover_environment` documents it as deliberately Rabbani-direct-only
    # (both agent allow-lists empty) so the already-shipped, live-verified "Start
    # discovery" UI button (sub-phase 22.1.9) keeps working - and
    # gds_api.capabilities.broker's step 13 makes Rabbani-direct vs. agent-only an
    # EXCLUSIVE choice per capability. Flipping that now would regress a real,
    # tested feature; a considered decision (duplicate the capability for agent use,
    # or move it to agent-only and rebuild the UI action through the agent path) is
    # correctly deferred, not resolved by this sub-phase. All six therefore stay
    # Planned, each with this real, structural reason instead of a fabricated
    # "missing credential" one for the roles that wouldn't actually need one.
    "cloud_security_coordinator": PlannedAgentManifest(
        name="cloud_security_coordinator",
        display_name="Cloud Security Coordinator",
        description=(
            "Would coordinate cloud discovery/inventory work across the four provider "
            "Inventory Analyst roles for a tenant's registered CloudEnvironments."
        ),
        team=Team.BLUE,
        department="Cloud Security",
        reason=(
            "The real cloud.discover_environment capability it would coordinate is "
            "deliberately Rabbani-direct-only today (capabilities/catalog.py), not "
            "agent-accessible, to preserve the already-shipped, live-verified 'Start "
            "discovery' UI action - the Capability Broker's own allow-list rule makes "
            "Rabbani-direct vs. agent-only an exclusive choice per capability. Not a "
            "missing-credential gap; a deferred broker-access design decision."
        ),
        workforce="purple-cybersecurity-workforce",
        purple_role_id="purple-11",
        purple_role_name="Cloud, Container and Kubernetes Security Agent",
        operational_domain="Cloud Security",
        mission_role=(
            "Would coordinate the four provider Inventory Analyst roles and the Cloud "
            "Asset Correlation Analyst across a tenant's registered CloudEnvironments."
        ),
        objectives=("Coordinate multi-provider discovery once agent-side broker access exists",),
        knowledge_domains=("multi-cloud inventory coordination",),
        skills=(),
        collaboration_contracts=(
            "aws_inventory_analyst",
            "azure_inventory_analyst",
            "gcp_inventory_analyst",
            "kubernetes_inventory_analyst",
            "cloud_asset_correlation_analyst",
        ),
        owner="Purple Security Command / Rabbani AI Core",
        documentation_reference="docs/architecture/unified-purple-workforce.md#purple-11",
    ),
    "aws_inventory_analyst": PlannedAgentManifest(
        name="aws_inventory_analyst",
        display_name="AWS Inventory Analyst",
        description=(
            "Would run governed AWS discovery for a registered CloudEnvironment using "
            "the real, operational AWS adapter (ADR 0050) once agent-side broker "
            "access to cloud.discover_environment exists."
        ),
        team=Team.BLUE,
        department="Cloud Security",
        reason=(
            "Same structural, deferred broker-access gap as cloud_security_coordinator "
            "(see that entry) - not a missing-credential gap for the discovery "
            "capability itself, though this dev environment also has no real AWS "
            "credentials configured (ADR 0050), so even agent-side execution would "
            "honestly report 0 assets today."
        ),
        required_connector_ids=("aws_readonly",),
        workforce="purple-cybersecurity-workforce",
        purple_role_id="purple-11",
        purple_role_name="Cloud, Container and Kubernetes Security Agent",
        operational_domain="Cloud Security",
        mission_role="Would run real AWS discovery for one registered CloudEnvironment.",
        objectives=("Real AWS asset/relationship discovery once agent-side access exists",),
        knowledge_domains=("AWS", "cloud asset discovery"),
        skills=(),
        collaboration_contracts=("cloud_security_coordinator", "cloud_asset_correlation_analyst"),
        owner="Purple Security Command / Rabbani AI Core",
        documentation_reference="docs/architecture/unified-purple-workforce.md#purple-11",
    ),
    "azure_inventory_analyst": PlannedAgentManifest(
        name="azure_inventory_analyst",
        display_name="Azure Inventory Analyst",
        description=(
            "Would run governed Azure discovery for a registered CloudEnvironment "
            "using the real, operational Azure adapter (ADR 0050) once agent-side "
            "broker access to cloud.discover_environment exists."
        ),
        team=Team.BLUE,
        department="Cloud Security",
        reason=(
            "Same structural, deferred broker-access gap as cloud_security_coordinator "
            "(see that entry); this dev environment also has no real Azure "
            "credentials configured (ADR 0050)."
        ),
        required_connector_ids=("azure_readonly",),
        workforce="purple-cybersecurity-workforce",
        purple_role_id="purple-11",
        purple_role_name="Cloud, Container and Kubernetes Security Agent",
        operational_domain="Cloud Security",
        mission_role="Would run real Azure discovery for one registered CloudEnvironment.",
        objectives=("Real Azure asset/relationship discovery once agent-side access exists",),
        knowledge_domains=("Azure", "cloud asset discovery"),
        skills=(),
        collaboration_contracts=("cloud_security_coordinator", "cloud_asset_correlation_analyst"),
        owner="Purple Security Command / Rabbani AI Core",
        documentation_reference="docs/architecture/unified-purple-workforce.md#purple-11",
    ),
    "gcp_inventory_analyst": PlannedAgentManifest(
        name="gcp_inventory_analyst",
        display_name="GCP Inventory Analyst",
        description=(
            "Would run governed GCP discovery for a registered CloudEnvironment using "
            "the real, operational GCP adapter (ADR 0050) once agent-side broker "
            "access to cloud.discover_environment exists."
        ),
        team=Team.BLUE,
        department="Cloud Security",
        reason=(
            "Same structural, deferred broker-access gap as cloud_security_coordinator "
            "(see that entry); this dev environment also has no real GCP credentials "
            "configured (ADR 0050)."
        ),
        required_connector_ids=("gcp_readonly",),
        workforce="purple-cybersecurity-workforce",
        purple_role_id="purple-11",
        purple_role_name="Cloud, Container and Kubernetes Security Agent",
        operational_domain="Cloud Security",
        mission_role="Would run real GCP discovery for one registered CloudEnvironment.",
        objectives=("Real GCP asset/relationship discovery once agent-side access exists",),
        knowledge_domains=("GCP", "cloud asset discovery"),
        skills=(),
        collaboration_contracts=("cloud_security_coordinator", "cloud_asset_correlation_analyst"),
        owner="Purple Security Command / Rabbani AI Core",
        documentation_reference="docs/architecture/unified-purple-workforce.md#purple-11",
    ),
    "kubernetes_inventory_analyst": PlannedAgentManifest(
        name="kubernetes_inventory_analyst",
        display_name="Kubernetes Inventory Analyst",
        description=(
            "Would run governed Kubernetes cluster discovery for a registered "
            "CloudEnvironment using the real, operational Kubernetes adapter (ADR "
            "0050) once agent-side broker access to cloud.discover_environment "
            "exists."
        ),
        team=Team.BLUE,
        department="Cloud Security",
        reason=(
            "Same structural, deferred broker-access gap as cloud_security_coordinator "
            "(see that entry); this dev environment also has no real Kubernetes "
            "cluster/kubeconfig configured."
        ),
        required_connector_ids=("kubernetes_readonly",),
        workforce="purple-cybersecurity-workforce",
        purple_role_id="purple-11",
        purple_role_name="Cloud, Container and Kubernetes Security Agent",
        operational_domain="Cloud Security",
        mission_role="Would run real Kubernetes discovery for one registered CloudEnvironment.",
        objectives=("Real Kubernetes asset/relationship discovery once agent-side access exists",),
        knowledge_domains=("Kubernetes", "cloud asset discovery"),
        skills=(),
        collaboration_contracts=("cloud_security_coordinator", "cloud_asset_correlation_analyst"),
        owner="Purple Security Command / Rabbani AI Core",
        documentation_reference="docs/architecture/unified-purple-workforce.md#purple-11",
    ),
    "cloud_asset_correlation_analyst": PlannedAgentManifest(
        name="cloud_asset_correlation_analyst",
        display_name="Cloud Asset Correlation Analyst",
        description=(
            "Would correlate real CloudAsset/CloudAssetRelationship records across "
            "providers and environments (e.g. the same workload appearing in AWS and "
            "in a connected Kubernetes cluster) - no cross-provider correlation logic "
            "exists yet beyond the real, direct relationships each discovery run "
            "records."
        ),
        team=Team.BLUE,
        department="Cloud Security",
        reason=(
            "No cross-provider correlation capability exists yet - this is a real, "
            "additional analysis step beyond ingestion (sub-phases 1-9 only persist "
            "the direct relationships each provider adapter itself reports), not yet "
            "designed or built. Distinct from the other five roles' gap: even with "
            "agent-side broker access, there is no real cloud.correlate_assets "
            "capability today for this role to be given."
        ),
        workforce="purple-cybersecurity-workforce",
        purple_role_id="purple-11",
        purple_role_name="Cloud, Container and Kubernetes Security Agent",
        operational_domain="Cloud Security",
        mission_role=(
            "Would identify real cross-provider/cross-environment asset correlations "
            "once a real correlation capability is designed and built."
        ),
        objectives=("Real cross-provider asset correlation once a real capability exists",),
        knowledge_domains=("cloud asset correlation", "multi-cloud topology"),
        skills=(),
        collaboration_contracts=(
            "cloud_security_coordinator",
            "aws_inventory_analyst",
            "azure_inventory_analyst",
            "gcp_inventory_analyst",
            "kubernetes_inventory_analyst",
        ),
        owner="Purple Security Command / Rabbani AI Core",
        documentation_reference="docs/architecture/unified-purple-workforce.md#purple-11",
    ),
    # EDP-009 Part 2, Section 52 (Specialist Agents): the minimum CSPM specialist
    # roster the section names. Real, non-fabricated reason, same structural shape
    # as Part 1's six discovery roles above: `cloud.posture.evaluate_environment`
    # (sub-phase 22.2.3) is deliberately Rabbani-direct-only
    # (allowed_team_types=(), allowed_agent_ids=() in capabilities/catalog.py),
    # preserving the already-shipped, live-verified "Run posture evaluation" UI
    # action (sub-phase 22.2.7) - the same Capability Broker exclusive-choice rule
    # (Rabbani-direct XOR agent-only per capability) that kept the six discovery
    # roles Planned applies here too. All seven stay Planned with this real
    # structural reason - never a fabricated "missing credential" one, since
    # evaluation itself needs no live cloud credential at all (it only reads
    # already-persisted inventory).
    "cloud_posture_coordinator": PlannedAgentManifest(
        name="cloud_posture_coordinator",
        display_name="Cloud Posture Coordinator",
        description=(
            "Would coordinate CSPM evaluation work across the four provider Posture "
            "Analyst roles and the Compliance Mapping/Finding Review analysts for a "
            "tenant's registered CloudEnvironments."
        ),
        team=Team.BLUE,
        department="Cloud Security",
        reason=(
            "The real cloud.posture.evaluate_environment capability it would "
            "coordinate is deliberately Rabbani-direct-only today "
            "(capabilities/catalog.py), not agent-accessible, to preserve the "
            "already-shipped, live-verified 'Run posture evaluation' UI action - "
            "the Capability Broker's own allow-list rule makes Rabbani-direct vs. "
            "agent-only an exclusive choice per capability. Not a missing-credential "
            "gap; a deferred broker-access design decision, same shape as "
            "cloud_security_coordinator's own real gap."
        ),
        workforce="purple-cybersecurity-workforce",
        purple_role_id="purple-11",
        purple_role_name="Cloud, Container and Kubernetes Security Agent",
        operational_domain="Cloud Security",
        mission_role=(
            "Would coordinate the four provider Posture Analyst roles and the "
            "Compliance Mapping/Finding Review analysts across a tenant's registered "
            "CloudEnvironments."
        ),
        objectives=(
            "Coordinate multi-provider posture evaluation once agent-side broker access exists",
        ),
        knowledge_domains=("multi-cloud posture coordination", "CSPM"),
        skills=(),
        collaboration_contracts=(
            "aws_posture_analyst",
            "azure_posture_analyst",
            "gcp_posture_analyst",
            "kubernetes_posture_analyst",
            "cloud_compliance_mapping_analyst",
            "cloud_finding_review_analyst",
        ),
        owner="Purple Security Command / Rabbani AI Core",
        documentation_reference="docs/architecture/unified-purple-workforce.md#purple-11",
    ),
    "aws_posture_analyst": PlannedAgentManifest(
        name="aws_posture_analyst",
        display_name="AWS Posture Analyst",
        description=(
            "Would review real AWS CSPM evaluation results (12 real policies, "
            "gds_api.cloud.posture.policies.aws) for a registered CloudEnvironment "
            "once agent-side broker access to cloud.posture.evaluate_environment "
            "exists."
        ),
        team=Team.BLUE,
        department="Cloud Security",
        reason=(
            "Same structural, deferred broker-access gap as "
            "cloud_posture_coordinator (see that entry) - evaluation itself needs "
            "no live AWS credential (it reads already-persisted inventory), so this "
            "is purely the agent-access design decision, not a credential gap."
        ),
        workforce="purple-cybersecurity-workforce",
        purple_role_id="purple-11",
        purple_role_name="Cloud, Container and Kubernetes Security Agent",
        operational_domain="Cloud Security",
        mission_role=(
            "Would review real AWS posture evaluation results for one registered "
            "CloudEnvironment."
        ),
        objectives=("Real AWS posture review once agent-side access exists",),
        knowledge_domains=("AWS", "CIS AWS Foundations Benchmark", "cloud posture evaluation"),
        skills=(),
        collaboration_contracts=("cloud_posture_coordinator", "cloud_finding_review_analyst"),
        owner="Purple Security Command / Rabbani AI Core",
        documentation_reference="docs/architecture/unified-purple-workforce.md#purple-11",
    ),
    "azure_posture_analyst": PlannedAgentManifest(
        name="azure_posture_analyst",
        display_name="Azure Posture Analyst",
        description=(
            "Would review real Azure CSPM evaluation results (6 real policies, "
            "gds_api.cloud.posture.policies.azure) for a registered CloudEnvironment "
            "once agent-side broker access to cloud.posture.evaluate_environment "
            "exists."
        ),
        team=Team.BLUE,
        department="Cloud Security",
        reason=(
            "Same structural, deferred broker-access gap as "
            "cloud_posture_coordinator (see that entry)."
        ),
        workforce="purple-cybersecurity-workforce",
        purple_role_id="purple-11",
        purple_role_name="Cloud, Container and Kubernetes Security Agent",
        operational_domain="Cloud Security",
        mission_role=(
            "Would review real Azure posture evaluation results for one registered "
            "CloudEnvironment."
        ),
        objectives=("Real Azure posture review once agent-side access exists",),
        knowledge_domains=(
            "Azure",
            "CIS Microsoft Azure Foundations Benchmark",
            "cloud posture evaluation",
        ),
        skills=(),
        collaboration_contracts=("cloud_posture_coordinator", "cloud_finding_review_analyst"),
        owner="Purple Security Command / Rabbani AI Core",
        documentation_reference="docs/architecture/unified-purple-workforce.md#purple-11",
    ),
    "gcp_posture_analyst": PlannedAgentManifest(
        name="gcp_posture_analyst",
        display_name="GCP Posture Analyst",
        description=(
            "Would review real GCP CSPM evaluation results (2 real policies, "
            "gds_api.cloud.posture.policies.gcp) for a registered CloudEnvironment "
            "once agent-side broker access to cloud.posture.evaluate_environment "
            "exists."
        ),
        team=Team.BLUE,
        department="Cloud Security",
        reason=(
            "Same structural, deferred broker-access gap as "
            "cloud_posture_coordinator (see that entry)."
        ),
        workforce="purple-cybersecurity-workforce",
        purple_role_id="purple-11",
        purple_role_name="Cloud, Container and Kubernetes Security Agent",
        operational_domain="Cloud Security",
        mission_role=(
            "Would review real GCP posture evaluation results for one registered "
            "CloudEnvironment."
        ),
        objectives=("Real GCP posture review once agent-side access exists",),
        knowledge_domains=(
            "GCP",
            "CIS Google Cloud Platform Foundation Benchmark",
            "cloud posture evaluation",
        ),
        skills=(),
        collaboration_contracts=("cloud_posture_coordinator", "cloud_finding_review_analyst"),
        owner="Purple Security Command / Rabbani AI Core",
        documentation_reference="docs/architecture/unified-purple-workforce.md#purple-11",
    ),
    "kubernetes_posture_analyst": PlannedAgentManifest(
        name="kubernetes_posture_analyst",
        display_name="Kubernetes Posture Analyst",
        description=(
            "Would review real Kubernetes CSPM evaluation results (4 real policies, "
            "gds_api.cloud.posture.policies.kubernetes - the smallest real policy "
            "set of any provider, per the Section 15 feasibility audit) for a "
            "registered CloudEnvironment once agent-side broker access to "
            "cloud.posture.evaluate_environment exists."
        ),
        team=Team.BLUE,
        department="Cloud Security",
        reason=(
            "Same structural, deferred broker-access gap as "
            "cloud_posture_coordinator (see that entry). Also honestly limited by "
            "the small real Kubernetes policy set itself - no RBAC or container "
            "securityContext data is collected by the current adapter (ADR 0050/ "
            "0051), so most of what this role could review is currently "
            "UNSUPPORTED, not just agent-access-blocked."
        ),
        workforce="purple-cybersecurity-workforce",
        purple_role_id="purple-11",
        purple_role_name="Cloud, Container and Kubernetes Security Agent",
        operational_domain="Cloud Security",
        mission_role=(
            "Would review real Kubernetes posture evaluation results for one "
            "registered CloudEnvironment."
        ),
        objectives=("Real Kubernetes posture review once agent-side access exists",),
        knowledge_domains=("Kubernetes", "CIS Kubernetes Benchmark", "cloud posture evaluation"),
        skills=(),
        collaboration_contracts=("cloud_posture_coordinator", "cloud_finding_review_analyst"),
        owner="Purple Security Command / Rabbani AI Core",
        documentation_reference="docs/architecture/unified-purple-workforce.md#purple-11",
    ),
    "cloud_compliance_mapping_analyst": PlannedAgentManifest(
        name="cloud_compliance_mapping_analyst",
        display_name="Cloud Compliance Mapping Analyst",
        description=(
            "Would maintain and review real policy-to-benchmark control mappings "
            "(gds_api.cloud.posture.registry.POLICY_TO_BENCHMARK_MAPPINGS) once a "
            "real mapping dataset exists."
        ),
        team=Team.BLUE,
        department="Cloud Security",
        reason=(
            "No real benchmark control mappings exist yet - POLICY_TO_BENCHMARK_"
            "MAPPINGS is honestly empty (sub-phase 22.2.1's own disclosed decision: "
            "exact CIS control numbering cannot be verified against a primary "
            "reference in this environment, and fabricating one would violate the "
            "prompt's own boundary against fabricating benchmark coverage). This "
            "role has no real data to review yet - a distinct gap from the "
            "broker-access-only roles above, not resolved by agent-side access "
            "alone."
        ),
        workforce="purple-cybersecurity-workforce",
        purple_role_id="purple-11",
        purple_role_name="Cloud, Container and Kubernetes Security Agent",
        operational_domain="Cloud Security",
        mission_role=(
            "Would review real benchmark control mappings once a real mapping "
            "dataset exists."
        ),
        objectives=("Real benchmark mapping review once a real mapping dataset exists",),
        knowledge_domains=("CIS Benchmarks", "compliance mapping methodology"),
        skills=(),
        collaboration_contracts=("cloud_posture_coordinator",),
        owner="Purple Security Command / Rabbani AI Core",
        documentation_reference="docs/architecture/unified-purple-workforce.md#purple-11",
    ),
    "cloud_finding_review_analyst": PlannedAgentManifest(
        name="cloud_finding_review_analyst",
        display_name="Cloud Finding Review Analyst",
        description=(
            "Would review real cloud findings (gds_api.cloud.posture.findings, "
            "sub-phase 22.2.4) and real governed suppression requests "
            "(gds_api.cloud.posture.suppression, sub-phase 22.2.5) for a tenant's "
            "registered CloudEnvironments."
        ),
        team=Team.BLUE,
        department="Cloud Security",
        reason=(
            "Findings and suppression are both real and operational today, but "
            "every real write path (request_suppression, the evaluation pipeline "
            "itself) is reached only through Rabbani-direct capability calls or "
            "direct RBAC-gated API endpoints (cloud_posture_api.py) - no agent-side "
            "capability exists yet for reviewing or acting on findings/suppressions, "
            "the same structural gap as the other CSPM roles above."
        ),
        workforce="purple-cybersecurity-workforce",
        purple_role_id="purple-11",
        purple_role_name="Cloud, Container and Kubernetes Security Agent",
        operational_domain="Cloud Security",
        mission_role=(
            "Would review real cloud findings and suppression requests once "
            "agent-side access exists."
        ),
        objectives=("Real cloud finding/suppression review once agent-side access exists",),
        knowledge_domains=("cloud finding triage", "risk acceptance workflows"),
        skills=(),
        collaboration_contracts=(
            "cloud_posture_coordinator",
            "aws_posture_analyst",
            "azure_posture_analyst",
            "gcp_posture_analyst",
            "kubernetes_posture_analyst",
        ),
        owner="Purple Security Command / Rabbani AI Core",
        documentation_reference="docs/architecture/unified-purple-workforce.md#purple-11",
    ),
    # Phase 20 (Continuation Prompt 7): eight Purple Workforce roles with no existing
    # agent counterpart. Each stays Planned this sub-phase - Rabbani AI Core continues
    # to coordinate missions directly today (Purple Security Command's own coordination
    # logic, Parts 7-8, is deliberately not built yet, per Prompt 7 Rule 3's requirement
    # that it never become a competing master authority before it's real) and every
    # offensive-adjacent role here requires new ADR-gated tooling per docs/adr/0007
    # before it can go Operational/Degraded. See
    # docs/architecture/purple-workforce-agent-migration.md for the full reasoning.
    "purple_security_command": PlannedAgentManifest(
        name="purple_security_command",
        display_name="Purple Security Command Agent",
        description=(
            "Would coordinate Purple Workforce missions beneath Rabbani AI Core - "
            "selecting specialist agents, tracking dependencies, consolidating "
            "findings, triggering approvals - subordinate to, never replacing, "
            "Rabbani AI Core."
        ),
        team=Team.PURPLE,
        department="Mission Coordination",
        reason=(
            "Real mission-execution-graph coordination (specialist assignment, "
            "dependency tracking, cross-agent finding consolidation) is not yet "
            "implemented. Rabbani AI Core continues to coordinate missions directly "
            "today - building a half-working coordinator would risk exactly the "
            "'competing master authority' Prompt 7 Rule 3 prohibits."
        ),
        workforce="purple-cybersecurity-workforce",
        purple_role_id="purple-01",
        purple_role_name="Purple Security Command Agent",
        operational_domain="Mission Coordination",
        objectives=("Coordinate Purple missions beneath Rabbani AI Core once built",),
        knowledge_domains=("mission orchestration",),
        collaboration_contracts=(
            "blue_team",
            "incident_response",
            "penetration_testing_coordinator",
            "security_documentation_reporting",
        ),
        owner="Rabbani AI Core",
        documentation_reference="docs/architecture/unified-purple-workforce.md#purple-01",
    ),
    "detection_engineering": PlannedAgentManifest(
        name="detection_engineering",
        display_name="Detection Engineering Agent",
        description=(
            "Would generate Sigma/YARA rules and SIEM/EDR detection content from "
            "real hunt/incident findings, and map/track ATT&CK coverage gaps."
        ),
        team=Team.BLUE,
        department="Detection Engineering",
        reason=(
            "No Sigma/YARA rule-generation or SIEM/EDR content-authoring tooling "
            "exists in this codebase (confirmed absent by the Phase 20 pre-build "
            "audit's security-domain search)."
        ),
        workforce="purple-cybersecurity-workforce",
        purple_role_id="purple-13",
        purple_role_name="Detection Engineering Agent",
        operational_domain="Detection Engineering",
        objectives=("Generate real Sigma/YARA rules from confirmed findings once built",),
        knowledge_domains=("Sigma", "YARA", "MITRE ATT&CK coverage mapping"),
        collaboration_contracts=("threat_hunting", "blue_team", "adversary_emulation"),
        owner="Rabbani AI Core",
        documentation_reference="docs/architecture/unified-purple-workforce.md#purple-13",
    ),
    "adversary_emulation": PlannedAgentManifest(
        name="adversary_emulation",
        display_name="Adversary Emulation and Breach Simulation Agent",
        description=(
            "Would run ATT&CK-aligned, non-destructive breach simulations to "
            "validate detection/defensive controls."
        ),
        team=Team.RED,
        department="Adversary Emulation",
        reason=(
            "Requires simulation tooling beyond the existing 3 passive/"
            "lightweight-active Red Team recon tools; per docs/adr/0007, any "
            "Red Team tooling expansion needs its own ADR before implementation."
        ),
        workforce="purple-cybersecurity-workforce",
        purple_role_id="purple-14",
        purple_role_name="Adversary Emulation and Breach Simulation Agent",
        operational_domain="Adversary Emulation",
        objectives=("Run real, non-destructive ATT&CK-aligned simulations once built",),
        knowledge_domains=("MITRE ATT&CK", "kill-chain modelling"),
        collaboration_contracts=("red_team", "detection_engineering", "validation_retest"),
        owner="Rabbani AI Core",
        documentation_reference="docs/architecture/unified-purple-workforce.md#purple-14",
    ),
    "ai_llm_security_testing": PlannedAgentManifest(
        name="ai_llm_security_testing",
        display_name="AI and LLM Security Testing Agent",
        description=(
            "Would test prompt injection, RAG poisoning, tool abuse, excessive "
            "agency and agent-identity spoofing - including against GDS Security "
            "OS itself, only in isolated, explicitly authorised test environments."
        ),
        team=Team.RED,
        department="AI/LLM Security",
        reason=(
            "Requires a dedicated isolated, explicitly authorised AI-system test "
            "environment and real prompt-injection/tool-abuse testing tooling, "
            "neither of which exists yet."
        ),
        workforce="purple-cybersecurity-workforce",
        purple_role_id="purple-15",
        purple_role_name="AI and LLM Security Testing Agent",
        operational_domain="AI/LLM Security",
        objectives=("Test AI/LLM-specific attack surfaces in an isolated environment once built",),
        knowledge_domains=("prompt injection", "MCP/connector security", "agent trust boundaries"),
        collaboration_contracts=("red_team", "security_architecture"),
        owner="Rabbani AI Core",
        documentation_reference="docs/architecture/unified-purple-workforce.md#purple-15",
    ),
    "security_documentation_reporting": PlannedAgentManifest(
        name="security_documentation_reporting",
        display_name="Security Documentation and Executive Reporting Agent",
        description=(
            "Would produce vulnerability/pentest/incident/threat-hunt/"
            "remediation/retest/compliance reports and executive summaries "
            "derived only from real findings, evidence and mission records."
        ),
        team=Team.BLUE,
        department="Security Reporting",
        reason=(
            "No dedicated report-generation tool exists yet beyond each agent's "
            "own ad-hoc mission narration (FoundationAgent.report). Deliberately "
            "kept distinct from the Foundation-team executive_advisor agent (which "
            "summarizes general mission activity for leadership, not "
            "security-specific findings/evidence) rather than conflating the two - "
            "see the pre-build audit's 'Summary for Part 2 planning'."
        ),
        workforce="purple-cybersecurity-workforce",
        purple_role_id="purple-20",
        purple_role_name="Security Documentation and Executive Reporting Agent",
        operational_domain="Security Reporting",
        objectives=("Produce real, evidence-derived security reports once built",),
        knowledge_domains=("technical writing", "executive risk communication"),
        collaboration_contracts=(
            "incident_response",
            "vulnerability_management",
            "risk_business_intelligence",
        ),
        owner="Rabbani AI Core",
        documentation_reference="docs/architecture/unified-purple-workforce.md#purple-20",
    ),
}
