"""Canonical role/policy/watchlist seed data. Single source of truth for scripts/seed.py
and the test suite, so they can never drift out of sync with each other.
"""

ROLE_PERMISSIONS: dict[str, list[str]] = {
    "platform_owner": [
        "audit:read",
        "evidence:read",
        "evidence:write",
        "policy:evaluate",
        "policy:manage",
        "approvals:read",
        "approvals:decide",
        "notifications:read",
        "users:manage",
        "missions:create",
        "missions:read",
        "findings:read",
        "incidents:read",
        "knowledge:read",
        "knowledge:write",
        "workflows:read",
        "workflows:manage",
        "redteam:read",
        "redteam:manage",
        "conversations:create",
        "conversations:read",
        "capabilities:read",
        "capabilities:request",
        "capabilities:manage",
        "repositories:read",
        "repositories:manage",
        "workspaces:read",
        "workspaces:manage",
        "engineering:read",
        "engineering:execute",
        "engineering:approve",
        "engineering:manage",
        # EDP-009 Part 1: Multi-Cloud Foundation. platform_owner is the only role
        # granted connection/environment *management* and validation/cancellation -
        # Section 33's own explicit instruction not to automatically grant
        # cloud-connection management to analyst/executive roles.
        "cloud:read",
        "cloud:environments:read",
        "cloud:environments:manage",
        "cloud:connections:read",
        "cloud:connections:manage",
        "cloud:connections:validate",
        "cloud:inventory:read",
        "cloud:inventory:run",
        "cloud:inventory:cancel",
        "cloud:assets:read",
        "cloud:graph:read",
        "cloud:evidence:read",
        "cloud:export",
        # EDP-009 Part 2, Section 53: full CSPM governance - the only role that may
        # manage findings, suppress, accept risk, or manage policy exceptions,
        # mirroring the same "management stays platform_owner-only" rule Section 33
        # already established for cloud connections/environments in Part 1.
        "cloud:posture:read",
        "cloud:posture:run",
        "cloud:posture:cancel",
        "cloud:posture:export",
        "cloud:policies:read",
        "cloud:benchmarks:read",
        "cloud:evaluations:read",
        "cloud:findings:read",
        "cloud:findings:manage",
        "cloud:findings:suppress",
        "cloud:findings:accept-risk",
        "cloud:exceptions:read",
        "cloud:exceptions:manage",
    ],
    "analyst": [
        "evidence:read",
        "evidence:write",
        "policy:evaluate",
        "approvals:read",
        "notifications:read",
        "missions:create",
        "missions:read",
        "findings:read",
        "incidents:read",
        "knowledge:read",
        "knowledge:write",
        "workflows:read",
        "redteam:read",
        "conversations:create",
        "conversations:read",
        "capabilities:read",
        "capabilities:request",
        "repositories:read",
        "workspaces:read",
        "workspaces:manage",
        "engineering:read",
        "engineering:execute",
        # EDP-009 Part 1: real inventory read/run access, no connection/environment
        # management (matching this role's existing engineering:execute-but-not
        # :manage pattern).
        "cloud:read",
        "cloud:environments:read",
        "cloud:connections:read",
        "cloud:inventory:read",
        "cloud:inventory:run",
        "cloud:assets:read",
        "cloud:graph:read",
        "cloud:evidence:read",
        "cloud:export",
        # EDP-009 Part 2, Section 53: read/run evaluation access plus the real
        # ability to request suppression (Section 29's own "Analysts may request
        # suppression") - never :manage/:accept-risk/:cancel/:exceptions:manage,
        # matching this role's existing run-but-not-manage pattern.
        "cloud:posture:read",
        "cloud:posture:run",
        "cloud:posture:export",
        "cloud:policies:read",
        "cloud:benchmarks:read",
        "cloud:evaluations:read",
        "cloud:findings:read",
        "cloud:findings:suppress",
        "cloud:exceptions:read",
    ],
    "auditor": [
        "audit:read",
        "evidence:read",
        "notifications:read",
        "missions:read",
        "findings:read",
        "incidents:read",
        "knowledge:read",
        "workflows:read",
        "redteam:read",
        "conversations:read",
        "capabilities:read",
        "repositories:read",
        "workspaces:read",
        "engineering:read",
        # EDP-009 Part 1: pure read, matching this role's existing pattern - no
        # :run/:manage/:validate/:cancel/:export.
        "cloud:read",
        "cloud:environments:read",
        "cloud:connections:read",
        "cloud:inventory:read",
        "cloud:assets:read",
        "cloud:graph:read",
        "cloud:evidence:read",
        # EDP-009 Part 2, Section 53: pure read, matching this role's existing
        # pattern - no :run/:manage/:suppress/:accept-risk/:cancel/:export/
        # :exceptions:manage.
        "cloud:posture:read",
        "cloud:policies:read",
        "cloud:benchmarks:read",
        "cloud:evaluations:read",
        "cloud:findings:read",
        "cloud:exceptions:read",
    ],
    "executive_viewer": [
        "notifications:read",
        "missions:read",
        "findings:read",
        "incidents:read",
        "knowledge:read",
        "workflows:read",
        "redteam:read",
        "conversations:read",
        "capabilities:read",
        "repositories:read",
        "workspaces:read",
        "engineering:read",
        # EDP-008 Part 6: a real, pre-existing gap found while auditing this role for
        # the new Executive Command Center - executive_viewer could not see the
        # Evidence Vault, Audit Trail, or Approval Centre at all despite the role's
        # own name implying broad oversight. The Executive Command Center's
        # Governance Overview and Evidence-linked panels need these three.
        "audit:read",
        "evidence:read",
        "approvals:read",
        # EDP-009 Part 1: overview-level read only, matching this role's existing
        # minimal-but-broad-read pattern - no :connections:read (connection profile
        # detail is an operational, not executive, concern) and no :run/:manage.
        "cloud:read",
        "cloud:environments:read",
        "cloud:assets:read",
        "cloud:graph:read",
        "cloud:evidence:read",
        # EDP-009 Part 2, Section 53: overview-level only, matching this role's
        # existing minimal-but-broad-read pattern - no policy/benchmark/evaluation/
        # exception detail (operational, not executive, concern).
        "cloud:posture:read",
        "cloud:findings:read",
    ],
}

# risk_class -> (requires_approval, min_role required to decide it)
POLICY_RULES: dict[str, tuple[bool, str]] = {
    "low": (False, "analyst"),
    "medium": (False, "analyst"),
    "high": (True, "platform_owner"),
    "critical": (True, "platform_owner"),
}

# Phase 5: what scripts/seed.py writes into the real, tenant-scoped Watchlist table
# (gds_api.models.Watchlist) - the Defensive Agents check real external feeds against
# this, not a hardcoded list in tool code, so it stays genuinely tenant-configurable.
# "Seeded finding flows" means detection is real (a real HTTP call to a real feed) but
# scoped to what this tenant told the platform to care about, not an unbounded scan of
# the entire internet's threat data.
#
# Real, well-known CVE IDs (Log4Shell, EternalBlue) chosen so check_cisa_kev has a
# realistic chance of a real match against the live CISA KEV feed, not just an empty
# result every time - though an empty result is still an honest, valid outcome if
# either CVE ever drops off the feed.
#
# Phase 7: domain/url kinds authorize the Network Security and API/Application Security
# Agents' real, passive TLS/header checks (gds_api.tool_gateway.check_domain_security/
# check_url_security_headers refuse any target not on this list). example.com/.org are
# IANA-reserved specifically for documentation/testing use (RFC 2606) - real, stable,
# and explicitly sanctioned for exactly this kind of check, avoiding any ambiguity about
# authorization to test a real production domain this project doesn't operate.
WATCHLIST_SEED: list[tuple[str, str, str | None]] = [
    # (kind, value, ecosystem)
    ("cve", "CVE-2021-44228", None),
    ("cve", "CVE-2017-0144", None),
    ("package", "lodash", "npm"),
    ("package", "django", "PyPI"),
    ("domain", "example.com", None),
    ("url", "https://example.com", None),
]
