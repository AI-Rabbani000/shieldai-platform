"""EDP-009 Part 2, Sections 6, 7 and 9: the controlled vocabularies the whole CSPM
system is built on. Every enum here asserts its own length at import time, the same
defensive pattern `gds_api.finding_lifecycle.FindingStatus` (15 states) already uses -
a silently-added or silently-removed value here would change dozens of policies'
meanings without anyone noticing.
"""

from __future__ import annotations

import re
from enum import StrEnum


class PolicySeverity(StrEnum):
    """Section 7's own vocabulary. INFORMATIONAL exists for policies that observe a
    fact worth surfacing (e.g. "Secret objects discovered") without asserting a real
    security risk - see gds_api.cloud.posture.registry's own rule that an
    INFORMATIONAL-severity policy's FAIL result never creates a platform Finding row
    (there is no risk to approve, suppress, or remediate)."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


_POLICY_SEVERITIES: frozenset[str] = frozenset(member.value for member in PolicySeverity)
assert len(_POLICY_SEVERITIES) == 5, "Section 7 defines exactly 5 severity levels"

# The existing platform-wide Finding.severity/risk_class vocabulary
# (gds_api.tool_gateway._SEVERITY_TO_RISK_CLASS) only has 4 values - INFORMATIONAL
# policies never reach a Finding row at all (see registry.py), so this is the exact
# subset of PolicySeverity a real Finding can ever carry.
FINDING_SEVERITIES: frozenset[str] = frozenset({"critical", "high", "medium", "low"})


class PolicyDomain(StrEnum):
    """Section 6's own controlled taxonomy, verbatim - no duplicate domain names with
    slightly different wording."""

    IDENTITY = "identity"
    PRIVILEGED_ACCESS = "privileged_access"
    AUTHENTICATION = "authentication"
    LOGGING = "logging"
    MONITORING = "monitoring"
    NETWORKING = "networking"
    INTERNET_EXPOSURE = "internet_exposure"
    DATA_PROTECTION = "data_protection"
    ENCRYPTION = "encryption"
    STORAGE = "storage"
    DATABASE = "database"
    COMPUTE = "compute"
    SERVERLESS = "serverless"
    CONTAINERS = "containers"
    KUBERNETES = "kubernetes"
    KEY_MANAGEMENT = "key_management"
    SECRET_MANAGEMENT = "secret_management"
    BACKUP_AND_RECOVERY = "backup_and_recovery"
    SECURITY_SERVICES = "security_services"
    GOVERNANCE = "governance"
    CONFIGURATION_MANAGEMENT = "configuration_management"
    ASSET_MANAGEMENT = "asset_management"


_POLICY_DOMAINS: frozenset[str] = frozenset(member.value for member in PolicyDomain)
assert len(_POLICY_DOMAINS) == 22, "Section 6 defines exactly 22 security domains"


class EvaluationResult(StrEnum):
    """Section 9's own strict taxonomy. Never collapsed into pass/fail - a caller
    counting "passed" must only ever count PASS, never UNSUPPORTED/SKIPPED/
    NOT_APPLICABLE/ERROR/INDETERMINATE (Section 9's own explicit rule)."""

    PASS = "pass"
    FAIL = "fail"
    NOT_APPLICABLE = "not_applicable"
    UNSUPPORTED = "unsupported"
    SKIPPED = "skipped"
    ERROR = "error"
    INDETERMINATE = "indeterminate"


_EVALUATION_RESULTS: frozenset[str] = frozenset(member.value for member in EvaluationResult)
assert len(_EVALUATION_RESULTS) == 7, "Section 9 defines exactly 7 evaluation result states"


class ApplicabilityState(StrEnum):
    """Section 8's own states - deliberately distinct from EvaluationResult. A policy
    that is not APPLICABLE never has its evaluator function invoked at all."""

    APPLICABLE = "applicable"
    NOT_APPLICABLE = "not_applicable"
    UNSUPPORTED = "unsupported"
    SKIPPED = "skipped"
    BLOCKED_BY_MISSING_DATA = "blocked_by_missing_data"


_APPLICABILITY_STATES: frozenset[str] = frozenset(member.value for member in ApplicabilityState)
assert len(_APPLICABILITY_STATES) == 5, "Section 8 defines exactly 5 applicability states"


class EvaluationType(StrEnum):
    """Distinguishes what an evaluator's EvaluationContext will contain: a single
    resource (Section 12-15's per-asset policies), an environment-wide fact with no
    single target asset (Section 16), or a relationship-based check that requires real
    CloudAssetRelationship rows (Section 17)."""

    RESOURCE_LEVEL = "resource_level"
    ENVIRONMENT_LEVEL = "environment_level"
    RELATIONSHIP_BASED = "relationship_based"


_EVALUATION_TYPES: frozenset[str] = frozenset(member.value for member in EvaluationType)
assert len(_EVALUATION_TYPES) == 3, "Exactly 3 evaluation types are defined"


class BenchmarkMappingType(StrEnum):
    """Section 5's own vocabulary."""

    DIRECT = "direct"
    PARTIAL = "partial"
    SUPPORTING = "supporting"
    RELATED = "related"


_BENCHMARK_MAPPING_TYPES: frozenset[str] = frozenset(
    member.value for member in BenchmarkMappingType
)
assert len(_BENCHMARK_MAPPING_TYPES) == 4, "Section 5 defines exactly 4 mapping types"


class BenchmarkCoverageState(StrEnum):
    """Section 4's own honesty rule ("do not claim complete implementation of any
    benchmark") - deliberately has no COMPLETE value. A benchmark's coverage is either
    NOT_STARTED (zero mapped policies) or PARTIAL (at least one, but the internal
    mapping registry never claims to represent the benchmark's full control set)."""

    NOT_STARTED = "not_started"
    PARTIAL = "partial"


_BENCHMARK_COVERAGE_STATES: frozenset[str] = frozenset(
    member.value for member in BenchmarkCoverageState
)
assert len(_BENCHMARK_COVERAGE_STATES) == 2, "Exactly 2 benchmark coverage states are defined"


# Section 2's own suggested format: CSPM.<PROVIDER>.<DOMAIN>.<CONTROL>. Provider is one
# of the four real Part 1 providers, or MULTI for a cross-provider policy (none exist
# yet, but the format allows it without a future rename). DOMAIN/CONTROL are
# upper-snake segments, matching Section 2's own worked examples verbatim.
_POLICY_ID_PATTERN = re.compile(
    r"^CSPM\.(AWS|AZURE|GCP|KUBERNETES|MULTI)\.[A-Z][A-Z0-9_]*\.[A-Z][A-Z0-9_]*$"
)


def is_valid_policy_id(policy_id: str) -> bool:
    return bool(_POLICY_ID_PATTERN.match(policy_id))
