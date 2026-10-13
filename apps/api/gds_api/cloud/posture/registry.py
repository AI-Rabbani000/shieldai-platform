"""EDP-009 Part 2, Sections 1-5: the Cloud Policy Registry and Benchmark Registry.

Code-defined, immutable dicts - mirroring `gds_api.cloud.providers.CLOUD_PROVIDER_REGISTRY`
(ADR 0050), `gds_api.capabilities.catalog.CAPABILITY_REGISTRY` (ADR 0015), and
`gds_api.agents.registry.AGENT_REGISTRY`/`PLANNED_AGENTS` (ADR 0012) - a policy's real
evaluation logic and a benchmark's real mapped-control set live in code, never
fabricated by a database row (ADR 0051, Decision D1/D2). No policy is ever synced into
a database table; every persisted evaluation/finding stores `policy_id` (str) and
`policy_version` (int) directly, which is sufficient to reconstruct history without one
(Section 3's own permission).

Do not implement a policy against a field the policy-feasibility matrix
(docs/reviews/phase-22-part2-policy-feasibility-matrix.md) marks "Not collected" -
its evaluator must return UNSUPPORTED, never guess PASS or FAIL (Section 11).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from gds_api.cloud.posture.taxonomy import (
    BenchmarkCoverageState,
    BenchmarkMappingType,
    EvaluationType,
    PolicyDomain,
    PolicySeverity,
    is_valid_policy_id,
)
from gds_api.cloud.posture.types import Evaluator


@dataclass(frozen=True)
class RemediationGuidance:
    """Section 27: non-executable remediation guidance. Never a shell/CLI command
    that is automatically run - guidance text only."""

    objective: str
    provider_specific_guidance: str
    validation_guidance: str
    rollback_considerations: str
    # A risk_class value from the existing gds_api.policy vocabulary
    # (low|medium|high|critical) - the approval class a *future* remediation
    # capability would require, not anything Part 2 itself executes.
    required_approval_class: str
    documentation_references: tuple[str, ...] = ()


@dataclass(frozen=True)
class PolicyDefinition:
    """Section 1's own full field list. `evaluator` is a plain function reference
    (gds_api.cloud.posture.types.Evaluator), never a string/expression stored in a
    mutable field - Section 1's own explicit prohibition on an unrestricted policy
    scripting language."""

    policy_id: str
    version: int
    name: str
    description: str
    # One of "aws"|"azure"|"gcp"|"kubernetes"|"multi".
    provider: str
    severity: PolicySeverity
    security_domain: PolicyDomain
    policy_family: str
    evaluation_type: EvaluationType
    evaluator: Evaluator
    # CloudEnvironment.environment_type values this policy applies to; empty tuple
    # means "no environment-type restriction".
    environment_types: tuple[str, ...] = ()
    # CloudAsset.provider_category values this policy targets; empty for an
    # ENVIRONMENT_LEVEL policy with no single target asset.
    asset_categories: tuple[str, ...] = ()
    native_resource_types: tuple[str, ...] = ()
    required_fields: tuple[str, ...] = ()
    required_relationships: tuple[str, ...] = ()
    evidence_fields: tuple[str, ...] = ()
    remediation_guidance: RemediationGuidance | None = None
    tags: tuple[str, ...] = ()
    enabled: bool = True
    experimental: bool = False
    deprecated: bool = False
    replacement_policy_id: str | None = None
    documentation_reference: str | None = None
    authoritative_source_reference: str | None = None
    data_quality_requirements: tuple[str, ...] = ()
    unsupported_conditions: tuple[str, ...] = ()
    skip_conditions: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not is_valid_policy_id(self.policy_id):
            raise ValueError(
                f"Policy ID '{self.policy_id}' does not match the required "
                "CSPM.<PROVIDER>.<DOMAIN>.<CONTROL> format (Section 2)"
            )
        if self.version < 1:
            raise ValueError(f"Policy '{self.policy_id}' version must be >= 1")
        if self.evaluation_type == EvaluationType.RESOURCE_LEVEL and not self.asset_categories:
            raise ValueError(
                f"RESOURCE_LEVEL policy '{self.policy_id}' must declare asset_categories"
            )
        if (
            self.evaluation_type == EvaluationType.RELATIONSHIP_BASED
            and not self.required_relationships
        ):
            raise ValueError(
                f"RELATIONSHIP_BASED policy '{self.policy_id}' must declare "
                "required_relationships"
            )


@dataclass(frozen=True)
class BenchmarkDefinition:
    """Section 4's own fields. Coverage/mapped-control counts are deliberately not
    fields here - see `benchmark_coverage()` below, computed live from
    POLICY_TO_BENCHMARK_MAPPINGS so they can never drift from the real mapping table."""

    benchmark_id: str
    name: str
    version: str
    provider: str
    publisher: str
    description: str
    documentation_reference: str | None = None
    licensing_note: str | None = None


@dataclass(frozen=True)
class BenchmarkMapping:
    """Section 5's own many-to-many mapping record."""

    policy_id: str
    policy_version: int
    benchmark_id: str
    benchmark_version: str
    control_id: str
    mapping_type: BenchmarkMappingType
    confidence_basis: str
    notes: str = ""
    evidence_limitations: str = ""


# ---------------------------------------------------------------------------
# Registries. Populated incrementally across this Part's sub-phases, exactly how
# PLANNED_AGENTS/CLOUD_PROVIDER_REGISTRY grew across Part 1's own sub-phases.
# ---------------------------------------------------------------------------

POLICY_REGISTRY: dict[str, PolicyDefinition] = {}

BENCHMARK_REGISTRY: dict[str, BenchmarkDefinition] = {
    "cis-aws-foundations": BenchmarkDefinition(
        benchmark_id="cis-aws-foundations",
        name="CIS Amazon Web Services Foundations Benchmark",
        version="3.0.0",
        provider="aws",
        publisher="Center for Internet Security",
        description=(
            "Foundational security configuration recommendations for AWS accounts. "
            "Only control identifiers and short internal descriptions of what each "
            "mapped control checks are used here, never reproduced benchmark text."
        ),
        documentation_reference="https://www.cisecurity.org/benchmark/amazon_web_services",
    ),
    "cis-azure-foundations": BenchmarkDefinition(
        benchmark_id="cis-azure-foundations",
        name="CIS Microsoft Azure Foundations Benchmark",
        version="2.1.0",
        provider="azure",
        publisher="Center for Internet Security",
        description=(
            "Foundational security configuration recommendations for Azure "
            "subscriptions. Only control identifiers and short internal descriptions "
            "are used here, never reproduced benchmark text."
        ),
        documentation_reference="https://www.cisecurity.org/benchmark/azure",
    ),
    "cis-gcp-foundations": BenchmarkDefinition(
        benchmark_id="cis-gcp-foundations",
        name="CIS Google Cloud Platform Foundation Benchmark",
        version="3.0.0",
        provider="gcp",
        publisher="Center for Internet Security",
        description=(
            "Foundational security configuration recommendations for GCP projects. "
            "Only control identifiers and short internal descriptions are used here, "
            "never reproduced benchmark text."
        ),
        documentation_reference="https://www.cisecurity.org/benchmark/google_cloud_computing_platform",
    ),
    "cis-kubernetes": BenchmarkDefinition(
        benchmark_id="cis-kubernetes",
        name="CIS Kubernetes Benchmark",
        version="1.9.0",
        provider="kubernetes",
        publisher="Center for Internet Security",
        description=(
            "Foundational security configuration recommendations for Kubernetes "
            "clusters. Only control identifiers and short internal descriptions are "
            "used here, never reproduced benchmark text."
        ),
        documentation_reference="https://www.cisecurity.org/benchmark/kubernetes",
    ),
}

POLICY_TO_BENCHMARK_MAPPINGS: tuple[BenchmarkMapping, ...] = ()


def register_policy(definition: PolicyDefinition) -> None:
    """The one real way a policy enters POLICY_REGISTRY - a plain function rather
    than direct dict literal assignment so every provider policy module
    (gds_api.cloud.posture.policies.*) can be a flat, readable list of
    `register_policy(PolicyDefinition(...))` calls, and so a duplicate policy_id
    across two provider modules fails loudly at import time instead of silently
    overwriting."""
    if definition.policy_id in POLICY_REGISTRY:
        raise ValueError(f"Policy ID '{definition.policy_id}' is already registered")
    POLICY_REGISTRY[definition.policy_id] = definition


def register_benchmark_mappings(*mappings: BenchmarkMapping) -> None:
    global POLICY_TO_BENCHMARK_MAPPINGS
    POLICY_TO_BENCHMARK_MAPPINGS = (*POLICY_TO_BENCHMARK_MAPPINGS, *mappings)


def get_policy(policy_id: str) -> PolicyDefinition | None:
    return POLICY_REGISTRY.get(policy_id)


def list_policies(
    *,
    provider: str | None = None,
    security_domain: PolicyDomain | None = None,
    severity: PolicySeverity | None = None,
    enabled: bool | None = None,
    experimental: bool | None = None,
    deprecated: bool | None = None,
) -> list[PolicyDefinition]:
    results = list(POLICY_REGISTRY.values())
    if provider is not None:
        results = [p for p in results if p.provider == provider]
    if security_domain is not None:
        results = [p for p in results if p.security_domain == security_domain]
    if severity is not None:
        results = [p for p in results if p.severity == severity]
    if enabled is not None:
        results = [p for p in results if p.enabled == enabled]
    if experimental is not None:
        results = [p for p in results if p.experimental == experimental]
    if deprecated is not None:
        results = [p for p in results if p.deprecated == deprecated]
    return sorted(results, key=lambda p: p.policy_id)


def get_benchmark(benchmark_id: str) -> BenchmarkDefinition | None:
    return BENCHMARK_REGISTRY.get(benchmark_id)


def list_benchmarks() -> list[BenchmarkDefinition]:
    return sorted(BENCHMARK_REGISTRY.values(), key=lambda b: b.benchmark_id)


def mappings_for_policy(policy_id: str) -> list[BenchmarkMapping]:
    return [m for m in POLICY_TO_BENCHMARK_MAPPINGS if m.policy_id == policy_id]


def mappings_for_benchmark(benchmark_id: str) -> list[BenchmarkMapping]:
    return [m for m in POLICY_TO_BENCHMARK_MAPPINGS if m.benchmark_id == benchmark_id]


@dataclass(frozen=True)
class BenchmarkCoverage:
    """Section 4/31/38's own honest coverage snapshot - every count computed live
    from POLICY_TO_BENCHMARK_MAPPINGS and POLICY_REGISTRY, never hand-maintained."""

    benchmark_id: str
    coverage_state: BenchmarkCoverageState
    mapped_control_count: int
    directly_covered_control_count: int
    partially_covered_control_count: int
    supporting_covered_control_count: int
    related_covered_control_count: int
    mapped_policy_count: int
    enabled_mapped_policy_count: int


def benchmark_coverage(benchmark_id: str) -> BenchmarkCoverage:
    mappings = mappings_for_benchmark(benchmark_id)
    control_ids = {m.control_id for m in mappings}
    policy_ids = {m.policy_id for m in mappings}
    enabled_policy_ids = {
        pid for pid in policy_ids if (p := get_policy(pid)) is not None and p.enabled
    }
    return BenchmarkCoverage(
        benchmark_id=benchmark_id,
        coverage_state=(
            BenchmarkCoverageState.PARTIAL if mappings else BenchmarkCoverageState.NOT_STARTED
        ),
        mapped_control_count=len(control_ids),
        directly_covered_control_count=len(
            {m.control_id for m in mappings if m.mapping_type == BenchmarkMappingType.DIRECT}
        ),
        partially_covered_control_count=len(
            {m.control_id for m in mappings if m.mapping_type == BenchmarkMappingType.PARTIAL}
        ),
        supporting_covered_control_count=len(
            {m.control_id for m in mappings if m.mapping_type == BenchmarkMappingType.SUPPORTING}
        ),
        related_covered_control_count=len(
            {m.control_id for m in mappings if m.mapping_type == BenchmarkMappingType.RELATED}
        ),
        mapped_policy_count=len(policy_ids),
        enabled_mapped_policy_count=len(enabled_policy_ids),
    )


def policy_registry_fingerprint() -> str:
    """Section 18's own "policy-registry version" persisted on every
    CloudPostureEvaluationRun - a real sha256 fingerprint of every registered
    policy's (policy_id, version) pair, computed live rather than hand-maintained,
    since POLICY_REGISTRY (a code-defined dict, ADR 0051 Decision D1/D2) has no
    single version counter of its own. Two runs against the exact same registry
    state always produce the same fingerprint; any policy addition, removal, or
    version bump changes it."""
    pairs = sorted(f"{policy_id}@{d.version}" for policy_id, d in POLICY_REGISTRY.items())
    return hashlib.sha256("|".join(pairs).encode("utf-8")).hexdigest()
