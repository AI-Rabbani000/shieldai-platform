"""EDP-009 Part 2, Sections 8 and 10: the typed context/outcome shapes the
Applicability Engine and every Deterministic Evaluator share. Split into its own
module (rather than living in registry.py or evaluator.py) so both can depend on it
without a circular import - registry.py needs `Evaluator` to type
`PolicyDefinition.evaluator`; evaluator.py needs `PolicyDefinition` from registry.py
for the Applicability Engine.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field

from gds_api.cloud.posture.taxonomy import ApplicabilityState, EvaluationResult
from gds_api.models import (
    CloudAsset,
    CloudAssetRelationship,
    CloudEnvironment,
    CloudInventorySnapshot,
)


@dataclass(frozen=True)
class EvaluationContext:
    """Everything a Deterministic Evaluator (Section 10) is handed. Built entirely
    from data already queried out of Postgres by the evaluation-run service - an
    evaluator never queries a database itself, never calls a cloud provider, and never
    mutates any of these objects (Section 10's own explicit rules)."""

    tenant_id: uuid.UUID
    environment: CloudEnvironment
    # None for an ENVIRONMENT_LEVEL policy (Section 16) - there is no single target
    # resource, only the environment and (for policies that need to scan every asset,
    # e.g. "no CloudTrail asset discovered") `all_environment_assets` below.
    asset: CloudAsset | None
    # Real CloudAssetRelationship rows already queried for a RELATIONSHIP_BASED policy
    # (Section 17) - never re-derived ad hoc inside the evaluator.
    relationships: tuple[CloudAssetRelationship, ...] = ()
    # The other end of each relationship in `relationships`, in the same order, so an
    # evaluator never needs to issue its own lookup.
    related_assets: tuple[CloudAsset, ...] = ()
    # Every asset currently known for this environment - only populated for
    # ENVIRONMENT_LEVEL policies that must scan the whole inventory (e.g. "is there
    # any CloudTrail trail anywhere in this account"). Left empty for
    # RESOURCE_LEVEL/RELATIONSHIP_BASED policies to avoid an unnecessary full-table
    # fetch on every single-asset evaluation.
    all_environment_assets: tuple[CloudAsset, ...] = ()
    snapshot: CloudInventorySnapshot | None = None


@dataclass(frozen=True)
class EvaluationOutcome:
    """What a Deterministic Evaluator returns (Section 10). `facts` are the bounded,
    structured evidence facts Section 19/25 require - small, JSON-serialisable, never
    a raw unrestricted provider payload (the evaluation-run service applies the same
    size bound `gds_api.cloud.assets._bounded_metadata` already established for
    CloudAsset.raw_metadata, so an evaluator does not need to bound its own output)."""

    result: EvaluationResult
    explanation: str
    facts: Mapping[str, object] = field(default_factory=dict)
    # complete|partial|missing - Section 10's own "required-data state". An evaluator
    # returning PASS/FAIL with data_state="partial" is asserting its own confidence is
    # still real (the fields it needed were present), just that the broader
    # environment scan behind it may not have been - the evaluation-run service uses
    # this to decide whether to trust the result when the underlying
    # CloudInventorySnapshot.completeness_status is not "complete".
    data_state: str = "complete"
    # Overrides the policy's own default remediation guidance reference for this
    # specific outcome, if a more specific one applies. None means "use the policy
    # definition's own remediation_guidance" (the common case).
    remediation_reference: str | None = None
    # Populated only when result == ERROR - a short, safe (never a raw stack trace or
    # exception message that could leak internal detail) category string.
    error_category: str | None = None


Evaluator = Callable[[EvaluationContext], EvaluationOutcome]


@dataclass(frozen=True)
class ApplicabilityResult:
    """What the Applicability Engine (Section 8) decides before a policy's evaluator
    is ever invoked."""

    state: ApplicabilityState
    reason: str
