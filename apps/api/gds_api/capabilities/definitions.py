"""Phase 16 (Continuation Prompt 3), Parts B-C: the Capability domain model - an
authorized operational power, distinct from (but linked to) a Tool, which is an
implementation. See docs/architecture/capability-domain-model.md for the full design and
docs/adr/0015-capability-definition-authority.md for why this stays a code-defined
catalogue (mirroring gds_api.agents.manifest/registry's own precedent, ADR 0012) with
only real-time enablement state in the database - never risk_class or any other
security-critical property.

Reuses gds_api.agents.manifest.Team directly rather than defining a second team enum -
"which teams may request this capability" and "which team does this agent belong to"
must always be the same vocabulary or the two systems could silently drift apart.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import StrEnum

from gds_api.agents.manifest import Team

_ID_NAMESPACE = uuid.UUID("9b1a2c3d-4e5f-4a6b-8c7d-1e2f3a4b5c6d")


class CapabilityStatus(StrEnum):
    OPERATIONAL = "OPERATIONAL"
    LIMITED = "LIMITED"
    PLANNED = "PLANNED"
    DISABLED = "DISABLED"
    DEPRECATED = "DEPRECATED"


class RiskClass(StrEnum):
    """R0-R5, per docs/security/capability-risk-model.md. Deliberately the SAME scale
    gds_api.agents.manifest.RiskCeiling already uses (Phase 14) - an agent's risk
    ceiling and a capability's risk_class must be directly comparable for the broker's
    "does this agent's ceiling cover this capability" check to mean anything. R0/R1 add
    real granularity within what Phase 14 called "low" (a genuinely side-effect-free
    read vs. a low-risk read with a minor real mutation) - R2/R3/R4 map unchanged from
    Phase 14's medium/high/critical, so no existing agent's risk_ceiling needed to
    change. See ADR 0014's "risk model" section for the full per-tool reasoning."""

    R0 = "R0"  # No external side effect (pure internal read).
    R1 = "R1"  # Low-risk read-only external activity, or a low-risk internal mutation.
    R2 = "R2"  # Controlled internal state change.
    R3 = "R3"  # External read with real side effects, or a destructive internal action.
    R4 = "R4"  # Offensive, disruptive, or potentially destructive against a real target.
    R5 = "R5"  # Prohibited - no capability may ever be defined at this level.


class SideEffectType(StrEnum):
    NONE = "NONE"
    READ_EXTERNAL = "READ_EXTERNAL"
    WRITE_INTERNAL = "WRITE_INTERNAL"
    WRITE_EXTERNAL = "WRITE_EXTERNAL"
    DESTRUCTIVE = "DESTRUCTIVE"
    OFFENSIVE = "OFFENSIVE"


@dataclass(frozen=True)
class CapabilityDefinition:
    stable_key: str
    display_name: str
    description: str
    category: str
    risk_class: RiskClass
    side_effect_type: SideEffectType
    required_tool_ids: tuple[str, ...]
    id: uuid.UUID = field(init=False)
    status: CapabilityStatus = CapabilityStatus.OPERATIONAL
    version: str = "1.0.0"
    target_types: tuple[str, ...] = ("none",)
    allowed_team_types: tuple[Team, ...] = ()
    allowed_agent_ids: tuple[str, ...] = ()
    required_connector_ids: tuple[str, ...] = ()
    requires_mission: bool = True
    requires_workflow_run: bool = True
    requires_case: bool = False
    requires_human_approval: bool = False
    requires_target_authorisation: bool = False
    requires_emergency_stop_clear: bool = False
    requires_sandbox: bool = False
    allows_network: bool = False
    network_policy_reference: str | None = None
    filesystem_policy_reference: str | None = None
    credential_policy_reference: str | None = None
    rate_limit_policy_reference: str | None = None
    maximum_duration_seconds: int = 90
    maximum_attempts: int = 1
    maximum_output_bytes: int | None = None
    evidence_required: bool = True
    rollback_required: bool = False
    independent_validation_required: bool = False
    audit_level: str = "standard"
    # Code-defined default - the ONE property a real DB-backed CapabilityState row may
    # override at runtime (disable only; a disabled default can never be re-enabled by
    # database state alone - see docs/adr/0015). Every other field on this dataclass is
    # immutable for the life of the running process.
    enabled: bool = True
    created_at: str = "2026-07-17"
    updated_at: str = "2026-07-17"

    def __post_init__(self) -> None:
        object.__setattr__(self, "id", uuid.uuid5(_ID_NAMESPACE, self.stable_key))
