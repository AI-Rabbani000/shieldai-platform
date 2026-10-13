"""Phase 4's real implementer of gds_api.agent_sdk.Agent - see docs/adr/0003 for why
this lives here instead of a separate packages/agent-sdk. One shared class,
FoundationAgent, parameterized by an AgentManifest, rather than five copy-pasted
implementations for the five Foundation Agents (gds_api.agents.registry).

Task-level assess/plan are intentionally thin: Rabbani AI Core's mission-level
assess_mission/decide_next_step (gds_api.workflows.activities) already decided which
tool this step needs and assigned it to this agent - a second per-task planning pass
would be redundant at this scope. execute/validate/report are where a Foundation Agent's
real work happens: enforcing its own tool allowlist, running the real tool via the Tool
Gateway, checking the outcome, and narrating it in its own voice.

Phase 14 (Continuation Prompt 1) extends AgentManifest with the authoritative
taxonomy/registry fields from docs/architecture/agent-registry.md - team, department,
status, risk_ceiling, and the rest. This stays a code-defined dict (see
gds_api.agents.registry), not a new database table: nothing here needs per-tenant
mutation or an admin UI to edit a single manifest field, and adding a DB table for
purely static data would be exactly the kind of premature parallel system ADR 0003
already argued against for the SDK itself. Revisit only when something real needs to
mutate a registry entry at runtime (e.g. the future Capability Broker).

Phase 20 (Continuation Prompt 7, ADR 0031) extends AgentManifest again with the
Unified Purple Cybersecurity Workforce taxonomy fields (workforce, purple_role_id,
purple_role_name, operational_domain, mission_role, objectives, knowledge_domains,
skills, approval_requirements, evidence_requirements, input_contracts,
output_contracts, collaboration_contracts, repository_permissions,
workspace_permissions, health_checks, degraded_reason, planned_reason, owner,
documentation_reference) - see docs/architecture/unified-purple-workforce.md and
docs/reviews/phase-20-purple-workforce-pre-build-audit.md for the reuse plan. These
are all additive fields with safe defaults: no existing manifest's real behavior
(tool access, capability access, risk ceiling) changes because of this extension.
Deliberately NOT added as new fields: `allowed_tools` (already covered by the
existing `allowed_tool_ids` property over `tool_names`), `risk_classes` plural
(the existing single `risk_ceiling` is the real enforced ceiling; per-capability
risk classes are already derivable via `allowed_capability_ids` ->
CAPABILITY_REGISTRY), `operational_status` (the existing `status` field already
serves this). `memory_permissions`/`repository_permissions`/`workspace_permissions`
are documentation-level declarations for the roster/taxonomy display only - real
enforcement stays exactly where it already lives (`memory_scopes`,
RepositoryPolicy.allowed_agents, WorkspacePolicy), not duplicated here.
"""

import json
import uuid
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from gds_api import model_router
from gds_api.agent_sdk import Agent

_ID_NAMESPACE = uuid.UUID("6f6e6f9e-2f0a-4c9a-9f0e-b7a8c1d2e3f4")


class Team(StrEnum):
    FOUNDATION = "FOUNDATION"
    BLUE = "BLUE"
    RED = "RED"
    PURPLE = "PURPLE"


class AgentStatus(StrEnum):
    OPERATIONAL = "OPERATIONAL"
    LIMITED = "LIMITED"
    PLANNED = "PLANNED"
    DISABLED = "DISABLED"
    # Phase 20 additions - the Prompt 7 status vocabulary (Operational, Degraded,
    # Planned, Blocked, Prohibited). LIMITED/DISABLED are not renamed or deprecated
    # (renaming a real enum value used nowhere as a string literal outside this file
    # would be safe, but zero current manifests use LIMITED and DISABLED has no
    # runtime meaning beyond "not loadable" - keeping both avoids two names for the
    # same thing while these new values give Phase 20 the vocabulary the prompt
    # requires): DEGRADED is a partially-working agent (some real capability, some
    # missing), BLOCKED is an agent whose code exists but is blocked by a missing
    # credential/dependency, PROHIBITED is a capability deliberately never to be
    # built regardless of future credentials (e.g. unrestricted shell execution).
    DEGRADED = "DEGRADED"
    BLOCKED = "BLOCKED"
    PROHIBITED = "PROHIBITED"


class RiskCeiling(StrEnum):
    """Highest real tool_gateway.TOOL_REGISTRY risk_class this agent's tool allow-list
    can reach: low->R1, medium->R2, high->R3, critical->R4. R0 is reserved for an
    agent with no tool access (none exist today); R5 is reserved for a future
    exploitation-class capability no current tool has."""

    R0 = "R0"
    R1 = "R1"
    R2 = "R2"
    R3 = "R3"
    R4 = "R4"
    R5 = "R5"


@dataclass(frozen=True)
class AgentManifest:
    name: str
    display_name: str
    description: str
    system_prompt: str
    tool_names: tuple[str, ...]
    team: Team
    department: str
    risk_ceiling: RiskCeiling
    # id/stable_key: `name` has been the real identity used everywhere else in the
    # system (MissionTask.agent_name, tool allow-lists, SSE events, the frontend URL
    # slug) since Phase 4 - it is not renamed here per the "no renaming stable
    # identifiers" rule. `stable_key` is an explicit alias equal to `name`, and `id` is
    # a real UUID5 deterministically derived from it (stable across restarts, not
    # randomly regenerated), added so the registry has a proper id field without a
    # second, drifting identity.
    id: uuid.UUID = field(init=False)
    stable_key: str = field(init=False)
    status: AgentStatus = AgentStatus.OPERATIONAL
    version: str = "1.0.0"
    implementation_class: str = "FoundationAgent"
    supervisor_agent_id: str | None = None
    supported_mission_types: tuple[str, ...] = ("direct", "chat")
    allowed_capability_ids: tuple[str, ...] = ()
    required_connector_ids: tuple[str, ...] = ()
    required_credentials: tuple[str, ...] = ()
    memory_scopes: tuple[str, ...] = ("relationship",)
    approval_policy: str = "risk-class-gated"
    target_authorisation_required: bool = False
    supports_streaming: bool = False
    supports_iterative_reasoning: bool = True
    supports_parallel_execution: bool = False
    # Real git commit dates for when this agent's registry entry was actually added
    # (`git log --follow -- apps/api/src/gds_api/agents/registry.py`), not fabricated
    # timestamps - see docs/architecture/agent-registry.md for the derivation.
    created_at: str = "2026-07-16"
    updated_at: str = "2026-07-16"

    # --- Phase 20 (Continuation Prompt 7) Unified Purple Cybersecurity Workforce
    # taxonomy fields. `workforce` is None for the 5 Foundation agents (platform
    # introspection, not a security-domain role) and "purple-cybersecurity-workforce"
    # for every agent realizing one of the 20 authoritative Purple roles defined in
    # gds_api.agents.purple_taxonomy. `purple_role_id`/`purple_role_name` are the
    # stable pointer into that taxonomy table - deliberately NOT a rename of `name`/
    # `stable_key` (see docs/architecture/purple-workforce-agent-migration.md: no
    # existing agent's stable identifier was renamed, to keep every historical
    # MissionTask.agent_name/Finding.source reference readable with zero alias
    # mechanism required). More than one agent manifest may share the same
    # purple_role_id where a Purple role is realized by multiple cooperating existing
    # agents (e.g. purple-03 Incident Response and DFIR = incident_response +
    # digital_forensics) - gds_api.agents.validation enforces that every one of the
    # 20 role IDs is covered by at least one manifest, and that no manifest points at
    # an unknown role ID.
    workforce: str | None = None
    purple_role_id: str | None = None
    purple_role_name: str | None = None
    operational_domain: str = ""
    mission_role: str = ""
    objectives: tuple[str, ...] = ()
    five_verb_contract: tuple[str, ...] = ("assess", "plan", "execute", "validate", "report")
    knowledge_domains: tuple[str, ...] = ()
    skills: tuple[str, ...] = ()
    approval_requirements: tuple[str, ...] = ()
    evidence_requirements: tuple[str, ...] = ()
    input_contracts: tuple[str, ...] = ()
    output_contracts: tuple[str, ...] = ()
    # Other agent stable keys (or purple_role_ids) this agent structurally
    # collaborates with - descriptive/roster-level today; Part 8's persisted
    # MissionMessage protocol is the real enforced collaboration channel.
    collaboration_contracts: tuple[str, ...] = ()
    repository_permissions: tuple[str, ...] = ()
    workspace_permissions: tuple[str, ...] = ()
    health_checks: tuple[str, ...] = ()
    degraded_reason: str = ""
    planned_reason: str = ""
    owner: str = ""
    documentation_reference: str = ""

    @property
    def allowed_tool_ids(self) -> tuple[str, ...]:
        return self.tool_names

    def __post_init__(self) -> None:
        object.__setattr__(self, "id", uuid.uuid5(_ID_NAMESPACE, self.name))
        object.__setattr__(self, "stable_key", self.name)


@dataclass(frozen=True)
class PlannedAgentManifest:
    """An agent that is real in taxonomy/intent but has no backend implementation yet -
    no AgentManifest, no tools, not returned by FoundationAgent/execute_task. Living
    here (not only as a frontend-only array) makes the backend the single source of
    truth for Planned agents too - see docs/reviews/phase-14-current-state-audit.md's
    'split source of truth' finding this fixes."""

    name: str
    display_name: str
    description: str
    team: Team
    department: str
    reason: str
    required_connector_ids: tuple[str, ...] = ()
    id: uuid.UUID = field(init=False)
    stable_key: str = field(init=False)
    status: AgentStatus = AgentStatus.PLANNED
    created_at: str = "2026-07-16"
    updated_at: str = "2026-07-17"

    # Phase 20 - same taxonomy fields as AgentManifest (see that class's comment),
    # minus the ones that only make sense for an agent with real tools/capabilities.
    workforce: str | None = None
    purple_role_id: str | None = None
    purple_role_name: str | None = None
    operational_domain: str = ""
    mission_role: str = ""
    objectives: tuple[str, ...] = ()
    knowledge_domains: tuple[str, ...] = ()
    skills: tuple[str, ...] = ()
    collaboration_contracts: tuple[str, ...] = ()
    owner: str = ""
    documentation_reference: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "id", uuid.uuid5(_ID_NAMESPACE, self.name))
        object.__setattr__(self, "stable_key", self.name)


class FoundationAgent(Agent):
    def __init__(self, manifest: AgentManifest) -> None:
        self.manifest = manifest

    async def assess(self, context: dict[str, Any]) -> dict[str, Any]:
        tool_name = context.get("tool_name")
        allowed = tool_name is None or tool_name in self.manifest.tool_names
        return {
            "can_execute": allowed,
            "reason": "" if allowed else f"{self.manifest.display_name} has no '{tool_name}' tool",
        }

    async def plan(self, context: dict[str, Any]) -> dict[str, Any]:
        # Pass-through by design - see module docstring.
        return {"tool_name": context.get("tool_name"), "input_data": context.get("input_data", {})}

    async def execute(self, plan: dict[str, Any]) -> dict[str, Any]:
        tool_name = plan.get("tool_name")
        if tool_name is None:
            return {"note": f"{self.manifest.display_name}: reasoning-only task, no tool call"}
        if tool_name not in self.manifest.tool_names:
            return {
                "error": f"{self.manifest.display_name} is not permitted to use tool '{tool_name}'"
            }

        # Phase 16, Part I: real tool execution must go through the Secure Capability
        # Broker's enforcement layer, never gds_api.tool_gateway.execute_tool directly -
        # see docs/reviews/phase-16-capability-control-audit.md's Entry Point A. A local
        # import avoids a real circular import (capabilities.gateway ->
        # capabilities.broker -> agents.registry -> agents.manifest).
        from gds_api.capabilities.gateway import (
            CapabilityExecutionDenied,
            execute_capability_request,
        )

        capability_request_id = plan.get("capability_request_id")
        if capability_request_id is None:
            return {
                "error": (
                    f"{self.manifest.display_name}: no capability decision was recorded for "
                    "this tool call - execution refused."
                )
            }

        db: AsyncSession = plan["db"]
        try:
            return await execute_capability_request(
                db,
                tenant_id=plan["tenant_id"],
                request_id=uuid.UUID(str(capability_request_id)),
                tool_name=tool_name,
                input_data=plan.get("input_data", {}),
                user_id=plan["user_id"],
                mission_id=plan["mission_id"],
            )
        except CapabilityExecutionDenied as denied:
            return {"error": denied.safe_message, "capability_decision": denied.decision}

    async def validate(self, result: dict[str, Any]) -> dict[str, Any]:
        output = result["output"]
        return {"valid": "error" not in output, "output": output}

    async def report(self, result: dict[str, Any]) -> str:
        db: AsyncSession = result["db"]
        return await model_router.complete(
            db,
            tenant_id=result["tenant_id"],
            mission_id=result["mission_id"],
            system=self.manifest.system_prompt,
            user_message=(
                f"You just completed this task: {result['task_description']}\n"
                f"Tool used: {result.get('tool_name') or 'none'}\n"
                f"Result: {json.dumps(result['output'], default=str)}\n\n"
                "Write 1-2 sentences reporting what you did and the real outcome, in "
                "first person as this agent. Plain text, no markdown."
            ),
            max_tokens=200,
        )
