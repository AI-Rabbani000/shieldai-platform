"""Read-only listing of the real agent registry (gds_api.agents.registry). Static,
non-sensitive metadata, so this reuses the existing missions:read permission rather than
inventing a new one just for it.

Phase 14 (Continuation Prompt 1), Part F: adds team/department/status filters to the
existing list endpoint, a real GET /agents/planned (the backend is now the single
source of truth for Planned agents too - see agents/registry.py's PLANNED_AGENTS), and
GET /agents/{name} for a single agent's full detail. No new permission is introduced -
everything here stays read-only and reuses missions:read, matching the existing design.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from gds_api.agents.manifest import AgentManifest
from gds_api.agents.registry import AGENT_REGISTRY, PLANNED_AGENTS
from gds_api.db import get_db
from gds_api.models import MissionTask
from gds_api.schemas import AgentActivityOut, AgentOut, PlannedAgentOut
from gds_api.security import CurrentUser, require_permission

router = APIRouter(prefix="/agents", tags=["agents"])


def _to_agent_out(manifest: AgentManifest) -> AgentOut:
    return AgentOut(
        id=manifest.id,
        name=manifest.name,
        stable_key=manifest.stable_key,
        display_name=manifest.display_name,
        description=manifest.description,
        tool_names=list(manifest.tool_names),
        team=manifest.team.value,
        department=manifest.department,
        status=manifest.status.value,
        version=manifest.version,
        implementation_class=manifest.implementation_class,
        supervisor_agent_id=manifest.supervisor_agent_id,
        risk_ceiling=manifest.risk_ceiling.value,
        supported_mission_types=list(manifest.supported_mission_types),
        allowed_capability_ids=list(manifest.allowed_capability_ids),
        required_connector_ids=list(manifest.required_connector_ids),
        required_credentials=list(manifest.required_credentials),
        memory_scopes=list(manifest.memory_scopes),
        approval_policy=manifest.approval_policy,
        target_authorisation_required=manifest.target_authorisation_required,
        supports_streaming=manifest.supports_streaming,
        supports_iterative_reasoning=manifest.supports_iterative_reasoning,
        supports_parallel_execution=manifest.supports_parallel_execution,
        created_at=manifest.created_at,
        updated_at=manifest.updated_at,
        workforce=manifest.workforce,
        purple_role_id=manifest.purple_role_id,
        purple_role_name=manifest.purple_role_name,
        operational_domain=manifest.operational_domain,
        mission_role=manifest.mission_role,
        objectives=list(manifest.objectives),
        five_verb_contract=list(manifest.five_verb_contract),
        knowledge_domains=list(manifest.knowledge_domains),
        skills=list(manifest.skills),
        approval_requirements=list(manifest.approval_requirements),
        evidence_requirements=list(manifest.evidence_requirements),
        input_contracts=list(manifest.input_contracts),
        output_contracts=list(manifest.output_contracts),
        collaboration_contracts=list(manifest.collaboration_contracts),
        repository_permissions=list(manifest.repository_permissions),
        workspace_permissions=list(manifest.workspace_permissions),
        health_checks=list(manifest.health_checks),
        degraded_reason=manifest.degraded_reason,
        planned_reason=manifest.planned_reason,
        owner=manifest.owner,
        documentation_reference=manifest.documentation_reference,
    )


@router.get("", response_model=list[AgentOut])
async def list_agents(
    team: str | None = None,
    department: str | None = None,
    status_filter: str | None = None,
    current_user: CurrentUser = Depends(require_permission("missions:read")),
) -> list[AgentOut]:
    """Real registry data only - no synthetic/fabricated status. `status_filter` is the
    query param name (not `status`) to avoid shadowing FastAPI's `status` module import
    elsewhere in this file."""
    agents = [_to_agent_out(manifest) for manifest in AGENT_REGISTRY.values()]
    if team:
        agents = [a for a in agents if a.team.lower() == team.lower()]
    if department:
        agents = [a for a in agents if a.department.lower() == department.lower()]
    if status_filter:
        agents = [a for a in agents if a.status.lower() == status_filter.lower()]
    return agents


@router.get("/planned", response_model=list[PlannedAgentOut])
async def list_planned_agents(
    current_user: CurrentUser = Depends(require_permission("missions:read")),
) -> list[PlannedAgentOut]:
    """Phase 14: the backend's own authoritative Planned-agent list, replacing the
    frontend-only apps/web/lib/agents-registry.ts hardcoded array as the source of
    truth."""
    return [
        PlannedAgentOut(
            id=planned.id,
            name=planned.name,
            stable_key=planned.stable_key,
            display_name=planned.display_name,
            description=planned.description,
            team=planned.team.value,
            department=planned.department,
            status=planned.status.value,
            reason=planned.reason,
            required_connector_ids=list(planned.required_connector_ids),
            created_at=planned.created_at,
            updated_at=planned.updated_at,
            workforce=planned.workforce,
            purple_role_id=planned.purple_role_id,
            purple_role_name=planned.purple_role_name,
            operational_domain=planned.operational_domain,
            mission_role=planned.mission_role,
            objectives=list(planned.objectives),
            knowledge_domains=list(planned.knowledge_domains),
            skills=list(planned.skills),
            collaboration_contracts=list(planned.collaboration_contracts),
            owner=planned.owner,
            documentation_reference=planned.documentation_reference,
        )
        for planned in PLANNED_AGENTS.values()
    ]


@router.get("/activity", response_model=list[AgentActivityOut])
async def get_agent_activity(
    current_user: CurrentUser = Depends(require_permission("missions:read")),
    db: AsyncSession = Depends(get_db),
) -> list[AgentActivityOut]:
    """Phase 12.2: a real busy/idle signal built from data that already exists -
    MissionTask.status == 'running' - rather than inventing new state. Fixes the
    hardcoded 'active' badge every agent got on the /agents page regardless of whether
    it was actually doing anything."""
    tasks = (
        (
            await db.execute(
                select(MissionTask).where(
                    MissionTask.tenant_id == current_user.tenant_id,
                    MissionTask.status == "running",
                    MissionTask.agent_name.is_not(None),
                )
            )
        )
        .scalars()
        .all()
    )
    return [
        AgentActivityOut(
            agent_name=task.agent_name,
            mission_id=task.mission_id,
            task_id=task.id,
            description=task.description,
        )
        for task in tasks
    ]


@router.get("/{agent_name}", response_model=AgentOut)
async def get_agent(
    agent_name: str,
    current_user: CurrentUser = Depends(require_permission("missions:read")),
) -> AgentOut:
    # Registered last (not right after list_agents) on purpose: FastAPI/Starlette
    # matches routes in registration order, and a path-parameter route registered
    # before /activity or /planned would swallow those literal-path requests as
    # agent_name="activity"/"planned" instead - a real routing bug caught during this
    # phase's own review before it shipped, same class of mistake main.py's own
    # /metrics/summary-vs-/metrics comment already documents.
    manifest = AGENT_REGISTRY.get(agent_name)
    if manifest is None:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND, f"Agent '{agent_name}' not found or not operational"
        )
    return _to_agent_out(manifest)
