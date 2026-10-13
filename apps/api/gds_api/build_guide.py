"""Real, checked build-guide status for the Phase 6 Build Guide page (spec section 30):
every section's status is computed from an actual check against running infrastructure,
the real agent/tool registries, or real tenant data - never a hardcoded "done".

Gated behind the same missions:read permission gds_api.agents_router already reuses for
read-only platform metadata (see its own docstring) - this is authenticated operator
insight, not public data, unlike /health.
"""

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from gds_api.agents.registry import AGENT_REGISTRY
from gds_api.config import settings
from gds_api.db import get_db
from gds_api.health import check_all_services
from gds_api.models import Mission
from gds_api.schemas import BuildGuideSectionOut, BuildGuideStatusOut
from gds_api.security import CurrentUser, require_permission
from gds_api.seed_data import POLICY_RULES
from gds_api.tool_gateway import TOOL_REGISTRY

router = APIRouter(prefix="/build-guide", tags=["build-guide"])

TOTAL_DEPARTMENT_AGENTS = 21


@router.get("/status", response_model=BuildGuideStatusOut)
async def get_build_guide_status(
    current_user: CurrentUser = Depends(require_permission("missions:read")),
    db: AsyncSession = Depends(get_db),
) -> BuildGuideStatusOut:
    sections: list[BuildGuideSectionOut] = []

    services = await check_all_services()
    unhealthy = [s for s in services if s.status != "healthy"]
    sections.append(
        BuildGuideSectionOut(
            id="infrastructure",
            label="Local infrastructure (Postgres/Redis/Neo4j/Qdrant/Temporal/NATS/MinIO)",
            status="complete" if not unhealthy else "failed",
            detail=(
                "All 7 services healthy"
                if not unhealthy
                else f"Unhealthy: {', '.join(s.name for s in unhealthy)}"
            ),
        )
    )

    sections.append(
        BuildGuideSectionOut(
            id="model_setup",
            label="Model provider (Anthropic)",
            status="complete" if settings.anthropic_api_key else "incomplete",
            detail=(
                "ANTHROPIC_API_KEY is set"
                if settings.anthropic_api_key
                else "ANTHROPIC_API_KEY is not set in .env - missions cannot run"
            ),
        )
    )

    agent_count = len(AGENT_REGISTRY)
    sections.append(
        BuildGuideSectionOut(
            id="agent_registration",
            label="Agent registry",
            status="complete" if agent_count >= TOTAL_DEPARTMENT_AGENTS else "warning",
            detail=f"{agent_count}/{TOTAL_DEPARTMENT_AGENTS} department agents registered",
        )
    )

    sections.append(
        BuildGuideSectionOut(
            id="tool_registration",
            label="Tool Gateway registry",
            status="complete" if TOOL_REGISTRY else "incomplete",
            detail=f"{len(TOOL_REGISTRY)} real tools registered",
        )
    )

    sections.append(
        BuildGuideSectionOut(
            id="policy_setup",
            label="Policy engine",
            status="complete" if POLICY_RULES else "incomplete",
            detail=f"{len(POLICY_RULES)} risk-class rules defined",
        )
    )

    sections.append(
        BuildGuideSectionOut(
            id="integrations",
            label="External integrations (AWS, GitHub, Azure, GCP, SIEM/EDR, IdP)",
            status="optional",
            detail="Phase 7 scope - agents needing these are registered as Planned until supplied",
        )
    )

    mission_count = (
        await db.execute(
            select(func.count(Mission.id)).where(Mission.tenant_id == current_user.tenant_id)
        )
    ).scalar_one()
    sections.append(
        BuildGuideSectionOut(
            id="first_mission",
            label="First mission run",
            status="complete" if mission_count > 0 else "incomplete",
            detail=(
                f"{mission_count} mission(s) created for this tenant"
                if mission_count > 0
                else "No missions created yet - create one from Mastermind"
            ),
        )
    )

    sections.append(
        BuildGuideSectionOut(
            id="backup_restore",
            label="Backup & restore",
            status="optional",
            detail="scripts/backup-gds.ps1 / restore-gds.ps1 - see docs/BUILD-STATUS.md Phase 9",
        )
    )

    sections.append(
        BuildGuideSectionOut(
            id="deployment",
            label="Deployment",
            status="optional",
            detail="Local-only by design (docs/adr/0001) - no cloud deployment planned",
        )
    )

    return BuildGuideStatusOut(sections=sections)
