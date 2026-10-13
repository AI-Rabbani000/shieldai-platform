"""Phase 20 (Continuation Prompt 7 / EDP-007), Part 7: the 23 authoritative Purple
Workforce security mission types, layered onto the existing `Mission` model via its
new nullable `mission_type` column (see models.py) - not a second mission schema.

`mission_type` is orthogonal to the existing `MissionKind` ("direct"/"chat" - which
Temporal workflow started the mission) - a chat-originated mission can still be a
real `vulnerability_assessment`, and a direct mission can be an ordinary
unclassified one. Neither concept replaces the other.

Eligibility validation here is deliberately narrower than the full Prompt 7 Part
11 Penetration Testing Coordinator / Part 10 Vulnerability-to-Auto-Fix workflows
(those own richer, dedicated Engagement/finding-lifecycle models planned for a
later Phase 20 sub-phase - see docs/build/phase-20.md). What's real today: a
`penetration_test`-typed mission fails closed unless the tenant has at least one
real, currently-active `AuthorizedTarget` row (reusing the existing Phase 8
Red Team safety model, not a new one); an `auto_fix`-typed mission fails closed
unless the tenant has at least one `Repository` whose `RepositoryPolicy.commit_allowed`
is True (reusing the existing Phase 17/18 governed write-path gate). Every other
mission type has no additional eligibility precondition beyond being a recognized
type.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import StrEnum

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from gds_api.models import AuthorizedTarget, CloudEnvironment, Repository, RepositoryPolicy


class MissionType(StrEnum):
    ALERT_TRIAGE = "alert_triage"
    INCIDENT_INVESTIGATION = "incident_investigation"
    THREAT_HUNT = "threat_hunt"
    THREAT_INTELLIGENCE = "threat_intelligence"
    VULNERABILITY_ASSESSMENT = "vulnerability_assessment"
    EXPOSURE_ASSESSMENT = "exposure_assessment"
    PENETRATION_TEST = "penetration_test"
    WEB_APPLICATION_TEST = "web_application_test"
    API_SECURITY_TEST = "api_security_test"
    NETWORK_SECURITY_TEST = "network_security_test"
    CLOUD_SECURITY_ASSESSMENT = "cloud_security_assessment"
    IDENTITY_SECURITY_ASSESSMENT = "identity_security_assessment"
    ADVERSARY_EMULATION = "adversary_emulation"
    AI_SECURITY_TEST = "ai_security_test"
    APPLICATION_SECURITY_REVIEW = "application_security_review"
    SUPPLY_CHAIN_ASSESSMENT = "supply_chain_assessment"
    DETECTION_ENGINEERING = "detection_engineering"
    REMEDIATION = "remediation"
    AUTO_FIX = "auto_fix"
    RETEST = "retest"
    COMPLIANCE_ASSESSMENT = "compliance_assessment"
    EXECUTIVE_REPORTING = "executive_reporting"
    FULL_PURPLE_ASSESSMENT = "full_purple_assessment"


MISSION_TYPES: frozenset[str] = frozenset(member.value for member in MissionType)

assert len(MISSION_TYPES) == 23, "Prompt 7 Part 7 requires exactly 23 mission types"


class MissionTypeIneligible(ValueError):
    """Raised when a mission of a sensitive type is requested without meeting its
    real, fail-closed eligibility precondition. Callers must surface this as a 4xx,
    never silently downgrade the mission_type or proceed anyway."""

    def __init__(self, mission_type: str, reason: str) -> None:
        self.mission_type = mission_type
        self.reason = reason
        super().__init__(f"Mission type '{mission_type}' is not eligible: {reason}")


def validate_mission_type_known(mission_type: str | None) -> None:
    """Fail closed on an unrecognized mission_type - never silently accept a typo
    or a future-reserved value that doesn't exist in the taxonomy yet."""
    if mission_type is not None and mission_type not in MISSION_TYPES:
        raise MissionTypeIneligible(
            mission_type, f"not one of the {len(MISSION_TYPES)} authoritative mission types"
        )


async def validate_mission_type_eligibility(
    db: AsyncSession, *, tenant_id: uuid.UUID, mission_type: str | None
) -> None:
    """Real, fail-closed eligibility checks for the mission types that need one.
    Raises MissionTypeIneligible; callers must not catch-and-proceed."""
    validate_mission_type_known(mission_type)

    if mission_type == MissionType.PENETRATION_TEST.value:
        now = datetime.now(UTC)
        result = await db.execute(
            select(AuthorizedTarget.id).where(
                AuthorizedTarget.tenant_id == tenant_id,
                AuthorizedTarget.status == "active",
                AuthorizedTarget.valid_from <= now,
                AuthorizedTarget.valid_until >= now,
            )
        )
        if result.first() is None:
            raise MissionTypeIneligible(
                mission_type,
                "no active, time-valid AuthorizedTarget exists for this tenant - a "
                "penetration_test mission must not be created without real, "
                "written authorisation scope (see gds_api.redteam_safety, ADR 0007)",
            )

    elif mission_type == MissionType.AUTO_FIX.value:
        result = await db.execute(
            select(Repository.id)
            .join(RepositoryPolicy, RepositoryPolicy.repository_id == Repository.id)
            .where(
                Repository.tenant_id == tenant_id,
                Repository.status == "AVAILABLE",
                RepositoryPolicy.commit_allowed.is_(True),
            )
        )
        if result.first() is None:
            raise MissionTypeIneligible(
                mission_type,
                "no available Repository with RepositoryPolicy.commit_allowed=True "
                "exists for this tenant - an auto_fix mission must not be created "
                "without a real, operator-approved governed write path",
            )

    elif mission_type == MissionType.CLOUD_SECURITY_ASSESSMENT.value:
        # EDP-009 Part 1, sub-phase 2: this real value has existed in the taxonomy
        # since Phase 20 Part 7 but never had an eligibility gate (confirmed via a
        # fresh read of this file before this Part's own pre-build audit, not
        # assumed) - CloudEnvironment (not AuthorizedTarget) is the real
        # authorised-scope record for cloud, per ADR 0050. This is the same
        # tenant-wide "does at least one eligible scope exist" pattern the two
        # branches above already use, not a check against one specific
        # environment_id - gds_api.cloud.discovery's own real job-creation flow
        # separately validates the specific target environment when a discovery
        # job actually starts.
        result = await db.execute(
            select(CloudEnvironment.id).where(
                CloudEnvironment.tenant_id == tenant_id,
                CloudEnvironment.enabled.is_(True),
            )
        )
        if result.first() is None:
            raise MissionTypeIneligible(
                mission_type,
                "no enabled CloudEnvironment exists for this tenant - a "
                "cloud_security_assessment mission must not be created without a "
                "real, registered, authorised cloud scope (see ADR 0050)",
            )
