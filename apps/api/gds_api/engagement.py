"""Phase 20 (Continuation Prompt 7 / EDP-007), Part 11: the real Engagement state
machine and technique vocabulary. Layered on top of gds_api.redteam_safety's existing
3-check safety boundary (emergency stop, target authorization, rate limit) - never
replacing it. Every real recon action gds_api.tool_gateway._coordinate_pentest_engagement
runs still passes through that exact boundary per target; this module only governs the
Engagement record's own lifecycle and which of the coordinator's known techniques an
engagement's rules of engagement permit.
"""

from __future__ import annotations

from enum import StrEnum


class EngagementStatus(StrEnum):
    PLANNED = "planned"
    AUTHORIZED = "authorized"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    ABORTED = "aborted"


ENGAGEMENT_STATUSES: frozenset[str] = frozenset(member.value for member in EngagementStatus)

_ALLOWED_TRANSITIONS: dict[str, frozenset[str]] = {
    EngagementStatus.PLANNED.value: frozenset(
        {EngagementStatus.AUTHORIZED.value, EngagementStatus.ABORTED.value}
    ),
    EngagementStatus.AUTHORIZED.value: frozenset(
        {EngagementStatus.IN_PROGRESS.value, EngagementStatus.ABORTED.value}
    ),
    EngagementStatus.IN_PROGRESS.value: frozenset(
        {EngagementStatus.COMPLETED.value, EngagementStatus.ABORTED.value}
    ),
    EngagementStatus.COMPLETED.value: frozenset(),
    EngagementStatus.ABORTED.value: frozenset(),
}


class InvalidEngagementTransition(ValueError):
    def __init__(self, current: str, target: str) -> None:
        self.current = current
        self.target = target
        super().__init__(f"Engagement cannot move from '{current}' to '{target}'")


def validate_engagement_transition(current: str, target: str) -> None:
    """Fails closed on any move not explicitly allowed - same discipline as
    gds_api.finding_lifecycle.validate_finding_transition."""
    if target not in _ALLOWED_TRANSITIONS.get(current, frozenset()):
        raise InvalidEngagementTransition(current, target)


# The real, fixed technique names gds_api.tool_gateway._coordinate_pentest_engagement
# actually knows how to run today - deliberately narrow (real DNS enumeration, a
# lightweight-active port scan, and a passive TLS probe; never exploitation or
# credential attacks). Honestly not a full MITRE ATT&CK technique catalogue - see
# docs/architecture/unified-purple-workforce.md#purple-07.
KNOWN_TECHNIQUES: frozenset[str] = frozenset({"dns_enumeration", "port_scan", "tls_probe"})
