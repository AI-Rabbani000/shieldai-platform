"""Phase 20 (Continuation Prompt 7 / EDP-007), Part 9: the one authoritative Finding
lifecycle state machine, replacing the prior 4-state vocabulary
(`new|triaged|escalated|closed`) with the real 15-state lifecycle EDP-007 requires.

No arbitrary status mutation: every real status change must go through
`validate_finding_transition()` first, which raises `InvalidFindingTransition` on
any move not in `ALLOWED_TRANSITIONS`. A finding is never marked `remediated`/
`closed` merely because a patch or commit exists - `remediated` is only reachable
from `awaiting_retest` (a real retest must have actually run and passed first).

Several transitions are not explicitly enumerated in EDP-007's own worked example
list (`remediation_planned -> remediation_in_progress`, and what `accepted_risk`/
`reopened` lead to next) - these are filled in here with the most conservative,
clearly-documented interpretation rather than left undefined; see the inline
comments on `ALLOWED_TRANSITIONS` for each judgment call.
"""

from __future__ import annotations

from enum import StrEnum


class FindingStatus(StrEnum):
    OBSERVED = "observed"
    TRIAGED = "triaged"
    ENRICHED = "enriched"
    PRIORITISED = "prioritised"
    AWAITING_VALIDATION = "awaiting_validation"
    VALIDATED = "validated"
    REJECTED = "rejected"
    ACCEPTED_RISK = "accepted_risk"
    REMEDIATION_PLANNED = "remediation_planned"
    REMEDIATION_IN_PROGRESS = "remediation_in_progress"
    AWAITING_RETEST = "awaiting_retest"
    RETEST_FAILED = "retest_failed"
    REMEDIATED = "remediated"
    CLOSED = "closed"
    REOPENED = "reopened"


FINDING_STATUSES: frozenset[str] = frozenset(member.value for member in FindingStatus)

assert len(FINDING_STATUSES) == 15, "EDP-007 Part 9 requires exactly 15 finding states"

# EDP-007's own explicit examples, plus conservative fills for transitions the
# prompt names as states but doesn't spell out an explicit "moves to" rule for:
#   - REMEDIATION_PLANNED -> REMEDIATION_IN_PROGRESS: the only sensible next step
#     for a plan that's been committed to (not explicit in the prompt, but the
#     alternative - a REMEDIATION_PLANNED state with no way to ever leave it other
#     than backing out - can't be what was intended).
#   - ACCEPTED_RISK -> {REMEDIATION_PLANNED, CLOSED}: a risk-acceptance decision
#     can later be reversed (something changes, remediation becomes worth doing)
#     or formally closed out as-is. Not explicit in the prompt; this is the
#     narrowest reasonable reading, not an open-ended one.
#   - REOPENED -> TRIAGED: re-enters the pipeline near the start rather than
#     assuming any prior enrichment/prioritisation is still valid - the safest
#     conservative choice, not explicit in the prompt.
#   - REJECTED: left terminal (no further transition given by the prompt).
ALLOWED_TRANSITIONS: dict[str, frozenset[str]] = {
    FindingStatus.OBSERVED: frozenset({FindingStatus.TRIAGED}),
    FindingStatus.TRIAGED: frozenset({FindingStatus.ENRICHED}),
    FindingStatus.ENRICHED: frozenset({FindingStatus.PRIORITISED}),
    FindingStatus.PRIORITISED: frozenset({FindingStatus.AWAITING_VALIDATION}),
    FindingStatus.AWAITING_VALIDATION: frozenset({FindingStatus.VALIDATED, FindingStatus.REJECTED}),
    FindingStatus.VALIDATED: frozenset(
        {FindingStatus.REMEDIATION_PLANNED, FindingStatus.ACCEPTED_RISK}
    ),
    FindingStatus.REJECTED: frozenset(),
    FindingStatus.ACCEPTED_RISK: frozenset(
        {FindingStatus.REMEDIATION_PLANNED, FindingStatus.CLOSED}
    ),
    FindingStatus.REMEDIATION_PLANNED: frozenset({FindingStatus.REMEDIATION_IN_PROGRESS}),
    FindingStatus.REMEDIATION_IN_PROGRESS: frozenset({FindingStatus.AWAITING_RETEST}),
    FindingStatus.AWAITING_RETEST: frozenset(
        {FindingStatus.REMEDIATED, FindingStatus.RETEST_FAILED}
    ),
    FindingStatus.RETEST_FAILED: frozenset({FindingStatus.REMEDIATION_PLANNED}),
    FindingStatus.REMEDIATED: frozenset({FindingStatus.CLOSED}),
    FindingStatus.CLOSED: frozenset({FindingStatus.REOPENED}),
    FindingStatus.REOPENED: frozenset({FindingStatus.TRIAGED}),
}

# Migration mapping from the pre-Phase-20 4-state vocabulary to the real 15-state
# one - applied once, as data, by migration 800f9c3ac27a's successor (see
# migrations/versions/ for the exact revision). "escalated" (a finding attached to
# a real Incident) maps to awaiting_validation, not any later state: escalation to
# an Incident is a SOC/IR-domain fact (IncidentFinding), not itself proof the
# finding was ever independently validated - Part 9's own rule that a finding is
# never closed merely because something downstream referenced it applies here too.
LEGACY_STATUS_MIGRATION: dict[str, str] = {
    "new": FindingStatus.OBSERVED.value,
    "triaged": FindingStatus.TRIAGED.value,
    "escalated": FindingStatus.AWAITING_VALIDATION.value,
    "closed": FindingStatus.CLOSED.value,
}


class InvalidFindingTransition(ValueError):
    def __init__(self, from_status: str, to_status: str, reason: str) -> None:
        self.from_status = from_status
        self.to_status = to_status
        super().__init__(f"Finding cannot move from '{from_status}' to '{to_status}': {reason}")


def validate_finding_transition(
    from_status: str, to_status: str, *, reopen_reason: str | None = None
) -> None:
    """Fails closed on any transition not explicitly allowed. The closed->reopened
    transition additionally requires a real, non-empty reopen_reason - "closed may
    move to reopened only with a documented reason" per EDP-007 Part 9."""
    if from_status not in FINDING_STATUSES:
        raise InvalidFindingTransition(
            from_status, to_status, f"'{from_status}' is not a real finding status"
        )
    if to_status not in FINDING_STATUSES:
        raise InvalidFindingTransition(
            from_status, to_status, f"'{to_status}' is not a real finding status"
        )
    allowed = ALLOWED_TRANSITIONS.get(from_status, frozenset())
    if to_status not in allowed:
        raise InvalidFindingTransition(
            from_status,
            to_status,
            f"not a permitted transition (allowed from '{from_status}': "
            f"{sorted(allowed) or 'none - terminal state'})",
        )
    if (
        from_status == FindingStatus.CLOSED.value
        and to_status == FindingStatus.REOPENED.value
        and not (reopen_reason or "").strip()
    ):
        raise InvalidFindingTransition(
            from_status, to_status, "reopening a closed finding requires a documented reason"
        )
