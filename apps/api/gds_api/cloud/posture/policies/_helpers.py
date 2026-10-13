"""Small, real helpers shared across provider policy modules - kept out of the
evaluators themselves so each evaluator function stays a short, readable, direct
statement of one policy's logic (Section 10's own "explanation should identify what
was evaluated / which fact failed" is easiest to keep true when the evaluator body is
short).
"""

from __future__ import annotations

from typing import Any

from gds_api.cloud.posture.taxonomy import EvaluationResult
from gds_api.cloud.posture.types import EvaluationContext, EvaluationOutcome


def is_truncated_metadata(raw_metadata: dict[str, Any]) -> bool:
    """gds_api.cloud.assets._bounded_metadata replaces raw_metadata with a
    `{"_truncated": true, ...}` marker when the real payload exceeded the 8,000-byte
    bound - an evaluator must never treat a truncated blob as "field genuinely
    absent" (which would misreport UNSUPPORTED) nor evaluate a partial fragment as if
    it were the whole picture (which could miss a real violation)."""
    return bool(raw_metadata.get("_truncated"))


def security_group_open_ip_permissions(
    raw_metadata: dict[str, Any], *, port: int | None = None
) -> list[dict[str, Any]]:
    """Real `IpPermissions` entries (the AWS adapter preserves this structure
    verbatim - docs/reviews/phase-22-part2-policy-feasibility-matrix.md) that allow
    ingress from 0.0.0.0/0 or ::/0, optionally restricted to entries that also cover
    the given port. Returns [] if `IpPermissions` is absent, empty, or malformed -
    never guessed."""
    permissions = raw_metadata.get("IpPermissions")
    if not isinstance(permissions, list):
        return []
    matches: list[dict[str, Any]] = []
    for entry in permissions:
        if not isinstance(entry, dict):
            continue
        ip_ranges = entry.get("IpRanges") or []
        ipv6_ranges = entry.get("Ipv6Ranges") or []
        open_to_world = any(
            isinstance(r, dict) and r.get("CidrIp") == "0.0.0.0/0" for r in ip_ranges
        ) or any(isinstance(r, dict) and r.get("CidrIpv6") == "::/0" for r in ipv6_ranges)
        if not open_to_world:
            continue
        if port is not None:
            from_port = entry.get("FromPort")
            to_port = entry.get("ToPort")
            protocol = entry.get("IpProtocol")
            covers_port = protocol == "-1" or (
                isinstance(from_port, int)
                and isinstance(to_port, int)
                and from_port <= port <= to_port
            )
            if not covers_port:
                continue
        matches.append(entry)
    return matches


_MISSING = object()


def get_nested(raw_metadata: dict[str, Any], *path: str) -> Any:
    """Walks a dotted path through nested dicts (e.g. Azure's `.as_dict()` output,
    which nests real fields under "properties"), returning the sentinel `_MISSING`
    (never `None`, which is itself a real, distinct value some fields can genuinely
    hold) if any segment is absent or not a dict. Callers compare against `_MISSING`
    explicitly, never `is None`, to keep "field absent" and "field present but null"
    distinguishable."""
    current: Any = raw_metadata
    for segment in path:
        if not isinstance(current, dict) or segment not in current:
            return _MISSING
        current = current[segment]
    return current


def is_missing(value: Any) -> bool:
    return value is _MISSING


def environment_level_absence_outcome(
    context: EvaluationContext, *, category: str, resource_label: str
) -> EvaluationOutcome | None:
    """Section 16's own rule: "If the relevant discovery category failed or was
    unsupported: Return UNSUPPORTED or INDETERMINATE. Do not fail the environment
    automatically." Returns None (meaning "a matching asset was found - caller should
    evaluate its state, not its absence") when at least one asset of `category`
    exists; otherwise returns the correct absence outcome given the environment's
    real, disclosed inventory-snapshot completeness."""
    matches = [a for a in context.all_environment_assets if a.provider_category == category]
    if matches:
        return None
    if context.snapshot is None:
        return EvaluationOutcome(
            result=EvaluationResult.INDETERMINATE,
            explanation=(
                f"No {resource_label} asset was found, but no inventory snapshot is "
                "available to confirm this environment's most recent discovery run was "
                "complete - absence cannot be treated as a confirmed finding."
            ),
            data_state="missing",
        )
    if context.snapshot.completeness_status != "complete":
        return EvaluationOutcome(
            result=EvaluationResult.INDETERMINATE,
            explanation=(
                f"No {resource_label} asset was found, but the environment's inventory "
                f"snapshot completeness_status is '{context.snapshot.completeness_status}' "
                "(not 'complete') - absence cannot be treated as a confirmed finding."
            ),
            data_state="partial",
        )
    return EvaluationOutcome(
        result=EvaluationResult.FAIL,
        explanation=f"No {resource_label} asset was discovered anywhere in this environment.",
        data_state="complete",
    )
