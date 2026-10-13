"""Phase 14 (Continuation Prompt 1), Part E: startup-time validation of
gds_api.agents.registry's AGENT_REGISTRY/PLANNED_AGENTS. Runs once at app startup
(gds_api.main) against the static in-code registry - cheap, synchronous, no DB/network
I/O needed since nothing here is tenant-scoped or externally-configured yet.

A failure raises RegistryValidationError with the offending agent's stable_key and the
exact rule violated - never silently drops or "corrects" an invalid entry, per this
programme's non-negotiable rules.
"""

from __future__ import annotations

from gds_api.agents.manifest import AgentStatus, RiskCeiling, Team
from gds_api.agents.registry import AGENT_REGISTRY, PLANNED_AGENTS
from gds_api.tool_gateway import TOOL_REGISTRY
from gds_api.reasoning.kernel_bridge import execute_tool as kernel_execute_tool

# Risk classes tool_gateway.TOOL_REGISTRY actually uses, ordered low -> critical, mapped
# to RiskCeiling so "does this agent's risk_ceiling cover its highest real tool" can be
# checked without a second hardcoded table drifting from tool_gateway's own values.
_TOOL_RISK_TO_CEILING = {
    "low": RiskCeiling.R1,
    "medium": RiskCeiling.R2,
    "high": RiskCeiling.R3,
    "critical": RiskCeiling.R4,
}
_CEILING_ORDER = [
    RiskCeiling.R0,
    RiskCeiling.R1,
    RiskCeiling.R2,
    RiskCeiling.R3,
    RiskCeiling.R4,
    RiskCeiling.R5,
]


class RegistryValidationError(ValueError):
    def __init__(self, agent_key: str, rule: str, detail: str) -> None:
        self.agent_key = agent_key
        self.rule = rule
        super().__init__(f"Agent registry validation failed for '{agent_key}': {rule} - {detail}")


def validate_agent_registry() -> None:
    """Raises RegistryValidationError on the first violation found. Called from
    gds_api.main at startup. Deliberately fails loudly rather than best-effort-fixing
    an invalid entry - a broken registry should stop the app from starting, not run
    with agents users can't trust."""
    _check_duplicate_keys()
    _check_duplicate_display_names()
    _check_planned_agents_not_operational()
    _check_operational_agents_loadable()
    _check_tool_references()
    _check_supervisor_references()
    _check_supervisor_cycles()
    _check_red_team_safety_policy()
    _check_high_risk_approval_policy()
    _check_risk_ceiling_covers_real_tools()
    _check_cloud_security_never_operational_without_connector()
    _check_allowed_capability_ids_consistent()
    _check_purple_taxonomy_consistency()


def _all_stable_keys() -> list[str]:
    return list(AGENT_REGISTRY.keys()) + list(PLANNED_AGENTS.keys())


def _check_duplicate_keys() -> None:
    keys = _all_stable_keys()
    seen: set[str] = set()
    for key in keys:
        if key in seen:
            raise RegistryValidationError(
                key,
                "duplicate_stable_key",
                "appears more than once across AGENT_REGISTRY/PLANNED_AGENTS",
            )
        seen.add(key)


def _check_duplicate_display_names() -> None:
    seen: dict[str, str] = {}
    all_display_names: list[tuple[str, str]] = [
        (key, manifest.display_name) for key, manifest in AGENT_REGISTRY.items()
    ] + [(key, planned.display_name) for key, planned in PLANNED_AGENTS.items()]
    for key, display_name in all_display_names:
        if display_name in seen and seen[display_name] != key:
            raise RegistryValidationError(
                key,
                "duplicate_display_name",
                f"shares display_name with '{seen[display_name]}'",
            )
        seen[display_name] = key


def _check_planned_agents_not_operational() -> None:
    for key, planned in PLANNED_AGENTS.items():
        if planned.status != AgentStatus.PLANNED:
            raise RegistryValidationError(
                key, "planned_agent_wrong_status", f"status={planned.status}, expected PLANNED"
            )
        if key in AGENT_REGISTRY:
            raise RegistryValidationError(
                key,
                "planned_agent_also_operational",
                "present in both PLANNED_AGENTS and AGENT_REGISTRY",
            )


def _check_operational_agents_loadable() -> None:
    from gds_api.agents.manifest import FoundationAgent

    # Phase 20: DEGRADED joins OPERATIONAL/LIMITED as a real AGENT_REGISTRY status -
    # a partially-working agent still has real, loadable code (unlike PLANNED/
    # BLOCKED/PROHIBITED, which have none), so it belongs here, not in
    # PLANNED_AGENTS.
    _loadable_statuses = (AgentStatus.OPERATIONAL, AgentStatus.LIMITED, AgentStatus.DEGRADED)
    for key, manifest in AGENT_REGISTRY.items():
        if manifest.status not in _loadable_statuses:
            raise RegistryValidationError(
                key,
                "operational_agent_bad_status",
                f"AGENT_REGISTRY entries must be one of {[s.value for s in _loadable_statuses]}, "
                f"got {manifest.status}",
            )
        if not manifest.tool_names:
            raise RegistryValidationError(
                key, "operational_agent_no_tools", "AGENT_REGISTRY entry has an empty tool_names"
            )
        if not manifest.system_prompt.strip():
            raise RegistryValidationError(
                key,
                "operational_agent_no_prompt",
                "AGENT_REGISTRY entry has an empty system_prompt",
            )
        try:
            FoundationAgent(manifest)
        except Exception as exc:  # noqa: BLE001 - any construction failure is the finding itself
            raise RegistryValidationError(key, "implementation_not_loadable", str(exc)) from exc


def _check_tool_references() -> None:
    for key, manifest in AGENT_REGISTRY.items():
        for tool_name in manifest.tool_names:
            if tool_name not in TOOL_REGISTRY:
                raise RegistryValidationError(
                    key,
                    "missing_tool_reference",
                    f"tool '{tool_name}' is not in tool_gateway.TOOL_REGISTRY",
                )


def _check_supervisor_references() -> None:
    for key, manifest in AGENT_REGISTRY.items():
        if (
            manifest.supervisor_agent_id is not None
            and manifest.supervisor_agent_id not in AGENT_REGISTRY
        ):
            raise RegistryValidationError(
                key,
                "missing_supervisor_reference",
                f"supervisor_agent_id '{manifest.supervisor_agent_id}' not found",
            )


def _check_supervisor_cycles() -> None:
    for start_key in AGENT_REGISTRY:
        seen: set[str] = set()
        current: str | None = start_key
        while current is not None:
            if current in seen:
                raise RegistryValidationError(
                    start_key,
                    "circular_supervisor_chain",
                    f"cycle detected starting from '{start_key}'",
                )
            seen.add(current)
            manifest = AGENT_REGISTRY.get(current)
            current = manifest.supervisor_agent_id if manifest else None


def _check_red_team_safety_policy() -> None:
    for key, manifest in AGENT_REGISTRY.items():
        if manifest.team == Team.RED:
            if not manifest.target_authorisation_required:
                raise RegistryValidationError(
                    key,
                    "red_team_missing_target_authorisation",
                    "team=RED but target_authorisation_required is False",
                )
            if manifest.risk_ceiling != RiskCeiling.R4 and manifest.risk_ceiling != RiskCeiling.R5:
                raise RegistryValidationError(
                    key,
                    "red_team_risk_ceiling_too_low",
                    f"team=RED must be R4/R5, got {manifest.risk_ceiling}",
                )


def _check_high_risk_approval_policy() -> None:
    high_risk = {RiskCeiling.R3, RiskCeiling.R4, RiskCeiling.R5}
    for key, manifest in AGENT_REGISTRY.items():
        if manifest.risk_ceiling in high_risk and not manifest.approval_policy.strip():
            raise RegistryValidationError(
                key,
                "high_risk_agent_missing_approval_policy",
                f"risk_ceiling={manifest.risk_ceiling}",
            )


def _check_risk_ceiling_covers_real_tools() -> None:
    for key, manifest in AGENT_REGISTRY.items():
        highest = RiskCeiling.R0
        for tool_name in manifest.tool_names:
            spec = TOOL_REGISTRY.get(tool_name)
            if spec is None:
                continue
            tool_ceiling = _TOOL_RISK_TO_CEILING.get(getattr(spec, "risk_class", "R0"), RiskCeiling.R0)
            if _CEILING_ORDER.index(tool_ceiling) > _CEILING_ORDER.index(highest):
                highest = tool_ceiling
        if _CEILING_ORDER.index(manifest.risk_ceiling) < _CEILING_ORDER.index(highest):
            raise RegistryValidationError(
                key,
                "risk_ceiling_below_real_tool_risk",
                f"declared risk_ceiling={manifest.risk_ceiling} but tool_names reach {highest}",
            )


def _check_allowed_capability_ids_consistent() -> None:
    """Phase 16 (Continuation Prompt 3), Part G: an agent's allowed_capability_ids must
    reference real capabilities, those capabilities' required_tool_ids must be a subset
    of the agent's own tool_names (an agent can't be allowed a capability that reaches a
    tool it doesn't have), and every one of the agent's real tools must be reachable
    through at least one allowed capability (no tool left ungoverned by the broker)."""
    from gds_api.capabilities.catalog import CAPABILITY_REGISTRY

    for key, manifest in AGENT_REGISTRY.items():
        covered_tools: set[str] = set()
        for capability_key in manifest.allowed_capability_ids:
            capability = CAPABILITY_REGISTRY.get(capability_key)
            if capability is None:
                raise RegistryValidationError(
                    key,
                    "missing_capability_reference",
                    f"allowed_capability_ids references unknown capability '{capability_key}'",
                )
            if not set(capability.required_tool_ids).issubset(manifest.tool_names):
                raise RegistryValidationError(
                    key,
                    "capability_reaches_tool_agent_lacks",
                    f"capability '{capability_key}' requires tools "
                    f"{capability.required_tool_ids}, not all present in tool_names "
                    f"{manifest.tool_names}",
                )
            covered_tools.update(capability.required_tool_ids)
        uncovered = set(manifest.tool_names) - covered_tools
        if uncovered:
            raise RegistryValidationError(
                key,
                "tool_not_covered_by_allowed_capability",
                f"tool_names {uncovered} have no matching entry in allowed_capability_ids",
            )


def _check_cloud_security_never_operational_without_connector() -> None:
    # No connector health-check infrastructure exists yet (no cloud SDK/credentials
    # configured anywhere in this repo, confirmed by the Phase 14 audit) - so the only
    # real check available today is structural: cloud_security must never appear in
    # AGENT_REGISTRY (the real/operational dict) until a real connector exists.
    if "cloud_security" in AGENT_REGISTRY:
        raise RegistryValidationError(
            "cloud_security",
            "cloud_security_operational_without_connector",
            "present in AGENT_REGISTRY with no real cloud connector configured in this repo",
        )


def _check_purple_taxonomy_consistency() -> None:
    """Phase 20 (Continuation Prompt 7), Part 2: fail closed on any manifest whose
    purple_role_id doesn't resolve to a real gds_api.agents.purple_taxonomy.PurpleRole,
    and structurally guarantee all twenty authoritative roles are represented by at
    least one manifest (AGENT_REGISTRY or PLANNED_AGENTS) - a role silently dropped
    during a future edit should stop the app from starting, not go unnoticed."""
    from gds_api.agents.purple_taxonomy import PURPLE_ROLE_BY_ID, PURPLE_ROLES

    all_manifests: list[tuple[str, object]] = list(AGENT_REGISTRY.items()) + list(
        PLANNED_AGENTS.items()
    )
    covered_role_ids: set[str] = set()
    for key, manifest in all_manifests:
        role_id = getattr(manifest, "purple_role_id", None)
        if role_id is None:
            continue
        if role_id not in PURPLE_ROLE_BY_ID:
            raise RegistryValidationError(
                key,
                "unknown_purple_role_id",
                f"purple_role_id '{role_id}' is not a role in gds_api.agents.purple_taxonomy",
            )
        if key not in PURPLE_ROLE_BY_ID[role_id].realized_by:
            raise RegistryValidationError(
                key,
                "purple_role_realized_by_mismatch",
                f"manifest declares purple_role_id '{role_id}' but that role's "
                f"realized_by {PURPLE_ROLE_BY_ID[role_id].realized_by} does not list '{key}'",
            )
        covered_role_ids.add(role_id)

    missing = {role.role_id for role in PURPLE_ROLES} - covered_role_ids
    if missing:
        raise RegistryValidationError(
            "purple_taxonomy",
            "purple_role_not_realized_by_any_manifest",
            f"role id(s) {sorted(missing)} have no AGENT_REGISTRY/PLANNED_AGENTS "
            "manifest pointing at them",
        )
