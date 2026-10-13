"""Phase 16 (Continuation Prompt 3): startup-time validation of
gds_api.capabilities.catalog.CAPABILITY_REGISTRY - the same real-startup-failure
discipline gds_api.agents.validation established in Phase 14. Runs once at app startup
(gds_api.main's lifespan), synchronous, no DB/network I/O needed since the catalogue is
a static in-code dict.
"""

from __future__ import annotations

from gds_api.capabilities.catalog import CAPABILITY_REGISTRY
from gds_api.capabilities.definitions import CapabilityStatus, RiskClass
from gds_api.tool_gateway import TOOL_REGISTRY

_TOOL_RISK_TO_CAPABILITY_FLOOR = {
    "low": RiskClass.R0,
    "medium": RiskClass.R2,
    "high": RiskClass.R3,
    "critical": RiskClass.R4,
}
_RISK_ORDER = [RiskClass.R0, RiskClass.R1, RiskClass.R2, RiskClass.R3, RiskClass.R4, RiskClass.R5]


class CapabilityValidationError(ValueError):
    def __init__(self, capability_key: str, rule: str, detail: str) -> None:
        self.capability_key = capability_key
        self.rule = rule
        super().__init__(
            f"Capability catalogue validation failed for '{capability_key}': {rule} - {detail}"
        )


def validate_capability_catalog() -> None:
    _check_r5_never_enabled()
    _check_planned_disabled_have_no_tools()
    _check_operational_have_real_tools()
    _check_every_real_tool_has_exactly_one_capability()
    _check_risk_class_covers_real_tool_risk()
    _check_red_team_safety_coupling()
    _check_offensive_requires_approval()
    _check_target_authorisation_implies_emergency_stop()


def _check_r5_never_enabled() -> None:
    for key, cap in CAPABILITY_REGISTRY.items():
        if cap.risk_class == RiskClass.R5 and (
            cap.enabled or cap.status != CapabilityStatus.DISABLED
        ):
            raise CapabilityValidationError(
                key,
                "r5_must_be_disabled",
                "R5 (prohibited) capabilities must always be enabled=False, status=DISABLED",
            )


def _check_planned_disabled_have_no_tools() -> None:
    for key, cap in CAPABILITY_REGISTRY.items():
        if cap.status != CapabilityStatus.OPERATIONAL and cap.required_tool_ids:
            raise CapabilityValidationError(
                key,
                "non_operational_has_tool_reference",
                f"status={cap.status} but required_tool_ids={cap.required_tool_ids} - a "
                "non-operational capability must never resolve to a real executable tool",
            )
        if cap.status != CapabilityStatus.OPERATIONAL and cap.enabled:
            raise CapabilityValidationError(
                key, "non_operational_enabled", f"status={cap.status} but enabled=True"
            )


def _check_operational_have_real_tools() -> None:
    for key, cap in CAPABILITY_REGISTRY.items():
        if cap.status != CapabilityStatus.OPERATIONAL:
            continue
        if not cap.required_tool_ids:
            raise CapabilityValidationError(
                key, "operational_no_tools", "OPERATIONAL capability has empty required_tool_ids"
            )
        for tool_id in cap.required_tool_ids:
            if tool_id not in TOOL_REGISTRY:
                raise CapabilityValidationError(
                    key,
                    "missing_tool_reference",
                    f"tool '{tool_id}' is not in tool_gateway.TOOL_REGISTRY",
                )


def _check_every_real_tool_has_exactly_one_capability() -> None:
    owners: dict[str, list[str]] = {}
    for key, cap in CAPABILITY_REGISTRY.items():
        if cap.status != CapabilityStatus.OPERATIONAL:
            continue
        for tool_id in cap.required_tool_ids:
            owners.setdefault(tool_id, []).append(key)
    for tool_id in TOOL_REGISTRY:
        capability_keys = owners.get(tool_id, [])
        if len(capability_keys) == 0:
            raise CapabilityValidationError(
                tool_id,
                "uncovered_real_tool",
                "a real tool exists with no OPERATIONAL capability covering it",
            )
        if len(capability_keys) > 1:
            raise CapabilityValidationError(
                tool_id,
                "tool_covered_by_multiple_capabilities",
                f"covered by {capability_keys} - a tool must map to exactly one capability "
                "in this phase (Part H's 'the specific requested capability must be "
                "explicit' - no inference)",
            )


def _check_risk_class_covers_real_tool_risk() -> None:
    for key, cap in CAPABILITY_REGISTRY.items():
        if cap.status != CapabilityStatus.OPERATIONAL:
            continue
        floor = RiskClass.R0
        for tool_id in cap.required_tool_ids:
            tool_floor = _TOOL_RISK_TO_CAPABILITY_FLOOR[TOOL_REGISTRY[tool_id].risk_class]
            if _RISK_ORDER.index(tool_floor) > _RISK_ORDER.index(floor):
                floor = tool_floor
        if _RISK_ORDER.index(cap.risk_class) < _RISK_ORDER.index(floor):
            raise CapabilityValidationError(
                key,
                "risk_class_understates_tool_risk",
                f"capability risk_class={cap.risk_class} but backing tool(s) require "
                f"at least {floor}",
            )


def _check_red_team_safety_coupling() -> None:
    for key, cap in CAPABILITY_REGISTRY.items():
        if cap.category == "red_team" and cap.status == CapabilityStatus.OPERATIONAL:
            if not (
                cap.requires_target_authorisation
                and cap.requires_emergency_stop_clear
                and cap.requires_human_approval
            ):
                raise CapabilityValidationError(
                    key,
                    "red_team_missing_safety_coupling",
                    "every operational red_team capability must require target authorisation, "
                    "emergency-stop clearance, and human approval",
                )


def _check_offensive_requires_approval() -> None:
    for key, cap in CAPABILITY_REGISTRY.items():
        if cap.side_effect_type.value == "OFFENSIVE" and cap.status == CapabilityStatus.OPERATIONAL:
            if not cap.requires_human_approval:
                raise CapabilityValidationError(
                    key,
                    "offensive_without_approval",
                    "an OFFENSIVE side-effect capability must require human approval",
                )


def _check_target_authorisation_implies_emergency_stop() -> None:
    for key, cap in CAPABILITY_REGISTRY.items():
        if cap.requires_target_authorisation and not cap.requires_emergency_stop_clear:
            raise CapabilityValidationError(
                key,
                "target_auth_without_emergency_stop",
                "a capability requiring target authorisation must also require "
                "emergency-stop clearance",
            )
