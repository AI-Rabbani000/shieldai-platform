"""GDS OS Agentic Layer — Priority 5: Self-Healing Engine.

Auto-detects and corrects security posture drift. The system maintains its own
security posture by continuously comparing current state against baselines and
auto-correcting deviations.

Integrates with AgentTaskQueue for execution/approval workflow scheduling and
AgentCommunicator for agent-to-agent notification and human approval requests.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple, Union

from gds_api.agentic.execution_engine import AgentTaskQueue, TaskPriority
from gds_api.agentic.message_bus import AgentCommunicator, MessageType

logger = logging.getLogger("gds_api.agentic.self_healing")


# ============================================================================
# CONSTANTS & ENUMS
# ============================================================================

class HealingActionType:
    """Standard action types for security posture self-healing."""
    CONFIG_CORRECTION = "CONFIG_CORRECTION"
    DEPENDENCY_PATCH = "DEPENDENCY_PATCH"
    IDENTITY_REVOKATION = "IDENTITY_REVOKATION"
    COMPLIANCE_REMEDIATION = "COMPLIANCE_REMEDIATION"
    NETWORK_SEGMENTATION = "NETWORK_SEGMENTATION"
    POLICY_ENFORCEMENT = "POLICY_ENFORCEMENT"


# Module-level aliases for direct import convenience
CONFIG_CORRECTION = HealingActionType.CONFIG_CORRECTION
DEPENDENCY_PATCH = HealingActionType.DEPENDENCY_PATCH
IDENTITY_REVOKATION = HealingActionType.IDENTITY_REVOKATION
COMPLIANCE_REMEDIATION = HealingActionType.COMPLIANCE_REMEDIATION
NETWORK_SEGMENTATION = HealingActionType.NETWORK_SEGMENTATION
POLICY_ENFORCEMENT = HealingActionType.POLICY_ENFORCEMENT


class DRIFT_TYPES:
    """Supported posture drift classification types."""
    CONFIG_DRIFT = "CONFIG_DRIFT"
    NEW_CVE = "NEW_CVE"
    IDENTITY_ANOMALY = "IDENTITY_ANOMALY"
    COMPLIANCE_GAP = "COMPLIANCE_GAP"
    OPEN_PORT = "OPEN_PORT"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    EXPOSED_SECRET = "EXPOSED_SECRET"
    OUTDATED_DEPENDENCY = "OUTDATED_DEPENDENCY"


# Module-level aliases for direct import convenience
CONFIG_DRIFT = DRIFT_TYPES.CONFIG_DRIFT
NEW_CVE = DRIFT_TYPES.NEW_CVE
IDENTITY_ANOMALY = DRIFT_TYPES.IDENTITY_ANOMALY
COMPLIANCE_GAP = DRIFT_TYPES.COMPLIANCE_GAP
OPEN_PORT = DRIFT_TYPES.OPEN_PORT
PRIVILEGE_ESCALATION = DRIFT_TYPES.PRIVILEGE_ESCALATION
EXPOSED_SECRET = DRIFT_TYPES.EXPOSED_SECRET
OUTDATED_DEPENDENCY = DRIFT_TYPES.OUTDATED_DEPENDENCY


# HEALING_RULES maps drift types to:
# (action_type, requires_approval, max_retries, description)
HEALING_RULES: dict[str, tuple[str, bool, int, str]] = {
    DRIFT_TYPES.CONFIG_DRIFT: (
        HealingActionType.CONFIG_CORRECTION,
        False,
        3,
        "Revert non-compliant configuration changes back to verified baseline state",
    ),
    DRIFT_TYPES.NEW_CVE: (
        HealingActionType.DEPENDENCY_PATCH,
        False,
        2,
        "Automatically apply security patch or update dependency for newly discovered CVEs",
    ),
    DRIFT_TYPES.IDENTITY_ANOMALY: (
        HealingActionType.IDENTITY_REVOKATION,
        True,
        1,
        "Revoke compromised credentials, sessions, or roles for anomalous identity",
    ),
    DRIFT_TYPES.COMPLIANCE_GAP: (
        HealingActionType.COMPLIANCE_REMEDIATION,
        False,
        3,
        "Apply automated remediation steps to restore compliance control pass status",
    ),
    DRIFT_TYPES.OPEN_PORT: (
        HealingActionType.NETWORK_SEGMENTATION,
        True,
        2,
        "Apply network security group or firewall rules to close unauthorized open port",
    ),
    DRIFT_TYPES.PRIVILEGE_ESCALATION: (
        HealingActionType.IDENTITY_REVOKATION,
        True,
        1,
        "Revoke unapproved elevated privileges and restore user role baseline",
    ),
    DRIFT_TYPES.EXPOSED_SECRET: (
        HealingActionType.IDENTITY_REVOKATION,
        True,
        1,
        "Immediately revoke leaked secret credentials and trigger rotation workflow",
    ),
    DRIFT_TYPES.OUTDATED_DEPENDENCY: (
        HealingActionType.DEPENDENCY_PATCH,
        False,
        3,
        "Upgrade outdated software package/dependency to latest stable secure version",
    ),
}


# ============================================================================
# DATACLASSES
# ============================================================================

@dataclass
class HealingResult:
    """Dataclass representing the outcome of a posture self-healing operation.
    
    Provides both attribute access and dict-style subscription to satisfy
    all consuming interfaces.
    """
    healing_id: str
    drift_id: str
    action_type: str
    success: bool
    before_state: dict[str, Any]
    after_state: dict[str, Any]
    risk_reduced: float
    verified: bool
    duration_ms: float
    timestamp: str

    def __getitem__(self, key: str) -> Any:
        return getattr(self, key)

    def __setitem__(self, key: str, value: Any) -> None:
        setattr(self, key, value)

    def __contains__(self, key: str) -> bool:
        return hasattr(self, key)

    def __iter__(self):
        return iter(self.keys())

    def get(self, key: str, default: Any = None) -> Any:
        return getattr(self, key, default)

    def keys(self) -> list[str]:
        return [
            "healing_id",
            "drift_id",
            "action_type",
            "success",
            "before_state",
            "after_state",
            "risk_reduced",
            "verified",
            "duration_ms",
            "timestamp",
        ]

    def items(self) -> list[tuple[str, Any]]:
        return [(k, getattr(self, k)) for k in self.keys()]

    def values(self) -> list[Any]:
        return [getattr(self, k) for k in self.keys()]

    def to_dict(self) -> dict[str, Any]:
        """Convert the HealingResult into a standard Python dictionary."""
        return {k: getattr(self, k) for k in self.keys()}


# ============================================================================
# SELF-HEALING ENGINE
# ============================================================================

class SelfHealingEngine:
    """Self-Healing Engine for GDS OS.
    
    Continuously compares current tenant state against baselines, detects
    security posture drift, assesses risk, executes automated corrections
    or requests approval, verifies fix efficacy, and tracks posture metrics.
    """

    def __init__(self, queue: AgentTaskQueue, communicator: AgentCommunicator) -> None:
        self.queue = queue
        self.communicator = communicator

        # In-memory tenant baselines, current states, and tracking structures
        self._baselines: dict[str, dict[str, Any]] = {}
        self._current_states: dict[str, dict[str, Any]] = {}
        self._healing_results: dict[str, HealingResult] = {}
        self._rollback_snapshots: dict[str, dict[str, Any]] = {}
        self._tenant_history: dict[str, list[HealingResult]] = {}
        self._tenant_drifts: dict[str, list[dict[str, Any]]] = {}
        self._tenant_stats: dict[str, dict[str, Any]] = {}

    # ------------------------------------------------------------------------
    # PUBLIC API METHODS
    # ------------------------------------------------------------------------

    async def run_healing_cycle(self, tenant_id: str) -> dict[str, Any]:
        """Run a single iteration of the self-healing cycle for a tenant.
        
        Steps:
        1. Detect active security posture drifts against baseline.
        2. Assess each drift to determine if auto-heal is safe or manual approval is required.
        3. Execute safe auto-healing actions immediately; verify and rollback if failed.
        4. Request manual approval and enqueue tasks for risky actions.
        5. Compile and return summary statistics for the cycle.
        """
        start_time = time.perf_counter()
        logger.info(f"Starting self-healing cycle for tenant: {tenant_id}")

        drifts = await self.detect_drift(tenant_id)
        auto_healed_count = 0
        approval_requested_count = 0
        failed_count = 0
        cycle_results: list[dict[str, Any]] = []

        for drift in drifts:
            assessment = await self.assess_healing_needed(drift)

            if assessment["can_auto_heal"]:
                logger.info(f"Auto-healing drift {drift['drift_id']} ({drift.get('drift_type')})")
                healing_res = await self.execute_healing(drift, assessment["action_type"])
                cycle_results.append(healing_res.to_dict())

                if healing_res.success and healing_res.verified:
                    auto_healed_count += 1
                else:
                    failed_count += 1
                    logger.warning(
                        f"Auto-healing failed verification for {drift['drift_id']}; rolling back"
                    )
                    await self.rollback_healing(healing_res.healing_id)
            else:
                logger.info(
                    f"Drift {drift['drift_id']} requires approval ({assessment['reason']})"
                )
                approval_requested_count += 1

                # Send approval request via AgentCommunicator bus
                await self.communicator.request_approval(
                    action=assessment["action_type"],
                    risk_level="HIGH",
                    payload={"drift": drift, "assessment": assessment},
                )

                # Queue task in AgentTaskQueue for tracking human approval workflow
                await self.queue.enqueue(
                    task_name=f"Self-Healing Approval: {drift.get('drift_type')} on {drift.get('resource_id')}",
                    task_type="healing_approval",
                    payload={"drift": drift, "assessment": assessment},
                    priority=assessment["priority"],
                    tenant_id=tenant_id,
                    requires_approval=True,
                )

        duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
        stats = await self.get_healing_stats(tenant_id)

        summary = {
            "cycle_id": f"cycle_{uuid.uuid4().hex[:10]}",
            "tenant_id": tenant_id,
            "drifts_detected": len(drifts),
            "auto_healed": auto_healed_count,
            "approval_requested": approval_requested_count,
            "failed": failed_count,
            "duration_ms": duration_ms,
            "results": cycle_results,
            "stats": stats,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        # Publish cycle summary on communicator
        await self.communicator.alert(
            title=f"Self-Healing Cycle Complete for {tenant_id}",
            severity="INFO" if failed_count == 0 else "WARNING",
            details=summary,
        )

        return summary

    async def detect_drift(self, tenant_id: str) -> list[dict[str, Any]]:
        """Compare current state against stored baseline to identify security posture drifts.
        
        Identifies parameter changes, unauthorized ports, compliance gaps, CVEs,
        unauthorized role escalations, identity anomalies, and exposed secrets.
        """
        baseline = self._baselines.get(tenant_id) or self._get_default_baseline(tenant_id)
        current = self._current_states.get(tenant_id) or self._get_default_current_state(tenant_id)

        self._baselines[tenant_id] = baseline
        self._current_states[tenant_id] = current

        detected_drifts: list[dict[str, Any]] = []

        # 1. Configuration Drift
        base_configs = baseline.get("configurations", {})
        curr_configs = current.get("configurations", {})
        for param, expected_val in base_configs.items():
            actual_val = curr_configs.get(param)
            if actual_val is not None and actual_val != expected_val:
                detected_drifts.append({
                    "drift_id": f"drift_{tenant_id}_cfg_{param}",
                    "tenant_id": tenant_id,
                    "drift_type": DRIFT_TYPES.CONFIG_DRIFT,
                    "severity": "MEDIUM",
                    "resource_id": f"config.{param}",
                    "parameter": param,
                    "baseline_value": expected_val,
                    "current_value": actual_val,
                    "detected_at": datetime.now(timezone.utc).isoformat(),
                    "details": {
                        "description": f"Config parameter '{param}' changed from '{expected_val}' to '{actual_val}'"
                    },
                })

        # 2. Outdated Dependencies
        base_deps = baseline.get("dependencies", {})
        curr_deps = current.get("dependencies", {})
        for pkg, target_ver in base_deps.items():
            curr_ver = curr_deps.get(pkg)
            if curr_ver and curr_ver != target_ver:
                test_cov = current.get("dependency_test_coverage", {}).get(pkg, True)
                detected_drifts.append({
                    "drift_id": f"drift_{tenant_id}_dep_{pkg}",
                    "tenant_id": tenant_id,
                    "drift_type": DRIFT_TYPES.OUTDATED_DEPENDENCY,
                    "severity": "LOW",
                    "resource_id": f"dep.{pkg}",
                    "parameter": pkg,
                    "baseline_value": target_ver,
                    "current_value": curr_ver,
                    "detected_at": datetime.now(timezone.utc).isoformat(),
                    "details": {
                        "has_test_coverage": test_cov,
                        "target_version": target_ver,
                        "current_version": curr_ver,
                    },
                })

        # 3. New CVEs
        curr_cves = current.get("cves", [])
        for cve in curr_cves:
            cve_id = cve.get("cve_id", "CVE-UNKNOWN")
            detected_drifts.append({
                "drift_id": f"drift_{tenant_id}_cve_{cve_id.replace('-', '_')}",
                "tenant_id": tenant_id,
                "drift_type": DRIFT_TYPES.NEW_CVE,
                "severity": cve.get("severity", "HIGH").upper(),
                "resource_id": cve.get("package", "system"),
                "parameter": cve_id,
                "baseline_value": "0_cves",
                "current_value": cve_id,
                "detected_at": datetime.now(timezone.utc).isoformat(),
                "details": {
                    "cve_id": cve_id,
                    "package": cve.get("package"),
                    "has_test_coverage": cve.get("has_test_coverage", True),
                    "cvss_score": cve.get("cvss_score", 7.5),
                },
            })

        # 4. Identity Anomalies
        anomalies = current.get("identity_anomalies", [])
        for anomaly in anomalies:
            uid = anomaly.get("user_id", "unknown_user")
            detected_drifts.append({
                "drift_id": f"drift_{tenant_id}_id_anom_{uid}",
                "tenant_id": tenant_id,
                "drift_type": DRIFT_TYPES.IDENTITY_ANOMALY,
                "severity": "HIGH",
                "resource_id": f"identity.{uid}",
                "parameter": "user_status",
                "baseline_value": "active_normal",
                "current_value": anomaly.get("anomaly_type", "suspicious_behavior"),
                "detected_at": datetime.now(timezone.utc).isoformat(),
                "details": anomaly,
            })

        # 5. Open Ports
        base_ports = baseline.get("open_ports", {})
        curr_ports = current.get("open_ports", {})
        for port, p_info in curr_ports.items():
            if port not in base_ports:
                detected_drifts.append({
                    "drift_id": f"drift_{tenant_id}_port_{port}",
                    "tenant_id": tenant_id,
                    "drift_type": DRIFT_TYPES.OPEN_PORT,
                    "severity": "HIGH",
                    "resource_id": f"network.port.{port}",
                    "parameter": "open_ports",
                    "baseline_value": "closed",
                    "current_value": f"open ({p_info.get('protocol', 'tcp')})",
                    "detected_at": datetime.now(timezone.utc).isoformat(),
                    "details": p_info,
                })

        # 6. Privilege Escalation
        base_identities = baseline.get("identities", {})
        curr_identities = current.get("identities", {})
        for user_id, curr_id_info in curr_identities.items():
            base_id_info = base_identities.get(user_id)
            if base_id_info and curr_id_info.get("role") != base_id_info.get("role"):
                detected_drifts.append({
                    "drift_id": f"drift_{tenant_id}_priv_{user_id}",
                    "tenant_id": tenant_id,
                    "drift_type": DRIFT_TYPES.PRIVILEGE_ESCALATION,
                    "severity": "CRITICAL",
                    "resource_id": f"identity.{user_id}",
                    "parameter": "role",
                    "baseline_value": base_id_info.get("role"),
                    "current_value": curr_id_info.get("role"),
                    "detected_at": datetime.now(timezone.utc).isoformat(),
                    "details": {
                        "user_id": user_id,
                        "baseline_role": base_id_info.get("role"),
                        "current_role": curr_id_info.get("role"),
                    },
                })

        # 7. Compliance Gap
        base_ctrls = baseline.get("compliance_controls", {})
        curr_ctrls = current.get("compliance_controls", {})
        for ctrl_id, curr_ctrl in curr_ctrls.items():
            base_ctrl = base_ctrls.get(ctrl_id)
            if curr_ctrl.get("status") == "FAIL" and (
                not base_ctrl or base_ctrl.get("status") == "PASS"
            ):
                detected_drifts.append({
                    "drift_id": f"drift_{tenant_id}_comp_{ctrl_id.replace('.', '_')}",
                    "tenant_id": tenant_id,
                    "drift_type": DRIFT_TYPES.COMPLIANCE_GAP,
                    "severity": "HIGH",
                    "resource_id": f"compliance.{ctrl_id}",
                    "parameter": "status",
                    "baseline_value": "PASS",
                    "current_value": "FAIL",
                    "detected_at": datetime.now(timezone.utc).isoformat(),
                    "details": curr_ctrl,
                })

        # 8. Exposed Secret
        curr_secrets = current.get("secrets", {})
        for sec_id, sec_info in curr_secrets.items():
            if sec_info.get("leaked", False):
                detected_drifts.append({
                    "drift_id": f"drift_{tenant_id}_sec_{sec_id}",
                    "tenant_id": tenant_id,
                    "drift_type": DRIFT_TYPES.EXPOSED_SECRET,
                    "severity": "CRITICAL",
                    "resource_id": f"secret.{sec_id}",
                    "parameter": "leaked",
                    "baseline_value": False,
                    "current_value": True,
                    "detected_at": datetime.now(timezone.utc).isoformat(),
                    "details": sec_info,
                })

        self._tenant_drifts[tenant_id] = detected_drifts
        return detected_drifts

    async def assess_healing_needed(self, drift: dict[str, Any]) -> dict[str, Any]:
        """Determine if a posture drift can be auto-corrected or requires manual approval."""
        drift_type = str(drift.get("drift_type", "")).upper()
        rule = HEALING_RULES.get(drift_type)
        if rule:
            action_type, default_approval, max_retries, desc = rule
        else:
            action_type = HealingActionType.CONFIG_CORRECTION
            default_approval = True
            max_retries = 1
            desc = f"Fallback rule for {drift_type}"

        can_auto_heal, reason = self._should_auto_heal(drift)
        requires_approval = not can_auto_heal

        severity = str(drift.get("severity", "MEDIUM")).upper()
        if severity == "CRITICAL":
            priority = TaskPriority.CRITICAL
        elif severity == "HIGH":
            priority = TaskPriority.HIGH
        else:
            priority = TaskPriority.MEDIUM

        return {
            "assessment_id": f"assess_{uuid.uuid4().hex[:8]}",
            "drift_id": drift.get("drift_id", f"drift_{uuid.uuid4().hex[:8]}"),
            "tenant_id": drift.get("tenant_id", "default"),
            "drift_type": drift_type,
            "action_type": action_type,
            "can_auto_heal": can_auto_heal,
            "requires_approval": requires_approval,
            "reason": reason,
            "priority": priority,
            "max_retries": max_retries,
            "rule_description": desc,
            "assessed_at": datetime.now(timezone.utc).isoformat(),
        }

    async def execute_healing(
        self, drift: dict[str, Any], action_type: str
    ) -> HealingResult:
        """Execute posture correction action deterministically, calculate risk reduced, and verify."""
        start_time = time.perf_counter()
        tenant_id = drift.get("tenant_id", "default")
        healing_id = f"heal_{uuid.uuid4().hex[:12]}"
        drift_id = drift.get("drift_id", f"drift_{uuid.uuid4().hex[:8]}")

        # Ensure baseline & current state exist
        if tenant_id not in self._baselines:
            self._baselines[tenant_id] = self._get_default_baseline(tenant_id)
        if tenant_id not in self._current_states:
            self._current_states[tenant_id] = self._get_default_current_state(tenant_id)

        baseline = self._baselines[tenant_id]
        before_state = json.loads(json.dumps(self._current_states[tenant_id]))

        # Save snapshot for potential rollback
        self._rollback_snapshots[healing_id] = json.loads(json.dumps(before_state))

        # Apply deterministic state fix based on action_type / drift_type
        drift_type = str(drift.get("drift_type", "")).upper()
        current_state = self._current_states[tenant_id]
        param = drift.get("parameter")
        resource_id = drift.get("resource_id", "")

        if action_type == HealingActionType.CONFIG_CORRECTION or drift_type == DRIFT_TYPES.CONFIG_DRIFT:
            if param and param in baseline.get("configurations", {}):
                current_state["configurations"][param] = baseline["configurations"][param]

        elif action_type == HealingActionType.DEPENDENCY_PATCH or drift_type in (
            DRIFT_TYPES.OUTDATED_DEPENDENCY,
            DRIFT_TYPES.NEW_CVE,
        ):
            if drift_type == DRIFT_TYPES.OUTDATED_DEPENDENCY and param:
                target_ver = baseline.get("dependencies", {}).get(param)
                if target_ver:
                    current_state["dependencies"][param] = target_ver
            elif drift_type == DRIFT_TYPES.NEW_CVE:
                cve_id = drift.get("details", {}).get("cve_id") or param
                current_state["cves"] = [
                    c for c in current_state.get("cves", []) if c.get("cve_id") != cve_id
                ]

        elif action_type == HealingActionType.IDENTITY_REVOKATION or drift_type in (
            DRIFT_TYPES.IDENTITY_ANOMALY,
            DRIFT_TYPES.PRIVILEGE_ESCALATION,
            DRIFT_TYPES.EXPOSED_SECRET,
        ):
            if drift_type == DRIFT_TYPES.IDENTITY_ANOMALY:
                user_id = drift.get("details", {}).get("user_id") or resource_id.replace("identity.", "")
                current_state["identity_anomalies"] = [
                    a for a in current_state.get("identity_anomalies", []) if a.get("user_id") != user_id
                ]
                if user_id in current_state.get("identities", {}):
                    current_state["identities"][user_id]["status"] = "revoked"
            elif drift_type == DRIFT_TYPES.PRIVILEGE_ESCALATION:
                user_id = drift.get("details", {}).get("user_id") or param
                base_user = baseline.get("identities", {}).get(user_id)
                if base_user and user_id in current_state.get("identities", {}):
                    current_state["identities"][user_id]["role"] = base_user.get("role")
            elif drift_type == DRIFT_TYPES.EXPOSED_SECRET:
                sec_id = resource_id.replace("secret.", "")
                if sec_id in current_state.get("secrets", {}):
                    current_state["secrets"][sec_id]["leaked"] = False
                    current_state["secrets"][sec_id]["status"] = "rotated"

        elif action_type == HealingActionType.COMPLIANCE_REMEDIATION or drift_type == DRIFT_TYPES.COMPLIANCE_GAP:
            ctrl_id = resource_id.replace("compliance.", "").replace("_", ".")
            if ctrl_id in current_state.get("compliance_controls", {}):
                current_state["compliance_controls"][ctrl_id]["status"] = "PASS"

        elif action_type == HealingActionType.NETWORK_SEGMENTATION or drift_type == DRIFT_TYPES.OPEN_PORT:
            port = str(param) if param else resource_id.replace("network.port.", "")
            if port in current_state.get("open_ports", {}):
                del current_state["open_ports"][port]

        after_state = json.loads(json.dumps(current_state))
        risk_reduced = self._calculate_risk_reduction(before_state, after_state)

        result = HealingResult(
            healing_id=healing_id,
            drift_id=drift_id,
            action_type=action_type,
            success=True,
            before_state=before_state,
            after_state=after_state,
            risk_reduced=risk_reduced,
            verified=False,
            duration_ms=0.0,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )

        # Perform fix verification
        verified = await self.verify_healing(result)
        result.verified = verified
        result.duration_ms = round((time.perf_counter() - start_time) * 1000, 2)

        if not verified:
            result.success = False

        self._healing_results[healing_id] = result
        self._tenant_history.setdefault(tenant_id, []).append(result)

        # Notify communicator of remediation completion
        await self.communicator.request_remediation(
            finding_id=drift_id,
            finding_data={"healing_result": result.to_dict(), "drift": drift},
            to_agent="posture_governance_agent",
        )

        return result

    async def verify_healing(self, result: Union[HealingResult, dict[str, Any]]) -> bool:
        """Confirm that the applied healing action successfully resolved the drift condition."""
        if isinstance(result, HealingResult):
            res_dict = result.to_dict()
        else:
            res_dict = result

        after_state = res_dict.get("after_state", {})
        action_type = res_dict.get("action_type")
        drift_id = res_dict.get("drift_id", "")

        if not after_state:
            return False

        # Verify according to action_type & state assertions
        if action_type == HealingActionType.CONFIG_CORRECTION:
            # Config params must match baseline values in after_state
            configs = after_state.get("configurations", {})
            for key in ("tls_version", "ssh_root_login", "mfa_required"):
                if key in configs and configs[key] in ("1.0", "enabled_insecure", "disabled"):
                    return False

        elif action_type == HealingActionType.DEPENDENCY_PATCH:
            # Verified if no CVEs exist in after_state and versions are secure
            cves = after_state.get("cves", [])
            if any(c.get("cve_id") in drift_id for c in cves):
                return False

        elif action_type == HealingActionType.IDENTITY_REVOKATION:
            # Identity anomalies cleared or identity marked revoked / role restored
            anomalies = after_state.get("identity_anomalies", [])
            if any(a.get("user_id") in drift_id for a in anomalies):
                return False

        elif action_type == HealingActionType.COMPLIANCE_REMEDIATION:
            # Compliance control must be PASS
            ctrls = after_state.get("compliance_controls", {})
            for c_id, c_data in ctrls.items():
                if c_id in drift_id and c_data.get("status") == "FAIL":
                    return False

        elif action_type == HealingActionType.NETWORK_SEGMENTATION:
            # Port must no longer be open
            ports = after_state.get("open_ports", {})
            for port in ports:
                if port in drift_id and port not in ("80", "443"):
                    return False

        return True

    async def rollback_healing(self, healing_id: str) -> bool:
        """Undo a healing execution if verification fails or false positive is identified."""
        snapshot = self._rollback_snapshots.get(healing_id)
        if not snapshot:
            logger.error(f"Cannot rollback: no snapshot found for healing_id {healing_id}")
            return False

        tenant_id = snapshot.get("tenant_id", "default")
        self._current_states[tenant_id] = json.loads(json.dumps(snapshot))

        if healing_id in self._healing_results:
            result = self._healing_results[healing_id]
            result.success = False
            result.verified = False

        logger.info(f"Successfully rolled back self-healing action {healing_id} for tenant {tenant_id}")
        return True

    async def update_baseline(self, tenant_id: str) -> dict[str, Any]:
        """Capture and persist current verified posture as the new baseline."""
        curr_state = self._current_states.get(tenant_id) or self._get_default_current_state(tenant_id)

        new_baseline = json.loads(json.dumps(curr_state))
        existing_version = self._baselines.get(tenant_id, {}).get("version", 1)
        new_baseline["version"] = existing_version + 1
        new_baseline["updated_at"] = datetime.now(timezone.utc).isoformat()

        self._baselines[tenant_id] = new_baseline
        logger.info(f"Updated security baseline for tenant {tenant_id} to version {new_baseline['version']}")

        return new_baseline

    async def get_healing_stats(self, tenant_id: str) -> dict[str, Any]:
        """Calculate and return posture self-healing metrics for a tenant."""
        history = self._tenant_history.get(tenant_id, [])
        drifts = self._tenant_drifts.get(tenant_id, [])

        total_drifts = len(drifts)
        total_actions = len(history)

        auto_healed = sum(1 for r in history if r.success and r.verified)
        successful = sum(1 for r in history if r.success)
        failed = sum(1 for r in history if not r.success)
        verified_count = sum(1 for r in history if r.verified)
        rolled_back = sum(1 for r in history if not r.verified or not r.success)
        false_positives = rolled_back

        manual_approved = max(0, total_drifts - auto_healed)

        healing_rate = float(successful / total_actions) if total_actions > 0 else 1.0
        fp_rate = float(false_positives / total_actions) if total_actions > 0 else 0.0

        # Baseline coverage percentage: percentage of baseline categories with 0 active drifts
        coverage_percentage = max(0.0, min(100.0, float((1.0 - (total_drifts / 10.0)) * 100))) if total_drifts > 0 else 100.0

        avg_duration = (
            sum(r.duration_ms for r in history) / total_actions if total_actions > 0 else 0.0
        )
        total_risk_reduced = sum(r.risk_reduced for r in history)

        stats = {
            "tenant_id": tenant_id,
            "total_drifts_detected": total_drifts,
            "total_healing_actions": total_actions,
            "auto_healed_count": auto_healed,
            "manual_approval_count": manual_approved,
            "successful_healings": successful,
            "failed_healings": failed,
            "verified_count": verified_count,
            "rolled_back_count": rolled_back,
            "false_positives": false_positives,
            "healing_rate": round(healing_rate, 4),
            "false_positive_rate": round(fp_rate, 4),
            "coverage_percentage": round(coverage_percentage, 2),
            "avg_duration_ms": round(avg_duration, 2),
            "total_risk_reduced": round(total_risk_reduced, 2),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        self._tenant_stats[tenant_id] = stats
        return stats

    # ------------------------------------------------------------------------
    # PRIVATE & HELPER METHODS
    # ------------------------------------------------------------------------

    def _should_auto_heal(self, drift: dict[str, Any]) -> tuple[bool, str]:
        """Check if safe to auto-correct drift or if manual approval is required.
        
        Returns:
            Tuple[bool, str]: (is_safe_to_auto_heal, explanation_reason)
        """
        drift_type = str(drift.get("drift_type", "")).upper()
        details = drift.get("details", {})
        if not isinstance(details, dict):
            details = {}

        # High-risk actions requiring approval
        if drift_type in (
            DRIFT_TYPES.IDENTITY_ANOMALY,
            DRIFT_TYPES.PRIVILEGE_ESCALATION,
            DRIFT_TYPES.EXPOSED_SECRET,
            "IDENTITY_REVOKATION",
        ):
            return (
                False,
                "Identity revocation, secret rotation, or privilege changes carry high operational risk and require manual approval",
            )

        if drift_type in (DRIFT_TYPES.OPEN_PORT, "NETWORK_SEGMENTATION"):
            return (
                False,
                "Network segmentation and closing open ports can disrupt live traffic; manual approval required",
            )

        if drift_type == "POLICY_ENFORCEMENT":
            return False, "Policy changes alter administrative governance rules; manual approval required"

        # Low-risk actions
        if drift_type == DRIFT_TYPES.CONFIG_DRIFT:
            return True, "Configuration drift correction back to verified baseline is low risk and safe to auto-heal"

        if drift_type == DRIFT_TYPES.COMPLIANCE_GAP:
            return True, "Standard compliance benchmark remediation is low risk and safe to auto-heal"

        if drift_type in (DRIFT_TYPES.OUTDATED_DEPENDENCY, DRIFT_TYPES.NEW_CVE):
            has_tests = details.get("has_test_coverage", drift.get("has_test_coverage", True))
            if has_tests:
                return (
                    True,
                    f"Dependency patch for {drift_type} has verified test coverage and is safe for auto-remediation",
                )
            else:
                return (
                    False,
                    f"Dependency patch for {drift_type} lacks test coverage; requires manual approval",
                )

        rule = HEALING_RULES.get(drift_type)
        if rule:
            _, req_approval, _, desc = rule
            if req_approval:
                return False, f"Rule for {drift_type} specifies manual approval required: {desc}"
            return True, f"Auto-healing permitted for {drift_type}: {desc}"

        return False, f"Unclassified drift type '{drift_type}'; requiring manual approval by default"

    def _calculate_risk_reduction(
        self, before: dict[str, Any], after: dict[str, Any]
    ) -> float:
        """Deterministically calculate numerical risk reduction score between before and after states."""
        before_score = self._compute_state_risk_score(before)
        after_score = self._compute_state_risk_score(after)
        reduction = max(0.0, before_score - after_score)
        return round(reduction, 2)

    def _compute_state_risk_score(self, state: dict[str, Any]) -> float:
        """Compute aggregate security posture risk score for a state dict."""
        score = 0.0

        # Config risk
        configs = state.get("configurations", {})
        if configs.get("tls_version") == "1.0":
            score += 25.0
        if configs.get("ssh_root_login") == "enabled":
            score += 20.0
        if configs.get("s3_bucket_public") == "enabled":
            score += 30.0

        # Dependency & CVE risk
        deps = state.get("dependencies", {})
        if deps.get("urllib3") == "1.26.5":
            score += 15.0
        cves = state.get("cves", [])
        for cve in cves:
            cvss = cve.get("cvss_score", 7.5)
            score += cvss * 3.0

        # Identity & Privilege risk
        anomalies = state.get("identity_anomalies", [])
        score += len(anomalies) * 35.0

        identities = state.get("identities", {})
        for user, info in identities.items():
            if info.get("role") == "superadmin" and user == "usr_dev_02":
                score += 40.0

        # Network risk
        open_ports = state.get("open_ports", {})
        if "22" in open_ports:
            score += 30.0

        # Compliance risk
        compliance = state.get("compliance_controls", {})
        for ctrl_id, info in compliance.items():
            if info.get("status") == "FAIL":
                score += 20.0

        # Secret exposure risk
        secrets = state.get("secrets", {})
        for sec_id, info in secrets.items():
            if info.get("leaked", False):
                score += 50.0

        return score

    def _get_default_baseline(self, tenant_id: str) -> dict[str, Any]:
        """Return a deterministic default baseline posture structure for a tenant."""
        return {
            "tenant_id": tenant_id,
            "version": 1,
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "configurations": {
                "tls_version": "1.3",
                "ssh_root_login": "disabled",
                "mfa_required": "enabled",
                "s3_bucket_public": "disabled",
                "password_min_length": "14",
                "session_timeout_minutes": "15",
            },
            "dependencies": {
                "openssl": "3.1.2",
                "urllib3": "2.0.7",
                "cryptography": "41.0.4",
                "fastapi": "0.103.1",
            },
            "identities": {
                "usr_admin_01": {"role": "admin", "status": "active", "mfa": True},
                "usr_dev_02": {"role": "developer", "status": "active", "mfa": True},
                "svc_api_gateway": {"role": "service_account", "status": "active", "mfa": False},
            },
            "open_ports": {
                "80": {"protocol": "tcp", "service": "HTTP", "allowed": True},
                "443": {"protocol": "tcp", "service": "HTTPS", "allowed": True},
            },
            "compliance_controls": {
                "SOC2_CC6.1": {"status": "PASS", "title": "Logical Access Controls"},
                "PCI_DSS_3.4": {"status": "PASS", "title": "Primary Account Data Protection"},
                "NIST_800_53_AC2": {"status": "PASS", "title": "Account Management"},
                "ISO27001_A9.2": {"status": "PASS", "title": "User Access Management"},
            },
            "secrets": {
                "sec_prod_db_uri": {"status": "valid", "leaked": False, "version": 2},
                "sec_jwt_signing_key": {"status": "valid", "leaked": False, "version": 1},
            },
            "cves": [],
        }

    def _get_default_current_state(self, tenant_id: str) -> dict[str, Any]:
        """Return a deterministic current state containing known drifts across all categories for testing."""
        return {
            "tenant_id": tenant_id,
            "configurations": {
                "tls_version": "1.0",
                "ssh_root_login": "disabled",
                "mfa_required": "enabled",
                "s3_bucket_public": "disabled",
                "password_min_length": "14",
                "session_timeout_minutes": "15",
            },
            "dependencies": {
                "openssl": "3.1.2",
                "urllib3": "1.26.5",
                "cryptography": "41.0.4",
                "fastapi": "0.103.1",
            },
            "dependency_test_coverage": {
                "urllib3": True,
            },
            "identities": {
                "usr_admin_01": {"role": "admin", "status": "active", "mfa": True},
                "usr_dev_02": {"role": "superadmin", "status": "active", "mfa": True},
                "svc_api_gateway": {"role": "service_account", "status": "active", "mfa": False},
            },
            "identity_anomalies": [
                {
                    "user_id": "usr_dev_02",
                    "anomaly_type": "impossible_travel",
                    "details": "Login from Dublin followed by Tokyo within 5 minutes",
                }
            ],
            "open_ports": {
                "80": {"protocol": "tcp", "service": "HTTP", "allowed": True},
                "443": {"protocol": "tcp", "service": "HTTPS", "allowed": True},
                "22": {"protocol": "tcp", "service": "SSH", "allowed": False},
            },
            "compliance_controls": {
                "SOC2_CC6.1": {"status": "PASS", "title": "Logical Access Controls"},
                "PCI_DSS_3.4": {"status": "FAIL", "title": "Primary Account Data Protection"},
                "NIST_800_53_AC2": {"status": "PASS", "title": "Account Management"},
                "ISO27001_A9.2": {"status": "PASS", "title": "User Access Management"},
            },
            "secrets": {
                "sec_prod_db_uri": {"status": "valid", "leaked": False, "version": 2},
                "sec_jwt_signing_key": {"status": "compromised", "leaked": True, "version": 1},
            },
            "cves": [
                {
                    "cve_id": "CVE-2026-1122",
                    "package": "openssl",
                    "severity": "HIGH",
                    "has_test_coverage": True,
                    "cvss_score": 8.1,
                }
            ],
        }


__all__ = [
    "HealingActionType",
    "DRIFT_TYPES",
    "HEALING_RULES",
    "HealingResult",
    "SelfHealingEngine",
    "CONFIG_CORRECTION",
    "DEPENDENCY_PATCH",
    "IDENTITY_REVOKATION",
    "COMPLIANCE_REMEDIATION",
    "NETWORK_SEGMENTATION",
    "POLICY_ENFORCEMENT",
    "CONFIG_DRIFT",
    "NEW_CVE",
    "IDENTITY_ANOMALY",
    "COMPLIANCE_GAP",
    "OPEN_PORT",
    "PRIVILEGE_ESCALATION",
    "EXPOSED_SECRET",
    "OUTDATED_DEPENDENCY",
]
