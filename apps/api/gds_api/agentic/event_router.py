"""GDS OS Agentic Layer — Priority 3: Event-Driven Response Router.

Connects external events (CVEs, security alerts, cloud configuration changes,
identity anomalies, compliance failures, dependency vulnerabilities, supply chain
events) to autonomous agent triggers.

When a CVE is published, it auto-triggers vulnerability assessment.
When a cloud config changes, it auto-triggers posture evaluation.
When a security alert fires, it auto-triggers incident triage.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
import uuid
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Any

from gds_api.agentic.execution_engine import AgentTaskQueue, TaskPriority

logger = logging.getLogger("gds_api.agentic.event_router")


# ============================================================================
# EVENT TYPES
# ============================================================================

class EventType:
    """Supported external event types for the Event Router."""

    CVE_PUBLISHED = "cve_published"
    CLOUD_CONFIG_CHANGE = "cloud_config_change"
    SECURITY_ALERT = "security_alert"
    IDENTITY_ANOMALY = "identity_anomaly"
    COMPLIANCE_FAILURE = "compliance_failure"
    DEPENDENCY_VULN = "dependency_vuln"
    SUPPLY_CHAIN_EVENT = "supply_chain_event"


# Top-level event type string constants
CVE_PUBLISHED = EventType.CVE_PUBLISHED
CLOUD_CONFIG_CHANGE = EventType.CLOUD_CONFIG_CHANGE
SECURITY_ALERT = EventType.SECURITY_ALERT
IDENTITY_ANOMALY = EventType.IDENTITY_ANOMALY
COMPLIANCE_FAILURE = EventType.COMPLIANCE_FAILURE
DEPENDENCY_VULN = EventType.DEPENDENCY_VULN
SUPPLY_CHAIN_EVENT = EventType.SUPPLY_CHAIN_EVENT


# ============================================================================
# EVENT ROUTING TABLE
# ============================================================================

# Maps EventType to a list of tuples: (task_type, agent_capability, priority, requires_approval)
EVENT_ROUTING_TABLE: dict[str, list[tuple[str, str, TaskPriority, bool]]] = {
    EventType.CVE_PUBLISHED: [
        ("vulnerability_scan", "vulnerability_assessment", TaskPriority.HIGH, False),
    ],
    EventType.CLOUD_CONFIG_CHANGE: [
        ("cloud_posture_scan", "cloud_security_eval", TaskPriority.MEDIUM, False),
    ],
    EventType.SECURITY_ALERT: [
        ("incident_triage", "threat_triage", TaskPriority.HIGH, False),
        ("auto_remediate", "automated_containment", TaskPriority.CRITICAL, True),
    ],
    EventType.IDENTITY_ANOMALY: [
        ("incident_triage", "identity_investigation", TaskPriority.HIGH, False),
    ],
    EventType.COMPLIANCE_FAILURE: [
        ("compliance_check", "compliance_audit", TaskPriority.MEDIUM, False),
    ],
    EventType.DEPENDENCY_VULN: [
        ("vulnerability_scan", "dependency_analysis", TaskPriority.MEDIUM, False),
    ],
    EventType.SUPPLY_CHAIN_EVENT: [
        ("vulnerability_scan", "supply_chain_inspection", TaskPriority.HIGH, False),
        ("compliance_check", "vendor_risk_eval", TaskPriority.MEDIUM, False),
    ],
}


# ============================================================================
# EVENT ROUTER CLASS
# ============================================================================

class EventRouter:
    """Event-driven response router connecting system/external events to agent tasks.

    Features sliding window rate limiting, hash-based event deduplication,
    severity-based task priority assignment, and multi-capability routing.
    """

    def __init__(
        self,
        queue: AgentTaskQueue | None = None,
        rate_limit_per_min: int = 60,
        dedup_ttl_seconds: float = 300.0,
    ):
        """Initialize the EventRouter.

        Args:
            queue: AgentTaskQueue instance used to enqueue triggered tasks.
            rate_limit_per_min: Max events allowed per event type in a 60-second window.
            dedup_ttl_seconds: Time window in seconds for deduplicating identical events.
        """
        self._queue = queue or AgentTaskQueue()
        self._rate_limit_per_min = max(1, rate_limit_per_min)
        self._dedup_ttl = max(1.0, dedup_ttl_seconds)

        # Sliding window timestamps per event type: event_type -> deque of epoch floats
        self._event_timestamps: dict[str, deque] = defaultdict(deque)

        # Hash-based dedup cache: event_hash -> float timestamp
        self._dedup_cache: dict[str, float] = {}

        self._created_at = time.time()
        self._stats = {
            "total_events_received": 0,
            "total_tasks_enqueued": 0,
            "rate_limited_count": 0,
            "deduplicated_count": 0,
            "errors_count": 0,
            "last_event_at": None,
            "events_by_type": defaultdict(int),
            "tasks_by_type": defaultdict(int),
        }

    async def route(
        self,
        event_type: str,
        payload: dict[str, Any],
        tenant_id: str = "",
    ) -> dict[str, Any]:
        """Route an incoming event to the appropriate agent capability handler.

        Applies sliding window rate limiting and hash-based deduplication before
        dispatching to handler or generic routing table.
        """
        self._stats["total_events_received"] += 1
        self._stats["events_by_type"][event_type] += 1
        self._stats["last_event_at"] = datetime.now(timezone.utc).isoformat()

        if self._should_rate_limit(event_type):
            return {
                "event_type": event_type,
                "status": "rate_limited",
                "reason": f"Rate limit of {self._rate_limit_per_min}/min exceeded for '{event_type}'",
                "tenant_id": tenant_id,
                "tasks_enqueued": [],
                "processed_at": datetime.now(timezone.utc).isoformat(),
            }

        if self._should_deduplicate(event_type, payload):
            return {
                "event_type": event_type,
                "status": "deduplicated",
                "reason": f"Duplicate event within {self._dedup_ttl}s correlation window",
                "tenant_id": tenant_id,
                "tasks_enqueued": [],
                "processed_at": datetime.now(timezone.utc).isoformat(),
            }

        handler_map = {
            EventType.CVE_PUBLISHED: self.handle_cve_published,
            EventType.CLOUD_CONFIG_CHANGE: self.handle_cloud_config_change,
            EventType.SECURITY_ALERT: self.handle_security_alert,
            EventType.IDENTITY_ANOMALY: self.handle_identity_anomaly,
            EventType.COMPLIANCE_FAILURE: self.handle_compliance_failure,
            EventType.DEPENDENCY_VULN: self.handle_dependency_vuln,
            EventType.SUPPLY_CHAIN_EVENT: self.handle_supply_chain_event,
        }

        handler = handler_map.get(event_type)
        if handler:
            return await handler(payload, tenant_id=tenant_id, _skip_checks=True)

        return await self._dispatch_generic_routing(event_type, payload, tenant_id=tenant_id)

    async def handle_cve_published(
        self,
        payload: dict[str, Any],
        tenant_id: str = "",
        _skip_checks: bool = False,
    ) -> dict[str, Any]:
        """Handle CVE_PUBLISHED event: triggers vulnerability assessment and remediation planning."""
        if not _skip_checks:
            pre_check = await self._run_event_checks(EventType.CVE_PUBLISHED, payload, tenant_id)
            if pre_check:
                return pre_check

        correlation_id = str(uuid.uuid4())
        event_id = str(uuid.uuid4())
        cve_id = payload.get("cve_id", "CVE-UNKNOWN")
        vendor = payload.get("vendor", "")

        priority = self._resolve_priority(payload, TaskPriority.HIGH)
        task_name = f"CVE Vulnerability Assessment: {cve_id}"

        enqueued_tasks = []
        try:
            task_info = await self._queue.enqueue(
                task_name=task_name,
                task_type="vulnerability_scan",
                payload={
                    "event_id": event_id,
                    "event_type": EventType.CVE_PUBLISHED,
                    "cve_id": cve_id,
                    "vendor": vendor,
                    "agent_capability": "vulnerability_assessment",
                    "event_payload": payload,
                    "triggered_at": datetime.now(timezone.utc).isoformat(),
                },
                priority=priority,
                correlation_id=correlation_id,
                tenant_id=tenant_id,
                requires_approval=False,
            )
            self._stats["total_tasks_enqueued"] += 1
            self._stats["tasks_by_type"]["vulnerability_scan"] += 1
            enqueued_tasks.append({
                "task_id": task_info.get("task_id"),
                "task_name": task_name,
                "task_type": "vulnerability_scan",
                "agent_capability": "vulnerability_assessment",
                "priority": priority.name,
                "requires_approval": False,
                "status": task_info.get("status", "queued"),
            })

            if priority == TaskPriority.CRITICAL or payload.get("auto_remediate", False):
                remediate_task_name = f"CVE Patch Planning: {cve_id}"
                remediate_info = await self._queue.enqueue(
                    task_name=remediate_task_name,
                    task_type="auto_remediate",
                    payload={
                        "event_id": event_id,
                        "event_type": EventType.CVE_PUBLISHED,
                        "cve_id": cve_id,
                        "agent_capability": "patch_planning",
                        "event_payload": payload,
                        "triggered_at": datetime.now(timezone.utc).isoformat(),
                    },
                    priority=TaskPriority.CRITICAL,
                    correlation_id=correlation_id,
                    tenant_id=tenant_id,
                    requires_approval=True,
                )
                self._stats["total_tasks_enqueued"] += 1
                self._stats["tasks_by_type"]["auto_remediate"] += 1
                enqueued_tasks.append({
                    "task_id": remediate_info.get("task_id"),
                    "task_name": remediate_task_name,
                    "task_type": "auto_remediate",
                    "agent_capability": "patch_planning",
                    "priority": TaskPriority.CRITICAL.name,
                    "requires_approval": True,
                    "status": remediate_info.get("status", "queued"),
                })

        except Exception as exc:
            logger.error(f"Error handling CVE_PUBLISHED for {cve_id}: {exc}", exc_info=True)
            self._stats["errors_count"] += 1

        return {
            "event_id": event_id,
            "event_type": EventType.CVE_PUBLISHED,
            "correlation_id": correlation_id,
            "status": "processed",
            "tenant_id": tenant_id,
            "tasks_enqueued": enqueued_tasks,
            "processed_at": datetime.now(timezone.utc).isoformat(),
        }

    async def handle_cloud_config_change(
        self,
        payload: dict[str, Any],
        tenant_id: str = "",
        _skip_checks: bool = False,
    ) -> dict[str, Any]:
        """Handle CLOUD_CONFIG_CHANGE event: triggers cloud posture scan and misconfiguration checks."""
        if not _skip_checks:
            pre_check = await self._run_event_checks(EventType.CLOUD_CONFIG_CHANGE, payload, tenant_id)
            if pre_check:
                return pre_check

        correlation_id = str(uuid.uuid4())
        event_id = str(uuid.uuid4())
        resource_id = payload.get("resource_id", "RES-UNKNOWN")
        provider = payload.get("cloud_provider", "cloud")
        change_type = payload.get("change_type", "modified")

        is_high_risk = change_type.lower() in ("iam_policy_change", "public_bucket", "security_group_open", "kms_disable")
        default_prio = TaskPriority.HIGH if is_high_risk else TaskPriority.MEDIUM
        priority = self._resolve_priority(payload, default_prio)

        task_name = f"Cloud Posture Evaluation: [{provider}] {resource_id}"
        enqueued_tasks = []

        try:
            task_info = await self._queue.enqueue(
                task_name=task_name,
                task_type="cloud_posture_scan",
                payload={
                    "event_id": event_id,
                    "event_type": EventType.CLOUD_CONFIG_CHANGE,
                    "resource_id": resource_id,
                    "cloud_provider": provider,
                    "change_type": change_type,
                    "agent_capability": "cloud_security_eval",
                    "event_payload": payload,
                    "triggered_at": datetime.now(timezone.utc).isoformat(),
                },
                priority=priority,
                correlation_id=correlation_id,
                tenant_id=tenant_id,
                requires_approval=False,
            )
            self._stats["total_tasks_enqueued"] += 1
            self._stats["tasks_by_type"]["cloud_posture_scan"] += 1
            enqueued_tasks.append({
                "task_id": task_info.get("task_id"),
                "task_name": task_name,
                "task_type": "cloud_posture_scan",
                "agent_capability": "cloud_security_eval",
                "priority": priority.name,
                "requires_approval": False,
                "status": task_info.get("status", "queued"),
            })

            if is_high_risk or priority == TaskPriority.CRITICAL:
                contain_task_name = f"Cloud Misconfig Auto-Remediate: {resource_id}"
                contain_info = await self._queue.enqueue(
                    task_name=contain_task_name,
                    task_type="auto_remediate",
                    payload={
                        "event_id": event_id,
                        "event_type": EventType.CLOUD_CONFIG_CHANGE,
                        "resource_id": resource_id,
                        "agent_capability": "cloud_remediation",
                        "event_payload": payload,
                        "triggered_at": datetime.now(timezone.utc).isoformat(),
                    },
                    priority=priority,
                    correlation_id=correlation_id,
                    tenant_id=tenant_id,
                    requires_approval=True,
                )
                self._stats["total_tasks_enqueued"] += 1
                self._stats["tasks_by_type"]["auto_remediate"] += 1
                enqueued_tasks.append({
                    "task_id": contain_info.get("task_id"),
                    "task_name": contain_task_name,
                    "task_type": "auto_remediate",
                    "agent_capability": "cloud_remediation",
                    "priority": priority.name,
                    "requires_approval": True,
                    "status": contain_info.get("status", "queued"),
                })

        except Exception as exc:
            logger.error(f"Error handling CLOUD_CONFIG_CHANGE for {resource_id}: {exc}", exc_info=True)
            self._stats["errors_count"] += 1

        return {
            "event_id": event_id,
            "event_type": EventType.CLOUD_CONFIG_CHANGE,
            "correlation_id": correlation_id,
            "status": "processed",
            "tenant_id": tenant_id,
            "tasks_enqueued": enqueued_tasks,
            "processed_at": datetime.now(timezone.utc).isoformat(),
        }

    async def handle_security_alert(
        self,
        payload: dict[str, Any],
        tenant_id: str = "",
        _skip_checks: bool = False,
    ) -> dict[str, Any]:
        """Handle SECURITY_ALERT event: triggers incident triage and automated containment."""
        if not _skip_checks:
            pre_check = await self._run_event_checks(EventType.SECURITY_ALERT, payload, tenant_id)
            if pre_check:
                return pre_check

        correlation_id = str(uuid.uuid4())
        event_id = str(uuid.uuid4())
        alert_id = payload.get("alert_id") or payload.get("id") or str(uuid.uuid4())[:8]
        title = payload.get("title", "Security Alert")

        priority = self._resolve_priority(payload, TaskPriority.HIGH)
        task_name = f"Incident Threat Triage: [{alert_id}] {title}"
        enqueued_tasks = []

        try:
            triage_info = await self._queue.enqueue(
                task_name=task_name,
                task_type="incident_triage",
                payload={
                    "event_id": event_id,
                    "event_type": EventType.SECURITY_ALERT,
                    "alert_id": alert_id,
                    "title": title,
                    "agent_capability": "threat_triage",
                    "event_payload": payload,
                    "triggered_at": datetime.now(timezone.utc).isoformat(),
                },
                priority=priority,
                correlation_id=correlation_id,
                tenant_id=tenant_id,
                requires_approval=False,
            )
            self._stats["total_tasks_enqueued"] += 1
            self._stats["tasks_by_type"]["incident_triage"] += 1
            enqueued_tasks.append({
                "task_id": triage_info.get("task_id"),
                "task_name": task_name,
                "task_type": "incident_triage",
                "agent_capability": "threat_triage",
                "priority": priority.name,
                "requires_approval": False,
                "status": triage_info.get("status", "queued"),
            })

            if priority in (TaskPriority.CRITICAL, TaskPriority.HIGH):
                contain_name = f"Automated Incident Containment: {alert_id}"
                contain_info = await self._queue.enqueue(
                    task_name=contain_name,
                    task_type="auto_remediate",
                    payload={
                        "event_id": event_id,
                        "event_type": EventType.SECURITY_ALERT,
                        "alert_id": alert_id,
                        "agent_capability": "automated_containment",
                        "event_payload": payload,
                        "triggered_at": datetime.now(timezone.utc).isoformat(),
                    },
                    priority=priority,
                    correlation_id=correlation_id,
                    tenant_id=tenant_id,
                    requires_approval=True,
                )
                self._stats["total_tasks_enqueued"] += 1
                self._stats["tasks_by_type"]["auto_remediate"] += 1
                enqueued_tasks.append({
                    "task_id": contain_info.get("task_id"),
                    "task_name": contain_name,
                    "task_type": "auto_remediate",
                    "agent_capability": "automated_containment",
                    "priority": priority.name,
                    "requires_approval": True,
                    "status": contain_info.get("status", "queued"),
                })

        except Exception as exc:
            logger.error(f"Error handling SECURITY_ALERT {alert_id}: {exc}", exc_info=True)
            self._stats["errors_count"] += 1

        return {
            "event_id": event_id,
            "event_type": EventType.SECURITY_ALERT,
            "correlation_id": correlation_id,
            "status": "processed",
            "tenant_id": tenant_id,
            "tasks_enqueued": enqueued_tasks,
            "processed_at": datetime.now(timezone.utc).isoformat(),
        }

    async def handle_identity_anomaly(
        self,
        payload: dict[str, Any],
        tenant_id: str = "",
        _skip_checks: bool = False,
    ) -> dict[str, Any]:
        """Handle IDENTITY_ANOMALY event: triggers identity investigation and account isolation."""
        if not _skip_checks:
            pre_check = await self._run_event_checks(EventType.IDENTITY_ANOMALY, payload, tenant_id)
            if pre_check:
                return pre_check

        correlation_id = str(uuid.uuid4())
        event_id = str(uuid.uuid4())
        user_identity = payload.get("user_email") or payload.get("user_id") or "unknown_user"
        anomaly_type = payload.get("anomaly_type", "anomaly")

        priority = self._resolve_priority(payload, TaskPriority.HIGH)
        task_name = f"Identity Anomaly Investigation: [{user_identity}] {anomaly_type}"
        enqueued_tasks = []

        try:
            task_info = await self._queue.enqueue(
                task_name=task_name,
                task_type="incident_triage",
                payload={
                    "event_id": event_id,
                    "event_type": EventType.IDENTITY_ANOMALY,
                    "user_identity": user_identity,
                    "anomaly_type": anomaly_type,
                    "agent_capability": "identity_investigation",
                    "event_payload": payload,
                    "triggered_at": datetime.now(timezone.utc).isoformat(),
                },
                priority=priority,
                correlation_id=correlation_id,
                tenant_id=tenant_id,
                requires_approval=False,
            )
            self._stats["total_tasks_enqueued"] += 1
            self._stats["tasks_by_type"]["incident_triage"] += 1
            enqueued_tasks.append({
                "task_id": task_info.get("task_id"),
                "task_name": task_name,
                "task_type": "incident_triage",
                "agent_capability": "identity_investigation",
                "priority": priority.name,
                "requires_approval": False,
                "status": task_info.get("status", "queued"),
            })

            if priority == TaskPriority.CRITICAL or anomaly_type in ("privilege_escalation", "mfa_bypass"):
                isolate_name = f"Identity Account Isolation: {user_identity}"
                isolate_info = await self._queue.enqueue(
                    task_name=isolate_name,
                    task_type="auto_remediate",
                    payload={
                        "event_id": event_id,
                        "event_type": EventType.IDENTITY_ANOMALY,
                        "user_identity": user_identity,
                        "agent_capability": "account_isolation",
                        "event_payload": payload,
                        "triggered_at": datetime.now(timezone.utc).isoformat(),
                    },
                    priority=TaskPriority.CRITICAL,
                    correlation_id=correlation_id,
                    tenant_id=tenant_id,
                    requires_approval=True,
                )
                self._stats["total_tasks_enqueued"] += 1
                self._stats["tasks_by_type"]["auto_remediate"] += 1
                enqueued_tasks.append({
                    "task_id": isolate_info.get("task_id"),
                    "task_name": isolate_name,
                    "task_type": "auto_remediate",
                    "agent_capability": "account_isolation",
                    "priority": TaskPriority.CRITICAL.name,
                    "requires_approval": True,
                    "status": isolate_info.get("status", "queued"),
                })

        except Exception as exc:
            logger.error(f"Error handling IDENTITY_ANOMALY for {user_identity}: {exc}", exc_info=True)
            self._stats["errors_count"] += 1

        return {
            "event_id": event_id,
            "event_type": EventType.IDENTITY_ANOMALY,
            "correlation_id": correlation_id,
            "status": "processed",
            "tenant_id": tenant_id,
            "tasks_enqueued": enqueued_tasks,
            "processed_at": datetime.now(timezone.utc).isoformat(),
        }

    async def handle_compliance_failure(
        self,
        payload: dict[str, Any],
        tenant_id: str = "",
        _skip_checks: bool = False,
    ) -> dict[str, Any]:
        """Handle COMPLIANCE_FAILURE event: triggers compliance audit and remediation checks."""
        if not _skip_checks:
            pre_check = await self._run_event_checks(EventType.COMPLIANCE_FAILURE, payload, tenant_id)
            if pre_check:
                return pre_check

        correlation_id = str(uuid.uuid4())
        event_id = str(uuid.uuid4())
        framework = payload.get("framework", "COMPLIANCE")
        control_id = payload.get("control_id", "CTRL-001")

        priority = self._resolve_priority(payload, TaskPriority.MEDIUM)
        task_name = f"Compliance Control Check: [{framework}] {control_id}"
        enqueued_tasks = []

        try:
            task_info = await self._queue.enqueue(
                task_name=task_name,
                task_type="compliance_check",
                payload={
                    "event_id": event_id,
                    "event_type": EventType.COMPLIANCE_FAILURE,
                    "framework": framework,
                    "control_id": control_id,
                    "agent_capability": "compliance_audit",
                    "event_payload": payload,
                    "triggered_at": datetime.now(timezone.utc).isoformat(),
                },
                priority=priority,
                correlation_id=correlation_id,
                tenant_id=tenant_id,
                requires_approval=False,
            )
            self._stats["total_tasks_enqueued"] += 1
            self._stats["tasks_by_type"]["compliance_check"] += 1
            enqueued_tasks.append({
                "task_id": task_info.get("task_id"),
                "task_name": task_name,
                "task_type": "compliance_check",
                "agent_capability": "compliance_audit",
                "priority": priority.name,
                "requires_approval": False,
                "status": task_info.get("status", "queued"),
            })

        except Exception as exc:
            logger.error(f"Error handling COMPLIANCE_FAILURE {framework} {control_id}: {exc}", exc_info=True)
            self._stats["errors_count"] += 1

        return {
            "event_id": event_id,
            "event_type": EventType.COMPLIANCE_FAILURE,
            "correlation_id": correlation_id,
            "status": "processed",
            "tenant_id": tenant_id,
            "tasks_enqueued": enqueued_tasks,
            "processed_at": datetime.now(timezone.utc).isoformat(),
        }

    async def handle_dependency_vuln(
        self,
        payload: dict[str, Any],
        tenant_id: str = "",
        _skip_checks: bool = False,
    ) -> dict[str, Any]:
        """Handle DEPENDENCY_VULN event: triggers dependency scanning and auto-patching."""
        if not _skip_checks:
            pre_check = await self._run_event_checks(EventType.DEPENDENCY_VULN, payload, tenant_id)
            if pre_check:
                return pre_check

        correlation_id = str(uuid.uuid4())
        event_id = str(uuid.uuid4())
        pkg = payload.get("package_name") or payload.get("package") or "unknown_package"
        version = payload.get("version", "latest")
        fix_version = payload.get("fix_version")

        priority = self._resolve_priority(payload, TaskPriority.MEDIUM)
        task_name = f"Dependency Analysis: {pkg}@{version}"
        enqueued_tasks = []

        try:
            task_info = await self._queue.enqueue(
                task_name=task_name,
                task_type="vulnerability_scan",
                payload={
                    "event_id": event_id,
                    "event_type": EventType.DEPENDENCY_VULN,
                    "package_name": pkg,
                    "version": version,
                    "fix_version": fix_version,
                    "agent_capability": "dependency_analysis",
                    "event_payload": payload,
                    "triggered_at": datetime.now(timezone.utc).isoformat(),
                },
                priority=priority,
                correlation_id=correlation_id,
                tenant_id=tenant_id,
                requires_approval=False,
            )
            self._stats["total_tasks_enqueued"] += 1
            self._stats["tasks_by_type"]["vulnerability_scan"] += 1
            enqueued_tasks.append({
                "task_id": task_info.get("task_id"),
                "task_name": task_name,
                "task_type": "vulnerability_scan",
                "agent_capability": "dependency_analysis",
                "priority": priority.name,
                "requires_approval": False,
                "status": task_info.get("status", "queued"),
            })

            if fix_version and priority in (TaskPriority.CRITICAL, TaskPriority.HIGH):
                patch_name = f"Dependency Auto-Patch: {pkg} -> {fix_version}"
                patch_info = await self._queue.enqueue(
                    task_name=patch_name,
                    task_type="auto_remediate",
                    payload={
                        "event_id": event_id,
                        "event_type": EventType.DEPENDENCY_VULN,
                        "package_name": pkg,
                        "fix_version": fix_version,
                        "agent_capability": "dependency_patching",
                        "event_payload": payload,
                        "triggered_at": datetime.now(timezone.utc).isoformat(),
                    },
                    priority=priority,
                    correlation_id=correlation_id,
                    tenant_id=tenant_id,
                    requires_approval=True,
                )
                self._stats["total_tasks_enqueued"] += 1
                self._stats["tasks_by_type"]["auto_remediate"] += 1
                enqueued_tasks.append({
                    "task_id": patch_info.get("task_id"),
                    "task_name": patch_name,
                    "task_type": "auto_remediate",
                    "agent_capability": "dependency_patching",
                    "priority": priority.name,
                    "requires_approval": True,
                    "status": patch_info.get("status", "queued"),
                })

        except Exception as exc:
            logger.error(f"Error handling DEPENDENCY_VULN for {pkg}: {exc}", exc_info=True)
            self._stats["errors_count"] += 1

        return {
            "event_id": event_id,
            "event_type": EventType.DEPENDENCY_VULN,
            "correlation_id": correlation_id,
            "status": "processed",
            "tenant_id": tenant_id,
            "tasks_enqueued": enqueued_tasks,
            "processed_at": datetime.now(timezone.utc).isoformat(),
        }

    async def handle_supply_chain_event(
        self,
        payload: dict[str, Any],
        tenant_id: str = "",
        _skip_checks: bool = False,
    ) -> dict[str, Any]:
        """Handle SUPPLY_CHAIN_EVENT event: triggers supply chain inspection & vendor risk evaluation."""
        if not _skip_checks:
            pre_check = await self._run_event_checks(EventType.SUPPLY_CHAIN_EVENT, payload, tenant_id)
            if pre_check:
                return pre_check

        correlation_id = str(uuid.uuid4())
        event_id = str(uuid.uuid4())
        vendor = payload.get("vendor_name") or payload.get("vendor_id") or "unknown_vendor"
        sub_event = payload.get("event_type", "supply_chain_alert")

        priority = self._resolve_priority(payload, TaskPriority.HIGH)
        task_name = f"Supply Chain Inspection: [{vendor}] {sub_event}"
        enqueued_tasks = []

        try:
            inspect_info = await self._queue.enqueue(
                task_name=task_name,
                task_type="vulnerability_scan",
                payload={
                    "event_id": event_id,
                    "event_type": EventType.SUPPLY_CHAIN_EVENT,
                    "vendor": vendor,
                    "agent_capability": "supply_chain_inspection",
                    "event_payload": payload,
                    "triggered_at": datetime.now(timezone.utc).isoformat(),
                },
                priority=priority,
                correlation_id=correlation_id,
                tenant_id=tenant_id,
                requires_approval=False,
            )
            self._stats["total_tasks_enqueued"] += 1
            self._stats["tasks_by_type"]["vulnerability_scan"] += 1
            enqueued_tasks.append({
                "task_id": inspect_info.get("task_id"),
                "task_name": task_name,
                "task_type": "vulnerability_scan",
                "agent_capability": "supply_chain_inspection",
                "priority": priority.name,
                "requires_approval": False,
                "status": inspect_info.get("status", "queued"),
            })

            eval_name = f"Vendor Risk Re-evaluation: {vendor}"
            eval_info = await self._queue.enqueue(
                task_name=eval_name,
                task_type="compliance_check",
                payload={
                    "event_id": event_id,
                    "event_type": EventType.SUPPLY_CHAIN_EVENT,
                    "vendor": vendor,
                    "agent_capability": "vendor_risk_eval",
                    "event_payload": payload,
                    "triggered_at": datetime.now(timezone.utc).isoformat(),
                },
                priority=TaskPriority.MEDIUM,
                correlation_id=correlation_id,
                tenant_id=tenant_id,
                requires_approval=False,
            )
            self._stats["total_tasks_enqueued"] += 1
            self._stats["tasks_by_type"]["compliance_check"] += 1
            enqueued_tasks.append({
                "task_id": eval_info.get("task_id"),
                "task_name": eval_name,
                "task_type": "compliance_check",
                "agent_capability": "vendor_risk_eval",
                "priority": TaskPriority.MEDIUM.name,
                "requires_approval": False,
                "status": eval_info.get("status", "queued"),
            })

        except Exception as exc:
            logger.error(f"Error handling SUPPLY_CHAIN_EVENT for {vendor}: {exc}", exc_info=True)
            self._stats["errors_count"] += 1

        return {
            "event_id": event_id,
            "event_type": EventType.SUPPLY_CHAIN_EVENT,
            "correlation_id": correlation_id,
            "status": "processed",
            "tenant_id": tenant_id,
            "tasks_enqueued": enqueued_tasks,
            "processed_at": datetime.now(timezone.utc).isoformat(),
        }

    # =========================================================================
    # INTERNAL HELPERS & METRICS
    # =========================================================================

    def _should_rate_limit(self, event_type: str) -> bool:
        """Sliding window rate limit calculation (max events per minute)."""
        now = time.time()
        cutoff = now - 60.0
        timestamps = self._event_timestamps[event_type]

        while timestamps and timestamps[0] <= cutoff:
            timestamps.popleft()

        if len(timestamps) >= self._rate_limit_per_min:
            self._stats["rate_limited_count"] += 1
            logger.warning(
                "event_rate_limited",
                extra={"event_type": event_type, "count": len(timestamps), "limit": self._rate_limit_per_min},
            )
            return True

        timestamps.append(now)
        return False

    def _compute_event_hash(self, event_type: str, payload: dict[str, Any]) -> str:
        """Generate a deterministic SHA-256 fingerprint for event deduplication."""
        key_fields = []
        if event_type == EventType.CVE_PUBLISHED:
            key_fields = [payload.get("cve_id"), payload.get("vendor")]
        elif event_type == EventType.CLOUD_CONFIG_CHANGE:
            key_fields = [payload.get("resource_id"), payload.get("change_type"), payload.get("cloud_provider")]
        elif event_type == EventType.SECURITY_ALERT:
            key_fields = [payload.get("alert_id") or payload.get("title"), payload.get("affected_asset")]
        elif event_type == EventType.IDENTITY_ANOMALY:
            key_fields = [payload.get("user_id") or payload.get("user_email"), payload.get("anomaly_type")]
        elif event_type == EventType.COMPLIANCE_FAILURE:
            key_fields = [payload.get("framework"), payload.get("control_id"), payload.get("resource_id")]
        elif event_type == EventType.DEPENDENCY_VULN:
            key_fields = [payload.get("package_name"), payload.get("version"), payload.get("cve_id")]
        elif event_type == EventType.SUPPLY_CHAIN_EVENT:
            key_fields = [payload.get("vendor_name") or payload.get("vendor_id"), payload.get("event_type")]

        valid_keys = [str(k) for k in key_fields if k is not None]
        if valid_keys:
            raw_key = f"{event_type}:" + ":".join(valid_keys)
        else:
            try:
                raw_key = f"{event_type}:" + json.dumps(payload, sort_keys=True, default=str)
            except Exception:
                raw_key = f"{event_type}:" + str(payload)

        return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()

    def _should_deduplicate(self, event_type: str, payload: dict[str, Any]) -> bool:
        """Hash-based event deduplication check within correlation time window."""
        now = time.time()
        event_hash = self._compute_event_hash(event_type, payload)

        expired_keys = [h for h, ts in self._dedup_cache.items() if now - ts > self._dedup_ttl]
        for h in expired_keys:
            del self._dedup_cache[h]

        if event_hash in self._dedup_cache:
            self._stats["deduplicated_count"] += 1
            logger.info("event_deduplicated", extra={"event_type": event_type, "hash": event_hash[:8]})
            return True

        self._dedup_cache[event_hash] = now
        return False

    def _resolve_priority(self, payload: dict[str, Any], default_priority: TaskPriority) -> TaskPriority:
        """Resolve TaskPriority from payload CVSS scores, risk scores, or severity strings."""
        cvss = payload.get("cvss_score") or payload.get("cvss") or payload.get("cvss_v3")
        if isinstance(cvss, (int, float)):
            if cvss >= 9.0:
                return TaskPriority.CRITICAL
            elif cvss >= 7.0:
                return TaskPriority.HIGH
            elif cvss >= 4.0:
                return TaskPriority.MEDIUM
            else:
                return TaskPriority.LOW

        severity = payload.get("severity") or payload.get("risk_level") or payload.get("priority")
        if isinstance(severity, str):
            sev_lower = severity.lower().strip()
            if sev_lower in ("critical", "crit", "p0", "cat1", "emergency"):
                return TaskPriority.CRITICAL
            elif sev_lower in ("high", "p1", "cat2", "major"):
                return TaskPriority.HIGH
            elif sev_lower in ("medium", "med", "p2", "cat3", "moderate"):
                return TaskPriority.MEDIUM
            elif sev_lower in ("low", "p3", "cat4", "minor", "info", "informational"):
                return TaskPriority.LOW

        risk_score = payload.get("risk_score") or payload.get("score")
        if isinstance(risk_score, (int, float)):
            if risk_score >= 85:
                return TaskPriority.CRITICAL
            elif risk_score >= 65:
                return TaskPriority.HIGH
            elif risk_score >= 35:
                return TaskPriority.MEDIUM
            else:
                return TaskPriority.LOW

        return default_priority

    async def _run_event_checks(
        self,
        event_type: str,
        payload: dict[str, Any],
        tenant_id: str,
    ) -> dict[str, Any] | None:
        """Helper to execute rate limiting and deduplication checks for direct handler invocations."""
        self._stats["total_events_received"] += 1
        self._stats["events_by_type"][event_type] += 1
        self._stats["last_event_at"] = datetime.now(timezone.utc).isoformat()

        if self._should_rate_limit(event_type):
            return {
                "event_type": event_type,
                "status": "rate_limited",
                "reason": f"Rate limit exceeded for event type '{event_type}'",
                "tenant_id": tenant_id,
                "tasks_enqueued": [],
                "processed_at": datetime.now(timezone.utc).isoformat(),
            }

        if self._should_deduplicate(event_type, payload):
            return {
                "event_type": event_type,
                "status": "deduplicated",
                "reason": "Duplicate event detected within correlation window",
                "tenant_id": tenant_id,
                "tasks_enqueued": [],
                "processed_at": datetime.now(timezone.utc).isoformat(),
            }

        return None

    async def _dispatch_generic_routing(
        self,
        event_type: str,
        payload: dict[str, Any],
        tenant_id: str = "",
    ) -> dict[str, Any]:
        """Fallback routing dispatcher for custom or generic event types using EVENT_ROUTING_TABLE."""
        correlation_id = str(uuid.uuid4())
        event_id = str(uuid.uuid4())
        rules = EVENT_ROUTING_TABLE.get(event_type, [])

        if not rules:
            logger.warning(f"No routing rule registered for event_type: {event_type}")
            return {
                "event_id": event_id,
                "event_type": event_type,
                "status": "unhandled",
                "reason": f"No routing rule registered for event type '{event_type}'",
                "tenant_id": tenant_id,
                "tasks_enqueued": [],
                "processed_at": datetime.now(timezone.utc).isoformat(),
            }

        enqueued_tasks = []
        for rule in rules:
            task_type, capability, default_priority, req_approval = rule
            priority = self._resolve_priority(payload, default_priority)
            task_name = f"Generic Event Trigger [{event_type}]: {capability}"

            try:
                task_info = await self._queue.enqueue(
                    task_name=task_name,
                    task_type=task_type,
                    payload={
                        "event_id": event_id,
                        "event_type": event_type,
                        "agent_capability": capability,
                        "event_payload": payload,
                        "triggered_at": datetime.now(timezone.utc).isoformat(),
                    },
                    priority=priority,
                    correlation_id=correlation_id,
                    tenant_id=tenant_id,
                    requires_approval=req_approval,
                )
                self._stats["total_tasks_enqueued"] += 1
                self._stats["tasks_by_type"][task_type] += 1
                enqueued_tasks.append({
                    "task_id": task_info.get("task_id"),
                    "task_name": task_name,
                    "task_type": task_type,
                    "agent_capability": capability,
                    "priority": priority.name,
                    "requires_approval": req_approval,
                    "status": task_info.get("status", "queued"),
                })
            except Exception as exc:
                logger.error(f"Error executing generic routing for {event_type}: {exc}", exc_info=True)
                self._stats["errors_count"] += 1

        return {
            "event_id": event_id,
            "event_type": event_type,
            "correlation_id": correlation_id,
            "status": "processed",
            "tenant_id": tenant_id,
            "tasks_enqueued": enqueued_tasks,
            "processed_at": datetime.now(timezone.utc).isoformat(),
        }

    async def get_stats(self) -> dict[str, Any]:
        """Return operational metrics and statistics for the EventRouter."""
        now = time.time()
        uptime = round(now - self._created_at, 2)
        cutoff = now - 60.0

        active_rate_limits = {
            et: sum(1 for ts in timestamps if ts > cutoff)
            for et, timestamps in self._event_timestamps.items()
            if sum(1 for ts in timestamps if ts > cutoff) > 0
        }

        return {
            "uptime_seconds": uptime,
            "total_events_received": self._stats["total_events_received"],
            "total_tasks_enqueued": self._stats["total_tasks_enqueued"],
            "rate_limited_count": self._stats["rate_limited_count"],
            "deduplicated_count": self._stats["deduplicated_count"],
            "errors_count": self._stats["errors_count"],
            "events_by_type": dict(self._stats["events_by_type"]),
            "tasks_by_type": dict(self._stats["tasks_by_type"]),
            "active_rate_limits": active_rate_limits,
            "active_dedup_entries": len(self._dedup_cache),
            "last_event_at": self._stats["last_event_at"],
        }


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    "EventType",
    "EVENT_ROUTING_TABLE",
    "EventRouter",
    "CVE_PUBLISHED",
    "CLOUD_CONFIG_CHANGE",
    "SECURITY_ALERT",
    "IDENTITY_ANOMALY",
    "COMPLIANCE_FAILURE",
    "DEPENDENCY_VULN",
    "SUPPLY_CHAIN_EVENT",
]
