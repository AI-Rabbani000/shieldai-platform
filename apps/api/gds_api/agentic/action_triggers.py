"""GDS OS Agentic Layer — Priority 6: Action Trigger Layer.

Converts passive CRUD operations into active agent-triggering endpoints.
Instead of just reading/writing database records, these routes trigger
autonomous agent actions via the AgentTaskQueue and publish coordination
events over the AgentMessageBus.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from gds_api.agentic.execution_engine import AgentTaskQueue, TaskPriority
from gds_api.agentic.message_bus import AgentMessageBus, MessageType
from gds_api.db import get_db
from gds_api.models import Approval, Evidence, Finding, Incident, User
from gds_api.security import CurrentUser, get_current_user


# ============================================================================
# REQUEST MODELS
# ============================================================================

class TriggerRequest(BaseModel):
    """Generic request payload for agent action triggers."""

    parameters: dict[str, Any] = {}
    priority: int = TaskPriority.MEDIUM.value
    correlation_id: str | None = None
    requires_approval: bool = False
    tenant_id: str | None = None


class CustomTaskRequest(BaseModel):
    """Request payload for custom fleet task submission."""

    task_name: str
    task_type: str
    payload: dict[str, Any] = {}
    agent_id: str | None = None
    priority: int = TaskPriority.MEDIUM.value
    requires_approval: bool = False
    correlation_id: str | None = None


# ============================================================================
# ACTION TRIGGER ROUTER
# ============================================================================

class ActionTriggerRouter:
    """Action Trigger Layer router.

    Creates FastAPI routes wrapping system operations with autonomous agent
    triggers. Each trigger endpoint validates entity state, enqueues a priority
    agent task, publishes a message on the bus, and returns a task tracking response.
    """

    def __init__(self, queue: AgentTaskQueue, bus: AgentMessageBus):
        self.queue = queue
        self.bus = bus
        self.router = APIRouter(prefix="/actions", tags=["action-triggers"])
        self._setup_routes()

    def get_router(self) -> APIRouter:
        """Return configured router with all trigger endpoints."""
        return self.router

    async def _dispatch_action(
        self,
        task_name: str,
        task_type: str,
        channel: str,
        message_type: str,
        payload: dict[str, Any],
        user: CurrentUser,
        priority: int = TaskPriority.MEDIUM.value,
        requires_approval: bool = False,
        correlation_id: str | None = None,
        agent_id: str | None = None,
        subject: str = "",
    ) -> dict[str, Any]:
        """Internal helper to enqueue task, publish message, and format response."""
        try:
            p_enum = TaskPriority(priority)
        except ValueError:
            p_enum = TaskPriority.MEDIUM

        corr_id = correlation_id or str(uuid.uuid4())
        context_payload = {
            "tenant_id": str(user.tenant_id),
            "triggered_by": str(user.user_id),
            "user_email": user.email,
            "triggered_at": datetime.now(timezone.utc).isoformat(),
            **payload,
        }

        queue_res = await self.queue.enqueue(
            task_name=task_name,
            task_type=task_type,
            payload=context_payload,
            agent_id=agent_id,
            priority=p_enum,
            correlation_id=corr_id,
            tenant_id=str(user.tenant_id),
            requires_approval=requires_approval,
        )

        task_id = queue_res["task_id"]

        await self.bus.publish(
            channel=channel,
            message_type=message_type,
            from_agent=f"user:{user.user_id}",
            to_agent=agent_id or "*",
            subject=subject or f"Action trigger: {task_name}",
            payload={"task_id": task_id, "task_type": task_type, **context_payload},
            correlation_id=corr_id,
            priority=p_enum.value,
        )

        return {
            "task_id": task_id,
            "status": queue_res.get("status", "queued"),
            "message_type": message_type,
            "agent_assigned": agent_id or "auto-assigned",
            "requires_approval": requires_approval,
            "correlation_id": corr_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    def _setup_routes(self) -> None:
        """Register all ~50 agent trigger endpoints."""

        # --------------------------------------------------------------------
        # 1. Incident Management
        # --------------------------------------------------------------------
        @self.router.post("/incidents/{id}/auto-investigate")
        async def auto_investigate_incident(
            id: str,
            body: TriggerRequest = TriggerRequest(),
            user: CurrentUser = Depends(get_current_user),
            db: AsyncSession = Depends(get_db),
        ):
            """Auto-investigate an incident by triggering triage agent."""
            try:
                obj_uuid = uuid.UUID(id)
                res = await db.execute(
                    select(Incident).where(
                        Incident.id == obj_uuid,
                        Incident.tenant_id == user.tenant_id,
                    )
                )
                incident = res.scalar_one_or_none()
                if not incident:
                    raise HTTPException(status_code=404, detail=f"Incident {id} not found")
                entity_info = {
                    "incident_id": str(incident.id),
                    "title": incident.title,
                    "severity": incident.severity,
                    "status": incident.status,
                }
            except ValueError:
                raise HTTPException(status_code=400, detail="Invalid incident UUID format")

            payload = {**entity_info, **body.parameters}
            return await self._dispatch_action(
                task_name=f"investigate-incident-{id}",
                task_type="incident_triage",
                channel="threats",
                message_type=MessageType.INCIDENT_CREATED,
                payload=payload,
                user=user,
                priority=body.priority,
                requires_approval=body.requires_approval,
                correlation_id=body.correlation_id,
                agent_id="agent-soc-triage",
                subject=f"Auto-investigate incident {id}",
            )

        @self.router.post("/incidents/batch-triage")
        async def batch_triage_incidents(
            body: TriggerRequest = TriggerRequest(),
            user: CurrentUser = Depends(get_current_user),
        ):
            """Trigger batch triage across all open incidents."""
            return await self._dispatch_action(
                task_name="batch-incident-triage",
                task_type="batch_incident_triage",
                channel="threats",
                message_type=MessageType.THREAT_DETECTED,
                payload=body.parameters,
                user=user,
                priority=body.priority,
                requires_approval=body.requires_approval,
                correlation_id=body.correlation_id,
                agent_id="agent-soc-triage",
                subject="Batch incident triage requested",
            )

        @self.router.post("/incidents/{id}/isolate-blast-radius")
        async def isolate_incident_blast_radius(
            id: str,
            body: TriggerRequest = TriggerRequest(),
            user: CurrentUser = Depends(get_current_user),
            db: AsyncSession = Depends(get_db),
        ):
            """Trigger active blast radius containment for an incident."""
            try:
                obj_uuid = uuid.UUID(id)
                res = await db.execute(
                    select(Incident).where(
                        Incident.id == obj_uuid,
                        Incident.tenant_id == user.tenant_id,
                    )
                )
                incident = res.scalar_one_or_none()
                if not incident:
                    raise HTTPException(status_code=404, detail=f"Incident {id} not found")
                entity_info = {"incident_id": str(incident.id), "severity": incident.severity}
            except ValueError:
                raise HTTPException(status_code=400, detail="Invalid incident UUID format")

            payload = {**entity_info, **body.parameters}
            return await self._dispatch_action(
                task_name=f"isolate-blast-radius-{id}",
                task_type="containment_isolation",
                channel="remediation",
                message_type=MessageType.REMEDIATION_REQUEST,
                payload=payload,
                user=user,
                priority=TaskPriority.CRITICAL.value,
                requires_approval=True,
                correlation_id=body.correlation_id,
                agent_id="agent-incident-responder",
                subject=f"Isolate blast radius for incident {id}",
            )

        # --------------------------------------------------------------------
        # 2. Finding & Remediation
        # --------------------------------------------------------------------
        @self.router.post("/findings/{id}/auto-remediate")
        async def auto_remediate_finding(
            id: str,
            body: TriggerRequest = TriggerRequest(),
            user: CurrentUser = Depends(get_current_user),
            db: AsyncSession = Depends(get_db),
        ):
            """Trigger autonomous remediation for a specific finding."""
            try:
                obj_uuid = uuid.UUID(id)
                res = await db.execute(
                    select(Finding).where(
                        Finding.id == obj_uuid,
                        Finding.tenant_id == user.tenant_id,
                    )
                )
                finding = res.scalar_one_or_none()
                if not finding:
                    raise HTTPException(status_code=404, detail=f"Finding {id} not found")
                entity_info = {
                    "finding_id": str(finding.id),
                    "title": finding.title,
                    "severity": finding.severity,
                    "cve": finding.cve,
                }
            except ValueError:
                raise HTTPException(status_code=400, detail="Invalid finding UUID format")

            payload = {**entity_info, **body.parameters}
            return await self._dispatch_action(
                task_name=f"auto-remediate-finding-{id}",
                task_type="auto_remediate",
                channel="remediation",
                message_type=MessageType.REMEDIATION_REQUEST,
                payload=payload,
                user=user,
                priority=body.priority,
                requires_approval=body.requires_approval,
                correlation_id=body.correlation_id,
                agent_id="agent-auto-fixer",
                subject=f"Auto-remediate finding {id}",
            )

        @self.router.post("/findings/bulk-remediate")
        async def bulk_remediate_findings(
            body: TriggerRequest = TriggerRequest(),
            user: CurrentUser = Depends(get_current_user),
        ):
            """Trigger bulk remediation across findings matching criteria."""
            return await self._dispatch_action(
                task_name="bulk-remediate-findings",
                task_type="bulk_finding_remediation",
                channel="remediation",
                message_type=MessageType.REMEDIATION_REQUEST,
                payload=body.parameters,
                user=user,
                priority=body.priority,
                requires_approval=True,
                correlation_id=body.correlation_id,
                agent_id="agent-auto-fixer",
                subject="Bulk finding remediation requested",
            )

        @self.router.post("/findings/{id}/verify-fix")
        async def verify_finding_fix(
            id: str,
            body: TriggerRequest = TriggerRequest(),
            user: CurrentUser = Depends(get_current_user),
            db: AsyncSession = Depends(get_db),
        ):
            """Trigger verification scanning for a remediated finding."""
            try:
                obj_uuid = uuid.UUID(id)
                res = await db.execute(
                    select(Finding).where(
                        Finding.id == obj_uuid,
                        Finding.tenant_id == user.tenant_id,
                    )
                )
                finding = res.scalar_one_or_none()
                if not finding:
                    raise HTTPException(status_code=404, detail=f"Finding {id} not found")
                entity_info = {"finding_id": str(finding.id), "status": finding.status}
            except ValueError:
                raise HTTPException(status_code=400, detail="Invalid finding UUID format")

            payload = {**entity_info, **body.parameters}
            return await self._dispatch_action(
                task_name=f"verify-fix-{id}",
                task_type="finding_verification",
                channel="remediation",
                message_type=MessageType.REMEDIATION_COMPLETE,
                payload=payload,
                user=user,
                priority=body.priority,
                requires_approval=False,
                correlation_id=body.correlation_id,
                agent_id="agent-verifier",
                subject=f"Verify fix for finding {id}",
            )

        # --------------------------------------------------------------------
        # 3. Cloud Accounts & Posture
        # --------------------------------------------------------------------
        @self.router.post("/cloud/{account_id}/auto-scan")
        async def auto_scan_cloud_account(
            account_id: str,
            body: TriggerRequest = TriggerRequest(),
            user: CurrentUser = Depends(get_current_user),
        ):
            """Trigger posture evaluation scan for a cloud account."""
            if not account_id.strip():
                raise HTTPException(status_code=400, detail="Cloud account_id required")

            payload = {"account_id": account_id, **body.parameters}
            return await self._dispatch_action(
                task_name=f"cloud-scan-{account_id}",
                task_type="cloud_posture_scan",
                channel="threats",
                message_type=MessageType.THREAT_DETECTED,
                payload=payload,
                user=user,
                priority=body.priority,
                requires_approval=body.requires_approval,
                correlation_id=body.correlation_id,
                agent_id="agent-cloud-auditor",
                subject=f"Cloud posture scan for account {account_id}",
            )

        @self.router.post("/cloud/{account_id}/drift-remediate")
        async def remediate_cloud_drift(
            account_id: str,
            body: TriggerRequest = TriggerRequest(),
            user: CurrentUser = Depends(get_current_user),
        ):
            """Trigger drift remediation for a cloud account."""
            if not account_id.strip():
                raise HTTPException(status_code=400, detail="Cloud account_id required")

            payload = {"account_id": account_id, **body.parameters}
            return await self._dispatch_action(
                task_name=f"remediate-drift-{account_id}",
                task_type="cloud_drift_remediation",
                channel="remediation",
                message_type=MessageType.REMEDIATION_REQUEST,
                payload=payload,
                user=user,
                priority=TaskPriority.HIGH.value,
                requires_approval=True,
                correlation_id=body.correlation_id,
                agent_id="agent-cloud-auditor",
                subject=f"Cloud drift remediation for account {account_id}",
            )

        @self.router.post("/cloud/multi-cloud-audit")
        async def multi_cloud_audit(
            body: TriggerRequest = TriggerRequest(),
            user: CurrentUser = Depends(get_current_user),
        ):
            """Trigger multi-cloud compliance and posture audit."""
            return await self._dispatch_action(
                task_name="multi-cloud-audit",
                task_type="multi_cloud_compliance_audit",
                channel="compliance",
                message_type=MessageType.COMPLIANCE_VIOLATION,
                payload=body.parameters,
                user=user,
                priority=body.priority,
                requires_approval=False,
                correlation_id=body.correlation_id,
                agent_id="agent-cloud-auditor",
                subject="Multi-cloud posture audit triggered",
            )

        # --------------------------------------------------------------------
        # 4. Compliance & Regulatory
        # --------------------------------------------------------------------
        @self.router.post("/compliance/{framework}/auto-fix")
        async def auto_fix_compliance(
            framework: str,
            body: TriggerRequest = TriggerRequest(),
            user: CurrentUser = Depends(get_current_user),
        ):
            """Trigger compliance check and remediation for a regulatory framework."""
            if not framework.strip():
                raise HTTPException(status_code=400, detail="Compliance framework required")

            payload = {"framework": framework, **body.parameters}
            return await self._dispatch_action(
                task_name=f"compliance-fix-{framework}",
                task_type="compliance_check",
                channel="compliance",
                message_type=MessageType.COMPLIANCE_VIOLATION,
                payload=payload,
                user=user,
                priority=body.priority,
                requires_approval=body.requires_approval,
                correlation_id=body.correlation_id,
                agent_id="agent-compliance-officer",
                subject=f"Compliance check and auto-fix for {framework}",
            )

        @self.router.post("/compliance/gap-analysis")
        async def compliance_gap_analysis(
            body: TriggerRequest = TriggerRequest(),
            user: CurrentUser = Depends(get_current_user),
        ):
            """Trigger automated compliance gap analysis across control frameworks."""
            return await self._dispatch_action(
                task_name="compliance-gap-analysis",
                task_type="compliance_gap_analysis",
                channel="compliance",
                message_type=MessageType.COMPLIANCE_VIOLATION,
                payload=body.parameters,
                user=user,
                priority=body.priority,
                requires_approval=False,
                correlation_id=body.correlation_id,
                agent_id="agent-compliance-officer",
                subject="Compliance gap analysis requested",
            )

        @self.router.post("/compliance/evidence-collect")
        async def collect_compliance_evidence(
            body: TriggerRequest = TriggerRequest(),
            user: CurrentUser = Depends(get_current_user),
        ):
            """Trigger evidence collection task for audit readiness."""
            return await self._dispatch_action(
                task_name="collect-compliance-evidence",
                task_type="evidence_collection",
                channel="compliance",
                message_type=MessageType.COORDINATION,
                payload=body.parameters,
                user=user,
                priority=body.priority,
                requires_approval=False,
                correlation_id=body.correlation_id,
                agent_id="agent-compliance-officer",
                subject="Evidence collection task triggered",
            )

        # --------------------------------------------------------------------
        # 5. Threat Intelligence
        # --------------------------------------------------------------------
        @self.router.post("/threats/{id}/auto-assess")
        async def auto_assess_threat(
            id: str,
            body: TriggerRequest = TriggerRequest(),
            user: CurrentUser = Depends(get_current_user),
        ):
            """Trigger threat intel assessment for a indicator or threat record."""
            payload = {"threat_id": id, **body.parameters}
            return await self._dispatch_action(
                task_name=f"assess-threat-{id}",
                task_type="threat_intel_update",
                channel="threats",
                message_type=MessageType.THREAT_DETECTED,
                payload=payload,
                user=user,
                priority=body.priority,
                requires_approval=body.requires_approval,
                correlation_id=body.correlation_id,
                agent_id="agent-threat-analyst",
                subject=f"Auto-assess threat {id}",
            )

        @self.router.post("/threats/feed-ingest")
        async def ingest_threat_feed(
            body: TriggerRequest = TriggerRequest(),
            user: CurrentUser = Depends(get_current_user),
        ):
            """Trigger active threat feed ingestion and correlation."""
            return await self._dispatch_action(
                task_name="threat-feed-ingest",
                task_type="threat_feed_ingestion",
                channel="threats",
                message_type=MessageType.THREAT_DETECTED,
                payload=body.parameters,
                user=user,
                priority=body.priority,
                requires_approval=False,
                correlation_id=body.correlation_id,
                agent_id="agent-threat-analyst",
                subject="Threat feed ingestion triggered",
            )

        @self.router.post("/threats/{id}/hunt")
        async def hunt_threat_indicator(
            id: str,
            body: TriggerRequest = TriggerRequest(),
            user: CurrentUser = Depends(get_current_user),
        ):
            """Trigger active threat hunting mission for specific indicator."""
            payload = {"indicator_id": id, **body.parameters}
            return await self._dispatch_action(
                task_name=f"threat-hunt-{id}",
                task_type="threat_hunting_mission",
                channel="threats",
                message_type=MessageType.THREAT_DETECTED,
                payload=payload,
                user=user,
                priority=TaskPriority.HIGH.value,
                requires_approval=False,
                correlation_id=body.correlation_id,
                agent_id="agent-threat-analyst",
                subject=f"Threat hunt mission for indicator {id}",
            )

        # --------------------------------------------------------------------
        # 6. Identity & Governance
        # --------------------------------------------------------------------
        @self.router.post("/identities/{id}/auto-revoke")
        async def auto_revoke_identity(
            id: str,
            body: TriggerRequest = TriggerRequest(),
            user: CurrentUser = Depends(get_current_user),
            db: AsyncSession = Depends(get_db),
        ):
            """Trigger identity revocation task (requires approval)."""
            try:
                obj_uuid = uuid.UUID(id)
                res = await db.execute(
                    select(User).where(
                        User.id == obj_uuid,
                        User.tenant_id == user.tenant_id,
                    )
                )
                identity_user = res.scalar_one_or_none()
                if not identity_user:
                    raise HTTPException(status_code=404, detail=f"Identity {id} not found")
                entity_info = {
                    "target_user_id": str(identity_user.id),
                    "email": identity_user.email,
                    "is_active": identity_user.is_active,
                }
            except ValueError:
                raise HTTPException(status_code=400, detail="Invalid user UUID format")

            payload = {**entity_info, **body.parameters}
            return await self._dispatch_action(
                task_name=f"revoke-identity-{id}",
                task_type="identity_remediation",
                channel="remediation",
                message_type=MessageType.REMEDIATION_REQUEST,
                payload=payload,
                user=user,
                priority=TaskPriority.HIGH.value,
                requires_approval=True,
                correlation_id=body.correlation_id,
                agent_id="agent-iam-governance",
                subject=f"Auto-revoke identity for user {id}",
            )

        @self.router.post("/identities/access-review")
        async def trigger_access_review(
            body: TriggerRequest = TriggerRequest(),
            user: CurrentUser = Depends(get_current_user),
        ):
            """Trigger tenant-wide IAM access review task."""
            return await self._dispatch_action(
                task_name="iam-access-review",
                task_type="identity_access_review",
                channel="compliance",
                message_type=MessageType.COMPLIANCE_VIOLATION,
                payload=body.parameters,
                user=user,
                priority=body.priority,
                requires_approval=False,
                correlation_id=body.correlation_id,
                agent_id="agent-iam-governance",
                subject="IAM access review scan triggered",
            )

        @self.router.post("/identities/{id}/isolate-session")
        async def isolate_user_session(
            id: str,
            body: TriggerRequest = TriggerRequest(),
            user: CurrentUser = Depends(get_current_user),
            db: AsyncSession = Depends(get_db),
        ):
            """Trigger immediate user session isolation (requires approval)."""
            try:
                obj_uuid = uuid.UUID(id)
                res = await db.execute(
                    select(User).where(
                        User.id == obj_uuid,
                        User.tenant_id == user.tenant_id,
                    )
                )
                target_user = res.scalar_one_or_none()
                if not target_user:
                    raise HTTPException(status_code=404, detail=f"User {id} not found")
                entity_info = {"target_user_id": str(target_user.id), "email": target_user.email}
            except ValueError:
                raise HTTPException(status_code=400, detail="Invalid user UUID format")

            payload = {**entity_info, **body.parameters}
            return await self._dispatch_action(
                task_name=f"isolate-session-{id}",
                task_type="identity_session_isolation",
                channel="remediation",
                message_type=MessageType.REMEDIATION_REQUEST,
                payload=payload,
                user=user,
                priority=TaskPriority.CRITICAL.value,
                requires_approval=True,
                correlation_id=body.correlation_id,
                agent_id="agent-iam-governance",
                subject=f"Isolate active sessions for user {id}",
            )

        # --------------------------------------------------------------------
        # 7. Penetration Testing
        # --------------------------------------------------------------------
        @self.router.post("/pentests/{id}/auto-run")
        async def auto_run_pentest(
            id: str,
            body: TriggerRequest = TriggerRequest(),
            user: CurrentUser = Depends(get_current_user),
        ):
            """Trigger automated penetration test execution."""
            payload = {"pentest_id": id, **body.parameters}
            return await self._dispatch_action(
                task_name=f"run-pentest-{id}",
                task_type="pentest_scan",
                channel="threats",
                message_type=MessageType.THREAT_DETECTED,
                payload=payload,
                user=user,
                priority=body.priority,
                requires_approval=body.requires_approval,
                correlation_id=body.correlation_id,
                agent_id="agent-red-team",
                subject=f"Auto-run penetration test {id}",
            )

        @self.router.post("/pentests/schedule-campaign")
        async def schedule_pentest_campaign(
            body: TriggerRequest = TriggerRequest(),
            user: CurrentUser = Depends(get_current_user),
        ):
            """Schedule offensive red team testing campaign."""
            return await self._dispatch_action(
                task_name="schedule-pentest-campaign",
                task_type="pentest_campaign_schedule",
                channel="coordination",
                message_type=MessageType.COORDINATION,
                payload=body.parameters,
                user=user,
                priority=body.priority,
                requires_approval=True,
                correlation_id=body.correlation_id,
                agent_id="agent-red-team",
                subject="Pentest testing campaign scheduled",
            )

        # --------------------------------------------------------------------
        # 8. Container & Supply Chain Security
        # --------------------------------------------------------------------
        @self.router.post("/containers/{image}/auto-scan")
        async def auto_scan_container(
            image: str,
            body: TriggerRequest = TriggerRequest(),
            user: CurrentUser = Depends(get_current_user),
        ):
            """Trigger vulnerability and malware scan for a container image."""
            if not image.strip():
                raise HTTPException(status_code=400, detail="Container image path required")

            payload = {"image": image, **body.parameters}
            return await self._dispatch_action(
                task_name=f"container-scan-{image}",
                task_type="container_scan",
                channel="threats",
                message_type=MessageType.VULN_FOUND,
                payload=payload,
                user=user,
                priority=body.priority,
                requires_approval=body.requires_approval,
                correlation_id=body.correlation_id,
                agent_id="agent-container-scanner",
                subject=f"Container scan for image {image}",
            )

        @self.router.post("/containers/scan-pipeline")
        async def container_pipeline_scan(
            body: TriggerRequest = TriggerRequest(),
            user: CurrentUser = Depends(get_current_user),
        ):
            """Trigger container image scanning across CI/CD pipeline images."""
            return await self._dispatch_action(
                task_name="container-pipeline-scan",
                task_type="container_pipeline_scan",
                channel="compliance",
                message_type=MessageType.VULN_FOUND,
                payload=body.parameters,
                user=user,
                priority=body.priority,
                requires_approval=False,
                correlation_id=body.correlation_id,
                agent_id="agent-container-scanner",
                subject="CI/CD container pipeline scan triggered",
            )

        # --------------------------------------------------------------------
        # 9. Kubernetes Security
        # --------------------------------------------------------------------
        @self.router.post("/k8s/{cluster}/auto-scan")
        async def auto_scan_k8s_cluster(
            cluster: str,
            body: TriggerRequest = TriggerRequest(),
            user: CurrentUser = Depends(get_current_user),
        ):
            """Trigger security posture scan for a Kubernetes cluster."""
            if not cluster.strip():
                raise HTTPException(status_code=400, detail="K8s cluster name required")

            payload = {"cluster": cluster, **body.parameters}
            return await self._dispatch_action(
                task_name=f"k8s-scan-{cluster}",
                task_type="k8s_scan",
                channel="threats",
                message_type=MessageType.VULN_FOUND,
                payload=payload,
                user=user,
                priority=body.priority,
                requires_approval=body.requires_approval,
                correlation_id=body.correlation_id,
                agent_id="agent-k8s-defender",
                subject=f"Kubernetes cluster scan for {cluster}",
            )

        @self.router.post("/k8s/{cluster}/policy-enforce")
        async def enforce_k8s_policy(
            cluster: str,
            body: TriggerRequest = TriggerRequest(),
            user: CurrentUser = Depends(get_current_user),
        ):
            """Trigger Kubernetes security policy enforcement and admission check."""
            if not cluster.strip():
                raise HTTPException(status_code=400, detail="K8s cluster name required")

            payload = {"cluster": cluster, **body.parameters}
            return await self._dispatch_action(
                task_name=f"k8s-policy-enforce-{cluster}",
                task_type="k8s_policy_enforcement",
                channel="remediation",
                message_type=MessageType.REMEDIATION_REQUEST,
                payload=payload,
                user=user,
                priority=TaskPriority.HIGH.value,
                requires_approval=True,
                correlation_id=body.correlation_id,
                agent_id="agent-k8s-defender",
                subject=f"Kubernetes policy enforcement on cluster {cluster}",
            )

        # --------------------------------------------------------------------
        # 10. Attack Graph
        # --------------------------------------------------------------------
        @self.router.post("/attack-graph/rebuild")
        async def rebuild_attack_graph(
            body: TriggerRequest = TriggerRequest(),
            user: CurrentUser = Depends(get_current_user),
        ):
            """Trigger attack graph rebuild based on latest asset telemetry."""
            return await self._dispatch_action(
                task_name="rebuild-attack-graph",
                task_type="attack_graph_build",
                channel="coordination",
                message_type=MessageType.COORDINATION,
                payload=body.parameters,
                user=user,
                priority=body.priority,
                requires_approval=body.requires_approval,
                correlation_id=body.correlation_id,
                agent_id="agent-graph-engine",
                subject="Rebuild attack graph requested",
            )

        @self.router.post("/attack-graph/blast-radius")
        async def compute_blast_radius(
            body: TriggerRequest = TriggerRequest(),
            user: CurrentUser = Depends(get_current_user),
        ):
            """Compute attack graph blast radius analysis for target node."""
            return await self._dispatch_action(
                task_name="compute-blast-radius",
                task_type="blast_radius_computation",
                channel="coordination",
                message_type=MessageType.COORDINATION,
                payload=body.parameters,
                user=user,
                priority=body.priority,
                requires_approval=False,
                correlation_id=body.correlation_id,
                agent_id="agent-graph-engine",
                subject="Blast radius graph analysis triggered",
            )

        # --------------------------------------------------------------------
        # 11. Adversary Simulation
        # --------------------------------------------------------------------
        @self.router.post("/adversary-sim/run")
        async def run_adversary_simulation(
            body: TriggerRequest = TriggerRequest(),
            user: CurrentUser = Depends(get_current_user),
        ):
            """Trigger adversary simulation execution (requires approval)."""
            return await self._dispatch_action(
                task_name="run-adversary-simulation",
                task_type="adversary_simulation",
                channel="coordination",
                message_type=MessageType.COORDINATION,
                payload=body.parameters,
                user=user,
                priority=TaskPriority.HIGH.value,
                requires_approval=True,
                correlation_id=body.correlation_id,
                agent_id="agent-red-team",
                subject="Run adversary simulation requested",
            )

        @self.router.post("/adversary-sim/emulate-apt")
        async def emulate_apt_scenario(
            body: TriggerRequest = TriggerRequest(),
            user: CurrentUser = Depends(get_current_user),
        ):
            """Trigger APT threat actor emulation scenario (requires approval)."""
            return await self._dispatch_action(
                task_name="emulate-apt-scenario",
                task_type="apt_emulation_run",
                channel="coordination",
                message_type=MessageType.COORDINATION,
                payload=body.parameters,
                user=user,
                priority=TaskPriority.HIGH.value,
                requires_approval=True,
                correlation_id=body.correlation_id,
                agent_id="agent-red-team",
                subject="APT emulation campaign execution requested",
            )

        # --------------------------------------------------------------------
        # 12. Digital Twin
        # --------------------------------------------------------------------
        @self.router.post("/digital-twin/{env_id}/chaos")
        async def run_chaos_experiment(
            env_id: str,
            body: TriggerRequest = TriggerRequest(),
            user: CurrentUser = Depends(get_current_user),
        ):
            """Trigger chaos experiment in digital twin environment (requires approval)."""
            if not env_id.strip():
                raise HTTPException(status_code=400, detail="Environment ID required")

            payload = {"env_id": env_id, **body.parameters}
            return await self._dispatch_action(
                task_name=f"chaos-experiment-{env_id}",
                task_type="chaos_experiment",
                channel="coordination",
                message_type=MessageType.COORDINATION,
                payload=payload,
                user=user,
                priority=TaskPriority.HIGH.value,
                requires_approval=True,
                correlation_id=body.correlation_id,
                agent_id="agent-digital-twin",
                subject=f"Digital twin chaos experiment in env {env_id}",
            )

        @self.router.post("/digital-twin/sync-state")
        async def sync_digital_twin_state(
            body: TriggerRequest = TriggerRequest(),
            user: CurrentUser = Depends(get_current_user),
        ):
            """Synchronize digital twin state with live environment state."""
            return await self._dispatch_action(
                task_name="sync-digital-twin",
                task_type="digital_twin_state_sync",
                channel="coordination",
                message_type=MessageType.COORDINATION,
                payload=body.parameters,
                user=user,
                priority=body.priority,
                requires_approval=False,
                correlation_id=body.correlation_id,
                agent_id="agent-digital-twin",
                subject="Digital twin state synchronization triggered",
            )

        # --------------------------------------------------------------------
        # 13. Marketplace
        # --------------------------------------------------------------------
        @self.router.post("/marketplace/{listing_id}/auto-certify")
        async def auto_certify_listing(
            listing_id: str,
            body: TriggerRequest = TriggerRequest(),
            user: CurrentUser = Depends(get_current_user),
        ):
            """Trigger automated certification for a marketplace listing."""
            if not listing_id.strip():
                raise HTTPException(status_code=400, detail="Listing ID required")

            payload = {"listing_id": listing_id, **body.parameters}
            return await self._dispatch_action(
                task_name=f"certify-listing-{listing_id}",
                task_type="certification",
                channel="compliance",
                message_type=MessageType.COMPLIANCE_VIOLATION,
                payload=payload,
                user=user,
                priority=body.priority,
                requires_approval=body.requires_approval,
                correlation_id=body.correlation_id,
                agent_id="agent-marketplace-evaluator",
                subject=f"Auto-certify marketplace listing {listing_id}",
            )

        @self.router.post("/marketplace/publish-agent")
        async def publish_agent_validation(
            body: TriggerRequest = TriggerRequest(),
            user: CurrentUser = Depends(get_current_user),
        ):
            """Trigger security verification before publishing a new agent listing."""
            return await self._dispatch_action(
                task_name="marketplace-publish-agent-check",
                task_type="agent_publication_check",
                channel="coordination",
                message_type=MessageType.COORDINATION,
                payload=body.parameters,
                user=user,
                priority=body.priority,
                requires_approval=False,
                correlation_id=body.correlation_id,
                agent_id="agent-marketplace-evaluator",
                subject="Marketplace publication verification triggered",
            )

        # --------------------------------------------------------------------
        # 14. Autonomous SOC & Self-Healing
        # --------------------------------------------------------------------
        @self.router.post("/soc/triage-queue")
        async def trigger_soc_triage_queue(
            body: TriggerRequest = TriggerRequest(),
            user: CurrentUser = Depends(get_current_user),
        ):
            """Trigger batch triage across pending SOC queue items."""
            return await self._dispatch_action(
                task_name="soc-triage-queue",
                task_type="batch_triage",
                channel="threats",
                message_type=MessageType.THREAT_DETECTED,
                payload=body.parameters,
                user=user,
                priority=body.priority,
                requires_approval=body.requires_approval,
                correlation_id=body.correlation_id,
                agent_id="agent-soc-triage",
                subject="SOC queue batch triage triggered",
            )

        @self.router.post("/soc/shift-handoff")
        async def trigger_soc_shift_handoff(
            body: TriggerRequest = TriggerRequest(),
            user: CurrentUser = Depends(get_current_user),
        ):
            """Trigger automated SOC shift handoff report and task transfer."""
            return await self._dispatch_action(
                task_name="soc-shift-handoff",
                task_type="soc_shift_handoff",
                channel="coordination",
                message_type=MessageType.HANDOFF,
                payload=body.parameters,
                user=user,
                priority=body.priority,
                requires_approval=False,
                correlation_id=body.correlation_id,
                agent_id="agent-soc-triage",
                subject="SOC shift handoff execution triggered",
            )

        @self.router.post("/self-heal/run")
        async def run_self_healing_cycle(
            body: TriggerRequest = TriggerRequest(),
            user: CurrentUser = Depends(get_current_user),
        ):
            """Trigger active self-healing system recovery cycle."""
            return await self._dispatch_action(
                task_name="run-self-healing-cycle",
                task_type="self_healing_cycle",
                channel="remediation",
                message_type=MessageType.REMEDIATION_REQUEST,
                payload=body.parameters,
                user=user,
                priority=TaskPriority.HIGH.value,
                requires_approval=body.requires_approval,
                correlation_id=body.correlation_id,
                agent_id="agent-self-healer",
                subject="Autonomous self-healing cycle initiated",
            )

        @self.router.post("/self-heal/rollback")
        async def rollback_self_healing(
            body: TriggerRequest = TriggerRequest(),
            user: CurrentUser = Depends(get_current_user),
        ):
            """Rollback previous self-healing action (requires approval)."""
            return await self._dispatch_action(
                task_name="rollback-self-healing",
                task_type="self_heal_rollback",
                channel="remediation",
                message_type=MessageType.REMEDIATION_REQUEST,
                payload=body.parameters,
                user=user,
                priority=TaskPriority.CRITICAL.value,
                requires_approval=True,
                correlation_id=body.correlation_id,
                agent_id="agent-self-healer",
                subject="Rollback self-healing change requested",
            )

        # --------------------------------------------------------------------
        # 15. SIEM Alerts & Webhooks
        # --------------------------------------------------------------------
        @self.router.post("/alerts/deduplicate")
        async def deduplicate_alerts(
            body: TriggerRequest = TriggerRequest(),
            user: CurrentUser = Depends(get_current_user),
        ):
            """Trigger active alert deduplication and correlation run."""
            return await self._dispatch_action(
                task_name="deduplicate-alerts",
                task_type="alert_deduplication",
                channel="threats",
                message_type=MessageType.THREAT_DETECTED,
                payload=body.parameters,
                user=user,
                priority=body.priority,
                requires_approval=False,
                correlation_id=body.correlation_id,
                agent_id="agent-soc-triage",
                subject="SIEM alert deduplication initiated",
            )

        @self.router.post("/alerts/{id}/enrich")
        async def enrich_alert(
            id: str,
            body: TriggerRequest = TriggerRequest(),
            user: CurrentUser = Depends(get_current_user),
        ):
            """Trigger automated enrichment for a target alert ID."""
            payload = {"alert_id": id, **body.parameters}
            return await self._dispatch_action(
                task_name=f"enrich-alert-{id}",
                task_type="alert_enrichment",
                channel="threats",
                message_type=MessageType.THREAT_DETECTED,
                payload=payload,
                user=user,
                priority=body.priority,
                requires_approval=False,
                correlation_id=body.correlation_id,
                agent_id="agent-threat-analyst",
                subject=f"Enrich alert {id}",
            )

        @self.router.post("/webhooks/replay")
        async def replay_webhooks(
            body: TriggerRequest = TriggerRequest(),
            user: CurrentUser = Depends(get_current_user),
        ):
            """Trigger webhook replay and analysis task."""
            return await self._dispatch_action(
                task_name="webhook-replay-analysis",
                task_type="webhook_replay_analysis",
                channel="broadcast",
                message_type=MessageType.BROADCAST,
                payload=body.parameters,
                user=user,
                priority=body.priority,
                requires_approval=False,
                correlation_id=body.correlation_id,
                agent_id="agent-integrations",
                subject="Webhook replay analysis task triggered",
            )

        # --------------------------------------------------------------------
        # 16. Application & Code Repository Security
        # --------------------------------------------------------------------
        @self.router.post("/code/sast-scan")
        async def trigger_sast_scan(
            body: TriggerRequest = TriggerRequest(),
            user: CurrentUser = Depends(get_current_user),
        ):
            """Trigger SAST static code analysis scan task."""
            return await self._dispatch_action(
                task_name="code-sast-scan",
                task_type="code_sast_scan",
                channel="compliance",
                message_type=MessageType.VULN_FOUND,
                payload=body.parameters,
                user=user,
                priority=body.priority,
                requires_approval=False,
                correlation_id=body.correlation_id,
                agent_id="agent-code-auditor",
                subject="SAST code scan task triggered",
            )

        @self.router.post("/code/secret-scan")
        async def trigger_secret_scan(
            body: TriggerRequest = TriggerRequest(),
            user: CurrentUser = Depends(get_current_user),
        ):
            """Trigger secret scanning across repositories and commits."""
            return await self._dispatch_action(
                task_name="code-secret-scan",
                task_type="code_secret_scan",
                channel="threats",
                message_type=MessageType.VULN_FOUND,
                payload=body.parameters,
                user=user,
                priority=TaskPriority.HIGH.value,
                requires_approval=False,
                correlation_id=body.correlation_id,
                agent_id="agent-code-auditor",
                subject="Repository secret scan triggered",
            )

        # --------------------------------------------------------------------
        # 17. Advanced Analytics, PQC & Behavioral AI
        # --------------------------------------------------------------------
        @self.router.post("/data-residency/verify")
        async def verify_data_residency(
            body: TriggerRequest = TriggerRequest(),
            user: CurrentUser = Depends(get_current_user),
        ):
            """Trigger data residency compliance verification task."""
            return await self._dispatch_action(
                task_name="data-residency-verify",
                task_type="data_residency_verification",
                channel="compliance",
                message_type=MessageType.COMPLIANCE_VIOLATION,
                payload=body.parameters,
                user=user,
                priority=body.priority,
                requires_approval=False,
                correlation_id=body.correlation_id,
                agent_id="agent-compliance-officer",
                subject="Data residency verification requested",
            )

        @self.router.post("/quantum-crypto/pqc-audit")
        async def pqc_crypto_audit(
            body: TriggerRequest = TriggerRequest(),
            user: CurrentUser = Depends(get_current_user),
        ):
            """Trigger post-quantum cryptographic algorithm audit."""
            return await self._dispatch_action(
                task_name="pqc-crypto-audit",
                task_type="pqc_crypto_audit",
                channel="compliance",
                message_type=MessageType.COMPLIANCE_VIOLATION,
                payload=body.parameters,
                user=user,
                priority=body.priority,
                requires_approval=False,
                correlation_id=body.correlation_id,
                agent_id="agent-crypto-analyst",
                subject="Post-quantum crypto audit triggered",
            )

        @self.router.post("/behavioral/anomaly-scan")
        async def behavioral_anomaly_scan(
            body: TriggerRequest = TriggerRequest(),
            user: CurrentUser = Depends(get_current_user),
        ):
            """Trigger ML-based behavioral anomaly detection scan."""
            return await self._dispatch_action(
                task_name="behavioral-anomaly-scan",
                task_type="behavioral_anomaly_scan",
                channel="threats",
                message_type=MessageType.THREAT_DETECTED,
                payload=body.parameters,
                user=user,
                priority=body.priority,
                requires_approval=False,
                correlation_id=body.correlation_id,
                agent_id="agent-ml-analytics",
                subject="Behavioral anomaly detection scan triggered",
            )

        @self.router.post("/executive/board-report")
        async def generate_executive_board_report(
            body: TriggerRequest = TriggerRequest(),
            user: CurrentUser = Depends(get_current_user),
        ):
            """Trigger executive security board report generation."""
            return await self._dispatch_action(
                task_name="generate-board-report",
                task_type="executive_report_generation",
                channel="broadcast",
                message_type=MessageType.BROADCAST,
                payload=body.parameters,
                user=user,
                priority=body.priority,
                requires_approval=False,
                correlation_id=body.correlation_id,
                agent_id="agent-executive-reporter",
                subject="Executive board report generation triggered",
            )

        @self.router.post("/redteam/recon")
        async def trigger_redteam_recon(
            body: TriggerRequest = TriggerRequest(),
            user: CurrentUser = Depends(get_current_user),
        ):
            """Trigger active red team reconnaissance scanning."""
            return await self._dispatch_action(
                task_name="redteam-recon-scan",
                task_type="redteam_recon_scan",
                channel="threats",
                message_type=MessageType.THREAT_DETECTED,
                payload=body.parameters,
                user=user,
                priority=body.priority,
                requires_approval=False,
                correlation_id=body.correlation_id,
                agent_id="agent-red-team",
                subject="Red team reconnaissance scan triggered",
            )

        # --------------------------------------------------------------------
        # 18. Governance & Approvals
        # --------------------------------------------------------------------
        @self.router.post("/approvals/{id}/auto-evaluate")
        async def auto_evaluate_approval(
            id: str,
            body: TriggerRequest = TriggerRequest(),
            user: CurrentUser = Depends(get_current_user),
            db: AsyncSession = Depends(get_db),
        ):
            """Trigger automated evaluation for pending approval request."""
            try:
                obj_uuid = uuid.UUID(id)
                res = await db.execute(
                    select(Approval).where(
                        Approval.id == obj_uuid,
                        Approval.tenant_id == user.tenant_id,
                    )
                )
                approval = res.scalar_one_or_none()
                if not approval:
                    raise HTTPException(status_code=404, detail=f"Approval {id} not found")
                entity_info = {
                    "approval_id": str(approval.id),
                    "risk_class": approval.risk_class,
                    "status": approval.status,
                }
            except ValueError:
                raise HTTPException(status_code=400, detail="Invalid approval UUID format")

            payload = {**entity_info, **body.parameters}
            return await self._dispatch_action(
                task_name=f"evaluate-approval-{id}",
                task_type="approval_policy_evaluation",
                channel="approvals",
                message_type=MessageType.APPROVAL_REQUEST,
                payload=payload,
                user=user,
                priority=body.priority,
                requires_approval=False,
                correlation_id=body.correlation_id,
                agent_id="agent-policy-engine",
                subject=f"Auto-evaluate approval request {id}",
            )

        @self.router.post("/evidence/auto-attest")
        async def auto_attest_evidence(
            body: TriggerRequest = TriggerRequest(),
            user: CurrentUser = Depends(get_current_user),
        ):
            """Trigger automated cryptographic attestation for evidence records."""
            return await self._dispatch_action(
                task_name="auto-attest-evidence",
                task_type="evidence_attestation",
                channel="compliance",
                message_type=MessageType.COMPLIANCE_VIOLATION,
                payload=body.parameters,
                user=user,
                priority=body.priority,
                requires_approval=False,
                correlation_id=body.correlation_id,
                agent_id="agent-compliance-officer",
                subject="Automated evidence attestation triggered",
            )

        # --------------------------------------------------------------------
        # 19. Task & Fleet Operations
        # --------------------------------------------------------------------
        @self.router.get("/tasks/{task_id}")
        async def get_task_status(
            task_id: str,
            user: CurrentUser = Depends(get_current_user),
        ):
            """Query task status by task ID."""
            task = await self.queue.get_task(task_id)
            if not task:
                raise HTTPException(status_code=404, detail=f"Task {task_id} not found")
            return task

        @self.router.get("/tasks")
        async def list_tasks(
            user: CurrentUser = Depends(get_current_user),
        ):
            """List agent task queue depth and claimed task metrics."""
            depth = await self.queue.get_queue_depth()
            return {
                "queue_depth": depth,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

        @self.router.get("/fleet/status")
        async def get_fleet_status(
            user: CurrentUser = Depends(get_current_user),
        ):
            """Get system fleet status, queue metrics, and bus statistics."""
            queue_depth = await self.queue.get_queue_depth()
            bus_stats = await self.bus.get_bus_stats()
            return {
                "status": "healthy",
                "queue": queue_depth,
                "bus": bus_stats,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

        @self.router.post("/fleet/submit")
        async def submit_custom_task(
            body: CustomTaskRequest,
            user: CurrentUser = Depends(get_current_user),
        ):
            """Submit custom task directly to the agent task queue."""
            return await self._dispatch_action(
                task_name=body.task_name,
                task_type=body.task_type,
                channel="coordination",
                message_type=MessageType.COORDINATION,
                payload=body.payload,
                user=user,
                priority=body.priority,
                requires_approval=body.requires_approval,
                correlation_id=body.correlation_id,
                agent_id=body.agent_id,
                subject=f"Custom task submission: {body.task_name}",
            )


__all__ = [
    "TriggerRequest",
    "CustomTaskRequest",
    "ActionTriggerRouter",
]
