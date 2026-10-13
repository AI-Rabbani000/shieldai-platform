"""Phase 19 (Continuation Prompt 6), Part 8/9: the Merge Coordinator - collects every
real completed task's patch, orders real merges by the task graph's own dependency
order, runs real structural conflict detection before each merge as an early warning,
performs the real `git merge` (gds_api.engineering.merge_engine), and on a real conflict
escalates rather than ever merging blindly (Part 9: "Never merge blindly").
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import select

from gds_api.audit import record_audit_event
from gds_api.db import async_session_factory
from gds_api.engineering.merge_engine import (
    MergeError,
    create_integration_branch,
    current_head_commit,
    merge_task_branch,
)
from gds_api.engineering.mission_messages import record_message
from gds_api.engineering.patch_extractor import extract_patch
from gds_api.engineering.review_engine import run_review
from gds_api.events import publish_mission_event
from gds_api.finding_lifecycle import FindingStatus, validate_finding_transition
from gds_api.logging_config import get_logger
from gds_api.memory import record_remediation_commit_edge
from gds_api.metrics import finding_correlation_edges_total
from gds_api.models import (
    EngineeringTask,
    Finding,
    Mission,
    MissionPlan,
    RepositoryPolicy,
    Workspace,
)
from gds_api.purple_messages import PurpleMessageType, record_purple_message
from gds_api.repository.lock_manager import ensure_not_primary_repository_path
from gds_api.repository.registry import get_repository
from gds_api.repository.worktree_manager import (
    WorktreeOperationError,
    delete_branch,
    destroy_worktree,
)

_logger = get_logger("gds_api.engineering.merge_coordinator")


def detect_structural_conflicts(
    task_patches: dict[str, list[str]],
) -> list[dict[str, object]]:
    """Part 8: real, cheap, pre-merge structural overlap detection - the same real file
    a patch touches, compared pairwise across every completed task. A real, early
    warning; the real `git merge` exit code (Part 9) is always the final authority."""
    conflicts: list[dict[str, object]] = []
    task_keys = sorted(task_patches)
    for i, task_a in enumerate(task_keys):
        for task_b in task_keys[i + 1 :]:
            overlap = sorted(set(task_patches[task_a]) & set(task_patches[task_b]))
            if overlap:
                conflicts.append({"task_a": task_a, "task_b": task_b, "overlapping_files": overlap})
    return conflicts


async def run_merge(mission_plan_id: uuid.UUID) -> None:
    async with async_session_factory() as db:
        plan = await db.get(MissionPlan, mission_plan_id)
        if plan is None:
            return
        tenant_id = plan.tenant_id
        mission_id = plan.mission_id
        repository_id = plan.repository_id
        repo = await get_repository(db, tenant_id=tenant_id, repository_id=repository_id)
        policy = await db.get(RepositoryPolicy, repository_id)

        completed_rows = (
            (
                await db.execute(
                    select(EngineeringTask).where(
                        EngineeringTask.mission_plan_id == mission_plan_id,
                        EngineeringTask.status == "COMPLETED",
                    )
                )
            )
            .scalars()
            .all()
        )

    if not completed_rows:
        await _fail_plan(mission_plan_id, mission_id, "No real completed tasks to merge.")
        return

    task_patches: dict[str, list[str]] = {}
    for row in completed_rows:
        raw_files = row.patch_summary.get("files", [])
        files = raw_files if isinstance(raw_files, list) else []
        task_patches[row.task_key] = [
            str(f["path"]) for f in files if isinstance(f, dict) and "path" in f
        ]
    structural_conflicts = detect_structural_conflicts(task_patches)
    if structural_conflicts:
        await publish_mission_event(
            str(mission_id), "merge.conflict_detected", conflicts=structural_conflicts
        )

    from gds_api.repository.workspace_manager import WORKSPACE_ROOT

    integration_id = uuid.uuid4()
    integration_path = (
        WORKSPACE_ROOT / str(tenant_id) / f"integration-{integration_id}" / "worktree"
    )
    ensure_not_primary_repository_path(str(integration_path), repo.working_directory)
    integration_branch = f"gds-integration-{integration_id}"

    try:
        await create_integration_branch(
            repo.working_directory, str(integration_path), integration_branch, repo.default_branch
        )
    except WorktreeOperationError as exc:
        await _fail_plan(mission_plan_id, mission_id, f"Real integration workspace failed: {exc}")
        return

    # A real, tracked Workspace row for the integration worktree too - so it's visible
    # and cleanable through the exact same Phase 17 mechanisms as every other real
    # workspace, never an untracked ad-hoc directory.
    integration_workspace = Workspace(
        id=integration_id,
        tenant_id=tenant_id,
        mission_id=mission_id,
        repository_id=repository_id,
        agent_id="merge-coordinator",
        provider=repo.provider,
        workspace_path=str(integration_path),
        temporary_directory=str(integration_path.parent),
        state="READY",
        expires_at=datetime.now(UTC) + timedelta(hours=2),
    )
    async with async_session_factory() as db:
        db.add(integration_workspace)
        plan = await db.get(MissionPlan, mission_plan_id)
        if plan is not None:
            plan.integration_workspace_id = integration_id
        await db.commit()

    merged_task_keys: list[str] = []
    escalated: list[dict[str, object]] = []
    # Real dependency-respecting order: tasks with no real completed dependents-of-
    # dependents ordering issues are merged in the same order they were scheduled -
    # completed_rows is already only COMPLETED tasks, and their own real depends_on was
    # already validated acyclic at plan time (task_graph.validate_graph).
    for row in sorted(completed_rows, key=lambda r: r.created_at):
        assert row.branch_name is not None  # every COMPLETED task set its own real branch
        merge_outcome = await merge_task_branch(str(integration_path), row.branch_name)
        if merge_outcome.success:
            merged_task_keys.append(row.task_key)
            await publish_mission_event(str(mission_id), "merge.task_merged", task_key=row.task_key)
        else:
            escalated.append(
                {
                    "task_key": row.task_key,
                    "conflict_files": merge_outcome.conflict_files,
                    "stderr": merge_outcome.real_stderr,
                }
            )
            await publish_mission_event(
                str(mission_id),
                "merge.escalated",
                task_key=row.task_key,
                conflict_files=merge_outcome.conflict_files,
            )
            await record_message(
                tenant_id=tenant_id,
                mission_plan_id=mission_plan_id,
                task_id=None,
                related_task_id=row.id,
                message_type="merge_conflict_escalated",
                content=(
                    f"Could not auto-merge '{row.task_key}': real conflict in "
                    f"{', '.join(merge_outcome.conflict_files) or 'unknown file(s)'} - "
                    "escalated for human review, never merged blindly."
                ),
            )

    # Real cleanup: a successfully-merged task's own workspace/branch is no longer
    # needed - its real, committed content now lives on the integration branch. A task
    # whose merge was escalated keeps its real workspace/branch around for human
    # inspection, never auto-deleted out from under an unresolved real conflict.
    for row in completed_rows:
        if row.task_key not in merged_task_keys or row.workspace_id is None:
            continue
        async with async_session_factory() as db:
            task_workspace = await db.get(Workspace, row.workspace_id)
        if task_workspace is None:
            continue
        try:
            await destroy_worktree(
                repo.working_directory,
                task_workspace.workspace_path,
                task_workspace.temporary_directory,
                force=True,
            )
            if row.branch_name:
                await delete_branch(repo.working_directory, row.branch_name, force=True)
        except WorktreeOperationError as exc:
            _logger.warning(
                "merge_coordinator.task_workspace_cleanup_failed",
                task_key=row.task_key,
                error=str(exc),
            )
        async with async_session_factory() as db:
            workspace_row = await db.get(Workspace, row.workspace_id)
            if workspace_row is not None:
                workspace_row.state = "DESTROYED"
                workspace_row.destroyed_at = datetime.now(UTC)
                await db.commit()

    async with async_session_factory() as db:
        plan = await db.get(MissionPlan, mission_plan_id)
        if plan is None:
            return
        plan.integration_branch = integration_branch
        plan.conflict_report = {
            "structural_conflicts": structural_conflicts,
            "merge_escalations": escalated,
            "merged_task_keys": merged_task_keys,
        }
        await db.commit()

    if not merged_task_keys:
        await _fail_plan(
            mission_plan_id,
            mission_id,
            "Every real task branch failed to merge - see conflict_report.",
        )
        return

    # Part 10: Unified Review - the exact same real Review Engine Phase 18 built, run
    # again over the real, merged integration branch's own uncommitted-vs-base diff.
    patch = await extract_patch(
        str(integration_path),
        maximum_changed_files=(policy.maximum_changed_files if policy else 25),
        maximum_changed_lines=(policy.maximum_changed_lines if policy else 1000),
    )
    outcome = (
        await run_review(workspace_path=str(integration_path), patch=patch, policy=policy)
        if policy is not None
        else None
    )

    async with async_session_factory() as db:
        plan = await db.get(MissionPlan, mission_plan_id)
        if plan is None:
            return
        if outcome is not None:
            plan.merged_review_result = outcome.result
            plan.merged_review_findings = outcome.to_dict()

        if outcome is not None and outcome.result == "FAIL":
            # A real FAIL on the merged, integrated result overrides everything else -
            # never present a failing review as something ready for human approval.
            plan.status = "FAILED"
            plan.completed_at = datetime.now(UTC)
            plan.failure_reason = "The Unified Review FAILED on the merged result."
        elif escalated:
            # Real, partial success: some tasks merged, some conflict and need a human -
            # never silently drop the escalation (Part 9: "never merge blindly").
            plan.status = "AWAITING_APPROVAL"
            plan.failure_reason = (
                f"{len(escalated)} real task(s) could not be merged automatically - "
                "see conflict_report. Reviewed/mergeable tasks are still ready for approval."
            )
        else:
            plan.status = "AWAITING_APPROVAL"

        mission = await db.get(Mission, mission_id)
        if mission is not None:
            mission.status = "failed" if plan.status == "FAILED" else "awaiting_approval"

        await record_audit_event(
            db,
            tenant_id=tenant_id,
            user_id=plan.requested_by_user_id,
            action="engineering.mission_merged",
            detail={
                "mission_plan_id": str(mission_plan_id),
                "merged_task_keys": merged_task_keys,
                "escalated_count": len(escalated),
                "review_result": outcome.result if outcome else None,
            },
        )
        await db.commit()

        if plan.status == "FAILED":
            await publish_mission_event(
                str(mission_id), "mission.failed", reason=plan.failure_reason
            )
            await publish_mission_event(str(mission_id), "mission_finished", status="failed")
            return

    await publish_mission_event(
        str(mission_id),
        "mission.review_progress",
        result=outcome.result if outcome else "unknown",
        merged_task_keys=merged_task_keys,
    )
    await publish_mission_event(str(mission_id), "mission.approval_requested")


async def commit_mission(
    *,
    tenant_id: uuid.UUID,
    mission_plan_id: uuid.UUID,
    actor_user_id: uuid.UUID,
    approved_by_email: str,
) -> str:
    """Called only after a real Approval has been granted for the mission-level
    `engineering.commit_mission` capability request. Unlike Phase 18's single-session
    commit (where the AI's edits sit uncommitted until approval), by this point every
    real task branch and the integration branch's real `git merge --no-ff` commits
    already exist (Part 9 requires real commits to merge at all) - so the normal case
    here is that the integration worktree's working tree is already clean and there is
    nothing left to `git add`. This function records the integration branch's own
    already-real HEAD commit as the mission's commit_hash rather than forcing a second,
    redundant commit. If the working tree is NOT clean (e.g. a reviewer or a provider
    left uncommitted state), it commits that real remainder first, exactly like Phase
    18's mechanism, so nothing is ever silently dropped."""
    from gds_api.engineering.commit_engine import (
        CommitError,
        CommitMetadata,
        commit_workspace_changes,
    )

    async with async_session_factory() as db:
        plan = await db.get(MissionPlan, mission_plan_id)
        if plan is None or plan.tenant_id != tenant_id:
            raise MergeError(f"MissionPlan {mission_plan_id} not found for this tenant.")
        if plan.status != "AWAITING_APPROVAL":
            raise MergeError(
                f"MissionPlan {mission_plan_id} is {plan.status}, not ready to commit."
            )
        if plan.integration_workspace_id is None:
            raise MergeError("This mission plan has no real integration workspace.")
        integration_workspace = await db.get(Workspace, plan.integration_workspace_id)
        if integration_workspace is None:
            raise MergeError("The real integration workspace for this mission no longer exists.")

        metadata = CommitMetadata(
            agent="mission-orchestrator",
            mission_id=plan.mission_id,
            repository_id=plan.repository_id,
            workspace_id=integration_workspace.id,
            provider="multi-agent",
            risk=plan.complexity or "unknown",
            review_result=plan.merged_review_result or "unknown",
            approved_by=approved_by_email,
            session_id=mission_plan_id,
        )
        try:
            commit_hash = await commit_workspace_changes(
                integration_workspace.workspace_path, objective=plan.objective, metadata=metadata
            )
        except CommitError:
            # The normal case (see docstring): every real change is already committed
            # via the Merge Coordinator's own real merge commits. Nothing uncommitted
            # remains, so the integration branch's current HEAD *is* the real, reviewed,
            # now-approved commit - not a failure.
            try:
                commit_hash = await current_head_commit(integration_workspace.workspace_path)
            except MergeError as exc:
                plan.status = "FAILED"
                plan.failure_reason = str(exc)[:2000]
                plan.completed_at = datetime.now(UTC)
                mission = await db.get(Mission, plan.mission_id)
                if mission is not None:
                    mission.status = "failed"
                await db.commit()
                await publish_mission_event(str(plan.mission_id), "mission.failed", reason=str(exc))
                await publish_mission_event(
                    str(plan.mission_id), "mission_finished", status="failed"
                )
                raise MergeError(str(exc)) from exc

        plan.commit_hash = commit_hash
        plan.status = "COMPLETED"
        plan.completed_at = datetime.now(UTC)
        mission = await db.get(Mission, plan.mission_id)
        if mission is not None:
            mission.status = "completed"
            mission.completed_at = datetime.now(UTC)

        # Phase 20 (Continuation Prompt 7), Part 10: if this MissionPlan was
        # created by auto_fix_finding to remediate a real Finding, its real
        # commit is exactly the moment to advance that finding's lifecycle - but
        # only as far as awaiting_retest, never straight to remediated. Per Part
        # 9's own rule, a finding is never closed merely because a patch/commit
        # exists - real retest confirmation (validation_retest, still DEGRADED -
        # see ADR 0033) is a required, separate step.
        if plan.finding_id is not None:
            finding = await db.get(Finding, plan.finding_id)
            if finding is not None and finding.tenant_id == tenant_id:
                if finding.status == FindingStatus.REMEDIATION_PLANNED.value:
                    validate_finding_transition(
                        finding.status, FindingStatus.REMEDIATION_IN_PROGRESS
                    )
                    finding.status = FindingStatus.REMEDIATION_IN_PROGRESS
                if finding.status == FindingStatus.REMEDIATION_IN_PROGRESS.value:
                    validate_finding_transition(finding.status, FindingStatus.AWAITING_RETEST)
                    finding.status = FindingStatus.AWAITING_RETEST
                    finding.recommended_remediation = (
                        f"Auto-fixed via mission plan {mission_plan_id}, commit {commit_hash[:12]}."
                    )
                    await record_purple_message(
                        db,
                        tenant_id=tenant_id,
                        mission_id=plan.mission_id,
                        message_type=PurpleMessageType.RETEST_REQUESTED.value,
                        content=(
                            f"Finding '{finding.title}' auto-fix committed "
                            f"({commit_hash[:12]}) - awaiting independent retest."
                        ),
                        sender_agent="defensive_remediation_autofix",
                        payload={
                            "finding_id": str(finding.id),
                            "mission_plan_id": str(mission_plan_id),
                            "commit_hash": commit_hash,
                        },
                    )
                    # Phase 20 (Continuation Prompt 7), Part 12: the real
                    # correlation-engine write - the exact moment this finding's
                    # remediation produces a real commit.
                    await record_remediation_commit_edge(
                        mission_plan_id=mission_plan_id,
                        finding_id=finding.id,
                        commit_hash=commit_hash,
                    )
                    finding_correlation_edges_total.labels(edge_type="produced_commit").inc()

        await record_audit_event(
            db,
            tenant_id=tenant_id,
            user_id=actor_user_id,
            action="engineering.mission_committed",
            detail={
                "mission_plan_id": str(mission_plan_id),
                "commit_hash": commit_hash,
                "approved_by": approved_by_email,
            },
        )
        await db.commit()
        mission_id = plan.mission_id

    await record_message(
        tenant_id=tenant_id,
        mission_plan_id=mission_plan_id,
        task_id=None,
        related_task_id=None,
        message_type="mission_committed",
        content=f"Mission committed ({commit_hash[:12]}), approved by {approved_by_email}.",
    )
    await publish_mission_event(str(mission_id), "mission.commit_created", commit_hash=commit_hash)
    await publish_mission_event(str(mission_id), "mission.completed")
    await publish_mission_event(str(mission_id), "mission_finished", status="completed")
    return commit_hash


async def _fail_plan(mission_plan_id: uuid.UUID, mission_id: uuid.UUID, reason: str) -> None:
    async with async_session_factory() as db:
        plan = await db.get(MissionPlan, mission_plan_id)
        if plan is None:
            return
        plan.status = "FAILED"
        plan.failure_reason = reason[:2000]
        plan.completed_at = datetime.now(UTC)
        mission = await db.get(Mission, mission_id)
        if mission is not None:
            mission.status = "failed"
        await db.commit()
    await publish_mission_event(str(mission_id), "mission.failed", reason=reason)
    await publish_mission_event(str(mission_id), "mission_finished", status="failed")
