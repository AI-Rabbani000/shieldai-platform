"""Phase 19 (Continuation Prompt 6): the Mission Orchestrator - the real component that
turns one real MissionPlan into real, parallel EngineeringTask execution, a real merge,
a real Unified Review, and (after real human approval) one real, mission-level commit.
Reuses Phase 18's real AIProvider/prompt-compiler/patch-extractor/review-engine
pipeline unchanged for every individual task; adds real task-graph scheduling
(asyncio.Semaphore-gated concurrency over a real topological order - ADR extending
ADR 0020's own asyncio-background-task architecture, never a new execution primitive)
and real git branch-per-task + merge (Part 9) on top.
"""

from __future__ import annotations

import asyncio
import time
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import select

from gds_api.audit import record_audit_event
from gds_api.db import async_session_factory
from gds_api.engineering.mission_messages import record_message
from gds_api.engineering.mission_planner import MissionPlanningError, plan_mission
from gds_api.engineering.patch_extractor import extract_patch
from gds_api.engineering.prompt_compiler import (
    PolicyContext,
    PromptInputs,
    RepositoryContext,
    compile_prompt,
)
from gds_api.engineering.providers import ProviderError, get_provider
from gds_api.engineering.review_engine import run_review
from gds_api.engineering.specialist_roles import get_specialist_role
from gds_api.engineering.task_graph import GraphNode, ready_tasks, topological_order
from gds_api.events import publish_mission_event
from gds_api.logging_config import get_logger
from gds_api.metrics import llm_call_duration_seconds, llm_calls_total
from gds_api.models import EngineeringTask, Mission, MissionPlan, Workspace
from gds_api.repository.git_exec import run_git
from gds_api.repository.lock_manager import ensure_not_primary_repository_path
from gds_api.repository.registry import get_repository, get_repository_policy
from gds_api.repository.worktree_manager import (
    WorktreeOperationError,
    create_branch_worktree,
)

_logger = get_logger("gds_api.engineering.mission_orchestrator")

_EVENT_TYPE_MAP = {
    "thinking": "task.thinking",
    "tool_use": "task.tool_execution",
    "assistant_text": "task.thinking",
    "file_change": "task.generated_files",
    "tool_result": "task.workspace_activity",
    "error": "task.failed",
    "result": "task.patch_progress",
}


class MissionOrchestratorError(Exception):
    pass


async def create_mission_plan(
    *,
    tenant_id: uuid.UUID,
    mission_id: uuid.UUID,
    repository_id: uuid.UUID,
    requested_by_user_id: uuid.UUID,
    objective: str,
    max_concurrency: int = 3,
    finding_id: uuid.UUID | None = None,
) -> uuid.UUID:
    """Part 1/2: real planning + persistence. Returns the new MissionPlan's real id."""
    async with async_session_factory() as db:
        repo = await get_repository(db, tenant_id=tenant_id, repository_id=repository_id)
        try:
            result = await plan_mission(
                db,
                tenant_id=tenant_id,
                mission_id=mission_id,
                objective=objective,
                repository_display_name=repo.display_name,
                repository_default_branch=repo.default_branch,
            )
        except MissionPlanningError as exc:
            raise MissionOrchestratorError(str(exc)) from exc

        plan = MissionPlan(
            tenant_id=tenant_id,
            mission_id=mission_id,
            repository_id=repository_id,
            requested_by_user_id=requested_by_user_id,
            finding_id=finding_id,
            objective=objective,
            complexity=result.complexity,
            affected_systems=result.affected_systems,
            execution_strategy=result.execution_strategy,
            status="READY",
            max_concurrency=max_concurrency,
            mission_memory={
                "objective": objective,
                "execution_strategy": result.execution_strategy,
                "affected_systems": result.affected_systems,
                "completed_tasks": [],
            },
        )
        db.add(plan)
        await db.flush()

        for task in result.tasks:
            db.add(
                EngineeringTask(
                    tenant_id=tenant_id,
                    mission_plan_id=plan.id,
                    repository_id=repository_id,
                    task_key=task.task_key,
                    title=task.title,
                    description=task.description,
                    specialist_role=task.specialist_role,
                    provider=get_specialist_role(task.specialist_role).default_provider,
                    depends_on=task.depends_on,
                    required_capabilities=task.required_capabilities,
                    status="PENDING",
                    risk_estimate=task.risk_estimate,
                )
            )
        plan.planned_at = datetime.now(UTC)
        await db.flush()

        await record_audit_event(
            db,
            tenant_id=tenant_id,
            user_id=requested_by_user_id,
            action="engineering.mission_planned",
            detail={
                "mission_plan_id": str(plan.id),
                "task_count": len(result.tasks),
                "complexity": result.complexity,
            },
        )
        await db.commit()
        plan_id = plan.id

    await record_message(
        tenant_id=tenant_id,
        mission_plan_id=plan_id,
        task_id=None,
        related_task_id=None,
        message_type="mission_planned",
        content=(
            f"Decomposed into {len(result.tasks)} task(s): "
            + ", ".join(t.task_key for t in result.tasks)
            + f". Strategy: {result.execution_strategy}"
        ),
    )
    await publish_mission_event(
        str(mission_id),
        "mission.planned",
        mission_plan_id=str(plan_id),
        task_count=len(result.tasks),
    )
    return plan_id


async def execute_mission_plan(mission_plan_id: uuid.UUID) -> None:
    """Part 5: real parallel task execution, respecting the real DAG and a real,
    configurable max concurrency (asyncio.Semaphore). Runs as a real background task,
    the same real architecture Phase 18's single-session orchestrator already
    established (ADR 0020)."""
    async with async_session_factory() as db:
        plan = await db.get(MissionPlan, mission_plan_id)
        if plan is None:
            return
        mission = await db.get(Mission, plan.mission_id)
        if mission is not None:
            mission.status = "running"
        plan.status = "EXECUTING"
        await db.commit()
        tenant_id = plan.tenant_id
        mission_id = plan.mission_id
        max_concurrency = plan.max_concurrency

        task_rows = (
            (
                await db.execute(
                    select(EngineeringTask).where(
                        EngineeringTask.mission_plan_id == mission_plan_id
                    )
                )
            )
            .scalars()
            .all()
        )
        nodes = [GraphNode(task_key=t.task_key, depends_on=tuple(t.depends_on)) for t in task_rows]
        topological_order(nodes)  # real, final validation before real execution begins

    await publish_mission_event(
        str(mission_id), "mission.execution_started", mission_plan_id=str(mission_plan_id)
    )

    semaphore = asyncio.Semaphore(max_concurrency)
    completed: set[str] = set()
    failed: set[str] = set()
    running: dict[str, asyncio.Task[None]] = {}

    while len(completed) + len(failed) < len(nodes):
        eligible = [
            key
            for key in ready_tasks(nodes, completed)
            if key not in running
            and not any(
                dep in failed for dep in next(n for n in nodes if n.task_key == key).depends_on
            )
        ]
        for task_key in eligible:
            running[task_key] = asyncio.create_task(
                _run_task_with_semaphore(semaphore, mission_plan_id, task_key, completed, failed)
            )
        blocked_keys = [
            n.task_key
            for n in nodes
            if n.task_key not in completed
            and n.task_key not in failed
            and n.task_key not in running
            and any(dep in failed for dep in n.depends_on)
        ]
        for key in blocked_keys:
            failed.add(key)
            async with async_session_factory() as db:
                row = (
                    (
                        await db.execute(
                            select(EngineeringTask).where(
                                EngineeringTask.mission_plan_id == mission_plan_id,
                                EngineeringTask.task_key == key,
                            )
                        )
                    )
                    .scalars()
                    .first()
                )
                if row is not None:
                    row.status = "BLOCKED"
                    row.failure_reason = "A real dependency task failed."
                    await db.commit()

        if not running:
            break
        done, _pending = await asyncio.wait(running.values(), return_when=asyncio.FIRST_COMPLETED)
        for task_key in [k for k, t in running.items() if t in done]:
            del running[task_key]

    await _finalize_execution(mission_plan_id, tenant_id, mission_id, failed_any=bool(failed))


async def _run_task_with_semaphore(
    semaphore: asyncio.Semaphore,
    mission_plan_id: uuid.UUID,
    task_key: str,
    completed: set[str],
    failed: set[str],
) -> None:
    async with semaphore:
        success = await _run_single_task(mission_plan_id, task_key)
    (completed if success else failed).add(task_key)


async def _run_single_task(mission_plan_id: uuid.UUID, task_key: str) -> bool:
    async with async_session_factory() as db:
        task_row = (
            (
                await db.execute(
                    select(EngineeringTask).where(
                        EngineeringTask.mission_plan_id == mission_plan_id,
                        EngineeringTask.task_key == task_key,
                    )
                )
            )
            .scalars()
            .first()
        )
        if task_row is None:
            return False
        plan = await db.get(MissionPlan, mission_plan_id)
        if plan is None:
            return False
        repo = await get_repository(
            db, tenant_id=task_row.tenant_id, repository_id=task_row.repository_id
        )
        policy = await get_repository_policy(
            db, tenant_id=task_row.tenant_id, repository_id=task_row.repository_id
        )
        role = get_specialist_role(task_row.specialist_role)

        task_row.status = "RUNNING"
        task_row.started_at = datetime.now(UTC)
        tenant_id = task_row.tenant_id
        mission_id = plan.mission_id
        repository_working_directory = repo.working_directory
        branch_name = f"gds-task-{task_row.id}"
        task_row.branch_name = branch_name
        await db.commit()

    from gds_api.repository.workspace_manager import WORKSPACE_ROOT

    workspace_path = WORKSPACE_ROOT / str(tenant_id) / f"task-{task_row.id}" / "worktree"
    ensure_not_primary_repository_path(str(workspace_path), repository_working_directory)

    await publish_mission_event(
        str(mission_id), "task.assigned", task_key=task_key, specialist_role=role.key
    )
    await record_message(
        tenant_id=tenant_id,
        mission_plan_id=mission_plan_id,
        task_id=task_row.id,
        related_task_id=None,
        message_type="task_started",
        content=f"[{role.key}] starting: {task_row.title}",
    )

    try:
        await create_branch_worktree(
            repository_working_directory, str(workspace_path), branch_name, repo.default_branch
        )
    except WorktreeOperationError as exc:
        await _fail_task(mission_plan_id, task_key, f"Real workspace allocation failed: {exc}")
        return False

    # A real, tracked Workspace row (Phase 17's "every workspace is a managed object"
    # principle) - not just an ad-hoc worktree directory. Referenced by the task so the
    # Merge Coordinator can later find and clean it up through the same real mechanisms
    # every other workspace in this platform uses.
    task_workspace = Workspace(
        tenant_id=tenant_id,
        mission_id=mission_id,
        repository_id=task_row.repository_id,
        agent_id=role.key,
        provider=repo.provider,
        workspace_path=str(workspace_path),
        temporary_directory=str(workspace_path.parent),
        state="READY",
        expires_at=datetime.now(UTC) + timedelta(hours=2),
    )
    async with async_session_factory() as db:
        db.add(task_workspace)
        await db.flush()
        row = (
            (
                await db.execute(
                    select(EngineeringTask).where(
                        EngineeringTask.mission_plan_id == mission_plan_id,
                        EngineeringTask.task_key == task_key,
                    )
                )
            )
            .scalars()
            .first()
        )
        if row is not None:
            row.workspace_id = task_workspace.id
        await db.commit()

    compiled_with_path = compile_prompt(
        PromptInputs(
            objective=task_row.description,
            repository=RepositoryContext(
                display_name=repo.display_name,
                default_branch=repo.default_branch,
                current_branch=repo.current_branch,
            ),
            policy=PolicyContext(
                forbidden_paths=tuple(policy.forbidden_paths),
                allowed_paths=tuple(policy.allowed_paths),
                maximum_changed_files=policy.maximum_changed_files,
                maximum_changed_lines=policy.maximum_changed_lines,
            ),
            workspace_path=str(workspace_path),
            developer_instructions=role.prompt_specialization,
            extra_context={
                "Mission context": (
                    f"Overall objective: {plan.mission_memory.get('objective', '')}\n"
                    f"Execution strategy: {plan.mission_memory.get('execution_strategy', '')}\n"
                    "This is one task among several running in parallel on the same "
                    "mission - stay strictly within your own task's real scope."
                )
            },
        )
    )

    provider = get_provider(task_row.provider)
    session_id = uuid.uuid4()
    # Same real-usage-visibility gap and fix as engineering/orchestrator.py's single-
    # session path (EDP-008 Part 8): reuses gds_llm_calls_total/
    # gds_llm_call_duration_seconds rather than adding a second, parallel metric family.
    provider_start = time.perf_counter()
    try:
        handle = await provider.start(
            session_id=session_id,
            prompt=compiled_with_path.text,
            workspace_path=str(workspace_path),
        )
        async for event in provider.stream(handle):
            sse_type = _EVENT_TYPE_MAP.get(event.type, "task.thinking")
            await publish_mission_event(str(mission_id), sse_type, task_key=task_key, **event.data)
        result = await provider.result(handle)
        await provider.shutdown()
    except ProviderError as exc:
        llm_calls_total.labels(model=task_row.provider, outcome="error").inc()
        llm_call_duration_seconds.labels(model=task_row.provider).observe(
            time.perf_counter() - provider_start
        )
        await _fail_task(mission_plan_id, task_key, str(exc))
        return False
    llm_calls_total.labels(model=task_row.provider, outcome="success").inc()
    llm_call_duration_seconds.labels(model=task_row.provider).observe(
        time.perf_counter() - provider_start
    )

    if result.exit_code != 0:
        await _fail_task(
            mission_plan_id, task_key, f"Provider exited non-zero ({result.exit_code})."
        )
        return False

    patch = await extract_patch(
        str(workspace_path),
        maximum_changed_files=policy.maximum_changed_files,
        maximum_changed_lines=policy.maximum_changed_lines,
    )
    if patch.total_files == 0:
        await _fail_task(mission_plan_id, task_key, "The provider made no real file changes.")
        return False

    outcome = await run_review(workspace_path=str(workspace_path), patch=patch, policy=policy)

    def _commit_task_branch() -> None:
        run_git(["add", "-A"], cwd=str(workspace_path))
        run_git(["commit", "-m", f"task: {task_row.title}"], cwd=str(workspace_path))

    await asyncio.to_thread(_commit_task_branch)

    async with async_session_factory() as db:
        row = (
            (
                await db.execute(
                    select(EngineeringTask).where(
                        EngineeringTask.mission_plan_id == mission_plan_id,
                        EngineeringTask.task_key == task_key,
                    )
                )
            )
            .scalars()
            .first()
        )
        if row is None:
            return False
        row.patch_summary = patch.to_dict()
        row.review_result = outcome.result
        row.review_findings = outcome.to_dict()
        row.input_tokens = result.input_tokens
        row.output_tokens = result.output_tokens
        row.cost_usd = result.cost_usd
        if outcome.result == "FAIL":
            row.status = "FAILED"
            row.failure_reason = "Automated review FAILED - see review_findings."
            row.completed_at = datetime.now(UTC)
            await db.commit()
            await record_message(
                tenant_id=row.tenant_id,
                mission_plan_id=mission_plan_id,
                task_id=row.id,
                related_task_id=None,
                message_type="task_failed",
                content=f"[{role.key}] review FAILED: {task_row.title}",
            )
            await publish_mission_event(str(mission_id), "task.failed", task_key=task_key)
            return False

        row.status = "COMPLETED"
        row.completed_at = datetime.now(UTC)
        plan_row = await db.get(MissionPlan, mission_plan_id)
        if plan_row is not None:
            memory = dict(plan_row.mission_memory)
            existing_completed = memory.get("completed_tasks", [])
            completed_tasks = (
                list(existing_completed) if isinstance(existing_completed, list) else []
            )
            completed_tasks.append(
                {"task_key": task_key, "title": row.title, "review_result": outcome.result}
            )
            memory["completed_tasks"] = completed_tasks
            plan_row.mission_memory = memory
        await db.commit()

    await record_message(
        tenant_id=tenant_id,
        mission_plan_id=mission_plan_id,
        task_id=task_row.id,
        related_task_id=None,
        message_type="task_completed",
        content=(
            f"[{role.key}] completed: {task_row.title} "
            f"({patch.total_files} file(s) changed, review {outcome.result})"
        ),
    )
    await publish_mission_event(
        str(mission_id), "task.complete", task_key=task_key, review_result=outcome.result
    )
    return True


async def _fail_task(mission_plan_id: uuid.UUID, task_key: str, reason: str) -> None:
    async with async_session_factory() as db:
        row = (
            (
                await db.execute(
                    select(EngineeringTask).where(
                        EngineeringTask.mission_plan_id == mission_plan_id,
                        EngineeringTask.task_key == task_key,
                    )
                )
            )
            .scalars()
            .first()
        )
        if row is None:
            return
        row.status = "FAILED"
        row.failure_reason = reason[:2000]
        row.completed_at = datetime.now(UTC)
        plan = await db.get(MissionPlan, mission_plan_id)
        if plan is None:
            return
        mission_id = plan.mission_id
        tenant_id = plan.tenant_id
        task_id = row.id
        await db.commit()
    await record_message(
        tenant_id=tenant_id,
        mission_plan_id=mission_plan_id,
        task_id=task_id,
        related_task_id=None,
        message_type="task_failed",
        content=f"Failed: {reason[:500]}",
    )
    await publish_mission_event(str(mission_id), "task.failed", task_key=task_key, reason=reason)


async def _finalize_execution(
    mission_plan_id: uuid.UUID, tenant_id: uuid.UUID, mission_id: uuid.UUID, *, failed_any: bool
) -> None:
    from gds_api.engineering.merge_coordinator import run_merge

    async with async_session_factory() as db:
        plan = await db.get(MissionPlan, mission_plan_id)
        if plan is None:
            return
        if failed_any:
            any_completed = False
            rows = (
                (
                    await db.execute(
                        select(EngineeringTask).where(
                            EngineeringTask.mission_plan_id == mission_plan_id
                        )
                    )
                )
                .scalars()
                .all()
            )
            any_completed = any(r.status == "COMPLETED" for r in rows)
            if not any_completed:
                plan.status = "FAILED"
                plan.failure_reason = "Every real task failed - nothing to merge."
                plan.completed_at = datetime.now(UTC)
                mission = await db.get(Mission, mission_id)
                if mission is not None:
                    mission.status = "failed"
                await db.commit()
                await publish_mission_event(str(mission_id), "mission_finished", status="failed")
                return
        plan.status = "MERGING"
        await db.commit()

    await run_merge(mission_plan_id)
