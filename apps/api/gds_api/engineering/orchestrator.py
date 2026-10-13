"""Phase 18 (Continuation Prompt 5), Part 1: the Engineering Orchestrator - the one real
component allowed to coordinate AI engineering work, per the build prompt's own
architecture diagram. Ties together every other real module this phase adds: workspace
allocation (Phase 17, reused unchanged), prompt compilation, provider selection/
execution, patch extraction, automated review, and (on a separate, broker-gated
commit call) the Git Commit Engine.

Runs the actual provider session as a real asyncio background task inside the running
API process - not a Temporal workflow (see docs/adr/0020's own "Options considered" for
why: making a real, long-running, externally-streamed subprocess/API call replay-
deterministic inside a Temporal workflow was judged more complex than the real value it
would add this phase, given the EngineeringSession row itself is already the durable,
real, resumable state - the same "the database row is the truth, not the process"
discipline Phase 17's own Workspace state machine already established). A future phase
can migrate this to a real Temporal workflow without changing the public functions below.
"""

from __future__ import annotations

import asyncio
import time
import uuid
from datetime import UTC, datetime

from gds_api.audit import record_audit_event
from gds_api.db import async_session_factory
from gds_api.engineering import session_manager
from gds_api.engineering.commit_engine import CommitError, CommitMetadata, commit_workspace_changes
from gds_api.engineering.patch_extractor import extract_patch
from gds_api.engineering.prompt_compiler import (
    PolicyContext,
    PromptInputs,
    RepositoryContext,
    compile_prompt,
)
from gds_api.engineering.providers import ProviderError, ProviderHandle, get_provider
from gds_api.engineering.review_engine import run_review
from gds_api.events import publish_mission_event
from gds_api.logging_config import get_logger
from gds_api.metrics import llm_call_duration_seconds, llm_calls_total
from gds_api.models import Mission, RepositoryPolicy
from gds_api.repository.registry import get_repository, get_repository_policy
from gds_api.repository.workspace_manager import resolve_or_create_workspace

_logger = get_logger("gds_api.engineering.orchestrator")

_EVENT_TYPE_MAP = {
    "thinking": "engineering.thinking",
    "tool_use": "engineering.tool_execution",
    "assistant_text": "engineering.thinking",
    "file_change": "engineering.generated_files",
    "tool_result": "engineering.workspace_activity",
    "error": "engineering.failed",
    "result": "engineering.patch_progress",
}


class OrchestratorError(Exception):
    pass


async def start_session(
    *,
    tenant_id: uuid.UUID,
    mission_id: uuid.UUID,
    workflow_run_id: uuid.UUID | None,
    repository_id: uuid.UUID,
    provider: str,
    objective: str,
    requested_by_user_id: uuid.UUID,
    agent_id: str | None,
    capability_decision_id: uuid.UUID | None,
    developer_instructions: str | None = None,
) -> uuid.UUID:
    """Real, fast side effect (matching Phase 17's repository.read precedent) - resolves/
    opens a real Workspace, compiles the real prompt, persists a real EngineeringSession,
    and schedules the actual provider run as a background task. Returns immediately with
    the new session's real id; the caller does not block on the real engineering work."""
    async with async_session_factory() as db:
        repo = await get_repository(db, tenant_id=tenant_id, repository_id=repository_id)
        policy = await get_repository_policy(db, tenant_id=tenant_id, repository_id=repository_id)
        if not policy.readable:
            raise OrchestratorError(
                "This repository's policy disables reading - cannot start a session."
            )

        workspace = await resolve_or_create_workspace(
            db,
            tenant_id=tenant_id,
            mission_id=mission_id,
            workflow_run_id=workflow_run_id,
            capability_decision_id=capability_decision_id,
            repository_id=repository_id,
            agent_id=agent_id,
        )

        compiled = compile_prompt(
            PromptInputs(
                objective=objective,
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
                    required_tests=policy.required_tests,
                    review_requirement=policy.review_requirement,
                ),
                workspace_path=workspace.workspace_path,
                developer_instructions=developer_instructions,
                capability_decision_summary=(
                    f"Authorized by capability decision {capability_decision_id}."
                    if capability_decision_id
                    else None
                ),
            )
        )

        session = await session_manager.create_session(
            db,
            tenant_id=tenant_id,
            mission_id=mission_id,
            workflow_run_id=workflow_run_id,
            repository_id=repository_id,
            workspace_id=workspace.id,
            capability_decision_id=capability_decision_id,
            provider=provider,
            requested_by_user_id=requested_by_user_id,
            agent_id=agent_id,
            objective=objective,
            compiled_prompt=compiled.text,
            prompt_version=compiled.version,
        )

    asyncio.create_task(_run_session(session.id))
    return session.id


async def _run_session(session_id: uuid.UUID) -> None:
    from gds_api.models import EngineeringSession, Workspace

    async with async_session_factory() as db:
        session_row = await db.get(EngineeringSession, session_id)
        if session_row is None:
            return
        mission_id = session_row.mission_id
        provider_name = session_row.provider
        compiled_prompt = session_row.compiled_prompt
        repository_id = session_row.repository_id
        workspace_row = await db.get(Workspace, session_row.workspace_id)
        workspace_path = workspace_row.workspace_path if workspace_row else None
        policy = await db.get(RepositoryPolicy, repository_id)
        mission = await db.get(Mission, mission_id)
        if mission is not None:
            mission.status = "running"
            await db.commit()

    if workspace_path is None:
        async with async_session_factory() as db:
            await session_manager.mark_terminal(
                db,
                session_id=session_id,
                status="FAILED",
                failure_reason="Real workspace no longer exists.",
            )
        return

    await publish_mission_event(str(mission_id), "engineering.started", session_id=str(session_id))
    async with async_session_factory() as db:
        await session_manager.mark_running(db, session_id=session_id)

    provider = get_provider(provider_name)
    handle: ProviderHandle | None = None
    # EDP-008 Part 8 observability finding: real Claude Code/OpenAI engineering-session
    # calls went through this subprocess-based provider path entirely, invisible to
    # gds_llm_calls_total/gds_llm_call_duration_seconds (which only ever saw
    # model_router.complete()'s SDK-based calls) - reusing those same metrics here
    # rather than adding new ones keeps one unified "real LLM usage" dashboard panel
    # covering both call shapes.
    provider_start = time.perf_counter()
    try:
        handle = await provider.start(
            session_id=session_id, prompt=compiled_prompt, workspace_path=workspace_path
        )
        async for event in provider.stream(handle):
            sse_type = _EVENT_TYPE_MAP.get(event.type, "engineering.thinking")
            await publish_mission_event(
                str(mission_id), sse_type, session_id=str(session_id), **event.data
            )
        result = await provider.result(handle)
    except ProviderError as exc:
        llm_calls_total.labels(model=provider_name, outcome="error").inc()
        llm_call_duration_seconds.labels(model=provider_name).observe(
            time.perf_counter() - provider_start
        )
        await _fail_session(session_id, mission_id, str(exc))
        return
    finally:
        if handle is not None:
            try:
                await provider.shutdown()
            except Exception:  # noqa: BLE001 - best-effort cleanup
                pass
    llm_calls_total.labels(model=provider_name, outcome="success").inc()
    llm_call_duration_seconds.labels(model=provider_name).observe(
        time.perf_counter() - provider_start
    )

    async with async_session_factory() as db:
        session_row = await db.get(EngineeringSession, session_id)
        if session_row is None:
            return
        session_row.exit_code = result.exit_code
        session_row.stdout_log = result.stdout[:50_000] if result.stdout else None
        session_row.stderr_log = result.stderr[:50_000] if result.stderr else None
        session_row.reasoning_summary = result.reasoning_summary[:5_000]
        session_row.input_tokens = result.input_tokens
        session_row.output_tokens = result.output_tokens
        session_row.cost_usd = result.cost_usd
        session_row.provider_session_id = result.provider_session_id
        await db.commit()

    if result.exit_code != 0:
        await _fail_session(
            session_id, mission_id, f"Provider exited non-zero ({result.exit_code})."
        )
        return

    max_files = policy.maximum_changed_files if policy else 25
    max_lines = policy.maximum_changed_lines if policy else 1000
    patch = await extract_patch(
        workspace_path, maximum_changed_files=max_files, maximum_changed_lines=max_lines
    )
    await publish_mission_event(
        str(mission_id), "engineering.patch_progress", session_id=str(session_id), **patch.to_dict()
    )

    if patch.total_files == 0:
        await _fail_session(
            session_id, mission_id, "The provider session made no real file changes."
        )
        return

    review_policy = policy
    if review_policy is None:
        await _fail_session(session_id, mission_id, "No real repository policy found for review.")
        return
    outcome = await run_review(workspace_path=workspace_path, patch=patch, policy=review_policy)
    await publish_mission_event(
        str(mission_id),
        "engineering.review_progress",
        session_id=str(session_id),
        result=outcome.result,
        findings=outcome.to_dict(),
    )

    async with async_session_factory() as db:
        session_row = await db.get(EngineeringSession, session_id)
        if session_row is None:
            return
        session_row.patch_summary = patch.to_dict()
        session_row.review_result = outcome.result
        session_row.review_findings = outcome.to_dict()
        session_row.sensitive_area_hit = patch.sensitive_area_hit
        if outcome.result == "FAIL":
            session_row.status = "FAILED"
            session_row.failure_reason = "Automated review FAILED - see review_findings."
            session_row.completed_at = datetime.now(UTC)
        else:
            session_row.status = "AWAITING_APPROVAL"
        await db.commit()
        final_status = session_row.status

    async with async_session_factory() as db:
        mission = await db.get(Mission, mission_id)
        if mission is not None:
            if final_status == "FAILED":
                mission.status = "failed"
                await db.commit()
                await publish_mission_event(
                    str(mission_id), "engineering.failed", session_id=str(session_id)
                )
                await publish_mission_event(str(mission_id), "mission_finished", status="failed")
            else:
                mission.status = "awaiting_approval"
                await db.commit()
                await publish_mission_event(
                    str(mission_id), "engineering.approval_requested", session_id=str(session_id)
                )


async def _fail_session(session_id: uuid.UUID, mission_id: uuid.UUID, reason: str) -> None:
    async with async_session_factory() as db:
        await session_manager.mark_terminal(
            db, session_id=session_id, status="FAILED", failure_reason=reason
        )
        mission = await db.get(Mission, mission_id)
        if mission is not None:
            mission.status = "failed"
            await db.commit()
    await publish_mission_event(
        str(mission_id), "engineering.failed", session_id=str(session_id), reason=reason
    )
    await publish_mission_event(str(mission_id), "mission_finished", status="failed")


async def commit_session(
    *, tenant_id: uuid.UUID, session_id: uuid.UUID, actor_user_id: uuid.UUID, approved_by_email: str
) -> str:
    """Called only after a real Approval has been granted for the `engineering.commit`
    capability request (Part 10 - "enforced by the Secure Capability Broker. No
    bypasses"). Performs the real, workspace-scoped commit and marks the session/mission
    COMPLETED."""
    from gds_api.models import EngineeringSession, Workspace

    async with async_session_factory() as db:
        session_row = await session_manager.get_session(
            db, tenant_id=tenant_id, session_id=session_id
        )
        if session_row.status not in ("AWAITING_APPROVAL", "APPROVED"):
            raise OrchestratorError(
                f"EngineeringSession {session_id} is {session_row.status}, not ready to commit."
            )
        workspace_row = await db.get(Workspace, session_row.workspace_id)
        if workspace_row is None:
            raise OrchestratorError("Real workspace for this session no longer exists.")

        policy = await db.get(RepositoryPolicy, session_row.repository_id)
        if policy is None or not policy.commit_allowed:
            raise OrchestratorError(
                "This repository's policy disables commits (commit_allowed=False)."
            )

        session_row.status = "COMMITTING"
        await db.commit()

        metadata = CommitMetadata(
            agent=session_row.agent_id or "rabbani-direct",
            mission_id=session_row.mission_id,
            repository_id=session_row.repository_id,
            workspace_id=session_row.workspace_id,
            provider=session_row.provider,
            risk=str(session_row.patch_summary.get("risk_score", "unknown"))
            if isinstance(session_row.patch_summary, dict)
            else "unknown",
            review_result=session_row.review_result or "unknown",
            approved_by=approved_by_email,
            session_id=session_id,
        )
        try:
            commit_hash = await commit_workspace_changes(
                workspace_row.workspace_path, objective=session_row.objective, metadata=metadata
            )
        except CommitError as exc:
            session_row2 = await db.get(EngineeringSession, session_id)
            if session_row2 is not None:
                session_row2.status = "FAILED"
                session_row2.failure_reason = str(exc)[:2000]
                session_row2.completed_at = datetime.now(UTC)
                await db.commit()
            mission = await db.get(Mission, session_row.mission_id)
            if mission is not None:
                mission.status = "failed"
                await db.commit()
            await publish_mission_event(
                str(session_row.mission_id),
                "engineering.failed",
                session_id=str(session_id),
                reason=str(exc),
            )
            await publish_mission_event(
                str(session_row.mission_id), "mission_finished", status="failed"
            )
            raise OrchestratorError(str(exc)) from exc

        session_row3 = await db.get(EngineeringSession, session_id)
        if session_row3 is not None:
            session_row3.commit_hash = commit_hash
            session_row3.status = "COMPLETED"
            session_row3.completed_at = datetime.now(UTC)
            await db.commit()

        await record_audit_event(
            db,
            tenant_id=tenant_id,
            user_id=actor_user_id,
            action="engineering.session_committed",
            detail={
                "session_id": str(session_id),
                "repository_id": str(session_row.repository_id),
                "workspace_id": str(session_row.workspace_id),
                "commit_hash": commit_hash,
                "approved_by": approved_by_email,
                "provider": session_row.provider,
            },
        )
        await db.commit()

        mission = await db.get(Mission, session_row.mission_id)
        if mission is not None:
            mission.status = "completed"
            mission.completed_at = datetime.now(UTC)
            await db.commit()

    await publish_mission_event(
        str(session_row.mission_id),
        "engineering.commit_created",
        session_id=str(session_id),
        commit_hash=commit_hash,
    )
    await publish_mission_event(
        str(session_row.mission_id), "engineering.completed", session_id=str(session_id)
    )
    await publish_mission_event(str(session_row.mission_id), "mission_finished", status="completed")
    return commit_hash
