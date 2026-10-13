"""Phase 17 (Continuation Prompt 4), Part 14: the real HTTP surface over the
Repository Registry, Repository/Workspace Policy, and the Workspace lifecycle.

Two distinct kinds of endpoint here, matching the IMPORTANT banner at the top of this
phase's own build prompt ("Nothing in this phase may execute repository operations
without Capability Broker approval"):

1. **Registry/lifecycle management** (register a repository, edit its policy, list/
   heartbeat/lock/destroy a Workspace) - plain RBAC-protected REST, no capability
   evaluation. These are administrative actions over the *catalogue* of repositories
   and workspaces, the same distinction Phase 16 already draws between
   `GET/PATCH /admin/capabilities*` (registry management) and `POST /capability-requests`
   (governed execution).
2. **`POST /repositories/{id}/execute/{capability}`** - the one real endpoint that
   touches actual repository *content* (branches, files, history, diffs, worktree
   listing). Every one of the 10 real repository capabilities goes through this single
   endpoint, which transparently opens (or reuses) a real "browsing" Mission and calls
   the exact same `evaluate_capability_request` -> `execute_capability_request` pipeline
   every other real capability in this platform uses - never a shortcut around the
   broker, even for a read-only browse click in the UI.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from gds_api.capabilities.broker import evaluate_capability_request
from gds_api.capabilities.gateway import CapabilityExecutionDenied, execute_capability_request
from gds_api.db import get_db
from gds_api.models import Mission, Repository, RepositoryPolicy, Workspace, WorkspacePolicy
from gds_api.repository import lock_manager, workspace_manager
from gds_api.repository.registry import (
    RepositoryNotFound,
    archive_repository,
    get_repository,
    get_repository_policy,
    get_workspace_policy,
    list_repositories,
    refresh_repository_status,
    register_repository,
    update_repository_policy,
    update_workspace_policy,
)
from gds_api.repository.workspace_manager import WorkspaceNotFound
from gds_api.schemas import (
    RepositoryCreateRequest,
    RepositoryExecuteCapabilityRequest,
    RepositoryExecuteCapabilityResponse,
    RepositoryOut,
    RepositoryPolicyOut,
    RepositoryPolicyPatchRequest,
    WorkspaceCleanupReportOut,
    WorkspaceOut,
    WorkspacePolicyOut,
    WorkspacePolicyPatchRequest,
)
from gds_api.security import CurrentUser, require_permission

router = APIRouter(tags=["repositories"])

# capability suffix ("read", "search", ...) -> (capability_key, tool_name)
_REPOSITORY_CAPABILITY_TOOLS: dict[str, tuple[str, str]] = {
    "read": ("repository.read", "read_repository"),
    "search": ("repository.search", "search_repository"),
    "list_files": ("repository.list_files", "list_repository_files"),
    "read_file": ("repository.read_file", "read_repository_file"),
    "list_branches": ("repository.list_branches", "list_repository_branches"),
    "list_tags": ("repository.list_tags", "list_repository_tags"),
    "repository_metadata": ("repository.repository_metadata", "get_repository_metadata"),
    "history": ("repository.history", "get_repository_history"),
    "diff_between_refs": ("repository.diff_between_refs", "diff_repository_refs"),
    "list_worktrees": ("repository.list_worktrees", "list_repository_worktrees"),
}


def _repo_to_out(repo: Repository) -> RepositoryOut:
    return RepositoryOut(
        id=repo.id,
        tenant_id=repo.tenant_id,
        display_name=repo.display_name,
        owner_user_id=repo.owner_user_id,
        provider=repo.provider,
        visibility=repo.visibility,
        default_branch=repo.default_branch,
        current_branch=repo.current_branch,
        remote_url=repo.remote_url,
        credential_reference=repo.credential_reference,
        working_directory=repo.working_directory,
        status=repo.status,
        status_detail=repo.status_detail,
        created_at=repo.created_at,
        updated_at=repo.updated_at,
    )


def _policy_to_out(policy: RepositoryPolicy) -> RepositoryPolicyOut:
    return RepositoryPolicyOut(
        repository_id=policy.repository_id,
        readable=policy.readable,
        searchable=policy.searchable,
        branch_creation=policy.branch_creation,
        worktree_creation=policy.worktree_creation,
        patch_creation=policy.patch_creation,
        commit_allowed=policy.commit_allowed,
        push_allowed=policy.push_allowed,
        pull_request_allowed=policy.pull_request_allowed,
        delete_worktree_allowed=policy.delete_worktree_allowed,
        allowed_agents=policy.allowed_agents,
        allowed_capabilities=policy.allowed_capabilities,
        allowed_branches=policy.allowed_branches,
        protected_branches=policy.protected_branches,
        forbidden_paths=policy.forbidden_paths,
        allowed_paths=policy.allowed_paths,
        maximum_changed_files=policy.maximum_changed_files,
        maximum_changed_lines=policy.maximum_changed_lines,
        required_tests=policy.required_tests,
        review_requirement=policy.review_requirement,
        approval_requirement=policy.approval_requirement,
        rollback_requirement=policy.rollback_requirement,
        updated_at=policy.updated_at,
    )


def _workspace_policy_to_out(policy: WorkspacePolicy) -> WorkspacePolicyOut:
    return WorkspacePolicyOut(
        repository_id=policy.repository_id,
        default_ttl_seconds=policy.default_ttl_seconds,
        maximum_ttl_seconds=policy.maximum_ttl_seconds,
        maximum_concurrent_workspaces=policy.maximum_concurrent_workspaces,
        allow_heartbeat_extension=policy.allow_heartbeat_extension,
        auto_cleanup_on_expire=policy.auto_cleanup_on_expire,
        updated_at=policy.updated_at,
    )


def _workspace_to_out(workspace: Workspace) -> WorkspaceOut:
    return WorkspaceOut(
        id=workspace.id,
        tenant_id=workspace.tenant_id,
        mission_id=workspace.mission_id,
        workflow_run_id=workspace.workflow_run_id,
        capability_decision_id=workspace.capability_decision_id,
        repository_id=workspace.repository_id,
        agent_id=workspace.agent_id,
        provider=workspace.provider,
        workspace_path=workspace.workspace_path,
        temporary_directory=workspace.temporary_directory,
        state=workspace.state,
        failure_reason=workspace.failure_reason,
        created_at=workspace.created_at,
        last_heartbeat_at=workspace.last_heartbeat_at,
        expires_at=workspace.expires_at,
        destroyed_at=workspace.destroyed_at,
    )


# ---- Repository registry -----------------------------------------------------------


@router.post("/repositories", response_model=RepositoryOut)
async def create_repository(
    body: RepositoryCreateRequest,
    current_user: CurrentUser = Depends(require_permission("repositories:manage")),
    db: AsyncSession = Depends(get_db),
) -> RepositoryOut:
    repo = await register_repository(
        db,
        tenant_id=current_user.tenant_id,
        owner_user_id=current_user.user_id,
        display_name=body.display_name,
        provider=body.provider,
        working_directory=body.working_directory,
        visibility=body.visibility,
        remote_url=body.remote_url,
        credential_reference=body.credential_reference,
    )
    return _repo_to_out(repo)


@router.get("/repositories", response_model=list[RepositoryOut])
async def list_repositories_endpoint(
    status_filter: str | None = None,
    current_user: CurrentUser = Depends(require_permission("repositories:read")),
    db: AsyncSession = Depends(get_db),
) -> list[RepositoryOut]:
    repos = await list_repositories(
        db, tenant_id=current_user.tenant_id, status_filter=status_filter
    )
    return [_repo_to_out(r) for r in repos]


@router.get("/repositories/{repository_id}", response_model=RepositoryOut)
async def get_repository_endpoint(
    repository_id: uuid.UUID,
    current_user: CurrentUser = Depends(require_permission("repositories:read")),
    db: AsyncSession = Depends(get_db),
) -> RepositoryOut:
    try:
        repo = await get_repository(
            db, tenant_id=current_user.tenant_id, repository_id=repository_id
        )
    except RepositoryNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Repository not found") from exc
    return _repo_to_out(repo)


@router.post("/repositories/{repository_id}/refresh", response_model=RepositoryOut)
async def refresh_repository_endpoint(
    repository_id: uuid.UUID,
    current_user: CurrentUser = Depends(require_permission("repositories:manage")),
    db: AsyncSession = Depends(get_db),
) -> RepositoryOut:
    try:
        repo = await get_repository(
            db, tenant_id=current_user.tenant_id, repository_id=repository_id
        )
    except RepositoryNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Repository not found") from exc
    await refresh_repository_status(db, repo)
    await db.commit()
    await db.refresh(repo)
    return _repo_to_out(repo)


@router.post("/repositories/{repository_id}/archive", response_model=RepositoryOut)
async def archive_repository_endpoint(
    repository_id: uuid.UUID,
    current_user: CurrentUser = Depends(require_permission("repositories:manage")),
    db: AsyncSession = Depends(get_db),
) -> RepositoryOut:
    try:
        repo = await archive_repository(
            db,
            tenant_id=current_user.tenant_id,
            repository_id=repository_id,
            actor_user_id=current_user.user_id,
        )
    except RepositoryNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Repository not found") from exc
    return _repo_to_out(repo)


@router.get("/repositories/{repository_id}/policy", response_model=RepositoryPolicyOut)
async def get_repository_policy_endpoint(
    repository_id: uuid.UUID,
    current_user: CurrentUser = Depends(require_permission("repositories:read")),
    db: AsyncSession = Depends(get_db),
) -> RepositoryPolicyOut:
    try:
        policy = await get_repository_policy(
            db, tenant_id=current_user.tenant_id, repository_id=repository_id
        )
    except RepositoryNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Repository not found") from exc
    return _policy_to_out(policy)


@router.patch("/repositories/{repository_id}/policy", response_model=RepositoryPolicyOut)
async def patch_repository_policy_endpoint(
    repository_id: uuid.UUID,
    body: RepositoryPolicyPatchRequest,
    current_user: CurrentUser = Depends(require_permission("repositories:manage")),
    db: AsyncSession = Depends(get_db),
) -> RepositoryPolicyOut:
    try:
        policy = await update_repository_policy(
            db,
            tenant_id=current_user.tenant_id,
            repository_id=repository_id,
            actor_user_id=current_user.user_id,
            updates=body.model_dump(exclude_unset=True),
        )
    except RepositoryNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Repository not found") from exc
    return _policy_to_out(policy)


@router.get("/repositories/{repository_id}/workspace-policy", response_model=WorkspacePolicyOut)
async def get_workspace_policy_endpoint(
    repository_id: uuid.UUID,
    current_user: CurrentUser = Depends(require_permission("repositories:read")),
    db: AsyncSession = Depends(get_db),
) -> WorkspacePolicyOut:
    try:
        policy = await get_workspace_policy(
            db, tenant_id=current_user.tenant_id, repository_id=repository_id
        )
    except RepositoryNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Repository not found") from exc
    return _workspace_policy_to_out(policy)


@router.patch("/repositories/{repository_id}/workspace-policy", response_model=WorkspacePolicyOut)
async def patch_workspace_policy_endpoint(
    repository_id: uuid.UUID,
    body: WorkspacePolicyPatchRequest,
    current_user: CurrentUser = Depends(require_permission("repositories:manage")),
    db: AsyncSession = Depends(get_db),
) -> WorkspacePolicyOut:
    try:
        policy = await update_workspace_policy(
            db,
            tenant_id=current_user.tenant_id,
            repository_id=repository_id,
            actor_user_id=current_user.user_id,
            updates=body.model_dump(exclude_unset=True),
        )
    except RepositoryNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Repository not found") from exc
    return _workspace_policy_to_out(policy)


@router.get("/repositories/{repository_id}/workspaces", response_model=list[WorkspaceOut])
async def list_repository_workspaces_endpoint(
    repository_id: uuid.UUID,
    current_user: CurrentUser = Depends(require_permission("workspaces:read")),
    db: AsyncSession = Depends(get_db),
) -> list[WorkspaceOut]:
    rows = (
        (
            await db.execute(
                select(Workspace)
                .where(
                    Workspace.repository_id == repository_id,
                    Workspace.tenant_id == current_user.tenant_id,
                )
                .order_by(Workspace.created_at.desc())
            )
        )
        .scalars()
        .all()
    )
    return [_workspace_to_out(w) for w in rows]


# ---- The one real, broker-gated content endpoint -----------------------------------


async def _get_or_create_browse_mission(
    db: AsyncSession, *, tenant_id: uuid.UUID, user_id: uuid.UUID, repository_id: uuid.UUID
) -> Mission:
    marker = f"[repository-browse:{repository_id}]"
    existing = (
        (
            await db.execute(
                select(Mission).where(
                    Mission.tenant_id == tenant_id,
                    Mission.requested_by_user_id == user_id,
                    Mission.status == "running",
                    Mission.objective.like(f"%{marker}"),
                )
            )
        )
        .scalars()
        .first()
    )
    if existing is not None:
        return existing
    mission = Mission(
        tenant_id=tenant_id,
        requested_by_user_id=user_id,
        objective=f"Repository browsing session {marker}",
        status="running",
    )
    db.add(mission)
    await db.commit()
    await db.refresh(mission)
    return mission


@router.post(
    "/repositories/{repository_id}/execute/{capability_suffix}",
    response_model=RepositoryExecuteCapabilityResponse,
)
async def execute_repository_capability(
    repository_id: uuid.UUID,
    capability_suffix: str,
    body: RepositoryExecuteCapabilityRequest,
    current_user: CurrentUser = Depends(require_permission("capabilities:request")),
    db: AsyncSession = Depends(get_db),
) -> RepositoryExecuteCapabilityResponse:
    tool_entry = _REPOSITORY_CAPABILITY_TOOLS.get(capability_suffix)
    if tool_entry is None:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND, f"Unknown repository capability '{capability_suffix}'"
        )
    capability_key, tool_name = tool_entry

    try:
        await get_repository(db, tenant_id=current_user.tenant_id, repository_id=repository_id)
    except RepositoryNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Repository not found") from exc

    mission = await _get_or_create_browse_mission(
        db,
        tenant_id=current_user.tenant_id,
        user_id=current_user.user_id,
        repository_id=repository_id,
    )
    input_data = {**body.parameters, "repository_id": str(repository_id)}

    eval_result = await evaluate_capability_request(
        db,
        tenant_id=current_user.tenant_id,
        user_id=current_user.user_id,
        mission_id=mission.id,
        requesting_agent_id=None,
        supervising_agent_id=None,
        capability_key=capability_key,
        requested_tool_id=tool_name,
        target_type=None,
        target_reference=None,
        target_scope=None,
        purpose=body.purpose,
        requested_parameters=input_data,
    )
    if eval_result.decision != "ALLOW":
        return RepositoryExecuteCapabilityResponse(
            decision=eval_result.decision,
            capability_key=capability_key,
            request_id=eval_result.request_id,
            output=None,
            safe_message=eval_result.safe_message,
        )

    try:
        output = await execute_capability_request(
            db,
            tenant_id=current_user.tenant_id,
            request_id=eval_result.request_id,
            tool_name=tool_name,
            input_data=input_data,
            user_id=current_user.user_id,
            mission_id=mission.id,
        )
    except CapabilityExecutionDenied as denied:
        return RepositoryExecuteCapabilityResponse(
            decision=denied.decision,
            capability_key=capability_key,
            request_id=eval_result.request_id,
            output=None,
            safe_message=denied.safe_message,
        )
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc

    return RepositoryExecuteCapabilityResponse(
        decision="ALLOW",
        capability_key=capability_key,
        request_id=eval_result.request_id,
        output=output,
        safe_message=None,
    )


# ---- Workspace lifecycle -------------------------------------------------------


@router.get("/workspaces", response_model=list[WorkspaceOut])
async def list_workspaces_endpoint(
    state_filter: str | None = None,
    current_user: CurrentUser = Depends(require_permission("workspaces:read")),
    db: AsyncSession = Depends(get_db),
) -> list[WorkspaceOut]:
    query = select(Workspace).where(Workspace.tenant_id == current_user.tenant_id)
    if state_filter:
        query = query.where(Workspace.state == state_filter)
    rows = (await db.execute(query.order_by(Workspace.created_at.desc()))).scalars().all()
    return [_workspace_to_out(w) for w in rows]


@router.get("/workspaces/{workspace_id}", response_model=WorkspaceOut)
async def get_workspace_endpoint(
    workspace_id: uuid.UUID,
    current_user: CurrentUser = Depends(require_permission("workspaces:read")),
    db: AsyncSession = Depends(get_db),
) -> WorkspaceOut:
    try:
        workspace = await workspace_manager.get_workspace(
            db, tenant_id=current_user.tenant_id, workspace_id=workspace_id
        )
    except (WorkspaceNotFound, lock_manager.CrossTenantAccessError) as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Workspace not found") from exc
    return _workspace_to_out(workspace)


@router.post("/workspaces/{workspace_id}/heartbeat", response_model=WorkspaceOut)
async def heartbeat_workspace_endpoint(
    workspace_id: uuid.UUID,
    current_user: CurrentUser = Depends(require_permission("workspaces:manage")),
    db: AsyncSession = Depends(get_db),
) -> WorkspaceOut:
    try:
        workspace = await workspace_manager.heartbeat_workspace(
            db, tenant_id=current_user.tenant_id, workspace_id=workspace_id
        )
    except WorkspaceNotFound as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    return _workspace_to_out(workspace)


@router.post("/workspaces/{workspace_id}/lock", response_model=WorkspaceOut)
async def lock_workspace_endpoint(
    workspace_id: uuid.UUID,
    reason: str = "Locked via API",
    current_user: CurrentUser = Depends(require_permission("workspaces:manage")),
    db: AsyncSession = Depends(get_db),
) -> WorkspaceOut:
    try:
        workspace = await workspace_manager.lock_workspace(
            db, tenant_id=current_user.tenant_id, workspace_id=workspace_id, reason=reason
        )
    except WorkspaceNotFound as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    return _workspace_to_out(workspace)


@router.post("/workspaces/{workspace_id}/unlock", response_model=WorkspaceOut)
async def unlock_workspace_endpoint(
    workspace_id: uuid.UUID,
    current_user: CurrentUser = Depends(require_permission("workspaces:manage")),
    db: AsyncSession = Depends(get_db),
) -> WorkspaceOut:
    try:
        workspace = await workspace_manager.unlock_workspace(
            db, tenant_id=current_user.tenant_id, workspace_id=workspace_id
        )
    except WorkspaceNotFound as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    return _workspace_to_out(workspace)


@router.post("/workspaces/{workspace_id}/destroy", response_model=WorkspaceOut)
async def destroy_workspace_endpoint(
    workspace_id: uuid.UUID,
    force: bool = False,
    current_user: CurrentUser = Depends(require_permission("workspaces:manage")),
    db: AsyncSession = Depends(get_db),
) -> WorkspaceOut:
    try:
        workspace = await workspace_manager.destroy_workspace(
            db,
            tenant_id=current_user.tenant_id,
            workspace_id=workspace_id,
            actor_user_id=current_user.user_id,
            force=force,
        )
    except (WorkspaceNotFound, workspace_manager.WorkspaceDestructionDenied) as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    except lock_manager.WorkspaceLockedError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    return _workspace_to_out(workspace)


@router.post("/workspaces/cleanup", response_model=WorkspaceCleanupReportOut)
async def cleanup_workspaces_endpoint(
    current_user: CurrentUser = Depends(require_permission("workspaces:manage")),
    db: AsyncSession = Depends(get_db),
) -> dict[str, object]:
    await workspace_manager.expire_due_workspaces(db)
    report = await workspace_manager.cleanup_workspaces(db, tenant_id=current_user.tenant_id)
    return {
        "expired_destroyed": [str(x) for x in report.expired_destroyed],
        "orphans_removed": report.orphans_removed,
        "marked_failed": [str(x) for x in report.marked_failed],
    }
