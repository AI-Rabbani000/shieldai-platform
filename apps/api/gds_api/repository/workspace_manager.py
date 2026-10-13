"""Phase 17 (Continuation Prompt 4), Part 5/11/12: the Workspace Manager - the real
lifecycle (create/open/heartbeat/expire/destroy/recover/orphan-detect/cleanup) for a
Workspace, the one durable record tying a Mission/WorkflowRun/CapabilityDecision to a
real, isolated `git worktree` (gds_api.repository.worktree_manager) over exactly one
Repository. Every guard from Part 7 (gds_api.repository.lock_manager) is enforced here,
not duplicated at each call site.
"""

from __future__ import annotations

import tempfile
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from gds_api.audit import record_audit_event
from gds_api.events import publish_mission_event
from gds_api.models import Repository, RepositoryPolicy, Workspace, WorkspacePolicy
from gds_api.repository.lock_manager import (
    acquire_repository_row_lock,
    ensure_no_duplicate_active_workspace,
    ensure_not_primary_repository_path,
    ensure_same_tenant,
    ensure_workspace_destroyable,
)
from gds_api.repository.worktree_manager import (
    WorktreeOperationError,
    create_worktree,
    destroy_worktree,
    list_worktrees,
    lock_worktree,
    unlock_worktree,
    verify_worktree,
)

# All real workspace directories live under one real, well-known root - never scattered
# across the OS temp directory unlabeled, so an operator can always find (and, if this
# system ever crashes mid-operation, manually inspect or remove) every real workspace
# this platform has ever allocated.
WORKSPACE_ROOT = Path(tempfile.gettempdir()) / "gds_workspaces"

_ACTIVE_STATES = ("ALLOCATED", "READY", "ACTIVE", "LOCKED")
_REUSABLE_STATES = ("READY", "ACTIVE")


class WorkspaceNotFound(Exception):
    pass


class WorkspaceCreationDenied(Exception):
    pass


class WorkspaceDestructionDenied(Exception):
    pass


@dataclass
class CleanupReport:
    expired_destroyed: list[uuid.UUID] = field(default_factory=list)
    orphans_removed: list[str] = field(default_factory=list)
    marked_failed: list[uuid.UUID] = field(default_factory=list)


async def create_workspace(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    mission_id: uuid.UUID,
    workflow_run_id: uuid.UUID | None,
    capability_decision_id: uuid.UUID | None,
    repository_id: uuid.UUID,
    agent_id: str | None,
) -> Workspace:
    """Real allocation + a real `git worktree add --detach`. Fails closed on: a
    repository that isn't AVAILABLE, a policy that disables worktree_creation, or the
    tenant's real concurrent-workspace limit for this repository already being met."""
    repo = await acquire_repository_row_lock(db, tenant_id=tenant_id, repository_id=repository_id)
    if repo.status != "AVAILABLE":
        raise WorkspaceCreationDenied(
            f"Repository is {repo.status}, not AVAILABLE - cannot create a workspace."
        )

    policy = await db.get(RepositoryPolicy, repository_id)
    if policy is None or not policy.worktree_creation:
        raise WorkspaceCreationDenied("This repository's policy disables worktree creation.")

    ws_policy = await db.get(WorkspacePolicy, repository_id)
    if ws_policy is None:
        raise WorkspaceCreationDenied("This repository has no real workspace policy row.")

    active_count = (
        await db.execute(
            select(Workspace).where(
                Workspace.repository_id == repository_id,
                Workspace.state.in_(_ACTIVE_STATES),
            )
        )
    ).scalars()
    if len(list(active_count)) >= ws_policy.maximum_concurrent_workspaces:
        raise WorkspaceCreationDenied(
            f"This repository already has {ws_policy.maximum_concurrent_workspaces} "
            "concurrent real workspaces - the real limit for this repository."
        )

    workspace_id = uuid.uuid4()
    temporary_directory = WORKSPACE_ROOT / str(tenant_id) / str(workspace_id)
    workspace_path = temporary_directory / "worktree"
    ensure_not_primary_repository_path(str(workspace_path), repo.working_directory)
    await ensure_no_duplicate_active_workspace(
        db, tenant_id=tenant_id, repository_id=repository_id, workspace_path=str(workspace_path)
    )

    now = datetime.now(UTC)
    workspace = Workspace(
        id=workspace_id,
        tenant_id=tenant_id,
        mission_id=mission_id,
        workflow_run_id=workflow_run_id,
        capability_decision_id=capability_decision_id,
        repository_id=repository_id,
        agent_id=agent_id,
        provider=repo.provider,
        workspace_path=str(workspace_path),
        temporary_directory=str(temporary_directory),
        state="ALLOCATED",
        expires_at=now + timedelta(seconds=ws_policy.default_ttl_seconds),
    )
    db.add(workspace)
    await db.flush()
    await publish_mission_event(
        str(mission_id),
        "workspace.created",
        workspace_id=str(workspace_id),
        repository_id=str(repository_id),
    )

    ref = repo.current_branch or repo.default_branch
    try:
        await create_worktree(repo.working_directory, str(workspace_path), ref)
    except WorktreeOperationError as exc:
        workspace.state = "FAILED"
        workspace.failure_reason = str(exc)[:2000]
        await record_audit_event(
            db,
            tenant_id=tenant_id,
            user_id=repo.owner_user_id,
            action="workspace.create_failed",
            detail={"workspace_id": str(workspace_id), "reason": str(exc)[:500]},
        )
        await db.commit()
        raise

    workspace.state = "READY"
    await record_audit_event(
        db,
        tenant_id=tenant_id,
        user_id=repo.owner_user_id,
        action="workspace.created",
        detail={
            "workspace_id": str(workspace_id),
            "repository_id": str(repository_id),
            "mission_id": str(mission_id),
            "ref": ref,
        },
    )
    await db.commit()
    await db.refresh(workspace)
    await publish_mission_event(
        str(mission_id),
        "workspace.ready",
        workspace_id=str(workspace_id),
        repository_id=str(repository_id),
    )
    await publish_mission_event(
        str(mission_id),
        "repository.opened",
        workspace_id=str(workspace_id),
        repository_id=str(repository_id),
    )
    return workspace


async def resolve_or_create_workspace(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    mission_id: uuid.UUID,
    workflow_run_id: uuid.UUID | None,
    capability_decision_id: uuid.UUID | None,
    repository_id: uuid.UUID,
    agent_id: str | None,
) -> Workspace:
    """The real entry point every repository capability's tool executor calls: reuse a
    real, still-valid workspace already open for this (tenant, mission, repository) if
    one exists, otherwise create one. This is what makes `repository.read` "open the
    repository" and the other 9 capabilities "operate on the already-open one" - Part 9's
    "every repository capability must require... Workspace"."""
    now = datetime.now(UTC)
    existing = (
        (
            await db.execute(
                select(Workspace)
                .where(
                    Workspace.tenant_id == tenant_id,
                    Workspace.mission_id == mission_id,
                    Workspace.repository_id == repository_id,
                    Workspace.state.in_(_REUSABLE_STATES),
                    Workspace.expires_at > now,
                )
                .order_by(Workspace.created_at.desc())
            )
        )
        .scalars()
        .first()
    )
    if existing is not None:
        return existing
    return await create_workspace(
        db,
        tenant_id=tenant_id,
        mission_id=mission_id,
        workflow_run_id=workflow_run_id,
        capability_decision_id=capability_decision_id,
        repository_id=repository_id,
        agent_id=agent_id,
    )


async def get_workspace(
    db: AsyncSession, *, tenant_id: uuid.UUID, workspace_id: uuid.UUID
) -> Workspace:
    workspace = await db.get(Workspace, workspace_id)
    if workspace is None:
        raise WorkspaceNotFound(f"Workspace {workspace_id} not found")
    ensure_same_tenant(workspace, tenant_id)
    return workspace


async def heartbeat_workspace(
    db: AsyncSession, *, tenant_id: uuid.UUID, workspace_id: uuid.UUID
) -> Workspace:
    """Real keep-alive: extends `expires_at` by the repository's real
    `default_ttl_seconds`, capped at `created_at + maximum_ttl_seconds` - a workspace
    can be kept alive by real, ongoing use, but never indefinitely."""
    workspace = await get_workspace(db, tenant_id=tenant_id, workspace_id=workspace_id)
    if workspace.state not in _REUSABLE_STATES:
        raise WorkspaceNotFound(
            f"Workspace {workspace_id} is {workspace.state}, not heartbeat-able"
        )
    ws_policy = await db.get(WorkspacePolicy, workspace.repository_id)
    now = datetime.now(UTC)
    workspace.last_heartbeat_at = now
    if ws_policy is not None and ws_policy.allow_heartbeat_extension:
        max_expiry = workspace.created_at + timedelta(seconds=ws_policy.maximum_ttl_seconds)
        proposed_expiry = now + timedelta(seconds=ws_policy.default_ttl_seconds)
        workspace.expires_at = min(proposed_expiry, max_expiry)
    await db.commit()
    await db.refresh(workspace)
    return workspace


async def lock_workspace(
    db: AsyncSession, *, tenant_id: uuid.UUID, workspace_id: uuid.UUID, reason: str
) -> Workspace:
    """Real `git worktree lock` - an explicit, real hold that also prevents this
    workspace's own real destroy (gds_api.repository.lock_manager.
    ensure_workspace_destroyable) until unlocked. Distinct from ACTIVE (a transient,
    in-progress-operation state) - LOCKED is a deliberate, human/operator-initiated
    hold."""
    workspace = await get_workspace(db, tenant_id=tenant_id, workspace_id=workspace_id)
    if workspace.state not in _REUSABLE_STATES:
        raise WorkspaceNotFound(f"Workspace {workspace_id} is {workspace.state}, not lockable")
    repo = await db.get(Repository, workspace.repository_id)
    if repo is None:
        raise WorkspaceNotFound(f"Repository for workspace {workspace_id} no longer exists")
    await lock_worktree(repo.working_directory, workspace.workspace_path, reason)
    workspace.state = "LOCKED"
    await record_audit_event(
        db,
        tenant_id=tenant_id,
        user_id=repo.owner_user_id,
        action="workspace.locked",
        detail={"workspace_id": str(workspace_id), "reason": reason},
    )
    await db.commit()
    await db.refresh(workspace)
    await publish_mission_event(
        str(workspace.mission_id),
        "workspace.locked",
        workspace_id=str(workspace_id),
        repository_id=str(workspace.repository_id),
    )
    return workspace


async def unlock_workspace(
    db: AsyncSession, *, tenant_id: uuid.UUID, workspace_id: uuid.UUID
) -> Workspace:
    workspace = await get_workspace(db, tenant_id=tenant_id, workspace_id=workspace_id)
    if workspace.state != "LOCKED":
        raise WorkspaceNotFound(f"Workspace {workspace_id} is {workspace.state}, not locked")
    repo = await db.get(Repository, workspace.repository_id)
    if repo is None:
        raise WorkspaceNotFound(f"Repository for workspace {workspace_id} no longer exists")
    await unlock_worktree(repo.working_directory, workspace.workspace_path)
    workspace.state = "READY"
    await db.commit()
    await db.refresh(workspace)
    return workspace


async def destroy_workspace(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    workspace_id: uuid.UUID,
    actor_user_id: uuid.UUID,
    force: bool = False,
) -> Workspace:
    workspace = await get_workspace(db, tenant_id=tenant_id, workspace_id=workspace_id)
    if workspace.state == "DESTROYED":
        return workspace
    ensure_workspace_destroyable(workspace, force=force)

    repo = await db.get(Repository, workspace.repository_id)
    if repo is not None and not force:
        policy = await db.get(RepositoryPolicy, workspace.repository_id)
        if policy is not None and not policy.delete_worktree_allowed:
            raise WorkspaceDestructionDenied(
                "This repository's policy disables worktree deletion "
                "(delete_worktree_allowed=False)."
            )
    if repo is not None:
        ensure_not_primary_repository_path(workspace.workspace_path, repo.working_directory)
        try:
            await destroy_worktree(
                repo.working_directory,
                workspace.workspace_path,
                workspace.temporary_directory,
                force=force,
            )
        except WorktreeOperationError as exc:
            workspace.state = "FAILED"
            workspace.failure_reason = f"destroy failed: {exc}"[:2000]
            await db.commit()
            raise

    workspace.state = "DESTROYED"
    workspace.destroyed_at = datetime.now(UTC)
    await record_audit_event(
        db,
        tenant_id=tenant_id,
        user_id=actor_user_id,
        action="workspace.destroyed",
        detail={"workspace_id": str(workspace_id), "forced": force},
    )
    await db.commit()
    await db.refresh(workspace)
    await publish_mission_event(
        str(workspace.mission_id),
        "workspace.destroyed",
        workspace_id=str(workspace_id),
        repository_id=str(workspace.repository_id),
    )
    await publish_mission_event(
        str(workspace.mission_id),
        "repository.closed",
        workspace_id=str(workspace_id),
        repository_id=str(workspace.repository_id),
    )
    return workspace


async def expire_due_workspaces(db: AsyncSession) -> list[Workspace]:
    """Part 11: real expiry - transitions any READY/ACTIVE workspace whose real
    `expires_at` has passed into EXPIRED. Does not destroy the worktree itself (that is
    `cleanup_workspaces`'s job, per Part 12's separate "destroy expired" step) - keeps
    the two real, separately-auditable actions distinct."""
    now = datetime.now(UTC)
    result = await db.execute(
        select(Workspace).where(
            Workspace.state.in_(_REUSABLE_STATES),
            Workspace.expires_at <= now,
        )
    )
    expired: list[Workspace] = list(result.scalars().all())
    for workspace in expired:
        workspace.state = "EXPIRED"
        await publish_mission_event(
            str(workspace.mission_id),
            "workspace.expired",
            workspace_id=str(workspace.id),
            repository_id=str(workspace.repository_id),
        )
    if expired:
        await db.commit()
    return expired


async def recover_workspace(
    db: AsyncSession, *, tenant_id: uuid.UUID, workspace_id: uuid.UUID
) -> Workspace:
    """Part 11: re-verifies a real workspace against real git state - a workspace stuck
    in ACTIVE/LOCKED (e.g. the process that held it crashed) is restored to READY if its
    worktree is still real and valid, or marked FAILED (never silently "fixed") if not."""
    workspace = await get_workspace(db, tenant_id=tenant_id, workspace_id=workspace_id)
    repo = await db.get(Repository, workspace.repository_id)
    if repo is None:
        workspace.state = "FAILED"
        workspace.failure_reason = "owning repository no longer exists"
        await db.commit()
        return workspace

    is_valid = await verify_worktree(repo.working_directory, workspace.workspace_path)
    if is_valid:
        if workspace.state in ("ACTIVE", "LOCKED", "ALLOCATED"):
            workspace.state = "READY"
    else:
        workspace.state = "FAILED"
        workspace.failure_reason = "real git worktree no longer exists or is prunable"
    await db.commit()
    await db.refresh(workspace)
    return workspace


async def cleanup_workspaces(
    db: AsyncSession, *, tenant_id: uuid.UUID | None = None
) -> CleanupReport:
    """Part 12: destroys EXPIRED workspaces (per each repository's real
    auto_cleanup_on_expire policy), detects and removes real orphaned git-level
    worktrees with no matching live Workspace row, and marks any DB row whose real
    worktree has silently disappeared as FAILED. Every destructive action here is real
    and audited - nothing here is a dry run."""
    report = CleanupReport()

    expired_query = select(Workspace).where(Workspace.state == "EXPIRED")
    if tenant_id is not None:
        expired_query = expired_query.where(Workspace.tenant_id == tenant_id)
    expired = (await db.execute(expired_query)).scalars().all()
    for workspace in expired:
        repo = await db.get(Repository, workspace.repository_id)
        ws_policy = await db.get(WorkspacePolicy, workspace.repository_id) if repo else None
        if repo is None or ws_policy is None or not ws_policy.auto_cleanup_on_expire:
            continue
        try:
            await destroy_worktree(
                repo.working_directory,
                workspace.workspace_path,
                workspace.temporary_directory,
                force=True,
            )
        except WorktreeOperationError:
            pass
        workspace.state = "DESTROYED"
        workspace.destroyed_at = datetime.now(UTC)
        report.expired_destroyed.append(workspace.id)
        await record_audit_event(
            db,
            tenant_id=workspace.tenant_id,
            user_id=repo.owner_user_id,
            action="workspace.cleanup_destroyed",
            detail={"workspace_id": str(workspace.id), "reason": "expired"},
        )

    # Orphan detection: a real git-level worktree with no matching non-terminal
    # Workspace row for any repository this tenant (or, unscoped, every tenant) owns.
    repo_query = select(Repository).where(Repository.status == "AVAILABLE")
    if tenant_id is not None:
        repo_query = repo_query.where(Repository.tenant_id == tenant_id)
    repos = (await db.execute(repo_query)).scalars().all()
    for repo in repos:
        try:
            git_worktrees = await list_worktrees(repo.working_directory)
        except WorktreeOperationError:
            continue
        known_paths = {
            str(Path(w.workspace_path).resolve())
            for w in (
                await db.execute(
                    select(Workspace).where(
                        Workspace.repository_id == repo.id,
                        Workspace.state.in_(_ACTIVE_STATES),
                    )
                )
            )
            .scalars()
            .all()
        }
        primary_path = str(Path(repo.working_directory).resolve())
        for wt in git_worktrees:
            wt_path = str(Path(wt.path).resolve())
            if wt_path == primary_path:
                continue
            if wt_path not in known_paths and str(WORKSPACE_ROOT) in wt_path:
                try:
                    await destroy_worktree(repo.working_directory, wt.path, wt.path, force=True)
                    report.orphans_removed.append(wt.path)
                    await record_audit_event(
                        db,
                        tenant_id=repo.tenant_id,
                        user_id=repo.owner_user_id,
                        action="workspace.cleanup_orphan_removed",
                        detail={"path": wt.path, "repository_id": str(repo.id)},
                    )
                except WorktreeOperationError:
                    pass

        # The reverse check: a real, non-terminal DB row whose worktree git no longer
        # recognizes at all - a genuinely broken/abandoned session.
        git_paths = {str(Path(w.path).resolve()) for w in git_worktrees}
        broken_query = select(Workspace).where(
            Workspace.repository_id == repo.id, Workspace.state.in_(_ACTIVE_STATES)
        )
        broken_rows = (await db.execute(broken_query)).scalars().all()
        for workspace in broken_rows:
            if str(Path(workspace.workspace_path).resolve()) not in git_paths:
                workspace.state = "FAILED"
                workspace.failure_reason = "orphan cleanup: git no longer recognizes this worktree"
                report.marked_failed.append(workspace.id)

    await db.commit()
    return report
