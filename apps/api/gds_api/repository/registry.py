"""Phase 17 (Continuation Prompt 4), Part 2: the Repository Registry - real
registration, lookup, and status-refresh for a Repository as a managed object.
Registering a repository never clones or mutates anything - it records real facts about
an already-existing local path and creates the two real, default-valued policy rows
every Repository must have (RepositoryPolicy, WorkspacePolicy - Part 2/4)."""

from __future__ import annotations

import asyncio
import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from gds_api.audit import record_audit_event
from gds_api.models import Repository, RepositoryPolicy, WorkspacePolicy
from gds_api.repository.providers import (
    OPERATIONAL_PROVIDERS,
    RepositoryProviderType,
    get_provider,
)


class RepositoryNotFound(Exception):
    pass


async def register_repository(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    owner_user_id: uuid.UUID,
    display_name: str,
    provider: str,
    working_directory: str,
    visibility: str = "private",
    remote_url: str | None = None,
    credential_reference: str | None = None,
) -> Repository:
    provider_type = RepositoryProviderType(provider)
    repo = Repository(
        tenant_id=tenant_id,
        display_name=display_name,
        owner_user_id=owner_user_id,
        provider=provider_type.value,
        visibility=visibility,
        working_directory=working_directory,
        remote_url=remote_url,
        credential_reference=credential_reference,
        status="REGISTERED",
    )
    db.add(repo)
    await db.flush()
    db.add(RepositoryPolicy(repository_id=repo.id))
    db.add(WorkspacePolicy(repository_id=repo.id))
    await db.flush()

    await refresh_repository_status(db, repo)

    await record_audit_event(
        db,
        tenant_id=tenant_id,
        user_id=owner_user_id,
        action="repository.registered",
        detail={
            "repository_id": str(repo.id),
            "display_name": display_name,
            "provider": provider_type.value,
            "status": repo.status,
        },
    )
    await db.commit()
    await db.refresh(repo)
    return repo


async def refresh_repository_status(db: AsyncSession, repo: Repository) -> Repository:
    """Real, on-demand verification - never a continuously-mirrored live status. Called
    at registration and whenever a caller explicitly asks (`POST /repositories/{id}/refresh`)
    or a workspace is about to be created against this repository."""
    provider_type = RepositoryProviderType(repo.provider)
    if provider_type not in OPERATIONAL_PROVIDERS:
        repo.status = "UNAVAILABLE"
        repo.status_detail = (
            f"Provider '{provider_type.value}' is Planned, not operational this phase."
        )
        return repo

    provider_impl = get_provider(provider_type)
    facts = await asyncio.to_thread(provider_impl.verify, repo.working_directory)
    if not facts.exists or not facts.is_git_repository:
        repo.status = "BROKEN"
    else:
        repo.status = "AVAILABLE"
        repo.current_branch = facts.current_branch
        if facts.default_branch:
            repo.default_branch = facts.default_branch
        if facts.remote_url:
            repo.remote_url = facts.remote_url
    repo.status_detail = facts.detail
    return repo


async def get_repository(
    db: AsyncSession, *, tenant_id: uuid.UUID, repository_id: uuid.UUID
) -> Repository:
    repo = await db.get(Repository, repository_id)
    if repo is None or repo.tenant_id != tenant_id:
        raise RepositoryNotFound(f"Repository {repository_id} not found for this tenant")
    return repo


async def list_repositories(
    db: AsyncSession, *, tenant_id: uuid.UUID, status_filter: str | None = None
) -> list[Repository]:
    query = select(Repository).where(Repository.tenant_id == tenant_id)
    if status_filter:
        query = query.where(Repository.status == status_filter)
    result = await db.execute(query.order_by(Repository.display_name))
    return list(result.scalars().all())


async def get_repository_policy(
    db: AsyncSession, *, tenant_id: uuid.UUID, repository_id: uuid.UUID
) -> RepositoryPolicy:
    await get_repository(db, tenant_id=tenant_id, repository_id=repository_id)
    policy = await db.get(RepositoryPolicy, repository_id)
    if policy is None:
        raise RepositoryNotFound(f"Repository {repository_id} has no policy row")
    return policy


async def get_workspace_policy(
    db: AsyncSession, *, tenant_id: uuid.UUID, repository_id: uuid.UUID
) -> WorkspacePolicy:
    await get_repository(db, tenant_id=tenant_id, repository_id=repository_id)
    policy = await db.get(WorkspacePolicy, repository_id)
    if policy is None:
        raise RepositoryNotFound(f"Repository {repository_id} has no workspace policy row")
    return policy


async def archive_repository(
    db: AsyncSession, *, tenant_id: uuid.UUID, repository_id: uuid.UUID, actor_user_id: uuid.UUID
) -> Repository:
    repo = await get_repository(db, tenant_id=tenant_id, repository_id=repository_id)
    repo.status = "ARCHIVED"
    repo.status_detail = "Archived by an administrator."
    await record_audit_event(
        db,
        tenant_id=tenant_id,
        user_id=actor_user_id,
        action="repository.archived",
        detail={"repository_id": str(repository_id)},
    )
    await db.commit()
    await db.refresh(repo)
    return repo


async def update_repository_policy(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    repository_id: uuid.UUID,
    actor_user_id: uuid.UUID,
    updates: dict[str, object],
) -> RepositoryPolicy:
    policy = await get_repository_policy(db, tenant_id=tenant_id, repository_id=repository_id)
    for key, value in updates.items():
        if value is not None and hasattr(policy, key):
            setattr(policy, key, value)
    await record_audit_event(
        db,
        tenant_id=tenant_id,
        user_id=actor_user_id,
        action="repository.policy_updated",
        detail={"repository_id": str(repository_id), "updates": updates},
    )
    await db.commit()
    await db.refresh(policy)
    return policy


async def update_workspace_policy(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    repository_id: uuid.UUID,
    actor_user_id: uuid.UUID,
    updates: dict[str, object],
) -> WorkspacePolicy:
    policy = await get_workspace_policy(db, tenant_id=tenant_id, repository_id=repository_id)
    for key, value in updates.items():
        if value is not None and hasattr(policy, key):
            setattr(policy, key, value)
    await record_audit_event(
        db,
        tenant_id=tenant_id,
        user_id=actor_user_id,
        action="repository.workspace_policy_updated",
        detail={"repository_id": str(repository_id), "updates": updates},
    )
    await db.commit()
    await db.refresh(policy)
    return policy
