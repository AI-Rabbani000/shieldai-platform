"""Phase 18 (Continuation Prompt 5), Part 11: the Git Commit Engine - the first real
`git add`/`git commit` in this codebase, deliberately added to Phase 17's own single
shared `git_exec.run_git` call surface (docs/reviews/phase-18-engineering-execution-audit.md)
rather than a second, parallel git-invocation path. Always runs inside an already-open
Workspace's worktree - never the primary repository - and never pushes; a real push is
explicitly out of scope for this phase (Part 11: "No push operations. Repository merges
belong to the next engineering phase.")."""

from __future__ import annotations

import asyncio
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

from gds_api.repository.git_exec import run_git


class CommitError(Exception):
    pass


@dataclass
class CommitMetadata:
    agent: str
    mission_id: uuid.UUID
    repository_id: uuid.UUID
    workspace_id: uuid.UUID
    provider: str
    risk: str
    review_result: str
    approved_by: str
    session_id: uuid.UUID


def _format_commit_message(objective: str, metadata: CommitMetadata) -> str:
    summary = (
        objective.strip().splitlines()[0][:72]
        if objective.strip()
        else "Engineering session commit"
    )
    return (
        f"{summary}\n\n"
        f"Agent: {metadata.agent}\n"
        f"Mission: {metadata.mission_id}\n"
        f"Repository: {metadata.repository_id}\n"
        f"Workspace: {metadata.workspace_id}\n"
        f"Provider: {metadata.provider}\n"
        f"Risk: {metadata.risk}\n"
        f"Review: {metadata.review_result}\n"
        f"Approved By: {metadata.approved_by}\n"
        f"Timestamp: {datetime.now(UTC).isoformat()}\n"
        f"Session: {metadata.session_id}\n"
    )


async def commit_workspace_changes(
    workspace_path: str, *, objective: str, metadata: CommitMetadata
) -> str:
    """Real `git add -A` + `git commit` inside the workspace's own worktree. Returns the
    real, new commit hash. Raises CommitError (never a silent no-op) if there is nothing
    to commit or if git itself fails."""

    def _status() -> str:
        return run_git(["status", "--porcelain=v1"], cwd=workspace_path).stdout

    status = await asyncio.to_thread(_status)
    if not status.strip():
        raise CommitError(
            "No real uncommitted changes exist in this workspace - nothing to commit."
        )

    def _add() -> None:
        result = run_git(["add", "-A"], cwd=workspace_path)
        if result.returncode != 0:
            raise CommitError(f"git add failed: {result.stderr.strip()[:500]}")

    await asyncio.to_thread(_add)

    message = _format_commit_message(objective, metadata)

    def _commit() -> str:
        result = run_git(["commit", "-m", message], cwd=workspace_path)
        if result.returncode != 0:
            raise CommitError(f"git commit failed: {result.stderr.strip()[:500]}")
        head = run_git(["rev-parse", "HEAD"], cwd=workspace_path)
        if head.returncode != 0:
            raise CommitError(
                f"git rev-parse HEAD failed after commit: {head.stderr.strip()[:500]}"
            )
        return head.stdout.strip()

    return await asyncio.to_thread(_commit)
