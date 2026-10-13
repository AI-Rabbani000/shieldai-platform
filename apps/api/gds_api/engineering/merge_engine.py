"""Phase 19 (Continuation Prompt 6), Part 9: the Merge Coordinator's real git mechanism
- the first real `git merge` in this codebase, added to the same shared `git_exec.
run_git` surface Phase 17/18 already established for every other real git operation.
Merges each real task branch into one real, dedicated integration Workspace/branch, in
real dependency order - never a custom patch-application layer. A real merge conflict
(`git merge` exits non-zero with real `CONFLICT` markers) is the authoritative signal;
Part 8's structural conflict detection (file/function/class overlap) runs first as a
real, cheap early warning, not a replacement for git's own real conflict resolution.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

from gds_api.repository.git_exec import run_git


class MergeError(Exception):
    pass


@dataclass
class MergeOutcome:
    branch_name: str
    success: bool
    conflict_files: list[str] = field(default_factory=list)
    real_stderr: str = ""


async def create_integration_branch(
    repo_working_directory: str, integration_path: str, branch_name: str, base_ref: str
) -> None:
    """A real, dedicated integration worktree/branch, distinct from every task's own -
    the Merge Coordinator never merges directly into a task's own workspace."""
    from gds_api.repository.worktree_manager import create_branch_worktree

    await create_branch_worktree(repo_working_directory, integration_path, branch_name, base_ref)


async def merge_task_branch(integration_path: str, task_branch: str) -> MergeOutcome:
    """Real `git merge --no-ff <task_branch>` inside the integration worktree. On a
    real conflict, aborts the merge (leaves the integration branch clean for the next
    real attempt or for human escalation) and returns the real list of conflicted files
    - never leaves a real repository in a half-merged state."""

    def _merge() -> tuple[int, str, str]:
        result = run_git(["merge", "--no-ff", "--no-edit", task_branch], cwd=integration_path)
        return result.returncode, result.stdout, result.stderr

    returncode, stdout, stderr = await asyncio.to_thread(_merge)
    if returncode == 0:
        return MergeOutcome(branch_name=task_branch, success=True)

    def _conflicted_files() -> list[str]:
        result = run_git(["diff", "--name-only", "--diff-filter=U"], cwd=integration_path)
        return [line for line in result.stdout.splitlines() if line]

    conflict_files = await asyncio.to_thread(_conflicted_files)

    def _abort() -> None:
        run_git(["merge", "--abort"], cwd=integration_path)

    await asyncio.to_thread(_abort)

    return MergeOutcome(
        branch_name=task_branch,
        success=False,
        conflict_files=conflict_files,
        real_stderr=stderr[:1000],
    )


async def current_head_commit(worktree_path: str) -> str:
    """Real `git rev-parse HEAD` - used by `commit_mission` to identify the integration
    branch's own already-real, already-merged HEAD commit when there is nothing left
    uncommitted to add (the normal case: every real task/merge commit already exists by
    the time a human approves)."""

    def _rev_parse() -> tuple[int, str, str]:
        result = run_git(["rev-parse", "HEAD"], cwd=worktree_path)
        return result.returncode, result.stdout, result.stderr

    returncode, stdout, stderr = await asyncio.to_thread(_rev_parse)
    if returncode != 0:
        raise MergeError(f"git rev-parse HEAD failed: {stderr.strip()[:500]}")
    return stdout.strip()
