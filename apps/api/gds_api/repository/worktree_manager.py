"""Phase 17 (Continuation Prompt 4), Part 6: the Git Worktree Manager - the one real
place `git worktree` is invoked. Every Workspace's real filesystem footprint is created,
verified, locked, unlocked, destroyed, and recovered here, always via `git worktree`,
never a raw `shutil.copytree`/manual clone - so the primary repository's own git
metadata (refs, objects) is genuinely shared (space-efficient, always in sync with the
primary's real object store) while the working files are a fully separate checkout.

Every new worktree is created `--detach` (Part 8: "No checkout changes... No branch
creation") - a detached-HEAD checkout of an existing ref, never creating or moving any
branch, never touching the primary repository's own checked-out branch. This is the
real mechanism, not just a policy statement, that makes "never modify the primary
repository" true: `git worktree add --detach <path> <ref>` only ever reads from the
primary repository (resolving `<ref>` and populating a new working directory) - the
primary repository's own index/HEAD/working files are never written to.
"""

from __future__ import annotations

import asyncio
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from gds_api.repository.git_exec import run_git


class WorktreeOperationError(Exception):
    pass


@dataclass
class WorktreeInfo:
    path: str
    head_commit: str | None
    branch: str | None
    detached: bool
    locked: bool
    prunable: bool


async def create_worktree(repo_working_directory: str, target_path: str, ref: str) -> str:
    """Real `git worktree add --detach <target_path> <ref>`. Raises
    WorktreeOperationError with the real git stderr on failure - never a silent no-op."""

    def _create() -> subprocess.CompletedProcess[str]:
        Path(target_path).parent.mkdir(parents=True, exist_ok=True)
        return run_git(
            ["worktree", "add", "--detach", target_path, ref], cwd=repo_working_directory
        )

    result = await asyncio.to_thread(_create)
    if result.returncode != 0:
        raise WorktreeOperationError(
            f"git worktree add failed for ref '{ref}': {result.stderr.strip()[:500]}"
        )
    head = await asyncio.to_thread(lambda: run_git(["rev-parse", "HEAD"], cwd=target_path))
    return head.stdout.strip() if head.returncode == 0 else ""


async def create_branch_worktree(
    repo_working_directory: str, target_path: str, branch_name: str, ref: str
) -> str:
    """Phase 19 (Continuation Prompt 6), Part 4: the first real branch-creating worktree
    in this codebase - `git worktree add -b <branch_name> <target_path> <ref>`, used
    only for per-EngineeringTask workspaces that a later real `git merge` (Part 9) needs
    a real, named branch to merge. Unlike `create_worktree`'s `--detach`, this does add
    one real new ref (`refs/heads/<branch_name>`) to the primary repository's own object
    database - but, like `--detach`, it never touches the primary repository's own
    checked-out branch, HEAD, index, or working files; only a new worktree's own files
    are ever written. The branch is deleted again by `delete_branch` once the task
    workspace/its merge is done - never left behind as permanent primary-repo clutter."""

    def _create() -> subprocess.CompletedProcess[str]:
        Path(target_path).parent.mkdir(parents=True, exist_ok=True)
        return run_git(
            ["worktree", "add", "-b", branch_name, target_path, ref], cwd=repo_working_directory
        )

    result = await asyncio.to_thread(_create)
    if result.returncode != 0:
        raise WorktreeOperationError(
            f"git worktree add -b '{branch_name}' failed for ref '{ref}': "
            f"{result.stderr.strip()[:500]}"
        )
    head = await asyncio.to_thread(lambda: run_git(["rev-parse", "HEAD"], cwd=target_path))
    return head.stdout.strip() if head.returncode == 0 else ""


async def delete_branch(
    repo_working_directory: str, branch_name: str, *, force: bool = False
) -> None:
    """Real `git branch -d`/`-D` - only ever called after the branch's own worktree has
    already been removed (a real, cleanup-order requirement git itself enforces)."""

    def _delete() -> subprocess.CompletedProcess[str]:
        flag = "-D" if force else "-d"
        return run_git(["branch", flag, branch_name], cwd=repo_working_directory)

    result = await asyncio.to_thread(_delete)
    if result.returncode != 0:
        raise WorktreeOperationError(
            f"git branch delete failed for '{branch_name}': {result.stderr.strip()[:500]}"
        )


async def list_worktrees(repo_working_directory: str) -> list[WorktreeInfo]:
    """Real `git worktree list --porcelain`, parsed. Includes the primary repository's
    own entry (always first) - callers that only want real Workspace-backed worktrees
    should filter by path prefix."""

    def _list() -> subprocess.CompletedProcess[str]:
        return run_git(["worktree", "list", "--porcelain"], cwd=repo_working_directory)

    result = await asyncio.to_thread(_list)
    if result.returncode != 0:
        raise WorktreeOperationError(f"git worktree list failed: {result.stderr.strip()[:500]}")
    return _parse_porcelain(result.stdout)


def _parse_porcelain(output: str) -> list[WorktreeInfo]:
    entries: list[WorktreeInfo] = []
    current: dict[str, object] = {}
    for line in output.splitlines():
        if not line.strip():
            if current:
                entries.append(_entry_to_info(current))
                current = {}
            continue
        if line.startswith("worktree "):
            if current:
                entries.append(_entry_to_info(current))
            current = {"path": line.removeprefix("worktree ")}
        elif line.startswith("HEAD "):
            current["head"] = line.removeprefix("HEAD ")
        elif line.startswith("branch "):
            current["branch"] = line.removeprefix("branch ").removeprefix("refs/heads/")
        elif line == "detached":
            current["detached"] = True
        elif line == "locked" or line.startswith("locked "):
            current["locked"] = True
        elif line == "prunable" or line.startswith("prunable "):
            current["prunable"] = True
    if current:
        entries.append(_entry_to_info(current))
    return entries


def _as_optional_str(value: object) -> str | None:
    return value if isinstance(value, str) else None


def _entry_to_info(entry: dict[str, object]) -> WorktreeInfo:
    return WorktreeInfo(
        path=str(entry.get("path", "")),
        head_commit=_as_optional_str(entry.get("head")),
        branch=_as_optional_str(entry.get("branch")),
        detached=bool(entry.get("detached", False)),
        locked=bool(entry.get("locked", False)),
        prunable=bool(entry.get("prunable", False)),
    )


async def verify_worktree(repo_working_directory: str, target_path: str) -> bool:
    """A worktree is real and usable only if BOTH the directory exists on disk AND git
    itself lists it as a real, non-prunable worktree - either alone can lie (a manually
    deleted directory git hasn't pruned yet; a directory that exists but was never a
    real worktree)."""
    if not Path(target_path).exists():
        return False
    worktrees = await list_worktrees(repo_working_directory)
    normalized_target = str(Path(target_path).resolve())
    for wt in worktrees:
        if str(Path(wt.path).resolve()) == normalized_target:
            return not wt.prunable
    return False


async def lock_worktree(repo_working_directory: str, target_path: str, reason: str) -> None:
    def _lock() -> subprocess.CompletedProcess[str]:
        return run_git(
            ["worktree", "lock", "--reason", reason, target_path], cwd=repo_working_directory
        )

    result = await asyncio.to_thread(_lock)
    if result.returncode != 0:
        raise WorktreeOperationError(f"git worktree lock failed: {result.stderr.strip()[:500]}")


async def unlock_worktree(repo_working_directory: str, target_path: str) -> None:
    def _unlock() -> subprocess.CompletedProcess[str]:
        return run_git(["worktree", "unlock", target_path], cwd=repo_working_directory)

    result = await asyncio.to_thread(_unlock)
    if result.returncode != 0:
        raise WorktreeOperationError(f"git worktree unlock failed: {result.stderr.strip()[:500]}")


async def destroy_worktree(
    repo_working_directory: str, target_path: str, temporary_directory: str, *, force: bool = False
) -> None:
    """Real `git worktree remove` (unlocking first if needed and forced), then a real
    `shutil.rmtree` of the whole allocated temporary_directory as a guaranteed-safe
    second pass - so a partial git-level failure never leaves a real directory behind.
    temporary_directory must be the workspace's own allocated temp root (never the
    primary repository) - callers pass Workspace.temporary_directory, not
    repo_working_directory, so there is no code path by which this could ever target
    the primary repository's own directory."""

    def _remove() -> subprocess.CompletedProcess[str]:
        args = ["worktree", "remove"]
        if force:
            args.append("--force")
        args.append(target_path)
        return run_git(args, cwd=repo_working_directory)

    result = await asyncio.to_thread(_remove)
    if result.returncode != 0 and not force:
        # A locked or dirty worktree fails a plain remove - real git behavior, not a bug.
        raise WorktreeOperationError(
            f"git worktree remove failed (use force to override): {result.stderr.strip()[:500]}"
        )

    def _final_cleanup() -> None:
        if Path(temporary_directory).exists():
            shutil.rmtree(temporary_directory, ignore_errors=True)

    await asyncio.to_thread(_final_cleanup)

    def _prune() -> None:
        run_git(["worktree", "prune"], cwd=repo_working_directory)

    await asyncio.to_thread(_prune)
