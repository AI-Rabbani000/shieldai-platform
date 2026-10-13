"""Phase 17 (Continuation Prompt 4), Part 10: the Repository Diff Engine - read-only,
real `git diff`/`git diff --numstat` against an already-open Workspace's worktree.
Supports commit-vs-commit, commit-vs-branch, branch-vs-branch (all just "two real
refs" to `git diff`), workspace-vs-base (ref_b omitted - diffs against the workspace's
own currently checked-out commit, `HEAD`), and an optional path to scope the diff to one
file or directory. No patch application - this module only ever reads, never writes.
"""

from __future__ import annotations

import asyncio
import subprocess
from dataclasses import dataclass

from gds_api.repository.git_exec import run_git

_MAX_PATCH_CHARS = 200_000


class DiffOperationError(Exception):
    pass


@dataclass
class DiffStats:
    files_changed: int
    insertions: int
    deletions: int


@dataclass
class DiffResult:
    ref_a: str
    ref_b: str
    path: str | None
    stats: DiffStats
    patch: str
    truncated: bool


def _parse_numstat(output: str) -> DiffStats:
    files_changed = 0
    insertions = 0
    deletions = 0
    for line in output.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        if len(parts) < 3:
            continue
        files_changed += 1
        added, removed = parts[0], parts[1]
        if added.isdigit():
            insertions += int(added)
        if removed.isdigit():
            deletions += int(removed)
    return DiffStats(files_changed=files_changed, insertions=insertions, deletions=deletions)


async def diff_between_refs(
    workspace_path: str, ref_a: str, ref_b: str | None = None, path: str | None = None
) -> DiffResult:
    resolved_ref_b = ref_b or "HEAD"

    def _diff() -> tuple[subprocess.CompletedProcess[str], subprocess.CompletedProcess[str]]:
        numstat_args = ["diff", "--numstat", ref_a, resolved_ref_b]
        patch_args = ["diff", ref_a, resolved_ref_b]
        if path:
            numstat_args += ["--", path]
            patch_args += ["--", path]
        numstat_result = run_git(numstat_args, cwd=workspace_path)
        patch_result = run_git(patch_args, cwd=workspace_path)
        return numstat_result, patch_result

    numstat_result, patch_result = await asyncio.to_thread(_diff)
    if numstat_result.returncode != 0:
        raise DiffOperationError(
            f"git diff failed between '{ref_a}' and '{resolved_ref_b}': "
            f"{numstat_result.stderr.strip()[:500]}"
        )

    stats = _parse_numstat(numstat_result.stdout)
    patch = patch_result.stdout
    truncated = len(patch) > _MAX_PATCH_CHARS
    if truncated:
        patch = patch[:_MAX_PATCH_CHARS]
    return DiffResult(
        ref_a=ref_a, ref_b=resolved_ref_b, path=path, stats=stats, patch=patch, truncated=truncated
    )
