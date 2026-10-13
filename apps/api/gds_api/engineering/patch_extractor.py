"""Phase 18 (Continuation Prompt 5), Part 8: the Patch Extraction Engine - real,
structured file-change tracking from a workspace's real, uncommitted working-tree state
(`git status --porcelain` + `git diff --numstat`), reusing Phase 17's one shared
`git_exec.run_git` subprocess wrapper rather than inventing a second git-invocation path.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

from gds_api.repository.git_exec import run_git

# A conservative, real risk-affecting heuristic - directories/paths that, if touched,
# should be surfaced prominently to a human reviewer even though (per ADR 0024) every
# real commit requires approval regardless. Not exhaustive; a real, named starting set
# mirroring the build prompt's own Part 10 example list.
_SENSITIVE_PATH_PATTERNS: tuple[str, ...] = (
    "auth",
    "security",
    "rbac",
    "capabilities/broker.py",
    "capabilities/gateway.py",
    "migrations/",
    "alembic/",
    "billing",
    "licens",
    "encrypt",
    "secret",
    "docker-compose",
    "infra/",
    "terraform/",
    "system_prompt",
    "seed_data.py",
    ".env",
)


@dataclass
class PatchFile:
    path: str
    change_type: str  # created|modified|deleted|renamed
    old_path: str | None = None
    insertions: int = 0
    deletions: int = 0
    is_binary: bool = False


@dataclass
class PatchSummary:
    files: list[PatchFile] = field(default_factory=list)
    total_files: int = 0
    total_insertions: int = 0
    total_deletions: int = 0
    affected_directories: list[str] = field(default_factory=list)
    sensitive_area_hit: bool = False
    risk_score: str = "low"  # low|medium|high

    def to_dict(self) -> dict[str, object]:
        return {
            "files": [
                {
                    "path": f.path,
                    "change_type": f.change_type,
                    "old_path": f.old_path,
                    "insertions": f.insertions,
                    "deletions": f.deletions,
                    "is_binary": f.is_binary,
                }
                for f in self.files
            ],
            "total_files": self.total_files,
            "total_insertions": self.total_insertions,
            "total_deletions": self.total_deletions,
            "affected_directories": self.affected_directories,
            "sensitive_area_hit": self.sensitive_area_hit,
            "risk_score": self.risk_score,
        }


def _is_sensitive(path: str) -> bool:
    lowered = path.lower()
    return any(pattern in lowered for pattern in _SENSITIVE_PATH_PATTERNS)


async def extract_patch(
    workspace_path: str, *, maximum_changed_files: int = 25, maximum_changed_lines: int = 1000
) -> PatchSummary:
    """Real, uncommitted working-tree changes only - this runs BEFORE any real `git add`/
    `git commit` (Part 11), so it reflects exactly what a provider session actually did,
    nothing staged or historical."""

    def _status() -> str:
        # --untracked-files=all is real and required, not cosmetic: git's default
        # collapses a brand-new directory into one line ("?? migrations/") instead of
        # listing the real files inside it - found live via this phase's own test suite
        # (test_review_engine_warns_on_migration_path) silently under-counting files and
        # missing path-pattern checks for any newly-created nested directory.
        result = run_git(["status", "--porcelain=v1", "--untracked-files=all"], cwd=workspace_path)
        return result.stdout

    def _numstat() -> str:
        result = run_git(["diff", "--numstat", "HEAD"], cwd=workspace_path)
        return result.stdout

    status_output, numstat_output = await asyncio.gather(
        asyncio.to_thread(_status), asyncio.to_thread(_numstat)
    )

    numstat_by_path: dict[str, tuple[int, int, bool]] = {}
    for line in numstat_output.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        if len(parts) != 3:
            continue
        added, removed, path = parts
        is_binary = added == "-" or removed == "-"
        numstat_by_path[path] = (
            0 if is_binary else int(added),
            0 if is_binary else int(removed),
            is_binary,
        )

    files: list[PatchFile] = []
    for line in status_output.splitlines():
        if not line.strip() or len(line) < 4:
            continue
        code = line[:2]
        rest = line[3:]
        old_path = None
        path = rest
        if "->" in rest and ("R" in code or "C" in code):
            old_path, path = (part.strip() for part in rest.split("->", 1))

        if "?" in code:
            change_type = "created"
        elif "D" in code:
            change_type = "deleted"
        elif "R" in code:
            change_type = "renamed"
        else:
            change_type = "modified"

        insertions, deletions, is_binary = numstat_by_path.get(path, (0, 0, False))
        files.append(
            PatchFile(
                path=path,
                change_type=change_type,
                old_path=old_path,
                insertions=insertions,
                deletions=deletions,
                is_binary=is_binary,
            )
        )

    total_insertions = sum(f.insertions for f in files)
    total_deletions = sum(f.deletions for f in files)
    directories = sorted({f.path.rsplit("/", 1)[0] if "/" in f.path else "." for f in files})
    sensitive_hit = any(_is_sensitive(f.path) for f in files)

    total_lines = total_insertions + total_deletions
    if sensitive_hit or len(files) > maximum_changed_files or total_lines > maximum_changed_lines:
        risk_score = "high"
    elif len(files) > max(1, maximum_changed_files // 4) or total_lines > max(
        1, maximum_changed_lines // 4
    ):
        risk_score = "medium"
    else:
        risk_score = "low"

    return PatchSummary(
        files=files,
        total_files=len(files),
        total_insertions=total_insertions,
        total_deletions=total_deletions,
        affected_directories=directories,
        sensitive_area_hit=sensitive_hit,
        risk_score=risk_score,
    )
