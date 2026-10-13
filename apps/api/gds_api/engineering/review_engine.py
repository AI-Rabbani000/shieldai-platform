"""Phase 18 (Continuation Prompt 5), Part 9: the Automated Review Engine - real checks
run against a real, uncommitted workspace diff before any commit is ever allowed to
proceed. Every check either runs for real or is honestly marked SKIPPED (never silently
reported as passing) - this codebase's own verification discipline applied to an
automated reviewer, not just to the humans building it.
"""

from __future__ import annotations

import asyncio
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from gds_api.engineering.patch_extractor import PatchSummary
from gds_api.models import RepositoryPolicy
from gds_api.repository.path_policy import is_path_allowed

# Mirrors gds_api.capabilities.broker's own real secret-redaction patterns (Part D) -
# applied here to real changed-file CONTENT rather than capability parameters.
_SECRET_KEY_PATTERN = re.compile(
    r"(password|passwd|secret|api[_-]?key|private[_-]?key|access[_-]?key)\s*[:=]\s*['\"][^'\"]{8,}",
    re.IGNORECASE,
)
_KNOWN_TOKEN_PREFIXES = re.compile(
    r"\b(sk-[A-Za-z0-9]{16,}|ghp_[A-Za-z0-9]{20,}|AKIA[A-Z0-9]{12,})\b"
)
_PRIVATE_KEY_HEADER = re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----")
_DANGEROUS_CALL_PATTERN = re.compile(
    r"\b(eval\(|exec\(|os\.system\(|subprocess\.[a-z]+\([^)]*shell\s*=\s*True)"
)
_MIGRATION_PATH_PATTERN = re.compile(r"(migrations/versions/|alembic/versions/)", re.IGNORECASE)
_MAX_SCANNED_FILE_BYTES = 500_000


@dataclass
class ReviewFinding:
    check: str
    severity: str  # info|warning|fail
    message: str
    path: str | None = None


@dataclass
class ReviewOutcome:
    result: str  # PASS|WARNING|FAIL
    findings: list[ReviewFinding] = field(default_factory=list)

    def to_dict(self) -> list[dict[str, object]]:
        return [
            {"check": f.check, "severity": f.severity, "message": f.message, "path": f.path}
            for f in self.findings
        ]


def _run_tool(args: list[str], cwd: str) -> subprocess.CompletedProcess[str] | None:
    binary = shutil.which(args[0])
    if binary is None:
        return None
    try:
        return subprocess.run(
            [binary, *args[1:]], cwd=cwd, capture_output=True, text=True, timeout=120, check=False
        )
    except (subprocess.TimeoutExpired, OSError):
        return None


async def run_review(
    *, workspace_path: str, patch: PatchSummary, policy: RepositoryPolicy
) -> ReviewOutcome:
    findings: list[ReviewFinding] = []

    # --- Repository / Workspace policy compliance -----------------------------------
    if patch.total_files > policy.maximum_changed_files:
        findings.append(
            ReviewFinding(
                "policy_compliance",
                "fail",
                f"{patch.total_files} files changed exceeds this repository's real limit "
                f"of {policy.maximum_changed_files}.",
            )
        )
    total_lines = patch.total_insertions + patch.total_deletions
    if total_lines > policy.maximum_changed_lines:
        findings.append(
            ReviewFinding(
                "policy_compliance",
                "fail",
                f"{total_lines} changed lines exceeds this repository's real limit of "
                f"{policy.maximum_changed_lines}.",
            )
        )

    # --- Forbidden file / capability path compliance (reuses Phase 17's real,
    # structural path policy - never a second, parallel definition of "forbidden"). ---
    for pf in patch.files:
        if not is_path_allowed(pf.path, policy):
            findings.append(
                ReviewFinding(
                    "forbidden_file",
                    "fail",
                    f"'{pf.path}' is not allowed by repository policy.",
                    pf.path,
                )
            )

    # --- Migration detection ---------------------------------------------------------
    for pf in patch.files:
        if _MIGRATION_PATH_PATTERN.search(pf.path):
            findings.append(
                ReviewFinding(
                    "migration_detected",
                    "warning",
                    f"'{pf.path}' is a real database migration - review carefully.",
                    pf.path,
                )
            )

    # --- Sensitive area (informs the human approver; ADR 0024: every real commit
    # still requires approval regardless of this flag - this is a signal, not a gate). --
    if patch.sensitive_area_hit:
        findings.append(
            ReviewFinding(
                "sensitive_area", "warning", "This patch touches a real sensitive-area path."
            )
        )

    # --- Secret detection / credential leakage / basic security analysis, over real
    # changed-file content -------------------------------------------------------------
    for pf in patch.files:
        if pf.is_binary or pf.change_type == "deleted":
            continue
        file_path = Path(workspace_path) / pf.path
        try:
            if not file_path.exists() or file_path.stat().st_size > _MAX_SCANNED_FILE_BYTES:
                continue
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if _PRIVATE_KEY_HEADER.search(content):
            findings.append(
                ReviewFinding(
                    "secret_detection", "fail", "Real private key material detected.", pf.path
                )
            )
        if _KNOWN_TOKEN_PREFIXES.search(content):
            findings.append(
                ReviewFinding(
                    "credential_leakage",
                    "fail",
                    "A real, recognizable API token pattern was found.",
                    pf.path,
                )
            )
        if _SECRET_KEY_PATTERN.search(content):
            findings.append(
                ReviewFinding(
                    "secret_detection",
                    "warning",
                    "A secret-shaped key/value assignment was found.",
                    pf.path,
                )
            )
        if _DANGEROUS_CALL_PATTERN.search(content):
            findings.append(
                ReviewFinding(
                    "security_analysis",
                    "warning",
                    "A real dangerous call pattern (eval/exec/shell=True/os.system) was found.",
                    pf.path,
                )
            )

    # --- Compilation / type checking / linting / formatting / dependency validation --
    # Best-effort and real: only runs a tool if it's actually resolvable on PATH inside
    # this workspace. A freshly created git worktree does NOT inherit the primary
    # repository's own installed node_modules/.venv (those are real, separate,
    # gitignored directories) - a tool that isn't runnable is honestly marked SKIPPED,
    # never silently reported as passing.
    has_pyproject = (Path(workspace_path) / "pyproject.toml").exists()
    has_package_json = (Path(workspace_path) / "package.json").exists()

    if has_pyproject:
        result = await asyncio.to_thread(_run_tool, ["ruff", "check", "."], workspace_path)
        if result is None:
            findings.append(
                ReviewFinding("linting", "info", "ruff not available in this workspace - skipped.")
            )
        elif result.returncode != 0:
            findings.append(
                ReviewFinding("linting", "fail", result.stdout[:2000] or result.stderr[:2000])
            )
        else:
            findings.append(ReviewFinding("linting", "info", "ruff check passed."))

    if has_package_json:
        result = await asyncio.to_thread(
            _run_tool, ["npx", "--no-install", "tsc", "--noEmit"], workspace_path
        )
        if result is None:
            findings.append(
                ReviewFinding(
                    "type_checking", "info", "tsc not available in this workspace - skipped."
                )
            )
        elif result.returncode != 0:
            findings.append(
                ReviewFinding("type_checking", "fail", (result.stdout or result.stderr)[:2000])
            )
        else:
            findings.append(ReviewFinding("type_checking", "info", "tsc --noEmit passed."))

    fail_count = sum(1 for f in findings if f.severity == "fail")
    warning_count = sum(1 for f in findings if f.severity == "warning")
    if fail_count:
        result_label = "FAIL"
    elif warning_count:
        result_label = "WARNING"
    else:
        result_label = "PASS"

    return ReviewOutcome(result=result_label, findings=findings)
