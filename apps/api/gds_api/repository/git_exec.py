"""Phase 17 (Continuation Prompt 4): the one real place a `git` subprocess is invoked
from - shared by every other module in `gds_api.repository`
(docs/reviews/phase-17-repository-audit.md Finding 6: direct CLI, no GitPython
dependency). Synchronous; every real caller wraps it in `asyncio.to_thread`, per this
codebase's established blocking-I/O convention (Finding 3). Never called at import time
or from workflow-side code - only from inside a real tool executor or activity
(Finding 2's Temporal-sandbox lesson).
"""

from __future__ import annotations

import subprocess


def run_git(args: list[str], *, cwd: str, timeout: int = 60) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args], cwd=cwd, capture_output=True, text=True, timeout=timeout, check=False
    )
