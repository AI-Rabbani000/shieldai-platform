"""
GDS CI Security Gate — /ci/gate
==============================
Real security gate endpoint for GitHub Actions CI (issue #9, PR #10 contract).

Auth contract (fail-closed, two independent factors):
  1. Authorization: Bearer <CI_GATE_API_KEY>   — dedicated CI credential
     (stored in /opt/.env on the VPS; NOT the production bridge key).
  2. Body github_token — verified LIVE against the repository commit via
     the GitHub API before any verdict is produced. A caller that cannot
     read the commit gets no verdict.

Response contract (always JSON, never HTML):
  200 {"status": "ok", "verdict": "pass"|"blocked", "pass": bool,
       "summary": {"critical": int, "high": int, "new_critical": int,
                   "secrets_found": int},
       "block_reasons": [...], "repo": str, "commit": str, "checked_at": iso}
  200 {"status": "integration_error", "pass": false, "block_reasons": [...]}
       — ONLY for downstream integration failures (GitHub API down, DB
       unreachable). The client must NOT treat this as a security verdict.
  401 — missing/invalid Bearer key. 403 — commit not verifiable.
  422 — malformed request body.

Security properties:
  - Secrets are detected by scanning ADDED diff lines with high-confidence
    patterns; only pattern NAMES are returned, never matched values.
  - No raw diff or response body is logged.
  - Repo allowlist: only configured repositories may request verdicts.
  - Critical counts come from the real security_findings table (open,
    repo-scoped by target). No simulation.
"""

import os
import re
import json
import secrets as _secrets
import datetime
import urllib.request
import urllib.error
from typing import List, Optional

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel, field_validator
import psycopg2

router = APIRouter(prefix="/ci", tags=["GDS CI Security Gate"])

# Repositories allowed to request verdicts (allowlist).
_ALLOWED_REPOS = {
    "Al-Rabbani/shieldai-platform",
    "AI-Rabbani000/shieldai-platform",
}

_REPO_RE = re.compile(r"^[A-Za-z0-9_.\-]+/[A-Za-z0-9_.\-]+$")
_SHA_RE = re.compile(r"^[0-9a-f]{7,40}$")

# High-confidence secret patterns — scanned on ADDED diff lines only.
_SECRET_PATTERNS = [
    ("aws_access_key_id", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,255}")),
    ("openai_api_key", re.compile(r"\bsk-[A-Za-z0-9_\-]{20,}\b")),
    ("anthropic_api_key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}")),
    ("stripe_secret_key", re.compile(r"\bsk_live_[A-Za-z0-9]{20,}\b")),
    ("private_key_block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("postgres_url_with_password", re.compile(
        r"postgres(?:ql)?://[^\s:@/]+:[^\s@/]{4,}@")),
]


def _verify_gate_auth(authorization: str = Header(None)):
    key = os.environ.get("CI_GATE_API_KEY", "")
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Missing Authorization: Bearer credential")
    if not key:
        raise HTTPException(503, "CI gate credential not configured on server")
    token = authorization.split("Bearer ", 1)[1].strip()
    if not _secrets.compare_digest(token.encode(), key.encode()):
        raise HTTPException(401, "Invalid CI gate credential")


class GateRequest(BaseModel):
    repo_full_name: str
    commit_sha: str
    pr_number: int = 0
    branch: str = ""
    github_token: str = ""
    block_on: List[str] = []
    fail_on_secrets: bool = False
    fail_on_new_critical: bool = False

    @field_validator("repo_full_name")
    @classmethod
    def _repo_shape(cls, v: str) -> str:
        if not _REPO_RE.match(v):
            raise ValueError("repo_full_name malformed")
        return v

    @field_validator("commit_sha")
    @classmethod
    def _sha_shape(cls, v: str) -> str:
        if not _SHA_RE.match(v):
            raise ValueError("commit_sha malformed")
        return v

    @field_validator("pr_number")
    @classmethod
    def _pr_shape(cls, v: int) -> int:
        if v < 0:
            raise ValueError("pr_number must be >= 0")
        return v


def _github_commit(repo: str, sha: str, token: str):
    """Live-verify the caller's token by fetching the commit. Returns
    (files_added_lines, ok). ok=False means integration failure."""
    url = f"https://api.github.com/repos/{repo}/commits/{sha}"
    req = urllib.request.Request(url, headers={
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "User-Agent": "gds-ci-gate",
    })
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
        added_lines = []
        for f in data.get("files", []):
            patch = f.get("patch") or ""
            for line in patch.splitlines():
                if line.startswith("+") and not line.startswith("+++"):
                    added_lines.append(line[1:])
        return added_lines, True
    except urllib.error.HTTPError as e:
        # 401/403/404 => caller cannot read the commit: no verdict.
        if e.code in (401, 403, 404):
            raise HTTPException(403, "github_token could not read the commit")
        return [], False  # 5xx etc. => integration error
    except Exception:
        return [], False


def _scan_secrets(lines: List[str]) -> List[str]:
    found = []
    for name, pattern in _SECRET_PATTERNS:
        for line in lines:
            if pattern.search(line):
                found.append(name)
                break
    return found


def _db_counts(repo: str) -> Optional[dict]:
    """Open critical/high counts from security_findings, scoped by target.
    Returns None on DB integration failure (never fabricated)."""
    db_url = os.environ.get("DATABASE_URL", "")
    if not db_url:
        return None
    try:
        conn = psycopg2.connect(db_url, connect_timeout=5)
        try:
            with conn.cursor() as cur:
                like = f"%{repo}%"
                cur.execute(
                    "SELECT severity, COUNT(*) FROM security_findings "
                    "WHERE status = 'open' AND target ILIKE %s "
                    "GROUP BY severity", (like,))
                counts = {sev: int(n) for sev, n in cur.fetchall()}
                since = (datetime.datetime.utcnow()
                         - datetime.timedelta(hours=24)).isoformat()
                cur.execute(
                    "SELECT COUNT(*) FROM security_findings "
                    "WHERE status = 'open' AND severity = 'critical' "
                    "AND target ILIKE %s AND detected_at >= %s",
                    (like, since))
                new_critical = int(cur.fetchone()[0])
        finally:
            conn.close()
        return {
            "critical": counts.get("critical", 0),
            "high": counts.get("high", 0),
            "new_critical": new_critical,
        }
    except Exception:
        return None


@router.post("/gate", dependencies=[Depends(_verify_gate_auth)])
async def security_gate(req: GateRequest):
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()

    if req.repo_full_name not in _ALLOWED_REPOS:
        raise HTTPException(403, "Repository not allowed by CI gate")

    # Caller authenticity: live GitHub read on the exact commit.
    added_lines, gh_ok = _github_commit(
        req.repo_full_name, req.commit_sha, req.github_token)
    if not gh_ok:
        return {
            "status": "integration_error", "pass": False,
            "block_reasons": ["github_api_unreachable"],
            "repo": req.repo_full_name, "commit": req.commit_sha,
            "checked_at": now,
        }

    counts = _db_counts(req.repo_full_name)
    if counts is None:
        return {
            "status": "integration_error", "pass": False,
            "block_reasons": ["findings_database_unavailable"],
            "repo": req.repo_full_name, "commit": req.commit_sha,
            "checked_at": now,
        }

    secret_names = _scan_secrets(added_lines)
    reasons = []
    if req.fail_on_secrets and secret_names:
        reasons.append(
            "secrets_detected: " + ", ".join(sorted(set(secret_names))))
    if "critical" in req.block_on and counts["critical"] > 0:
        reasons.append(
            f"open critical findings for this repo: {counts['critical']}")
    if req.fail_on_new_critical and counts["new_critical"] > 0:
        reasons.append(
            f"new critical findings in last 24h: {counts['new_critical']}")

    passed = not reasons
    return {
        "status": "ok",
        "verdict": "pass" if passed else "blocked",
        "pass": passed,
        "summary": {
            "critical": counts["critical"],
            "high": counts["high"],
            "new_critical": counts["new_critical"],
            "secrets_found": len(secret_names),
        },
        "block_reasons": reasons,
        "repo": req.repo_full_name,
        "commit": req.commit_sha,
        "branch": req.branch,
        "pr_number": req.pr_number,
        "checked_at": now,
    }
