"""
GDS CI Security Gate — /ci/gate
==============================
Real security gate endpoint for GitHub Actions (issue #9, PR #10/#11 contract).

PR #11 review corrections (Codex, Oct 13):
  1. Full diff coverage: the commit's complete unified diff is fetched via
     Accept: application/vnd.github.diff (no 300-file JSON cap). A diff that
     cannot be fully obtained is an integration_error — never a false pass.
  2. Severity values are case-normalized (LOWER()) so uppercase records
     ('Critical', 'HIGH') are counted.
  3. block_on is enforced for ANY requested severity (critical/high/medium/
     low), not just 'critical'. Invalid block_on values are rejected (422).
  4. The handler is a sync `def` — FastAPI runs it in its thread pool, so
     the blocking urllib/psycopg2 calls never stall the event loop.

Auth contract (fail-closed, two independent factors):
  1. Authorization: Bearer <CI_GATE_API_KEY>  (dedicated CI credential in
     /opt/.env on the VPS; NOT the production bridge key).
  2. Body github_token — verified LIVE: the full diff for the exact commit
     must be readable via the GitHub API before any verdict is produced.

Response contract (always JSON, never HTML):
  200 {"status": "ok", "verdict": "pass"|"blocked", "pass": bool,
       "summary": {"critical", "high", "new_critical", "secrets_found",
                   "files_scanned"},
       "block_reasons": [...], "repo", "commit", "branch", "pr_number",
       "checked_at"}
  200 {"status": "integration_error", "pass": false, "block_reasons": [...]}
       — ONLY downstream integration failures (GitHub API 5xx, DB down,
       diff unobtainable/too large). NOT a security verdict.
  401 — missing/invalid Bearer key. 403 — commit unreadable or repo not
  allowlisted. 422 — malformed request.

Security properties:
  - Secrets detected on ADDED diff lines only; pattern NAMES returned,
    never matched values. No raw diff or response body is logged.
  - Repo allowlist enforced.
  - Counts come from the real security_findings table (open, repo-scoped).
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

_ALLOWED_REPOS = {
    "Al-Rabbani/shieldai-platform",
    "AI-Rabbani000/shieldai-platform",
}
_BLOCKABLE = {"critical", "high", "medium", "low"}

_REPO_RE = re.compile(r"^[A-Za-z0-9_.\-]+/[A-Za-z0-9_.\-]+$")
_SHA_RE = re.compile(r"^[0-9a-f]{7,40}$")

# High-confidence secret patterns — scanned on ADDED diff lines only.
# User/host parts are restricted to realistic characters so that regex
# source text (e.g. pattern definitions in security code) is not a
# false positive.
_SECRET_PATTERNS = [
    ("aws_access_key_id", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,255}")),
    ("openai_api_key", re.compile(r"\bsk-(?!ant-)[A-Za-z0-9_\-]{20,}\b")),
    ("anthropic_api_key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}")),
    ("stripe_secret_key", re.compile(r"\bsk_live_[A-Za-z0-9]{20,}\b")),
    ("private_key_block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("postgres_url_with_password", re.compile(
        r"postgres(?:ql)?://[a-zA-Z0-9_.\-]+:[^\s@/]{4,}@")),
]

# Diff size cap: bigger commits are classified integration_error rather
# than silently scanned partially.
_MAX_DIFF_BYTES = 16 * 1024 * 1024


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

    @field_validator("block_on")
    @classmethod
    def _block_on_shape(cls, v: List[str]) -> List[str]:
        normalized = [item.strip().lower() for item in v]
        invalid = [x for x in normalized if x not in _BLOCKABLE]
        if invalid:
            raise ValueError(f"block_on values must be among {sorted(_BLOCKABLE)}")
        return normalized


def _github_commit_diff(repo: str, sha: str, token: str) -> Optional[str]:
    """Fetch the commit's FULL unified diff. Returns the diff text, or
    None on integration failure (never a partial/absent diff). Caller
    authenticity is proven by the same live request (401/403/404 raise)."""
    url = f"https://api.github.com/repos/{repo}/commits/{sha}"
    req = urllib.request.Request(url, headers={
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github.diff",
        "User-Agent": "gds-ci-gate",
    })
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read(_MAX_DIFF_BYTES + 1)
    except urllib.error.HTTPError as e:
        if e.code in (401, 403, 404):
            raise HTTPException(403, "github_token could not read the commit")
        return None  # 5xx etc. => integration error
    except Exception:
        return None
    if len(raw) > _MAX_DIFF_BYTES:
        return None  # too large to scan fully — never a partial verdict
    return raw.decode("utf-8", "replace")


def _scan_diff(diff_text: str):
    """Return (added_lines, files_scanned)."""
    added = []
    files = 0
    for line in diff_text.splitlines():
        if line.startswith("diff --git"):
            files += 1
        elif line.startswith("+") and not line.startswith("+++"):
            added.append(line[1:])
    return added, files


def _scan_secrets(lines: List[str]) -> List[str]:
    found = []
    for name, pattern in _SECRET_PATTERNS:
        for line in lines:
            if pattern.search(line):
                found.append(name)
                break
    return found


def _db_counts(repo: str) -> Optional[dict]:
    """Open severity counts from security_findings, repo-scoped by target,
    case-normalized. Returns None on DB integration failure (never
    fabricated)."""
    db_url = os.environ.get("DATABASE_URL", "")
    if not db_url:
        return None
    try:
        conn = psycopg2.connect(db_url, connect_timeout=5)
        try:
            with conn.cursor() as cur:
                like = f"%{repo}%"
                cur.execute(
                    "SELECT LOWER(severity), COUNT(*) FROM security_findings "
                    "WHERE status = 'open' AND target ILIKE %s "
                    "GROUP BY LOWER(severity)", (like,))
                counts = {sev: int(n) for sev, n in cur.fetchall()}
                since = (datetime.datetime.utcnow()
                         - datetime.timedelta(hours=24)).isoformat()
                cur.execute(
                    "SELECT COUNT(*) FROM security_findings "
                    "WHERE status = 'open' AND LOWER(severity) = 'critical' "
                    "AND target ILIKE %s AND detected_at >= %s",
                    (like, since))
                new_critical = int(cur.fetchone()[0])
        finally:
            conn.close()
        return {
            "critical": counts.get("critical", 0),
            "high": counts.get("high", 0),
            "medium": counts.get("medium", 0),
            "low": counts.get("low", 0),
            "new_critical": new_critical,
        }
    except Exception:
        return None


@router.post("/gate", dependencies=[Depends(_verify_gate_auth)])
def security_gate(req: GateRequest):
    # Sync handler: FastAPI runs this in its thread pool, so the blocking
    # GitHub/psycopg2 calls below never stall the event loop.
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()

    if req.repo_full_name not in _ALLOWED_REPOS:
        raise HTTPException(403, "Repository not allowed by CI gate")

    # Caller authenticity + full diff coverage: one live GitHub request.
    diff_text = _github_commit_diff(
        req.repo_full_name, req.commit_sha, req.github_token)
    if diff_text is None or not diff_text.strip():
        return {
            "status": "integration_error", "pass": False,
            "block_reasons": ["commit_diff_unavailable"],
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

    added_lines, files_scanned = _scan_diff(diff_text)
    secret_names = _scan_secrets(added_lines)

    reasons = []
    if req.fail_on_secrets and secret_names:
        reasons.append(
            "secrets_detected: " + ", ".join(sorted(set(secret_names))))
    # Enforce every requested blocking severity (case-normalized at the
    # validator; counts are normalized in SQL).
    for sev in req.block_on:
        if counts.get(sev, 0) > 0:
            reasons.append(
                f"open {sev} findings for this repo: {counts[sev]}")
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
            "files_scanned": files_scanned,
        },
        "block_reasons": reasons,
        "repo": req.repo_full_name,
        "commit": req.commit_sha,
        "branch": req.branch,
        "pr_number": req.pr_number,
        "checked_at": now,
    }
