"""Phase 17 (Continuation Prompt 4), Part 4/8: real path-policy enforcement for every
read-only repository capability. Two independent layers, both real:

1. A structural, non-configurable baseline (git internals and common secret-bearing
   filenames) that no RepositoryPolicy can ever override - reading `.git/config` could
   leak a credential embedded in a remote URL; reading `.env` could leak a real secret.
   This is enforced regardless of what any repository's own policy says, the same
   "structural, not policy-driven" discipline gds_api.capabilities.broker.redact_secrets
   already applies to capability parameters.
2. The repository's own real, editable `forbidden_paths`/`allowed_paths`
   (gds_api.models.RepositoryPolicy) - `forbidden_paths` always wins over
   `allowed_paths` for the same path.
"""

from __future__ import annotations

import fnmatch

from gds_api.models import RepositoryPolicy

_STRUCTURAL_FORBIDDEN_PATTERNS: tuple[str, ...] = (
    ".git",
    ".git/*",
    ".git/**",
    ".env",
    ".env.*",
    "*.pem",
    "*.key",
    "id_rsa",
    "id_rsa.*",
    "id_ed25519",
    "id_ed25519.*",
    "*.pfx",
    "*.p12",
)


def _normalize(relative_path: str) -> str:
    return relative_path.replace("\\", "/").lstrip("/")


def _matches_any(path: str, patterns: tuple[str, ...] | list[str]) -> bool:
    for pattern in patterns:
        normalized_pattern = pattern.replace("\\", "/").lstrip("/")
        if fnmatch.fnmatch(path, normalized_pattern):
            return True
        # A directory-style pattern ("secrets/", "secrets") also forbids everything
        # beneath it, not just an exact name match.
        stripped = normalized_pattern.rstrip("/*")
        if stripped and (path == stripped or path.startswith(stripped + "/")):
            return True
    return False


def is_path_allowed(relative_path: str, policy: RepositoryPolicy) -> bool:
    path = _normalize(relative_path)
    if _matches_any(path, _STRUCTURAL_FORBIDDEN_PATTERNS):
        return False
    if _matches_any(path, policy.forbidden_paths):
        return False
    if policy.allowed_paths:
        return _matches_any(path, policy.allowed_paths)
    return True
