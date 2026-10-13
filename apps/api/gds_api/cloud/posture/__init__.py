"""EDP-009 Part 2: the deterministic Cloud Security Posture Management (CSPM)
assessment layer built above Part 1's provider-neutral cloud inventory. See
docs/adr/0051-deterministic-cloud-security-posture-management.md and
docs/reviews/phase-22-part2-policy-feasibility-matrix.md.
"""

from __future__ import annotations

# Import side effect: registers every real policy module's PolicyDefinition entries
# into gds_api.cloud.posture.registry.POLICY_REGISTRY at import time.
from gds_api.cloud.posture import policies as _policies  # noqa: F401
