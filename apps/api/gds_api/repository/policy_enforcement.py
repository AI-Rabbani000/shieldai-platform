"""Phase 17 (Continuation Prompt 4), Part 4/9: real RepositoryPolicy enforcement shared
by every one of the 10 real repository tool executors (gds_api.tool_gateway). See
gds_api.models.RepositoryPolicy's own docstring for exactly which policy fields are
enforced this phase versus real-but-inert (stored for a future write-capability phase).
"""

from __future__ import annotations

from gds_api.models import RepositoryPolicy

_RABBANI_DIRECT_TOKEN = "rabbani"


class RepositoryCapabilityDenied(Exception):
    pass


def ensure_readable(policy: RepositoryPolicy) -> None:
    if not policy.readable:
        raise RepositoryCapabilityDenied(
            "This repository's policy disables reading (readable=False)."
        )


def ensure_searchable(policy: RepositoryPolicy) -> None:
    if not policy.searchable:
        raise RepositoryCapabilityDenied(
            "This repository's policy disables searching (searchable=False)."
        )


def ensure_agent_and_capability_allowed(
    policy: RepositoryPolicy, *, capability_key: str, requesting_agent_id: str | None
) -> None:
    """Empty allowed_agents/allowed_capabilities means "no additional restriction
    beyond the Secure Capability Broker's own real allow-list check" - these lists can
    only narrow further, never widen. `requesting_agent_id=None` (Rabbani-direct,
    the only real caller for every repository capability this phase) is represented by
    the literal token "rabbani" in a real, non-empty allowed_agents list."""
    if policy.allowed_capabilities and capability_key not in policy.allowed_capabilities:
        raise RepositoryCapabilityDenied(
            f"Capability '{capability_key}' is not in this repository's allowed_capabilities."
        )
    if policy.allowed_agents:
        agent_token = requesting_agent_id or _RABBANI_DIRECT_TOKEN
        if agent_token not in policy.allowed_agents:
            raise RepositoryCapabilityDenied(
                f"'{agent_token}' is not in this repository's allowed_agents."
            )
