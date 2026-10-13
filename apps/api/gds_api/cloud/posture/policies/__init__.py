"""Import side effect: each real provider policy module registers its policies into
`gds_api.cloud.posture.registry.POLICY_REGISTRY` at import time (mirrors
`gds_api.cloud.adapters`' own import-side-effect adapter registration pattern).
Importing `gds_api.cloud.posture` (this package's parent) is enough to make every
policy in every provider module below available - no separate, forgettable manual
startup-registration step.
"""

from __future__ import annotations

from gds_api.cloud.posture.policies import aws as _aws_policies  # noqa: F401
from gds_api.cloud.posture.policies import azure as _azure_policies  # noqa: F401
from gds_api.cloud.posture.policies import gcp as _gcp_policies  # noqa: F401
from gds_api.cloud.posture.policies import kubernetes as _kubernetes_policies  # noqa: F401
