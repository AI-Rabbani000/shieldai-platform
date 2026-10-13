"""EDP-009 Part 1: the Multi-Cloud Foundation - provider-neutral cloud environment
registration, governed connections, discovery, and asset intelligence. See
docs/adr/0050-provider-neutral-cloud-foundation.md and
docs/reviews/phase-22-cloud-foundation-pre-build-audit.md for the design and the
real pre-build audit this package's architecture is grounded in.
"""

from __future__ import annotations

# Import side effect: each real concrete adapter module registers itself into
# gds_api.cloud.adapter.ADAPTER_REGISTRY at import time (see
# gds_api/cloud/adapters/aws.py's own trailing register_adapter() call). Importing
# them here means any import of gds_api.cloud.* (main.py already does this via
# cloud_api) is enough to make every real adapter available - no separate,
# forgettable manual startup-registration step.
from gds_api.cloud.adapters import aws as _aws_adapter  # noqa: F401
from gds_api.cloud.adapters import azure as _azure_adapter  # noqa: F401
from gds_api.cloud.adapters import gcp as _gcp_adapter  # noqa: F401
from gds_api.cloud.adapters import k8s as _k8s_adapter  # noqa: F401

# EDP-009 Part 2: same import-side-effect pattern, one level up - registers every
# real CSPM policy (gds_api.cloud.posture.policies.*) into
# gds_api.cloud.posture.registry.POLICY_REGISTRY at import time.
from gds_api.cloud import posture as _posture  # noqa: F401,E402
