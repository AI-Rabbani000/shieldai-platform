"""EDP-009 Part 1, Sections 8-11: real, concrete ProviderAdapter implementations.
One module per provider (`aws.py` this sub-phase; `azure.py`/`gcp.py`/`kubernetes.py`
in later sub-phases of this same Part). Each module registers itself into
`gds_api.cloud.adapter.ADAPTER_REGISTRY` as an import side effect - triggered by
`gds_api.cloud`'s own package `__init__.py`, so any import of `gds_api.cloud.*`
(which `main.py` already does via `cloud_api`) is enough to make every real adapter
available, without a separate manual startup-registration step to forget.
"""
