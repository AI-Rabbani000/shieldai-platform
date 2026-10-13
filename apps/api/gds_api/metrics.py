"""Prometheus metrics - a single shared default registry (uvicorn runs single-process,
no --workers, so no multiprocess registry setup is needed). Scraped by the real
Prometheus container added to docker-compose.yml via GET /metrics (main.py).
"""

from prometheus_client import Counter, Gauge, Histogram

# EDP-008 Part 8, Section 5/7: no SSE observability existed anywhere before this -
# added specifically because this same part's live SSE audit found a real, disclosed
# defect (the idle heartbeat path delivering zero bytes to the client) that these two
# metrics would make directly visible in Grafana going forward: a connection whose
# gds_sse_connections_active stays elevated with no matching growth in
# gds_sse_heartbeats_sent_total is exactly the failure signature found this session.
sse_connections_active = Gauge(
    "gds_sse_connections_active", "Real open mission SSE connections right now"
)
sse_heartbeats_sent_total = Counter(
    "gds_sse_heartbeats_sent_total", "Total real SSE idle-heartbeat frames yielded"
)
sse_events_sent_total = Counter(
    "gds_sse_events_sent_total", "Total real SSE data events yielded", ["event_type"]
)

http_requests_total = Counter(
    "gds_http_requests_total", "Total HTTP requests", ["method", "path", "status_code"]
)
http_request_duration_seconds = Histogram(
    "gds_http_request_duration_seconds", "HTTP request duration in seconds", ["method", "path"]
)

tool_executions_total = Counter(
    "gds_tool_executions_total", "Total Tool Gateway executions", ["tool_name", "outcome"]
)
tool_execution_duration_seconds = Histogram(
    "gds_tool_execution_duration_seconds",
    "Tool Gateway execution duration in seconds",
    ["tool_name"],
)

llm_calls_total = Counter(
    "gds_llm_calls_total", "Total real Anthropic API calls", ["model", "outcome"]
)
llm_call_duration_seconds = Histogram(
    "gds_llm_call_duration_seconds", "Real Anthropic API call duration in seconds", ["model"]
)

# Phase 20 (Continuation Prompt 7 / EDP-007), Part 16: Purple Workforce observability.
# Every real Purple Workforce tool call (coordinate_pentest_engagement,
# auto_fix_finding, enrich_finding, etc.) already increments tool_executions_total
# above for free, via tool_gateway.execute_tool's one shared instrumentation point -
# these four are additive, covering real signals that aren't tool executions:
# structured inter-agent messages, the Engagement lifecycle's own state transitions,
# recorded lessons, and correlation-graph writes.
purple_messages_total = Counter(
    "gds_purple_messages_total",
    "Total real Purple Workforce inter-agent messages recorded",
    ["message_type", "classification"],
)
pentest_engagement_transitions_total = Counter(
    "gds_pentest_engagement_transitions_total",
    "Total real Engagement lifecycle transitions",
    ["to_status"],
)
mission_lessons_recorded_total = Counter(
    "gds_mission_lessons_recorded_total", "Total real mission lessons recorded", ["lesson_type"]
)
finding_correlation_edges_total = Counter(
    "gds_finding_correlation_edges_total",
    "Total real Finding correlation-graph edges written",
    ["edge_type"],
)

# EDP-009 Part 1, sub-phase 22.1.11, Section 37: real cloud discovery/inventory
# observability. Labels stay low-cardinality throughout (provider/status/category -
# never a real asset/job/environment ID), per Section 37's own explicit rule.
cloud_environments_registered_total = Counter(
    "gds_cloud_environments_registered_total",
    "Total real CloudEnvironment registrations",
    ["provider"],
)
cloud_connection_validations_total = Counter(
    "gds_cloud_connection_validations_total",
    "Total real cloud connection-validation attempts",
    ["provider", "status"],
)
cloud_discovery_jobs_total = Counter(
    "gds_cloud_discovery_jobs_total",
    "Total real cloud discovery jobs by terminal status",
    ["provider", "status"],
)
cloud_discovery_duration_seconds = Histogram(
    "gds_cloud_discovery_duration_seconds",
    "Real cloud discovery job duration in seconds, start to terminal status",
    ["provider"],
)
cloud_assets_discovered_total = Counter(
    "gds_cloud_assets_discovered_total", "Total real new CloudAsset rows created", ["provider"]
)
cloud_relationships_discovered_total = Counter(
    "gds_cloud_relationships_discovered_total",
    "Total real new CloudAssetRelationship rows created",
    ["provider"],
)
cloud_graph_sync_duration_seconds = Histogram(
    "gds_cloud_graph_sync_duration_seconds",
    "Real Neo4j graph sync duration in seconds",
    ["provider"],
)
cloud_graph_sync_failures_total = Counter(
    "gds_cloud_graph_sync_failures_total", "Total real graph sync failures", ["provider"]
)
cloud_adapter_errors_total = Counter(
    "gds_cloud_adapter_errors_total",
    "Total real provider adapter errors during discovery, classified by category",
    ["provider", "error_category"],
)
# A real, one-time-at-startup gauge over the code-defined CLOUD_PROVIDER_REGISTRY
# (see gds_api.main's lifespan hook) - provider support state is a static,
# per-deployment fact, not something that changes mid-process, so this is set
# once rather than re-derived on every scrape.
cloud_provider_status = Gauge(
    "gds_cloud_provider_status",
    "1 if this provider currently has this exact CloudProviderStatus value, else 0",
    ["provider", "status"],
)
# EDP-009 Part 2, Section 20 (Cloud Posture Metrics) - same gds_cloud_* domain
# prefix as the Part 1 metrics above, not a new gds_cspm_* domain, since this is a
# sub-domain of the same cloud metrics family (ADR 0051 Decision D8). Labels stay
# low-cardinality (provider/status/result/severity - never a policy/asset/finding
# ID), per the same rule Part 1 followed.
cloud_posture_evaluation_runs_total = Counter(
    "gds_cloud_posture_evaluation_runs_total",
    "Total real cloud posture evaluation runs by terminal status",
    ["provider", "status"],
)
cloud_posture_evaluation_run_duration_seconds = Histogram(
    "gds_cloud_posture_evaluation_run_duration_seconds",
    "Real cloud posture evaluation run duration in seconds, start to terminal status",
    ["provider"],
)
cloud_posture_evaluations_total = Counter(
    "gds_cloud_posture_evaluations_total",
    "Total real individual policy evaluations by result",
    ["provider", "result"],
)
