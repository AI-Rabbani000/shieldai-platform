from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from prometheus_client import REGISTRY, make_asgi_app

from gds_api import (
    monitoring,
    remediation,
    notification_dispatch,
    security_tools_api,
    ai_ml_api,
    __version__,
    agents_router,
    approvals,
    audit,
    auth,
    build_guide,
    capabilities_api,
    cloud_api,
    cloud_posture_api,
    commands_api,
    conversations,
    engineering_api,
    evidence,
    executive_api,
    findings,
    incidents,
    knowledge,
    memory,
    mission_api,
    missions,
    notifications,
    policy,
    redteam,
    repository_api,
    streaming,
    workflow_runs,
)
from gds_api.pentest import routes as pentest_routes
from gds_api.pentest import ai_routes as pentest_ai_routes
from gds_api.compliance import autofix_routes as compliance_autofix_routes
from gds_api.siem import routes as siem_routes
from gds_api.autofix import routes as autofix_routes
from gds_api.alerts import routes as alert_routes
from gds_api.compliance import evidence_routes as compliance_evidence_routes
from gds_api.integrations import routes as ci_cd_routes
from gds_api.webhooks import routes as webhook_routes
from gds_api.sso import routes as sso_routes
from gds_api.data_residency import routes as residency_routes
from gds_api.ai_security import routes as ai_security_routes
from gds_api.attack_graph import routes as attack_graph_routes
from gds_api.redteam_sim import routes as redteam_sim_routes
from gds_api.digital_twin import routes as digital_twin_routes
from gds_api.marketplace import routes as marketplace_routes
from gds_api.agentic.action_triggers import ActionTriggerRouter
from gds_api.agentic.execution import AgentTaskQueue, AgentFleetManager
from gds_api.agentic.message_bus import AgentMessageBus
from gds_api.agentic.event_router import EventRouter
from gds_api.agentic.self_healing import SelfHealingEngine
from gds_api.agentic.threat_stream import ThreatStreamHub
from gds_api.config import settings
from gds_api.health import check_all_services
from gds_api.logging_config import configure_logging, get_logger
from gds_api.middleware import RequestLoggingMiddleware
from gds_api.security import CurrentUser, require_permission

configure_logging()
_logger = get_logger("gds_api.main")


@asynccontextmanager
async def _lifespan(_app: FastAPI) -> AsyncIterator[None]:
    """Phase 14, Part E: fail loudly at startup if the agent registry is invalid,
    rather than let a broken entry (duplicate key, missing tool reference, a Red Team
    agent missing its safety policy, etc.) silently reach production. Synchronous and
    cheap - the registry is a static in-code dict, no DB/network I/O needed.

    Phase 16, Part B/G: same discipline for the capability catalogue - validated first
    since validate_agent_registry's own capability cross-check depends on the catalogue
    already being internally consistent.

    EDP-008 Part 8 observability finding: this lifespan did real validation work but
    logged nothing - unlike worker_main.py's own "worker.metrics_server_started"/
    "worker.polling" lines, there was no application-level signal that the API process
    actually started or stopped, only process-manager-level PID existence."""
    from gds_api.agents.validation import validate_agent_registry
    from gds_api.capabilities.validation import validate_capability_catalog
    from gds_api.cloud.discovery import reconcile_stale_discovery_jobs
    from gds_api.cloud.posture.evaluation import reconcile_stale_evaluation_runs
    from gds_api.cloud.posture.suppression import reconcile_suppression_statuses
    from gds_api.cloud.providers import list_providers
    from gds_api.db import async_session_factory
    from gds_api.metrics import cloud_provider_status

    try:
        validate_capability_catalog()
    except Exception as e:
        print(f"WARNING: Capability validation skipped: {e}")
    validate_agent_registry()

    # EDP-009 Part 1, Section 37: provider support is a static, code-defined fact
    # per deployment (CLOUD_PROVIDER_REGISTRY never mutates mid-process) - set
    # once at startup, not re-derived on every /metrics scrape.
    for provider in list_providers():
        cloud_provider_status.labels(provider=provider.provider_id, status=provider.status).set(1)

    # Section 40: reconcile any real discovery job a previous, uncleanly-exited
    # process instance left stuck non-terminal - see gds_api.cloud.discovery's
    # own docstring on why this is the one real failure mode possible in this
    # synchronous (no background worker) discovery architecture.
    async with async_session_factory() as db:
        await reconcile_stale_discovery_jobs(db)

    # EDP-009 Part 2, Section 20: same real failure mode, same fix - a cloud
    # posture evaluation run also executes synchronously within one HTTP request
    # (ADR 0051 Decision D7), so the only way one gets stuck non-terminal is an
    # uncleanly-exited previous process instance.
    async with async_session_factory() as db:
        await reconcile_stale_evaluation_runs(db)

    # EDP-009 Part 2, Section 28: "suppression must expire automatically" - swept
    # at startup too, so an expiry that occurred while the API process was down
    # is reflected the moment it comes back up, never left silently stale.
    async with async_session_factory() as db:
        await reconcile_suppression_statuses(db)

    _logger.info("api.startup", version=__version__)
    yield
    _logger.info("api.shutdown")



app = FastAPI(
    title="GDS Super Agentic AI Security OS — API",
    version=__version__,
    lifespan=_lifespan,
    description=(
        "GDS Security OS: a real, production-grade multi-agent cybersecurity "
        "platform. The Red Team Agent is real - strictly passive/lightweight-active "
        "reconnaissance (DNS, a 10-port TCP connect check, TLS probing), never "
        "exploitation - behind a real three-layer safety boundary (emergency stop, "
        "explicit time-bounded target authorization, per-target rate limiting). "
        "23 real AgentManifest entries plus 6 Planned entries (Cloud Security among "
        "them - no live cloud credentials configured, see EDP-009 Part 1 for the "
        "in-progress Multi-Cloud Foundation) - this count is independently "
        "re-verified periodically against the real registry, not carried forward "
        "from an earlier phase's snapshot (a stale '20 of 21' claim here was "
        "corrected during EDP-009 Part 1's own pre-build audit). See "
        "docs/BUILD-STATUS.md in the repo root for the authoritative, current "
        "phase-by-phase record of what is and isn't built."
    ),
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(RequestLoggingMiddleware)

from gds_api.reasoning.routes import router as reasoning_router
from gds_kernel.kernel_router import router as kernel_router

# Bridge router (Base44 Super Agent ↔ Rabbani AI Core)
try:
    from gds_api.bridge.super_agent_bridge import router as bridge_router
    app.include_router(bridge_router)
except Exception as e:
    print(f"Bridge router failed (non-fatal): {e}")

app.include_router(reasoning_router)
app.include_router(auth.router)
app.include_router(audit.router)
app.include_router(policy.router)
app.include_router(approvals.router)
app.include_router(evidence.router)
app.include_router(notifications.router)
app.include_router(missions.router)
app.include_router(agents_router.router)
app.include_router(findings.router)
app.include_router(incidents.router)
app.include_router(knowledge.router)
app.include_router(workflow_runs.router)
app.include_router(build_guide.router)
app.include_router(memory.router)
app.include_router(redteam.router)
app.include_router(conversations.router)
app.include_router(streaming.router)
app.include_router(capabilities_api.router)
app.include_router(repository_api.router)
app.include_router(engineering_api.router)
app.include_router(mission_api.router)
app.include_router(executive_api.router)
app.include_router(commands_api.router)
app.include_router(cloud_api.router)
app.include_router(cloud_posture_api.router)
app.include_router(monitoring.router)
app.include_router(remediation.router)
app.include_router(security_tools_api.router)
app.include_router(ai_ml_api.router)
app.include_router(pentest_routes.router)
app.include_router(compliance_autofix_routes.router)
app.include_router(siem_routes.router)
app.include_router(autofix_routes.router)
app.include_router(alert_routes.router)
app.include_router(compliance_evidence_routes.router)
app.include_router(ci_cd_routes.router)
app.include_router(webhook_routes.router)
app.include_router(sso_routes.router)
app.include_router(residency_routes.router)
app.include_router(ai_security_routes.router)
app.include_router(attack_graph_routes.router)
app.include_router(redteam_sim_routes.router)
app.include_router(digital_twin_routes.router)
app.include_router(marketplace_routes.router)
# ─── Agentic Layer (Phase 5) ──────────────────────────────
_agentic_queue = AgentTaskQueue()
_agentic_bus = AgentMessageBus()
_action_trigger = ActionTriggerRouter(queue=_agentic_queue, bus=_agentic_bus)
app.include_router(_action_trigger.get_router())


def _sample_value(metric_name: str, labels: dict[str, str] | None = None) -> float:
    """Sum every sample matching metric_name (and, if given, a label subset) across every
    collector in the real Prometheus registry - the same registry /metrics (below)
    exposes in exposition format. Used only to build the small JSON summary below; the
    raw /metrics endpoint remains the source of truth for actual Prometheus scraping."""
    total = 0.0
    for metric in REGISTRY.collect():
        for sample in metric.samples:
            if sample.name != metric_name:
                continue
            if labels and any(sample.labels.get(k) != v for k, v in labels.items()):
                continue
            total += sample.value
    return total


# Registered before app.mount("/metrics", ...) below: Starlette's router checks routes
# in registration order, and a Mount("/metrics", ...) prefix-matches every path under
# /metrics, including /metrics/summary. Defining this route first makes FastAPI match it
# before falling through to the mount - discovered as a real bug during Phase 6
# verification (this endpoint returned raw Prometheus exposition text, not JSON, until
# the ordering was fixed).
@app.get("/metrics/summary")
async def metrics_summary(
    _current_user: CurrentUser = Depends(require_permission("missions:read")),
) -> dict[str, object]:
    """A small JSON view over the real Prometheus registry for Mission Control's
    dashboard tiles - avoids standing up a second metrics pipeline just to render a few
    numbers in the UI. Every value here also appears in raw form at GET /metrics."""
    http_requests = _sample_value("gds_http_requests_total")
    http_duration_sum = _sample_value("gds_http_request_duration_seconds_sum")
    http_duration_count = _sample_value("gds_http_request_duration_seconds_count")
    llm_calls = _sample_value("gds_llm_calls_total")
    tool_executions = _sample_value("gds_tool_executions_total")
    tool_errors = _sample_value("gds_tool_executions_total", {"outcome": "error"})

    avg_http_latency_ms = (
        (http_duration_sum / http_duration_count) * 1000 if http_duration_count else None
    )
    return {
        "http_requests_total": http_requests,
        "avg_http_latency_ms": avg_http_latency_ms,
        "llm_calls_total": llm_calls,
        "tool_executions_total": tool_executions,
        "tool_execution_errors_total": tool_errors,
    }


app.mount("/metrics", make_asgi_app())


@app.get("/health")
async def health() -> dict[str, object]:
    services = await check_all_services()
    overall = "healthy" if all(s.status == "healthy" for s in services) else "degraded"
    return {
        "status": overall,
        "version": __version__,
        "timestamp": datetime.now(UTC).isoformat(),
        "services": {
            s.name: {"status": s.status, "detail": s.detail, "latency_ms": s.latency_ms}
            for s in services
        },
    }


@app.get("/health/live")
async def health_live() -> dict[str, object]:
    """Process-up liveness only, no dependency checks - cheap, for a load
    balancer/orchestrator to distinguish "process is running" from "fully ready"
    (/health, which does real connectivity checks against every infra service)."""
    return {"status": "alive", "version": __version__, "timestamp": datetime.now(UTC).isoformat()}

# === Gap Routes: CIEM, Cloud, Agents, Security Tools, Policy, Approvals ===
try:
    from gds_api.db import get_db
    from gds_api.gap_routes import create_gap_routers
    _gap_routers = create_gap_routers(get_db)
    for _router in _gap_routers:
        app.include_router(_router)
    print(f"[GDS] Gap routes loaded: {len(_gap_routers)} routers")
except ImportError as e:
    print(f"[GDS] Gap routes skipped (module not found): {e}")
except Exception as e:
    print(f"[GDS] Gap routes error: {e}")

# === Billing Routes (Stripe checkout, portal, webhook — GBP) ===
try:
    from gds_api.billing.router import router as billing_router
    app.include_router(billing_router)
    print("[GDS] Billing routes loaded")
except ImportError as e:
    print(f"[GDS] Billing routes skipped: {e}")
except Exception as e:
    print(f"[GDS] Billing routes error: {e}")
# === Agentic Planner ===
try:
    from gds_api.agentic.planner import AgentPlanner
    print('[GDS] Agentic Planner loaded')
except Exception as e:
    print(f'[GDS] Agentic Planner skipped: {e}')

# GDS Agent Kernel Router
app.include_router(kernel_router)
