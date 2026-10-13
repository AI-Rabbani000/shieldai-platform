"""Temporal worker entrypoint: registers MissionWorkflow, ConversationTurnWorkflow
(Phase 10.3 - a real chat turn, backed by the exact same activities), MonitoringWorkflow
(continuous monitoring engine), and every activity, then polls the gds-missions task
queue. Run with the venv's python:
`.venv\\Scripts\\python.exe -m gds_api.worker_main` (start-gds.ps1 does this alongside
the API and web processes).

Every real LLM call and tool execution happens inside activities.py, which runs in THIS
process, not the FastAPI process - prometheus_client's default registry is per-process,
so main.py's /metrics endpoint can never see this process's counters. This process gets
its own tiny metrics HTTP server (prometheus_client.start_http_server), scraped as a
second Prometheus target - a real gap only found by actually checking Grafana/Prometheus
for mission data after a real mission run, not by assuming the shared-registry design
from main.py would just work this too.
"""

import asyncio

from prometheus_client import start_http_server
from temporalio.worker import Worker

from gds_api.config import settings
from gds_api.logging_config import configure_logging, get_logger
from gds_api.temporal_client import TASK_QUEUE, get_temporal_client
from gds_api.workflows import activities
from gds_api.workflows.conversation_workflow import ConversationTurnWorkflow
from gds_api.workflows.mission_workflow import MissionWorkflow
from gds_api.workflows.monitoring_workflow import (
    MonitoringWorkflow,
    run_monitoring_cycle_activity,
    _check_schedule_active,
    _get_schedule_interval,
)

configure_logging()
logger = get_logger("gds_api.worker")


async def main() -> None:
    start_http_server(settings.worker_metrics_port)
    logger.info("worker.metrics_server_started", port=settings.worker_metrics_port)
    client = await get_temporal_client()
    worker = Worker(
        client,
        task_queue=TASK_QUEUE,
        workflows=[
            MissionWorkflow,
            ConversationTurnWorkflow,
            MonitoringWorkflow,
        ],
        activities=[
            activities.assess_mission,
            activities.decide_next_step,
            activities.evaluate_task,
            activities.check_approval,
            activities.execute_task,
            activities.deny_task,
            activities.synthesize_report,
            activities.mark_mission_failed,
            # Monitoring activities
            run_monitoring_cycle_activity,
            _check_schedule_active,
            _get_schedule_interval,
        ],
    )
    logger.info("worker.polling", task_queue=TASK_QUEUE)
    await worker.run()


if __name__ == "__main__":
    asyncio.run(main())
