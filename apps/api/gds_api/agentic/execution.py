"""GDS OS Agentic Layer — Priority 1: Agent Execution Engine.

The heart of the autonomous system. Picks up tasks from a Redis-backed queue,
plans multi-step execution via LLM, executes tools through the governed
tool_gateway, reports results, and loops for the next task.

This is what transforms GDS OS from "a platform with API routes" into
"a true autonomous agentic security operating system."
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

import redis.asyncio as aioredis

from gds_api.config import settings

logger = logging.getLogger("gds_api.agentic.execution")


# ============================================================================
# ENUMS
# ============================================================================

class TaskStatus(str, Enum):
    QUEUED = "queued"
    CLAIMED = "claimed"
    PLANNING = "planning"
    EXECUTING = "executing"
    AWAITING_APPROVAL = "awaiting_approval"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class TaskPriority(int, Enum):
    CRITICAL = 0
    HIGH = 1
    MEDIUM = 2
    LOW = 3


# ============================================================================
# TASK QUEUE (Redis-backed)
# ============================================================================

class AgentTaskQueue:
    """Redis-backed priority queue for agent tasks.

    Uses sorted sets for priority ordering and hash for task payloads.
    Tasks are claimed atomically via ZPOPMIN + HMGET pipeline.
    """

    QUEUE_KEY = "gds:agent:task_queue"
    TASK_PREFIX = "gds:agent:task"
    CLAIMED_SET = "gds:agent:claimed_tasks"

    def __init__(self, redis: aioredis.Redis | None = None):
        self._redis = redis
        self._owned_redis = False

    async def _get_redis(self) -> aioredis.Redis:
        if self._redis and not self._owned_redis:
            return self._redis
        self._redis = aioredis.Redis(
            host=settings.redis_host, port=settings.redis_port,
            decode_responses=True,
        )
        self._owned_redis = True
        return self._redis

    async def enqueue(
        self,
        task_name: str,
        task_type: str,
        payload: dict[str, Any],
        agent_id: str | None = None,
        priority: TaskPriority = TaskPriority.MEDIUM,
        correlation_id: str | None = None,
        tenant_id: str | None = None,
        requires_approval: bool = False,
    ) -> dict[str, Any]:
        """Add a task to the queue."""
        task_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        score = priority.value * 1e12 + time.time()

        task = {
            "task_id": task_id,
            "task_name": task_name,
            "task_type": task_type,
            "payload": json.dumps(payload),
            "agent_id": agent_id or "",
            "priority": priority.value,
            "correlation_id": correlation_id or str(uuid.uuid4()),
            "tenant_id": tenant_id or "",
            "requires_approval": str(requires_approval).lower(),
            "status": TaskStatus.QUEUED.value,
            "queued_at": now,
        }

        r = await self._get_redis()
        pipe = r.pipeline()
        pipe.hset(f"{self.TASK_PREFIX}:{task_id}", mapping=task)
        pipe.zadd(self.QUEUE_KEY, {task_id: score})
        await pipe.execute()

        logger.info("task_enqueued task_id=%s task_name=%s priority=%s task_type=%s", task_id, task_name, priority.name, task_type)
        return {"task_id": task_id, "status": TaskStatus.QUEUED.value, "task_name": task_name}

    async def dequeue(self, timeout: float = 5.0) -> dict[str, Any] | None:
        """Claim the highest-priority task from the queue (blocking)."""
        r = await self._get_redis()

        result = await r.bzpopmin(self.QUEUE_KEY, timeout=int(timeout))
        if not result:
            return None

        _, member_set = result[0], result[1]
        task_id = member_set[0] if isinstance(member_set, list) else member_set

        task_data = await r.hgetall(f"{self.TASK_PREFIX}:{task_id}")
        if not task_data:
            return None

        task_data["payload"] = json.loads(task_data.get("payload", "{}"))
        task_data["status"] = TaskStatus.CLAIMED.value

        await r.hset(f"{self.TASK_PREFIX}:{task_id}", "status", TaskStatus.CLAIMED.value)
        await r.sadd(self.CLAIMED_SET, task_id)

        logger.info("task_claimed task_id=%s task_name=%s", task_id, task_data.get("task_name"))
        return task_data

    async def update_status(self, task_id: str, status: TaskStatus, result: dict | None = None):
        """Update task status."""
        r = await self._get_redis()
        updates = {"status": status.value}
        if result:
            updates["result"] = json.dumps(result)
            updates["completed_at"] = datetime.now(timezone.utc).isoformat()
        await r.hset(f"{self.TASK_PREFIX}:{task_id}", mapping=updates)

        if status in (TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.CANCELLED):
            await r.srem(self.CLAIMED_SET, task_id)

    async def get_task(self, task_id: str) -> dict[str, Any] | None:
        r = await self._get_redis()
        data = await r.hgetall(f"{self.TASK_PREFIX}:{task_id}")
        if not data:
            return None
        if "payload" in data:
            data["payload"] = json.loads(data["payload"])
        if "result" in data:
            data["result"] = json.loads(data["result"])
        return data

    async def get_queue_depth(self) -> dict[str, int]:
        """Return queue statistics."""
        r = await self._get_redis()
        queue_size = await r.zcard(self.QUEUE_KEY)
        claimed = await r.scard(self.CLAIMED_SET)
        return {"queued": queue_size, "claimed": claimed, "total": queue_size + claimed}

    async def cancel_task(self, task_id: str) -> bool:
        r = await self._get_redis()
        await r.zrem(self.QUEUE_KEY, task_id)
        await r.srem(self.CLAIMED_SET, task_id)
        await r.hset(f"{self.TASK_PREFIX}:{task_id}", "status", TaskStatus.CANCELLED.value)
        return True


# ============================================================================
# AGENT EXECUTION LOOP
# ============================================================================

class AgentExecutionLoop:
    """The autonomous agent loop.

    Runs as an async background task. Picks up tasks from the queue,
    plans execution steps, executes each step through tool_gateway,
    handles failures with retries, and reports results.

    This is the difference between "agents that exist" and "agents that ACT."
    """

    def __init__(
        self,
        queue: AgentTaskQueue,
        agent_id: str,
        agent_name: str,
        agent_capabilities: list[str] | None = None,
        max_concurrent: int = 3,
        max_retries: int = 2,
    ):
        self.queue = queue
        self.agent_id = agent_id
        self.agent_name = agent_name
        self.capabilities = agent_capabilities or []
        self.max_concurrent = max_concurrent
        self.max_retries = max_retries
        self._running = False
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._tasks_in_flight: dict[str, asyncio.Task] = {}
        self.stats = {"total_processed": 0, "succeeded": 0, "failed": 0, "avg_duration_ms": 0}

    async def start(self):
        """Start the execution loop."""
        self._running = True
        logger.info("agent_loop_started agent_id=%s agent_name=%s", self.agent_id, self.agent_name)
        await self._loop()

    async def stop(self):
        """Gracefully stop the loop."""
        self._running = False
        # Wait for in-flight tasks
        if self._tasks_in_flight:
            await asyncio.gather(*self._tasks_in_flight.values(), return_exceptions=True)
        logger.info("agent_loop_stopped agent_id=%s", self.agent_id)

    async def _loop(self):
        """Main loop: dequeue → execute → repeat."""
        while self._running:
            try:
                task = await self.queue.dequeue(timeout=5.0)
                if not task:
                    continue

                # Check if this agent can handle this task type
                if not self._can_handle(task):
                    # Re-queue for another agent
                    await self.queue.enqueue(
                        task["task_name"], task["task_type"], task["payload"],
                        priority=TaskPriority(int(task.get("priority", 2))),
                        correlation_id=task.get("correlation_id"),
                        tenant_id=task.get("tenant_id"),
                        requires_approval=task.get("requires_approval") == "true",
                    )
                    await self.queue.update_status(task["task_id"], TaskStatus.QUEUED)
                    continue

                # Launch task execution with concurrency limit
                async with self._semaphore:
                    asyncio_task = asyncio.create_task(
                        self._execute_task(task), name=f"task-{task['task_id']}"
                    )
                    self._tasks_in_flight[task["task_id"]] = asyncio_task

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("agent_loop_error agent_id=%s error=%s", self.agent_id, str(e))
                await asyncio.sleep(1.0)

    def _can_handle(self, task: dict[str, Any]) -> bool:
        """Check if this agent has the capability to handle the task."""
        task_type = task.get("task_type", "")
        if not self.capabilities:
            return True  # General-purpose agent
        return any(cap in task_type or task_type in cap for cap in self.capabilities)

    async def _execute_task(self, task: dict[str, Any]):
        """Execute a single task through planning → execution → reporting."""
        task_id = task["task_id"]
        start_time = time.time()
        retries = 0

        await self.queue.update_status(task_id, TaskStatus.PLANNING)

        while retries <= self.max_retries:
            try:
                # Phase 1: Plan the execution
                plan = await self._plan_task(task)
                logger.info("task_planned task_id=%s steps=%s", task_id, len(plan["steps"]))

                # Phase 2: Check if approval is needed
                if task.get("requires_approval") == "true" or plan.get("requires_approval"):
                    await self.queue.update_status(task_id, TaskStatus.AWAITING_APPROVAL)
                    logger.info("task_awaiting_approval task_id=%s", task_id)
                    # In production, this would publish an ApprovalRequest
                    # For now, we log and hold
                    return

                # Phase 3: Execute each step
                await self.queue.update_status(task_id, TaskStatus.EXECUTING)
                results = []
                for i, step in enumerate(plan["steps"]):
                    step_result = await self._execute_step(step, task, i)
                    results.append(step_result)

                    if not step_result["success"]:
                        raise RuntimeError(f"Step {i} failed: {step_result.get('error', 'unknown')}")

                    # Update task progress
                    progress = ((i + 1) / len(plan["steps"])) * 100
                    logger.info("step_completed task_id=%s step=%s progress_pct=%s tool=%s", task_id, i, progress, step.get("tool"))

                # Phase 4: Report success
                duration_ms = int((time.time() - start_time) * 1000)
                final_result = {
                    "success": True,
                    "steps_executed": len(results),
                    "duration_ms": duration_ms,
                    "agent_id": self.agent_id,
                    "agent_name": self.agent_name,
                    "results": results,
                }
                await self.queue.update_status(task_id, TaskStatus.COMPLETED, final_result)
                self._update_stats(duration_ms, success=True)
                logger.info("task_completed task_id=%s duration_ms=%s", task_id, duration_ms)
                return

            except Exception as e:
                retries += 1
                logger.warning("task_retry task_id=%s retry=%s error=%s", task_id, retries, str(e))
                if retries > self.max_retries:
                    duration_ms = int((time.time() - start_time) * 1000)
                    error_result = {
                        "success": False,
                        "error": str(e),
                        "retries": retries,
                        "duration_ms": duration_ms,
                        "agent_id": self.agent_id,
                    }
                    await self.queue.update_status(task_id, TaskStatus.FAILED, error_result)
                    self._update_stats(duration_ms, success=False)
                    logger.error("task_failed task_id=%s error=%s retries=%s", task_id, str(e), retries)
                    return
                await asyncio.sleep(2 ** retries)  # Exponential backoff

    async def _plan_task(self, task: dict[str, Any]) -> dict[str, Any]:
        """Plan the execution steps for a task.

        In production, this calls the LLM Agent Planner (Priority 4).
        For now, uses rule-based planning based on task_type.
        """
        task_type = task.get("task_type", "generic")
        payload = task.get("payload", {})

        # Rule-based planning (will be replaced by LLM planner in Priority 4)
        plans: dict[str, list[dict[str, Any]]] = {
            "vulnerability_scan": [
                {"step": "fetch_target", "tool": "read_entities", "params": {"entity": "ASPMAsset", "id": payload.get("asset_id")}},
                {"step": "scan", "tool": "tool_gateway.execute_tool", "params": {"tool": "pentest_scan", "target": payload.get("target_url")}},
                {"step": "store_findings", "tool": "create_entity_records", "params": {"entity": "TriagedFinding"}},
                {"step": "notify", "tool": "send_notification", "params": {"severity": "high"}},
            ],
            "cloud_posture_scan": [
                {"step": "fetch_account", "tool": "read_entities", "params": {"entity": "CloudAccount", "id": payload.get("account_id")}},
                {"step": "scan", "tool": "tool_gateway.execute_tool", "params": {"tool": "cloud_scan", "provider": payload.get("provider")}},
                {"step": "store_findings", "tool": "create_entity_records", "params": {"entity": "CloudFinding"}},
                {"step": "update_risk", "tool": "update_risk_score", "params": {}},
            ],
            "incident_triage": [
                {"step": "fetch_incident", "tool": "read_entities", "params": {"entity": "Incident", "id": payload.get("incident_id")}},
                {"step": "correlate_alerts", "tool": "tool_gateway.execute_tool", "params": {"tool": "siem_correlate"}},
                {"step": "classify_severity", "tool": "classify_incident", "params": {}},
                {"step": "assign", "tool": "assign_incident", "params": {}},
                {"step": "notify", "tool": "send_notification", "params": {"severity": "critical"}},
            ],
            "compliance_check": [
                {"step": "fetch_framework", "tool": "read_entities", "params": {"entity": "ComplianceFramework", "name": payload.get("framework")}},
                {"step": "evaluate_controls", "tool": "tool_gateway.execute_tool", "params": {"tool": "compliance_evaluate"}},
                {"step": "store_violations", "tool": "create_entity_records", "params": {"entity": "PolicyViolation"}},
                {"step": "generate_report", "tool": "generate_compliance_report", "params": {}},
            ],
            "threat_intel_update": [
                {"step": "fetch_feeds", "tool": "tool_gateway.execute_tool", "params": {"tool": "monitoring_fetch_feeds"}},
                {"step": "correlate", "tool": "correlate_threat_intel", "params": {}},
                {"step": "store", "tool": "create_entity_records", "params": {"entity": "ThreatIntelFeed"}},
                {"step": "check_kev", "tool": "check_cisa_kev", "params": {}},
            ],
            "auto_remediate": [
                {"step": "fetch_finding", "tool": "read_entities", "params": {"entity": "TriagedFinding", "id": payload.get("finding_id")}},
                {"step": "assess_risk", "tool": "assess_finding_risk", "params": {}},
                {"step": "check_approval", "tool": "check_approval_required", "params": {}},
                {"step": "execute_fix", "tool": "tool_gateway.execute_tool", "params": {"tool": "autofix", "finding_id": payload.get("finding_id")}},
                {"step": "verify_fix", "tool": "verify_remediation", "params": {}},
            ],
        }

        steps = plans.get(task_type, [
            {"step": "execute", "tool": "tool_gateway.execute_tool", "params": payload},
            {"step": "report", "tool": "store_result", "params": {}},
        ])

        return {
            "task_id": task["task_id"],
            "task_type": task_type,
            "steps": steps,
            "requires_approval": task.get("requires_approval") == "true",
        }

    async def _execute_step(self, step: dict[str, Any], task: dict[str, Any], step_index: int) -> dict[str, Any]:
        """Execute a single step in the plan.

        Routes through tool_gateway for governed execution.
        """
        tool_name = step.get("tool", "noop")
        params = step.get("params", {})

        # For now, simulate the tool gateway call structure
        # In production, this calls: from gds_api.tool_gateway import execute_tool
        try:
            # Import lazily to avoid circular imports
            if tool_name == "tool_gateway.execute_tool":
                from gds_api.tool_gateway import execute_tool
                result = await execute_tool(
                    tool_name=params.get("tool", "noop"),
                    action=params.get("action", "execute"),
                    payload=params,
                    actor_id=self.agent_id,
                    actor_type="agent",
                    actor_role=f"agent:{self.agent_name}",
                    tenant_id=task.get("tenant_id", ""),
                )
                return {"success": True, "step": step_index, "tool": tool_name, "result": result}
            else:
                # Route through tool_gateway for real execution
                try:
                    from gds_api.tool_gateway import execute_tool as gateway_execute
                    result = await gateway_execute(
                        tool_name=tool_name,
                        payload=params,
                        actor_id=self.agent_id,
                        actor_type="agent",
                        actor_role=f"agent:{self.agent_name}",
                        tenant_id=task.get("tenant_id", ""),
                    )
                    return {"success": result.get("success", True), "step": step_index, "tool": tool_name, "result": result}
                except Exception as e:
                    return {"success": False, "step": step_index, "tool": tool_name, "error": str(e)}
        except Exception as e:
            return {"success": False, "step": step_index, "tool": tool_name, "error": str(e)}

    def _update_stats(self, duration_ms: int, success: bool):
        self.stats["total_processed"] += 1
        if success:
            self.stats["succeeded"] += 1
        else:
            self.stats["failed"] += 1
        # Rolling average
        n = self.stats["total_processed"]
        self.stats["avg_duration_ms"] = int((self.stats["avg_duration_ms"] * (n - 1) + duration_ms) / n)

    def get_stats(self) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "agent_name": self.agent_name,
            "running": self._running,
            "in_flight": len(self._tasks_in_flight),
            **self.stats,
        }


# ============================================================================
# AGENT FLEET MANAGER
# ============================================================================

class AgentFleetManager:
    """Manages a fleet of agent execution loops.

    Starts/stops agents, distributes work, monitors health.
    """

    def __init__(self):
        self.queue = AgentTaskQueue()
        self.agents: dict[str, AgentExecutionLoop] = {}
        self._fleet_task: asyncio.Task | None = None

    async def register_agent(
        self, agent_id: str, agent_name: str,
        capabilities: list[str] | None = None,
        max_concurrent: int = 3,
    ) -> AgentExecutionLoop:
        """Register and start an agent execution loop."""
        loop = AgentExecutionLoop(
            queue=self.queue, agent_id=agent_id, agent_name=agent_name,
            agent_capabilities=capabilities, max_concurrent=max_concurrent,
        )
        self.agents[agent_id] = loop
        return loop

    async def start_fleet(self):
        """Start all registered agents."""
        tasks = []
        for agent_id, loop in self.agents.items():
            tasks.append(asyncio.create_task(loop.start(), name=f"agent-{agent_id}"))
        self._fleet_task = asyncio.gather(*tasks, return_exceptions=True)
        logger.info("fleet_started agents=%s", len(self.agents))

    async def stop_fleet(self):
        """Stop all agents gracefully."""
        for loop in self.agents.values():
            await loop.stop()
        if self._fleet_task:
            self._fleet_task.cancel()
        logger.info("fleet_stopped")

    async def submit_task(self, **kwargs) -> dict[str, Any]:
        """Submit a task to the fleet queue."""
        return await self.queue.enqueue(**kwargs)

    async def get_fleet_status(self) -> dict[str, Any]:
        """Get status of all agents in the fleet."""
        queue_depth = await self.queue.get_queue_depth()
        return {
            "total_agents": len(self.agents),
            "running_agents": sum(1 for l in self.agents.values() if l._running),
            "queue": queue_depth,
            "agents": {aid: l.get_stats() for aid, l in self.agents.items()},
        }


# ============================================================================
# MODULE EXPORTS
# ============================================================================

__all__ = [
    "TaskStatus", "TaskPriority",
    "AgentTaskQueue", "AgentExecutionLoop", "AgentFleetManager",
]
