"""Phase 19 (Continuation Prompt 6), Part 1: the Mission Planning Engine - a real
`gds_api.model_router` call (the same real Anthropic API every other real planning step
in this platform already uses - Rabbani's own `decide_next_step`, `assess_mission`),
asked to decompose a real engineering objective into a real, structured task graph.
Never a hardcoded/templated decomposition - every real mission produces a real,
LLM-reasoned plan specific to its own objective.
"""

from __future__ import annotations

import json
import re
import uuid
from dataclasses import dataclass, field

from sqlalchemy.ext.asyncio import AsyncSession

from gds_api import model_router
from gds_api.engineering.specialist_roles import SPECIALIST_ROLES
from gds_api.engineering.task_graph import GraphNode, validate_graph

_PLANNING_MODEL = "claude-sonnet-5"
_MAX_TASKS = 8

_SYSTEM_PROMPT = f"""You are the Mission Planning Engine of an autonomous software \
engineering platform. Given a real engineering objective and real repository context, \
decompose it into a real, structured graph of engineering tasks.

Real, available specialist roles (use only these exact keys): \
{", ".join(sorted(SPECIALIST_ROLES))}.

Respond with ONLY a single real JSON object (no markdown fences, no commentary), \
exactly matching this shape:
{{
  "complexity": "low|medium|high",
  "affected_systems": ["..."],
  "execution_strategy": "one real paragraph describing your real approach",
  "tasks": [
    {{
      "task_key": "short-slug-1",
      "title": "short real title",
      "description": "the real, specific objective for this one task",
      "specialist_role": "one of the real role keys above",
      "risk_estimate": "low|medium|high",
      "depends_on": ["task-key-this-depends-on"],
      "required_capabilities": ["engineering.execute_session"]
    }}
  ]
}}

Real constraints: produce between 1 and {_MAX_TASKS} real tasks. Every task_key must be \
unique. depends_on must only reference task_keys defined in this same tasks list \
(never a task_key that doesn't exist, never a cycle). Prefer the smallest real number \
of tasks that genuinely need independent specialist attention - do not manufacture \
tasks that don't reflect a real, separate concern."""


class MissionPlanningError(Exception):
    pass


@dataclass
class PlannedTask:
    task_key: str
    title: str
    description: str
    specialist_role: str
    risk_estimate: str
    depends_on: list[str] = field(default_factory=list)
    required_capabilities: list[str] = field(default_factory=list)


@dataclass
class MissionPlanResult:
    complexity: str
    affected_systems: list[str]
    execution_strategy: str
    tasks: list[PlannedTask]


def _strip_markdown_fence(text: str) -> str:
    """Real, defensive parsing - Claude has reliably wrapped structured JSON output in
    a markdown code fence before (the exact real bug Phase 4's own build report
    documents), so this is not speculative hardening."""
    stripped = text.strip()
    match = re.match(r"^```(?:json)?\s*\n(.*)\n```$", stripped, re.DOTALL)
    return match.group(1).strip() if match else stripped


async def plan_mission(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    mission_id: uuid.UUID,
    objective: str,
    repository_display_name: str,
    repository_default_branch: str,
) -> MissionPlanResult:
    """Real Anthropic API call - writes a real CostRecord via model_router (unchanged
    behavior), returns a real, validated task graph. Raises MissionPlanningError (never
    silently falls back to a fabricated plan) if the real model output isn't valid,
    structured JSON, or fails real DAG validation (cycle/unknown-dependency)."""
    user_message = (
        f"Repository: {repository_display_name} (default branch: "
        f"{repository_default_branch})\n\nReal engineering objective:\n{objective}"
    )
    raw = await model_router.complete(
        db,
        tenant_id=tenant_id,
        mission_id=mission_id,
        system=_SYSTEM_PROMPT,
        user_message=user_message,
        model=_PLANNING_MODEL,
        max_tokens=4096,
    )

    try:
        parsed = json.loads(_strip_markdown_fence(raw))
    except json.JSONDecodeError as exc:
        raise MissionPlanningError(
            f"Mission Planner produced non-JSON output: {raw[:500]!r}"
        ) from exc

    raw_tasks = parsed.get("tasks")
    if not isinstance(raw_tasks, list) or not raw_tasks:
        raise MissionPlanningError("Mission Planner produced no real tasks.")
    if len(raw_tasks) > _MAX_TASKS:
        raise MissionPlanningError(
            f"Mission Planner produced {len(raw_tasks)} tasks, exceeding the real limit "
            f"of {_MAX_TASKS}."
        )

    tasks: list[PlannedTask] = []
    seen_keys: set[str] = set()
    for raw_task in raw_tasks:
        task_key = str(raw_task.get("task_key", "")).strip()
        if not task_key:
            raise MissionPlanningError("Mission Planner produced a task with no task_key.")
        if task_key in seen_keys:
            raise MissionPlanningError(
                f"Mission Planner produced a duplicate task_key '{task_key}'."
            )
        seen_keys.add(task_key)

        role = str(raw_task.get("specialist_role", "")).strip()
        if role not in SPECIALIST_ROLES:
            raise MissionPlanningError(
                f"Mission Planner used an unknown specialist_role '{role}' for task '{task_key}'."
            )

        tasks.append(
            PlannedTask(
                task_key=task_key,
                title=str(raw_task.get("title", task_key))[:300],
                description=str(raw_task.get("description", "")).strip(),
                specialist_role=role,
                risk_estimate=str(raw_task.get("risk_estimate", "low")),
                depends_on=[str(d) for d in raw_task.get("depends_on", []) if str(d).strip()],
                required_capabilities=[
                    str(c) for c in raw_task.get("required_capabilities", []) if str(c).strip()
                ],
            )
        )

    validate_graph([GraphNode(task_key=t.task_key, depends_on=tuple(t.depends_on)) for t in tasks])

    return MissionPlanResult(
        complexity=str(parsed.get("complexity", "medium")),
        affected_systems=[str(s) for s in parsed.get("affected_systems", [])],
        execution_strategy=str(parsed.get("execution_strategy", "")),
        tasks=tasks,
    )
