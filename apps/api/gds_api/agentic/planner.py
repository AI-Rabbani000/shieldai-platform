"""GDS OS Agentic Layer — Priority 4: LLM Agent Planner.

Gives agents the ability to reason and plan using LLM integration.
Instead of following fixed code paths, agents decompose goals into sub-tasks,
select appropriate tools, plan execution sequences, evaluate results,
and decide next steps.
"""
from __future__ import annotations

import json
import logging
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

from gds_api.config import settings

logger = logging.getLogger("gds_api.agentic.planner")

# ============================================================================
# CONSTANTS & CONFIGURATION
# ============================================================================

CONFIDENCE_LEVELS: dict[str, tuple[float, float]] = {
    "high": (0.8, 1.0),
    "medium": (0.5, 0.79),
    "low": (0.0, 0.49),
}

APPROVAL_TRIGGERS: list[dict[str, Any]] = [
    {
        "category": "destructive_actions",
        "keywords": ["delete", "destroy", "terminate", "drop", "wipe", "clear", "purge", "truncate", "kill"],
        "reason": "Destructive operation detected that modifies or removes persistent infrastructure or data.",
    },
    {
        "category": "iam_changes",
        "keywords": ["iam", "modify_policy", "grant_role", "create_user", "permission_change", "role_binding", "revoke_access", "attach_policy"],
        "reason": "Identity and Access Management (IAM) modification detected.",
    },
    {
        "category": "data_deletion",
        "keywords": ["data_delete", "truncate", "drop_table", "delete_records", "purge_logs", "remove_db"],
        "reason": "Bulk data deletion or database modification requested.",
    },
    {
        "category": "external_communication",
        "keywords": ["external_email", "public_broadcast", "send_external_alert", "slack_post_channel", "webhook_trigger", "external_notify"],
        "reason": "External notification or broadcast to external systems required.",
    },
    {
        "category": "privileged_access",
        "keywords": ["sudo", "root_access", "grant_admin", "rotate_master_key", "elevate_privileges", "admin_override", "secret_export"],
        "reason": "Operation requires root/privileged access or credential elevation.",
    },
]

SYSTEM_PROMPT = """You are the Autonomous Agent Planner for GDS OS Security Operations.
Your role is to reason through security goals, decompose complex tasks into ordered sub-tasks,
select appropriate tools and tool actions, assess risks and required human approvals, and generate precise execution plans.

When given a goal or security task:
1. Decompose the goal into logical, ordered sub-tasks (PlanStep).
2. For each step, specify:
   - step_number: Sequential integer starting from 1.
   - step_name: Concise descriptive name for the sub-task.
   - tool_name: Target tool (e.g., 'read_entities', 'create_entity_records', 'tool_gateway.execute_tool', 'autofix', 'pentest_scan', 'cloud_scan', 'siem_correlate', 'compliance_evaluate').
   - tool_action: Specific action for the tool (e.g., 'read', 'execute', 'scan', 'triage', 'remediate', 'correlate').
   - params: Dictionary of parameters needed for tool execution.
   - depends_on: List of step_numbers that must complete before this step can execute.
   - requires_approval: Boolean indicating if human approval is required before running this step.
   - estimated_duration_s: Estimated execution time in seconds.

3. Quantify uncertainty with a confidence_score between 0.0 and 1.0.
4. Evaluate whether human approval is required for the entire plan based on sensitive operations (destructive actions, IAM changes, data deletion, external communication, privileged access).
5. Output ONLY a valid JSON object matching this schema:
{
  "goal": "string",
  "confidence_score": 0.9,
  "confidence_level": "high",
  "requires_approval": false,
  "approval_reason": "",
  "estimated_duration_s": 120,
  "steps": [
    {
      "step_number": 1,
      "step_name": "fetch_target",
      "tool_name": "read_entities",
      "tool_action": "read",
      "params": {"entity": "ASPMAsset"},
      "depends_on": [],
      "requires_approval": false,
      "estimated_duration_s": 10
    }
  ]
}
Do not include markdown code block backticks or commentary outside the JSON response."""


# ============================================================================
# DATACLASSES / PLAN MODELS
# ============================================================================

@dataclass
class PlanStep:
    """Represents a single executable step within an AgentPlan."""

    step_number: int
    step_name: str
    tool_name: str
    tool_action: str
    params: dict[str, Any] = field(default_factory=dict)
    depends_on: list[int] = field(default_factory=list)
    requires_approval: bool = False
    estimated_duration_s: int = 30

    def to_dict(self) -> dict[str, Any]:
        return {
            "step_number": self.step_number,
            "step_name": self.step_name,
            "tool_name": self.tool_name,
            "tool_action": self.tool_action,
            "params": self.params,
            "depends_on": self.depends_on,
            "requires_approval": self.requires_approval,
            "estimated_duration_s": self.estimated_duration_s,
        }

    def __getitem__(self, key: str) -> Any:
        if hasattr(self, key):
            return getattr(self, key)
        raise KeyError(key)

    def __setitem__(self, key: str, value: Any) -> None:
        if hasattr(self, key):
            setattr(self, key, value)
        else:
            raise KeyError(key)

    def get(self, key: str, default: Any = None) -> Any:
        return getattr(self, key, default)

    def keys(self):
        return self.to_dict().keys()

    def values(self):
        return self.to_dict().values()

    def items(self):
        return self.to_dict().items()

    def __contains__(self, key: str) -> bool:
        return hasattr(self, key)


@dataclass
class AgentPlan:
    """Represents a complete reasoning plan generated for an agent task."""

    plan_id: str
    task_id: str
    goal: str
    steps: list[PlanStep]
    confidence_score: float
    confidence_level: str
    requires_approval: bool
    approval_reason: str
    estimated_duration_s: int
    created_at: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "plan_id": self.plan_id,
            "task_id": self.task_id,
            "goal": self.goal,
            "steps": [s.to_dict() if isinstance(s, PlanStep) else s for s in self.steps],
            "confidence_score": self.confidence_score,
            "confidence_level": self.confidence_level,
            "requires_approval": self.requires_approval,
            "approval_reason": self.approval_reason,
            "estimated_duration_s": self.estimated_duration_s,
            "created_at": self.created_at,
        }

    def __getitem__(self, key: str) -> Any:
        if hasattr(self, key):
            val = getattr(self, key)
            if key == "steps":
                return [s.to_dict() if isinstance(s, PlanStep) else s for s in val]
            return val
        raise KeyError(key)

    def __setitem__(self, key: str, value: Any) -> None:
        if hasattr(self, key):
            setattr(self, key, value)
        else:
            raise KeyError(key)

    def get(self, key: str, default: Any = None) -> Any:
        if hasattr(self, key):
            return self[key]
        return default

    def keys(self):
        return self.to_dict().keys()

    def values(self):
        return self.to_dict().values()

    def items(self):
        return self.to_dict().items()

    def __contains__(self, key: str) -> bool:
        return hasattr(self, key)


# ============================================================================
# AGENT PLANNER CLASS
# ============================================================================

class AgentPlanner:
    """LLM-driven Agent Planner for GDS OS.

    Decomposes task goals into sub-tasks, selects tools, computes confidence
    scores, assesses human approval requirements, handles plan revisions,
    and supports multi-agent collaboration planning.
    """

    def __init__(
        self,
        agent_id: str,
        agent_name: str,
        capabilities: list[str] | None = None,
        llm_provider: str = "anthropic",
    ):
        self.agent_id = agent_id
        self.agent_name = agent_name
        self.capabilities = capabilities or []
        self.llm_provider = llm_provider.lower()
        self.logger = logger

    async def _call_llm(self, system: str, user_prompt: str) -> str | None:
        """Call LLM provider (Anthropic or OpenAI) without direct module import."""
        try:
            if self.llm_provider in ("anthropic", "claude"):
                if not settings.anthropic_api_key:
                    logger.debug("anthropic_api_key not configured, falling back to rule-based plan")
                    return None
                import anthropic

                client = anthropic.AsyncAnthropic(
                    api_key=settings.anthropic_api_key, max_retries=2, timeout=30.0
                )
                model = getattr(settings, "model_router_default_model", "claude-sonnet-5")
                response = await client.messages.create(
                    model=model,
                    max_tokens=4096,
                    system=system,
                    messages=[{"role": "user", "content": user_prompt}],
                )
                return "".join(b.text for b in response.content if b.type == "text")

            elif self.llm_provider == "openai":
                if not settings.openai_api_key:
                    logger.debug("openai_api_key not configured, falling back to rule-based plan")
                    return None
                import openai

                client = openai.AsyncOpenAI(
                    api_key=settings.openai_api_key, max_retries=2, timeout=30.0
                )
                model = getattr(settings, "engineering_openai_model", "gpt-5.3-codex")
                response = await client.chat.completions.create(
                    model=model,
                    messages=[
                        {"role": "system", "content": system},
                        {"role": "user", "content": user_prompt},
                    ],
                    max_tokens=4096,
                )
                return response.choices[0].message.content
            else:
                logger.warning(f"Unsupported llm_provider '{self.llm_provider}', using fallback plan")
                return None
        except Exception as e:
            logger.warning(f"LLM call failed for provider '{self.llm_provider}': {e}")
            return None

    def _build_planning_prompt(self, task: dict[str, Any]) -> str:
        """Build structured planning prompt for LLM from task payload."""
        task_id = task.get("task_id", str(uuid.uuid4()))
        task_name = task.get("task_name", "Security Task")
        task_type = task.get("task_type", "generic")
        payload = task.get("payload", {})
        goal = payload.get("goal") or payload.get("description") or f"Execute {task_name} ({task_type})"

        prompt = f"""Plan the execution steps for the following security task.

Task ID: {task_id}
Task Name: {task_name}
Task Type: {task_type}
Goal: {goal}
Agent ID: {self.agent_id}
Agent Name: {self.agent_name}
Agent Capabilities: {json.dumps(self.capabilities)}
Task Payload Context:
{json.dumps(payload, indent=2)}

Decompose this goal into a sequential or dependency-ordered list of execution steps (PlanStep).
Ensure every step selects the correct tool and parameters. Estimate execution duration and assess whether approval is needed."""
        return prompt

    def _parse_llm_response(self, response: str, task: dict[str, Any] | None = None) -> AgentPlan:
        """Parse raw LLM string into an AgentPlan object."""
        cleaned = response.strip()
        if cleaned.startswith("```"):
            lines = cleaned.splitlines()
            if lines[0].startswith("```"):
                lines = lines[1:]
            if lines and lines[-1].startswith("```"):
                lines = lines[:-1]
            cleaned = "\n".join(lines).strip()

        data = json.loads(cleaned)
        task_id = (task.get("task_id") if task else None) or data.get("task_id") or str(uuid.uuid4())
        goal = data.get("goal") or (task.get("task_name") if task else "Security Task")

        raw_steps = data.get("steps", [])
        steps: list[PlanStep] = []
        for idx, s in enumerate(raw_steps, start=1):
            if isinstance(s, dict):
                steps.append(
                    PlanStep(
                        step_number=int(s.get("step_number", idx)),
                        step_name=str(s.get("step_name", f"step_{idx}")),
                        tool_name=str(s.get("tool_name", "tool_gateway.execute_tool")),
                        tool_action=str(s.get("tool_action", "execute")),
                        params=s.get("params", {}),
                        depends_on=[int(d) for d in s.get("depends_on", []) if str(d).isdigit()],
                        requires_approval=bool(s.get("requires_approval", False)),
                        estimated_duration_s=int(s.get("estimated_duration_s", 30)),
                    )
                )

        confidence_score = float(data.get("confidence_score", 0.85))
        confidence_level = str(data.get("confidence_level", "high"))
        requires_approval = bool(data.get("requires_approval", False))
        approval_reason = str(data.get("approval_reason", ""))
        estimated_duration_s = int(
            data.get("estimated_duration_s", sum(st.estimated_duration_s for st in steps))
        )
        plan_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        return AgentPlan(
            plan_id=plan_id,
            task_id=task_id,
            goal=goal,
            steps=steps,
            confidence_score=confidence_score,
            confidence_level=confidence_level,
            requires_approval=requires_approval,
            approval_reason=approval_reason,
            estimated_duration_s=estimated_duration_s,
            created_at=now,
        )

    def _fallback_plan(self, task: dict[str, Any]) -> AgentPlan:
        """Rule-based planning fallback when LLM is unavailable or unconfigured.

        Matches and extends execution_engine.py's task_type rule-based plans.
        """
        task_id = task.get("task_id", str(uuid.uuid4()))
        task_name = task.get("task_name", "Security Task")
        task_type = task.get("task_type", "generic")
        payload = task.get("payload", {})
        goal = payload.get("goal") or f"Execute {task_name} ({task_type})"

        rule_plans: dict[str, list[dict[str, Any]]] = {
            "vulnerability_scan": [
                {
                    "step_name": "fetch_target",
                    "tool_name": "read_entities",
                    "tool_action": "read",
                    "params": {"entity": "ASPMAsset", "id": payload.get("asset_id")},
                    "depends_on": [],
                    "requires_approval": False,
                    "estimated_duration_s": 10,
                },
                {
                    "step_name": "scan",
                    "tool_name": "tool_gateway.execute_tool",
                    "tool_action": "pentest_scan",
                    "params": {"tool": "pentest_scan", "target": payload.get("target_url")},
                    "depends_on": [1],
                    "requires_approval": False,
                    "estimated_duration_s": 120,
                },
                {
                    "step_name": "store_findings",
                    "tool_name": "create_entity_records",
                    "tool_action": "create",
                    "params": {"entity": "TriagedFinding"},
                    "depends_on": [2],
                    "requires_approval": False,
                    "estimated_duration_s": 15,
                },
                {
                    "step_name": "notify",
                    "tool_name": "send_notification",
                    "tool_action": "notify",
                    "params": {"severity": "high"},
                    "depends_on": [3],
                    "requires_approval": False,
                    "estimated_duration_s": 5,
                },
            ],
            "cloud_posture_scan": [
                {
                    "step_name": "fetch_account",
                    "tool_name": "read_entities",
                    "tool_action": "read",
                    "params": {"entity": "CloudAccount", "id": payload.get("account_id")},
                    "depends_on": [],
                    "requires_approval": False,
                    "estimated_duration_s": 10,
                },
                {
                    "step_name": "scan",
                    "tool_name": "tool_gateway.execute_tool",
                    "tool_action": "cloud_scan",
                    "params": {"tool": "cloud_scan", "provider": payload.get("provider")},
                    "depends_on": [1],
                    "requires_approval": False,
                    "estimated_duration_s": 90,
                },
                {
                    "step_name": "store_findings",
                    "tool_name": "create_entity_records",
                    "tool_action": "create",
                    "params": {"entity": "CloudFinding"},
                    "depends_on": [2],
                    "requires_approval": False,
                    "estimated_duration_s": 15,
                },
                {
                    "step_name": "update_risk",
                    "tool_name": "update_risk_score",
                    "tool_action": "update",
                    "params": {},
                    "depends_on": [3],
                    "requires_approval": False,
                    "estimated_duration_s": 10,
                },
            ],
            "incident_triage": [
                {
                    "step_name": "fetch_incident",
                    "tool_name": "read_entities",
                    "tool_action": "read",
                    "params": {"entity": "Incident", "id": payload.get("incident_id")},
                    "depends_on": [],
                    "requires_approval": False,
                    "estimated_duration_s": 10,
                },
                {
                    "step_name": "correlate_alerts",
                    "tool_name": "tool_gateway.execute_tool",
                    "tool_action": "siem_correlate",
                    "params": {"tool": "siem_correlate"},
                    "depends_on": [1],
                    "requires_approval": False,
                    "estimated_duration_s": 30,
                },
                {
                    "step_name": "classify_severity",
                    "tool_name": "classify_incident",
                    "tool_action": "classify",
                    "params": {},
                    "depends_on": [2],
                    "requires_approval": False,
                    "estimated_duration_s": 15,
                },
                {
                    "step_name": "assign",
                    "tool_name": "assign_incident",
                    "tool_action": "assign",
                    "params": {},
                    "depends_on": [3],
                    "requires_approval": False,
                    "estimated_duration_s": 5,
                },
                {
                    "step_name": "notify",
                    "tool_name": "send_notification",
                    "tool_action": "notify",
                    "params": {"severity": "critical"},
                    "depends_on": [4],
                    "requires_approval": False,
                    "estimated_duration_s": 5,
                },
            ],
            "compliance_check": [
                {
                    "step_name": "fetch_framework",
                    "tool_name": "read_entities",
                    "tool_action": "read",
                    "params": {"entity": "ComplianceFramework", "name": payload.get("framework")},
                    "depends_on": [],
                    "requires_approval": False,
                    "estimated_duration_s": 10,
                },
                {
                    "step_name": "evaluate_controls",
                    "tool_name": "tool_gateway.execute_tool",
                    "tool_action": "compliance_evaluate",
                    "params": {"tool": "compliance_evaluate"},
                    "depends_on": [1],
                    "requires_approval": False,
                    "estimated_duration_s": 60,
                },
                {
                    "step_name": "store_violations",
                    "tool_name": "create_entity_records",
                    "tool_action": "create",
                    "params": {"entity": "PolicyViolation"},
                    "depends_on": [2],
                    "requires_approval": False,
                    "estimated_duration_s": 15,
                },
                {
                    "step_name": "generate_report",
                    "tool_name": "generate_compliance_report",
                    "tool_action": "generate",
                    "params": {},
                    "depends_on": [3],
                    "requires_approval": False,
                    "estimated_duration_s": 20,
                },
            ],
            "threat_intel_update": [
                {
                    "step_name": "fetch_feeds",
                    "tool_name": "tool_gateway.execute_tool",
                    "tool_action": "monitoring_fetch_feeds",
                    "params": {"tool": "monitoring_fetch_feeds"},
                    "depends_on": [],
                    "requires_approval": False,
                    "estimated_duration_s": 45,
                },
                {
                    "step_name": "correlate",
                    "tool_name": "correlate_threat_intel",
                    "tool_action": "correlate",
                    "params": {},
                    "depends_on": [1],
                    "requires_approval": False,
                    "estimated_duration_s": 30,
                },
                {
                    "step_name": "store",
                    "tool_name": "create_entity_records",
                    "tool_action": "create",
                    "params": {"entity": "ThreatIntelFeed"},
                    "depends_on": [2],
                    "requires_approval": False,
                    "estimated_duration_s": 15,
                },
                {
                    "step_name": "check_kev",
                    "tool_name": "check_cisa_kev",
                    "tool_action": "check",
                    "params": {},
                    "depends_on": [3],
                    "requires_approval": False,
                    "estimated_duration_s": 15,
                },
            ],
            "auto_remediate": [
                {
                    "step_name": "fetch_finding",
                    "tool_name": "read_entities",
                    "tool_action": "read",
                    "params": {"entity": "TriagedFinding", "id": payload.get("finding_id")},
                    "depends_on": [],
                    "requires_approval": False,
                    "estimated_duration_s": 10,
                },
                {
                    "step_name": "assess_risk",
                    "tool_name": "assess_finding_risk",
                    "tool_action": "assess",
                    "params": {},
                    "depends_on": [1],
                    "requires_approval": False,
                    "estimated_duration_s": 15,
                },
                {
                    "step_name": "check_approval",
                    "tool_name": "check_approval_required",
                    "tool_action": "check",
                    "params": {},
                    "depends_on": [2],
                    "requires_approval": False,
                    "estimated_duration_s": 5,
                },
                {
                    "step_name": "execute_fix",
                    "tool_name": "tool_gateway.execute_tool",
                    "tool_action": "autofix",
                    "params": {"tool": "autofix", "finding_id": payload.get("finding_id")},
                    "depends_on": [3],
                    "requires_approval": True,
                    "estimated_duration_s": 60,
                },
                {
                    "step_name": "verify_fix",
                    "tool_name": "verify_remediation",
                    "tool_action": "verify",
                    "params": {},
                    "depends_on": [4],
                    "requires_approval": False,
                    "estimated_duration_s": 20,
                },
            ],
        }

        default_steps = [
            {
                "step_name": "execute",
                "tool_name": "tool_gateway.execute_tool",
                "tool_action": "execute",
                "params": payload,
                "depends_on": [],
                "requires_approval": False,
                "estimated_duration_s": 30,
            },
            {
                "step_name": "report",
                "tool_name": "store_result",
                "tool_action": "store",
                "params": {},
                "depends_on": [1],
                "requires_approval": False,
                "estimated_duration_s": 10,
            },
        ]

        raw_step_defs = rule_plans.get(task_type, default_steps)
        steps: list[PlanStep] = []
        for idx, s in enumerate(raw_step_defs, start=1):
            steps.append(
                PlanStep(
                    step_number=idx,
                    step_name=s["step_name"],
                    tool_name=s["tool_name"],
                    tool_action=s["tool_action"],
                    params=s.get("params", {}),
                    depends_on=s.get("depends_on", []),
                    requires_approval=s.get("requires_approval", False),
                    estimated_duration_s=s.get("estimated_duration_s", 30),
                )
            )

        total_duration = sum(st.estimated_duration_s for st in steps)
        plan = AgentPlan(
            plan_id=str(uuid.uuid4()),
            task_id=task_id,
            goal=goal,
            steps=steps,
            confidence_score=0.85,
            confidence_level="high",
            requires_approval=task.get("requires_approval") == "true" or any(s.requires_approval for s in steps),
            approval_reason="Task requires human approval per safety policy." if task.get("requires_approval") == "true" else "",
            estimated_duration_s=total_duration,
            created_at=datetime.now(timezone.utc).isoformat(),
        )
        return plan

    async def plan_task(self, task: dict[str, Any]) -> AgentPlan:
        """Calls LLM for goal decomposition and generates an AgentPlan.

        Falls back to rule-based planning if LLM is unconfigured or fails.
        """
        user_prompt = self._build_planning_prompt(task)
        llm_response = await self._call_llm(SYSTEM_PROMPT, user_prompt)

        if llm_response:
            try:
                plan = self._parse_llm_response(llm_response, task)
                score, level = await self.assess_confidence(plan)
                req_app, reason = await self.check_approval_needed(plan)
                plan.confidence_score = score
                plan.confidence_level = level
                if req_app:
                    plan.requires_approval = True
                    plan.approval_reason = reason
                return plan
            except Exception as e:
                logger.warning(f"Failed to parse LLM planning response: {e}. Falling back to rules.")

        plan = self._fallback_plan(task)
        score, level = await self.assess_confidence(plan)
        req_app, reason = await self.check_approval_needed(plan)
        plan.confidence_score = score
        plan.confidence_level = level
        if req_app:
            plan.requires_approval = True
            plan.approval_reason = reason
        return plan

    async def revise_plan(
        self,
        plan: AgentPlan | dict[str, Any],
        step_index: int,
        result: dict[str, Any],
    ) -> AgentPlan:
        """Revise plan dynamically based on step execution results."""
        if isinstance(plan, dict):
            current_steps = plan.get("steps", [])
            goal = plan.get("goal", "Security Task")
            task_id = plan.get("task_id", str(uuid.uuid4()))
        else:
            current_steps = [s.to_dict() if isinstance(s, PlanStep) else s for s in plan.steps]
            goal = plan.goal
            task_id = plan.task_id

        user_prompt = f"""Plan Revision Requested due to Step {step_index} execution result.

Goal: {goal}
Executed Step Index: {step_index}
Execution Result:
{json.dumps(result, indent=2)}

Original Steps:
{json.dumps(current_steps, indent=2)}

Please re-evaluate the remaining steps starting from step {step_index}.
If necessary, insert recovery or diagnostic steps, modify parameters, or adjust dependencies.
Return a full updated JSON plan matching the system prompt schema."""

        llm_response = await self._call_llm(SYSTEM_PROMPT, user_prompt)
        if llm_response:
            try:
                revised = self._parse_llm_response(llm_response, {"task_id": task_id, "task_name": goal})
                return revised
            except Exception as e:
                logger.warning(f"Failed to parse revised plan from LLM: {e}")

        # Fallback revision logic
        revised_steps: list[PlanStep] = []
        for idx, s in enumerate(current_steps, start=1):
            step_obj = PlanStep(
                step_number=idx,
                step_name=s.get("step_name", f"step_{idx}"),
                tool_name=s.get("tool_name", "tool_gateway.execute_tool"),
                tool_action=s.get("tool_action", "execute"),
                params=s.get("params", {}),
                depends_on=s.get("depends_on", []),
                requires_approval=s.get("requires_approval", False),
                estimated_duration_s=s.get("estimated_duration_s", 30),
            )
            if idx == step_index and not result.get("success", True):
                # Add retry or error handler flag in params
                step_obj.params["revised_attempt"] = True
                step_obj.params["last_error"] = str(result.get("error", "Failed execution"))
            revised_steps.append(step_obj)

        new_plan = AgentPlan(
            plan_id=str(uuid.uuid4()),
            task_id=task_id,
            goal=goal,
            steps=revised_steps,
            confidence_score=0.70,
            confidence_level="medium",
            requires_approval=False,
            approval_reason="",
            estimated_duration_s=sum(s.estimated_duration_s for s in revised_steps),
            created_at=datetime.now(timezone.utc).isoformat(),
        )
        score, level = await self.assess_confidence(new_plan)
        req_app, reason = await self.check_approval_needed(new_plan)
        new_plan.confidence_score = score
        new_plan.confidence_level = level
        new_plan.requires_approval = req_app
        new_plan.approval_reason = reason
        return new_plan

    async def assess_confidence(self, plan: AgentPlan | dict[str, Any]) -> tuple[float, str]:
        """Quantify uncertainty in plans and assign confidence level."""
        steps = plan.get("steps") if isinstance(plan, dict) else plan.steps
        if not steps:
            return 0.0, "low"

        score = 0.90  # Base confidence

        # Check tool alignment against capabilities if capabilities are defined
        known_tools = {
            "read_entities", "create_entity_records", "update_entity_records",
            "tool_gateway.execute_tool", "autofix", "pentest_scan", "cloud_scan",
            "siem_correlate", "compliance_evaluate", "send_notification",
            "classify_incident", "assign_incident", "update_risk_score",
        }

        all_step_numbers = {
            s["step_number"] if isinstance(s, dict) else s.step_number for s in steps
        }

        for s in steps:
            tool = s.get("tool_name") if isinstance(s, dict) else s.tool_name
            deps = s.get("depends_on") if isinstance(s, dict) else s.depends_on

            # Deduct if tool is completely unknown
            if tool not in known_tools and not any(cap in tool for cap in self.capabilities):
                score -= 0.05

            # Check invalid dependencies
            for dep in deps:
                if dep not in all_step_numbers:
                    score -= 0.10

        # Adjust score bounds
        score = max(0.0, min(1.0, round(score, 2)))

        level = "low"
        for l_name, (low_b, high_b) in CONFIDENCE_LEVELS.items():
            if low_b <= score <= high_b:
                level = l_name
                break

        return score, level

    async def check_approval_needed(self, plan: AgentPlan | dict[str, Any]) -> tuple[bool, str]:
        """Determine if human approval is required for executing the plan."""
        steps = plan.get("steps") if isinstance(plan, dict) else plan.steps
        goal = (plan.get("goal") if isinstance(plan, dict) else plan.goal).lower()

        # Check plan-level explicit approval flag
        if isinstance(plan, dict) and plan.get("requires_approval"):
            return True, plan.get("approval_reason") or "Plan explicitly marked for approval."
        elif isinstance(plan, AgentPlan) and plan.requires_approval:
            return True, plan.approval_reason or "Plan explicitly marked for approval."

        for trigger in APPROVAL_TRIGGERS:
            category = trigger["category"]
            keywords = trigger["keywords"]
            reason = trigger["reason"]

            # Check goal against keywords
            for kw in keywords:
                if kw in goal:
                    return True, f"Approval required ({category}): Goal mentions '{kw}'. {reason}"

            # Check steps against keywords
            for s in steps:
                s_dict = s if isinstance(s, dict) else s.to_dict()
                s_req = s_dict.get("requires_approval", False)
                if s_req:
                    return True, f"Approval required: Step '{s_dict.get('step_name')}' explicitly requires human approval."

                combined_text = f"{s_dict.get('step_name', '')} {s_dict.get('tool_name', '')} {s_dict.get('tool_action', '')} {json.dumps(s_dict.get('params', {}))}".lower()
                for kw in keywords:
                    if kw in combined_text:
                        return True, f"Approval required ({category}): Step '{s_dict.get('step_name')}' involves '{kw}'. {reason}"

        return False, ""

    async def decompose_goal(self, goal: str, context: dict[str, Any] | None = None) -> list[PlanStep]:
        """LLM-driven goal decomposition into an ordered sequence of PlanSteps."""
        context = context or {}
        task = {
            "task_id": str(uuid.uuid4()),
            "task_name": "Goal Decomposition",
            "task_type": "decomposition",
            "payload": {"goal": goal, "context": context},
        }
        plan = await self.plan_task(task)
        return plan.steps

    async def select_tool(self, sub_task: str, available_tools: list[str] | None = None) -> str:
        """Choose the right tool name for a sub-task."""
        if available_tools is None:
            available_tools = [
                "read_entities", "create_entity_records", "update_entity_records",
                "tool_gateway.execute_tool", "autofix", "pentest_scan", "cloud_scan",
                "siem_correlate", "compliance_evaluate", "send_notification",
            ]

        user_prompt = f"""Sub-task: {sub_task}
Available Tools: {json.dumps(available_tools)}

Select the single best tool from Available Tools to execute this sub-task.
Return JSON: {{"selected_tool": "tool_name"}}"""

        llm_response = await self._call_llm(
            "You are a tool selection engine. Return JSON with key 'selected_tool'.",
            user_prompt,
        )
        if llm_response:
            try:
                cleaned = llm_response.strip()
                if cleaned.startswith("```"):
                    cleaned = "\n".join(cleaned.splitlines()[1:-1]).strip()
                data = json.loads(cleaned)
                tool = data.get("selected_tool")
                if tool and tool in available_tools:
                    return tool
            except Exception:
                pass

        # Semantic heuristic fallback
        st_lower = sub_task.lower()
        if "fix" in st_lower or "remediate" in st_lower or "patch" in st_lower:
            return "autofix"
        elif "scan" in st_lower or "pentest" in st_lower or "vulnerability" in st_lower:
            return "pentest_scan" if "cloud" not in st_lower else "cloud_scan"
        elif "compliance" in st_lower or "framework" in st_lower:
            return "compliance_evaluate"
        elif "correlate" in st_lower or "siem" in st_lower or "threat" in st_lower:
            return "siem_correlate"
        elif "fetch" in st_lower or "read" in st_lower or "get" in st_lower:
            return "read_entities"
        elif "store" in st_lower or "create" in st_lower or "save" in st_lower:
            return "create_entity_records"
        elif "notify" in st_lower or "alert" in st_lower:
            return "send_notification"

        return available_tools[0] if available_tools else "tool_gateway.execute_tool"

    async def evaluate_result(
        self, step: PlanStep | dict[str, Any], result: dict[str, Any]
    ) -> dict[str, Any]:
        """Evaluate step execution results to determine success, failure, or retry."""
        step_dict = step if isinstance(step, dict) else step.to_dict()
        success = result.get("success", False)
        error = result.get("error", "")

        if success:
            return {
                "status": "success",
                "reason": f"Step '{step_dict.get('step_name')}' executed successfully.",
                "next_action": "proceed",
                "should_revise": False,
                "details": result.get("result", {}),
            }

        # Check if error indicates transient issue (timeout or rate limit)
        is_transient = any(
            t in str(error).lower() for t in ["timeout", "rate_limit", "connection_reset", "503", "429"]
        )

        if is_transient:
            return {
                "status": "retry",
                "reason": f"Transient failure in step '{step_dict.get('step_name')}': {error}",
                "next_action": "retry_step",
                "should_revise": False,
                "details": {"error": error},
            }

        return {
            "status": "fail",
            "reason": f"Hard failure in step '{step_dict.get('step_name')}': {error}",
            "next_action": "revise_plan",
            "should_revise": True,
            "details": {"error": error},
        }

    async def suggest_next_action(
        self, current_state: dict[str, Any], history: list[dict[str, Any]]
    ) -> dict[str, Any]:
        """Suggest next system action based on current state and execution history."""
        status = current_state.get("status", "")
        current_step_idx = current_state.get("current_step_index", 1)
        total_steps = current_state.get("total_steps", 1)
        requires_approval = current_state.get("requires_approval", False)
        approval_granted = current_state.get("approval_granted", False)

        if requires_approval and not approval_granted:
            return {
                "action": "pause_for_approval",
                "reason": "Plan requires human approval before proceeding with execution.",
                "suggested_step_index": current_step_idx,
            }

        if status == "failed":
            recent_failures = sum(1 for h in history if not h.get("success", True))
            if recent_failures >= 3:
                return {
                    "action": "abort",
                    "reason": "Max retry attempts reached for plan steps.",
                    "suggested_step_index": current_step_idx,
                }
            return {
                "action": "revise",
                "reason": "Step execution failed; plan revision recommended.",
                "suggested_step_index": current_step_idx,
            }

        if current_step_idx > total_steps:
            return {
                "action": "complete",
                "reason": "All steps executed successfully.",
                "suggested_step_index": None,
            }

        return {
            "action": "continue",
            "reason": f"Proceeding with step {current_step_idx} of {total_steps}.",
            "suggested_step_index": current_step_idx,
        }

    async def determine_collaborating_agents(
        self, task: dict[str, Any], available_agents: list[dict[str, Any]] | None = None
    ) -> list[dict[str, Any]]:
        """Multi-agent planning: determine which specialized agents should collaborate."""
        task_type = task.get("task_type", "generic")
        payload = task.get("payload", {})

        if available_agents is None:
            available_agents = [
                {"agent_id": "agent-redteam-01", "agent_name": "RedTeam Agent", "capabilities": ["pentest_scan", "vulnerability_scan"]},
                {"agent_id": "agent-cloud-01", "agent_name": "Cloud Posture Agent", "capabilities": ["cloud_scan", "posture_eval"]},
                {"agent_id": "agent-autofix-01", "agent_name": "Remediation Agent", "capabilities": ["autofix", "patch_apply"]},
                {"agent_id": "agent-compliance-01", "agent_name": "Compliance Agent", "capabilities": ["compliance_evaluate", "report_gen"]},
            ]

        collaborators: list[dict[str, Any]] = []

        if task_type == "auto_remediate" or "remediate" in task_type:
            for agent in available_agents:
                caps = agent.get("capabilities", [])
                if any(c in ["pentest_scan", "vulnerability_scan"] for c in caps):
                    collaborators.append({
                        "agent_id": agent.get("agent_id"),
                        "agent_name": agent.get("agent_name"),
                        "role": "vulnerability_assessor",
                        "assigned_task": "Validate finding and assess impact",
                        "assigned_steps": [1, 2],
                        "reason": "Specialized in finding verification.",
                    })
                elif any(c in ["autofix", "patch_apply"] for c in caps):
                    collaborators.append({
                        "agent_id": agent.get("agent_id"),
                        "agent_name": agent.get("agent_name"),
                        "role": "remediator",
                        "assigned_task": "Execute automated code/config patch",
                        "assigned_steps": [3, 4],
                        "reason": "Specialized in automated code and infrastructure fixes.",
                    })
        elif task_type == "vulnerability_scan":
            for agent in available_agents:
                caps = agent.get("capabilities", [])
                if any(c in ["pentest_scan", "vulnerability_scan"] for c in caps):
                    collaborators.append({
                        "agent_id": agent.get("agent_id"),
                        "agent_name": agent.get("agent_name"),
                        "role": "scanner",
                        "assigned_task": "Perform vulnerability assessment scan",
                        "assigned_steps": [1, 2],
                        "reason": "RedTeam scanning capabilities.",
                    })
        else:
            # Default single-agent assignment
            collaborators.append({
                "agent_id": self.agent_id,
                "agent_name": self.agent_name,
                "role": "primary_executor",
                "assigned_task": f"Execute {task_type} primary workflow",
                "assigned_steps": [1, 2],
                "reason": "Assigned primary agent for task execution.",
            })

        return collaborators


# ============================================================================
# MODULE EXPORTS
# ============================================================================

__all__ = [
    "PlanStep",
    "AgentPlan",
    "AgentPlanner",
    "SYSTEM_PROMPT",
    "CONFIDENCE_LEVELS",
    "APPROVAL_TRIGGERS",
]
