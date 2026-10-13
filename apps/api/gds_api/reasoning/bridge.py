"""Bridge between the new LLM Reasoning Engine and the existing execution layer.

This wires the AgenticLoop into the existing AgentExecutionLoop and
AgentTaskQueue so that when a task is dequeued, it runs through the
LLM reasoning loop instead of the pre-programmed routing.
"""
import os, sys, json, asyncio, logging
from datetime import datetime

logger = logging.getLogger("gds.reasoning.bridge")

sys.path.insert(0, "/opt/gds-os/apps/api")

from gds_api.reasoning.agent_loop import AgenticLoop, AgentResult
from gds_api.reasoning.prompts import AGENT_REGISTRY, list_agents


class ReasoningBridge:
    """Bridges the LLM reasoning engine with the existing task queue.
    
    When a task is dequeued from AgentTaskQueue, instead of running
    pre-programmed routing, it runs through the AgenticLoop which uses
    OpenAI function calling to decide which tools to use.
    """
    
    def __init__(self):
        self.active_missions = {}  # mission_id → AgentResult
    
    async def execute_task(self, agent_id: str, goal: str, context: dict = None) -> AgentResult:
        """Execute a task using the LLM reasoning loop.
        
        Args:
            agent_id: Which agent to use (e.g. "ai-vuln-director")
            goal: Natural language goal
            context: Additional context
        
        Returns:
            AgentResult with summary and tool call history
        """
        logger.info(f"Bridge executing task: agent={agent_id}, goal={goal[:100]}")
        
        # Create the agentic loop for this agent
        loop = AgenticLoop(agent_id=agent_id)
        
        # Run the reasoning loop
        result = await loop.run(goal, context)
        
        # Store result
        mission_id = f"mission_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}_{agent_id}"
        self.active_missions[mission_id] = result
        
        logger.info(f"Task complete: {mission_id}, success={result.success}, "
                    f"tools={len(result.tool_calls)}, duration={result.duration_ms}ms")
        
        return result
    
    async def auto_select_agent(self, goal: str) -> str:
        """Use LLM to select the best agent for a goal.
        
        Instead of pre-programmed routing, ask the LLM which agent
        should handle this goal based on the agent descriptions.
        """
        from openai import AsyncOpenAI
        
        client = AsyncOpenAI(api_key=os.environ.get("OPENAI_API_KEY"))
        
        agents = list_agents()
        agent_descriptions = "\n".join([
            f"- {a['id']}: {a['name']} — {a['role']} (tools: {', '.join(a['tools'])})"
            for a in agents
        ])
        
        response = await client.chat.completions.create(
            model="gpt-4.1",
            messages=[
                {"role": "system", "content": f"You are a security mission router. Select the best agent for the given goal.\n\nAvailable agents:\n{agent_descriptions}\n\nRespond with ONLY the agent_id (e.g. ai-vuln-director). No other text."},
                {"role": "user", "content": f"Goal: {goal}"}
            ],
            temperature=0,
            max_tokens=50
        )
        
        agent_id = response.choices[0].message.content.strip()
        
        # Validate
        if agent_id not in AGENT_REGISTRY:
            # Fallback: find closest match
            goal_lower = goal.lower()
            if "scan" in goal_lower or "vuln" in goal_lower:
                agent_id = "ai-vuln-director"
            elif "cloud" in goal_lower or "aws" in goal_lower:
                agent_id = "ai-cloud-director"
            elif "compliance" in goal_lower or "audit" in goal_lower:
                agent_id = "ai-compliance-director"
            elif "threat" in goal_lower or "hunt" in goal_lower:
                agent_id = "ai-threat-hunter"
            elif "recon" in goal_lower or "discover" in goal_lower:
                agent_id = "ai-recon-agent"
            elif "report" in goal_lower:
                agent_id = "ai-report-agent"
            elif "fix" in goal_lower or "remediate" in goal_lower or "patch" in goal_lower:
                agent_id = "ai-autofix-agent"
            else:
                agent_id = "ai-vuln-director"  # Default
        
        logger.info(f"Auto-selected agent: {agent_id} for goal: {goal[:100]}")
        return agent_id
    
    async def run_with_auto_select(self, goal: str, context: dict = None) -> AgentResult:
        """Auto-select the best agent and execute the goal."""
        agent_id = await self.auto_select_agent(goal)
        return await self.execute_task(agent_id, goal, context)
    
    def get_mission_status(self, mission_id: str) -> dict:
        """Get status of a mission."""
        result = self.active_missions.get(mission_id)
        if not result:
            return {"error": "Mission not found"}
        
        return {
            "mission_id": mission_id,
            "agent_id": result.agent_id,
            "goal": result.goal,
            "success": result.success,
            "summary": result.summary,
            "tool_calls": [
                {"tool": tc.tool_name, "args": tc.arguments, "result": tc.result, "duration_ms": tc.duration_ms}
                for tc in result.tool_calls
            ],
            "iterations": result.iterations,
            "duration_ms": result.duration_ms,
            "error": result.error
        }
    
    def list_missions(self) -> list[dict]:
        """List all missions."""
        return [
            {
                "mission_id": mid,
                "agent_id": r.agent_id,
                "goal": r.goal,
                "success": r.success,
                "tool_calls": len(r.tool_calls),
                "duration_ms": r.duration_ms
            }
            for mid, r in self.active_missions.items()
        ]


# Singleton instance
reasoning_bridge = ReasoningBridge()
