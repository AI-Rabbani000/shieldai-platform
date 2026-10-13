"""FastAPI routes for the LLM Reasoning Engine.

Endpoints:
  POST /reasoning/mission        — Create and execute a mission
  GET  /reasoning/missions       — List all missions
  GET  /reasoning/mission/{id}   — Get mission status
  GET  /reasoning/agents          — List all agents
  POST /reasoning/auto            — Auto-select agent and execute
"""
import os, sys, json, logging
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional

logger = logging.getLogger("gds.reasoning.routes")

sys.path.insert(0, "/opt/gds-os/apps/api")

from gds_api.reasoning.bridge import reasoning_bridge
from gds_api.reasoning.prompts import list_agents, AGENT_REGISTRY

router = APIRouter(prefix="/reasoning", tags=["reasoning"])


class MissionRequest(BaseModel):
    goal: str
    agent_id: Optional[str] = None  # If null, auto-select
    context: Optional[dict] = None


@router.post("/mission")
async def create_mission(req: MissionRequest):
    """Create and execute a mission using the LLM reasoning loop."""
    try:
        if req.agent_id:
            result = await reasoning_bridge.execute_task(req.agent_id, req.goal, req.context)
        else:
            result = await reasoning_bridge.run_with_auto_select(req.goal, req.context)
        
        return {
            "success": result.success,
            "agent_id": result.agent_id,
            "goal": result.goal,
            "summary": result.summary,
            "tool_calls": [
                {
                    "tool": tc.tool_name,
                    "arguments": tc.arguments,
                    "result": tc.result,
                    "duration_ms": tc.duration_ms
                }
                for tc in result.tool_calls
            ],
            "iterations": result.iterations,
            "duration_ms": result.duration_ms,
            "error": result.error
        }
    except Exception as e:
        logger.error(f"Mission error: {e}")
        raise HTTPException(500, str(e))


@router.get("/missions")
async def list_missions():
    """List all completed missions."""
    return {"missions": reasoning_bridge.list_missions()}


@router.get("/mission/{mission_id}")
async def get_mission(mission_id: str):
    """Get detailed status of a specific mission."""
    result = reasoning_bridge.get_mission_status(mission_id)
    if "error" in result:
        raise HTTPException(404, result["error"])
    return result


@router.get("/agents")
async def get_agents():
    """List all available agents and their capabilities."""
    return {"agents": list_agents(), "count": len(AGENT_REGISTRY)}


@router.post("/auto")
async def auto_execute(req: MissionRequest):
    """Auto-select the best agent and execute the goal."""
    result = await reasoning_bridge.run_with_auto_select(req.goal, req.context)
    return {
        "success": result.success,
        "selected_agent": result.agent_id,
        "summary": result.summary,
        "tool_calls": len(result.tool_calls),
        "iterations": result.iterations,
        "duration_ms": result.duration_ms
    }
