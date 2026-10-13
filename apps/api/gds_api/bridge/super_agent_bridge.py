"""Bridge API — Base44 Super Agent ↔ Rabbani AI Core.

This is the connection point between the Base44 Super Agent (the Co-Pilot)
and the Rabbani AI Core (the VPS reasoning engine).

The Super Agent calls these endpoints to:
  - Create missions (trigger agent reasoning loops)
  - Check mission status
  - List available agents
  - Invoke specific agents directly
  - Get reasoning engine health

Authentication: Bearer token (BRIDGE_API_KEY from /opt/.env)
"""
from fastapi import Request
import os, sys, json, asyncio, uuid, logging
from datetime import datetime
from fastapi import APIRouter, Header, HTTPException, BackgroundTasks
from pydantic import BaseModel
from typing import Optional
from gds_api.reasoning.kernel_agent_runner import run_kernel_agent_runner
from gds_api.reasoning.mission_orchestrator import run_mission as _run_mission_async, start_mission_async as _start_mission_async, get_mission_status as _get_mission_status


class DictWrapper:
    """Wraps a dict so existing dot-notation code works with dict results."""
    def __init__(self, d):
        self.__dict__["_d"] = d
    def __getattr__(self, name):
        d = self.__dict__.get("_d", {})
        val = d.get(name)
        if name == "tool_calls" and isinstance(val, list):
            return [DictWrapper(tc) if isinstance(tc, dict) else tc for tc in val]
        return val
    def get(self, key, default=None):
        return self.__dict__.get("_d", {}).get(key, default)
    def __getitem__(self, key):
        return self.__dict__["_d"][key]
    def __repr__(self):
        return "DictWrapper(%r)" % self.__dict__.get("_d", {})


logger = logging.getLogger("gds.bridge")

sys.path.insert(0, "/opt/gds-os/apps/api")

router = APIRouter(prefix="/bridge", tags=["bridge"])

# Bridge authentication key
BRIDGE_API_KEY = os.environ.get("BRIDGE_API_KEY", "")

# In-memory mission store (missions are also stored in the reasoning bridge)
_mission_store = {}


def _verify_auth(authorization: str = None):
    """Verify bridge API key."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Missing or invalid Authorization header")
    token = authorization.replace("Bearer ", "")
    if token != BRIDGE_API_KEY:
        raise HTTPException(401, "Invalid bridge API key")
    return True


# ============================================================
# MODELS
# ============================================================

class MissionRequest(BaseModel):
    goal: str
    agent_id: Optional[str] = None  # If null, auto-select
    context: Optional[dict] = None
    priority: Optional[str] = "normal"  # low, normal, high, critical


class AgentInvokeRequest(BaseModel):
    goal: str
    context: Optional[dict] = None


# ============================================================
# ENDPOINTS
# ============================================================

@router.get("/health")
async def bridge_health():
    """Bridge health check — no auth required."""
    try:
        from gds_api.reasoning.prompts import AGENT_REGISTRY
        from gds_api.tool_gateway import TOOL_REGISTRY
        
        return {
            "status": "healthy",
            "bridge": "base44-rabbani",
            "agents_available": len(AGENT_REGISTRY),
            "tools_available": len(TOOL_REGISTRY),
            "reasoning_engine": "active",
            "timestamp": datetime.utcnow().isoformat()
        }
    except Exception as e:
        return {"status": "degraded", "error": str(e)}


@router.get("/agents")
async def list_agents(authorization: Optional[str] = Header(None)):
    """List all available Rabbani AI Core agents."""
    _verify_auth(authorization)
    
    from gds_api.reasoning.prompts import list_agents
    agents = list_agents()
    
    return {
        "agents": agents,
        "count": len(agents),
        "bridge": "rabbani-ai-core"
    }



@router.get("/mission/{mission_id}")
async def get_mission_status_endpoint(mission_id: str):
    """Phase 6 v2: Get mission status (in-memory or PostgreSQL)."""
    result = _get_mission_status(mission_id)
    return result
@router.get("/missions")
async def list_missions(
    status: Optional[str] = None,
    authorization: Optional[str] = Header(None)
):
    """List all missions, optionally filtered by status."""
    _verify_auth(authorization)
    
    missions = list(_mission_store.values())
    if status:
        missions = [m for m in missions if m["status"] == status]
    
    return {
        "missions": [
            {
                "mission_id": m["mission_id"],
                "goal": m["goal"],
                "agent_id": m.get("agent_id"),
                "status": m["status"],
                "created_at": m["created_at"]
            }
            for m in missions
        ],
        "count": len(missions)
    }


@router.post("/agent/{agent_id}/invoke")
async def invoke_agent_directly(
    agent_id: str,
    req: AgentInvokeRequest,
    authorization: Optional[str] = Header(None)
):
    """Invoke a specific agent directly (synchronous).
    
    This runs the full LLM reasoning loop and waits for completion.
    Use for quick tasks. For long-running tasks, use POST /bridge/mission.
    """
    _verify_auth(authorization)
    
    try:
        from gds_api.reasoning.agent_loop import AgenticLoop
        
        # Verify agent exists
        from gds_api.reasoning.prompts import AGENT_REGISTRY
        if agent_id not in AGENT_REGISTRY:
            raise HTTPException(404, f"Agent {agent_id} not found. Available: {list(AGENT_REGISTRY.keys())[:10]}")
        
        # Phase 5: kernel-managed memory (no AgenticLoop)
        result_dict = await run_kernel_agent_runner(agent_id=agent_id, goal=req.goal, context=req.context)
        result = DictWrapper(result_dict)
        
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
            "error": result.error,
            "kernel_managed": getattr(result, 'kernel_managed', False),
            "pid": result.pid
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Agent invoke error: {e}")
        raise HTTPException(500, str(e))


@router.post("/auto")
async def auto_select_and_run(
    req: AgentInvokeRequest,
    authorization: Optional[str] = Header(None)
):
    """Auto-select the best agent for the goal and run synchronously.
    
    Uses LLM to pick the best agent, then runs the reasoning loop.
    """
    _verify_auth(authorization)
    
    try:
        from gds_api.reasoning.bridge import reasoning_bridge
        
        result = await reasoning_bridge.run_with_auto_select(req.goal, req.context)
        
        return {
            "success": result.success,
            "selected_agent": result.agent_id,
            "goal": result.goal,
            "summary": result.summary,
            "tool_calls": len(result.tool_calls),
            "iterations": result.iterations,
            "duration_ms": result.duration_ms,
            "error": result.error,
            "kernel_managed": getattr(result, 'kernel_managed', False),
            "pid": result.pid
        }
    except Exception as e:
        logger.error(f"Auto-run error: {e}")
        raise HTTPException(500, str(e))


# ============================================================
# BACKGROUND MISSION RUNNER
# ============================================================

async def _run_mission(mission_id: str, goal: str, agent_id: Optional[str], context: Optional[dict]):
    """Run a mission in the background and update the store."""
    try:
        _mission_store[mission_id]["status"] = "running"
        _mission_store[mission_id]["started_at"] = datetime.utcnow().isoformat()
        
        from gds_api.reasoning.bridge import reasoning_bridge
        
        if agent_id:
            result = await reasoning_bridge.execute_task(agent_id, goal, context)
        else:
            result = await reasoning_bridge.run_with_auto_select(goal, context)
        
        _mission_store[mission_id]["status"] = "completed" if result.success else "failed"
        _mission_store[mission_id]["result"] = {
            "success": result.success,
            "agent_id": result.agent_id,
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
            "error": result.error,
            "kernel_managed": getattr(result, 'kernel_managed', False),
            "pid": result.pid
        }
        _mission_store[mission_id]["completed_at"] = datetime.utcnow().isoformat()
        
        logger.info(f"Mission {mission_id} completed: success={result.success}")
        
    except Exception as e:
        _mission_store[mission_id]["status"] = "failed"
        _mission_store[mission_id]["error"] = str(e)
        _mission_store[mission_id]["completed_at"] = datetime.utcnow().isoformat()
        logger.error(f"Mission {mission_id} failed: {e}")



@router.post("/mission")
async def bridge_mission(request: Request):
    """Phase 6 v2: Multi-agent mission orchestration with async support."""
    try:
        body = await request.json()
        goal = body.get("goal", "")
        context = body.get("context", {})
        async_mode = body.get("async", False)
        
        if not goal:
            raise HTTPException(status_code=400, detail="goal is required")
        
        if async_mode:
            result = await _start_mission_async(goal, context)
            return result
        else:
            result = await _run_mission_async(goal, context)
            return {
                "success": result.get("successful_agents", 0) > 0,
                "mission_id": result.get("mission_id"),
                "goal": result.get("goal"),
                "plan": result.get("plan"),
                "agent_results": result.get("agent_results"),
                "unified_report": result.get("unified_report"),
                "duration_ms": result.get("duration_ms"),
                "kernel_managed": result.get("kernel_managed", False),
                "mission_pid": result.get("mission_pid"),
                "total_tool_calls": result.get("total_tool_calls", 0),
                "successful_agents": result.get("successful_agents", 0),
                "total_agents": result.get("total_agents", 0)
            }
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Mission failed: %s" % str(e))
        raise HTTPException(status_code=500, detail=str(e))