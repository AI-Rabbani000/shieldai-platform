#!/usr/bin/env python3
"""
GDS Kernel Phase 6 — Multi-Agent Mission Orchestration (v2)
Features:
  - Async mission execution (returns mission_id immediately, poll for status)
  - Agent-to-agent IPC through shared kernel memory namespace
  - Persistent mission memory (PostgreSQL — survives API restarts)
  - Sync mode still available (default for backward compat)
"""
import sys
import os
import logging
import time
import uuid
import asyncio
import json
import threading
from datetime import datetime
from typing import Dict, Any, List, Optional

logger = logging.getLogger("gds.kernel.mission")

# Import kernel
KERNEL_AVAILABLE = False
MemorySegmentType = None
try:
    from gds_kernel.kernel_router import get_kernel
    from gds_kernel.memory import MemorySegmentType as _MST
    MemorySegmentType = _MST
    KERNEL_AVAILABLE = True
except Exception as e:
    logger.warning("Kernel not available: %s" % e)

# Import agent runner
try:
    from gds_api.reasoning.kernel_agent_runner import run_kernel_agent_runner
    AGENT_RUNNER_AVAILABLE = True
except Exception as e:
    logger.warning("Agent runner not available: %s" % e)
    AGENT_RUNNER_AVAILABLE = False

# ═══════════════════════════════════════════════════════════
# FEATURE 2: In-memory mission registry (for async polling)
# ═══════════════════════════════════════════════════════════
_MISSIONS: Dict[str, Dict[str, Any]] = {}
_MISSIONS_LOCK = threading.Lock()

# ═══════════════════════════════════════════════════════════
# FEATURE 4: PostgreSQL persistence
# ═══════════════════════════════════════════════════════════
DB_AVAILABLE = False
try:
    import psycopg2
    DB_AVAILABLE = True
except ImportError:
    pass

def _get_db():
    """Get PostgreSQL connection."""
    if not DB_AVAILABLE:
        return None
    try:
        db_url = os.getenv("DATABASE_URL", "")
        return psycopg2.connect(db_url)
    except Exception as e:
        logger.debug("DB connection failed: %s" % e)
        return None

def _ensure_mission_table():
    """Create mission_results table if it doesn't exist."""
    conn = _get_db()
    if not conn:
        return
    try:
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS mission_results (
                mission_id VARCHAR(64) PRIMARY KEY,
                goal TEXT NOT NULL,
                status VARCHAR(32) NOT NULL DEFAULT 'running',
                plan JSONB,
                agent_results JSONB,
                unified_report TEXT,
                mission_pid VARCHAR(128),
                total_tool_calls INTEGER DEFAULT 0,
                successful_agents INTEGER DEFAULT 0,
                total_agents INTEGER DEFAULT 0,
                duration_ms INTEGER,
                kernel_managed BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT NOW(),
                completed_at TIMESTAMP
            );
        """)
        conn.commit()
        logger.info("mission_results table ensured")
    except Exception as e:
        logger.error("Failed to create mission_results table: %s" % e)
    finally:
        conn.close()

def _persist_mission(mission_data: Dict[str, Any]):
    """Persist mission to PostgreSQL."""
    conn = _get_db()
    if not conn:
        return
    try:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO mission_results (mission_id, goal, status, plan, agent_results, unified_report,
                mission_pid, total_tool_calls, successful_agents, total_agents, duration_ms,
                kernel_managed, completed_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (mission_id) DO UPDATE SET
                status = EXCLUDED.status,
                agent_results = EXCLUDED.agent_results,
                unified_report = EXCLUDED.unified_report,
                total_tool_calls = EXCLUDED.total_tool_calls,
                successful_agents = EXCLUDED.successful_agents,
                duration_ms = EXCLUDED.duration_ms,
                completed_at = EXCLUDED.completed_at
        """, (
            mission_data.get("mission_id"),
            mission_data.get("goal", ""),
            mission_data.get("status", "completed"),
            json.dumps(mission_data.get("plan", {})),
            json.dumps(mission_data.get("agent_results", [])),
            mission_data.get("unified_report", ""),
            mission_data.get("mission_pid", ""),
            mission_data.get("total_tool_calls", 0),
            mission_data.get("successful_agents", 0),
            mission_data.get("total_agents", 0),
            mission_data.get("duration_ms", 0),
            mission_data.get("kernel_managed", False),
            mission_data.get("completed_at")
        ))
        conn.commit()
        logger.info("Mission %s persisted to PostgreSQL" % mission_data.get("mission_id"))
    except Exception as e:
        logger.error("Failed to persist mission: %s" % e)
    finally:
        conn.close()

def _load_mission_from_db(mission_id: str) -> Optional[Dict[str, Any]]:
    """Load a mission from PostgreSQL."""
    conn = _get_db()
    if not conn:
        return None
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM mission_results WHERE mission_id = %s", (mission_id,))
        row = cur.fetchone()
        if not row:
            return None
        cols = [desc[0] for desc in cur.description]
        data = dict(zip(cols, row))
        # Parse JSON fields
        if data.get("plan"):
            data["plan"] = json.loads(data["plan"]) if isinstance(data["plan"], str) else data["plan"]
        if data.get("agent_results"):
            data["agent_results"] = json.loads(data["agent_results"]) if isinstance(data["agent_results"], str) else data["agent_results"]
        return data
    except Exception as e:
        logger.error("Failed to load mission: %s" % e)
        return None
    finally:
        conn.close()

# Initialize table on import
_ensure_mission_table()

# ═══════════════════════════════════════════════════════════
# Agent catalog
# ═══════════════════════════════════════════════════════════
AGENT_CATALOG = {
    "ai-vuln-director": {
        "tools": ["nmap_scan", "cisa_kev_check", "osv_check", "security_headers_check"],
        "specialty": "Vulnerability scanning, CVE analysis, CISA KEV tracking",
        "use_when": "Scanning for vulnerabilities, checking CVEs, security headers"
    },
    "ai-cloud-director": {
        "tools": ["aws_iam_scan"],
        "specialty": "Cloud security, IAM analysis, CIEM, privilege escalation",
        "use_when": "AWS cloud scanning, IAM audit, privilege analysis"
    },
    "ai-threat-hunter": {
        "tools": ["nmap_scan", "nuclei_scan", "security_headers_check"],
        "specialty": "Threat hunting, attack surface mapping, active reconnaissance",
        "use_when": "Hunting for threats, attack surface analysis, reconnaissance"
    },
    "ai-incident-commander": {
        "tools": ["get_findings", "store_finding"],
        "specialty": "Incident response, finding triage, evidence collection",
        "use_when": "Investigating incidents, triaging findings, evidence collection"
    },
    "ai-remediation-director": {
        "tools": ["get_findings", "store_finding"],
        "specialty": "Remediation planning, patch prioritization, fix tracking",
        "use_when": "Planning remediation, prioritizing patches, tracking fixes"
    },
    "ai-soc-director": {
        "tools": ["get_findings", "cisa_kev_check"],
        "specialty": "SOC operations, alert triage, security monitoring",
        "use_when": "SOC summary, alert triage, security monitoring overview"
    },
    "ai-compliance-director": {
        "tools": ["get_findings"],
        "specialty": "Compliance assessment, audit preparation, framework mapping",
        "use_when": "Compliance checking, audit prep, framework mapping"
    },
    "ai-chief-ciso": {
        "tools": ["get_findings"],
        "specialty": "Executive risk assessment, board reporting, strategic decisions",
        "use_when": "Executive summary, board report, risk assessment"
    },
}

# ═══════════════════════════════════════════════════════════
# Mission planning
# ═══════════════════════════════════════════════════════════
async def plan_mission(goal: str, model: str = "gpt-4.1") -> Dict[str, Any]:
    """Use GPT-4.1 to plan which agents to invoke."""
    agent_descriptions = "\n".join([
        "- %s: %s (Use when: %s)" % (aid, info["specialty"], info["use_when"])
        for aid, info in AGENT_CATALOG.items()
    ])
    
    planning_prompt = """You are the GDS OS Mission Planner. Given a security goal, decide which AI agents to invoke and in what order.

Available agents:
%s

Rules:
1. Select 1-5 agents that are most relevant to the goal
2. If agents are independent (no dependencies), they run in parallel
3. If one agent's output is needed by another, mark them as sequential
4. Assign a specific sub-goal to each agent
5. Choose an aggregator agent to synthesize the final report

Respond with JSON only, no markdown:
{
  "agents": ["agent_id1", "agent_id2"],
  "parallel": true,
  "steps": [{"agent": "agent_id", "goal": "specific sub-goal for this agent"}],
  "aggregator": "agent_id for final synthesis",
  "rationale": "brief explanation"
}""" % agent_descriptions
    
    try:
        import openai
        from dotenv import load_dotenv
        load_dotenv("/opt/.env")
        client = openai.OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
        
        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": planning_prompt},
                {"role": "user", "content": "Goal: %s" % goal}
            ],
            temperature=0.1,
            max_tokens=1000,
            response_format={"type": "json_object"}
        )
        plan = json.loads(response.choices[0].message.content)
        logger.info("Mission plan: %d agents, parallel=%s" % (len(plan.get("agents", [])), plan.get("parallel", False)))
        return plan
    except Exception as e:
        logger.error("Mission planning failed: %s" % e)
        return _fallback_plan(goal)

def _fallback_plan(goal: str) -> Dict[str, Any]:
    """Keyword-based agent selection fallback."""
    goal_lower = goal.lower()
    agents, steps = [], []
    
    if any(kw in goal_lower for kw in ["vuln", "cve", "scan", "kev", "nmap", "headers"]):
        agents.append("ai-vuln-director")
        steps.append({"agent": "ai-vuln-director", "goal": "Run vulnerability scans: nmap, CISA KEV, security headers"})
    if any(kw in goal_lower for kw in ["cloud", "aws", "iam", "privilege"]):
        agents.append("ai-cloud-director")
        steps.append({"agent": "ai-cloud-director", "goal": "Scan AWS IAM for misconfigurations"})
    if any(kw in goal_lower for kw in ["threat", "hunt", "recon", "attack surface"]):
        agents.append("ai-threat-hunter")
        steps.append({"agent": "ai-threat-hunter", "goal": "Hunt for threats: nmap, nuclei, security headers"})
    if any(kw in goal_lower for kw in ["incident", "investigate", "triage"]):
        agents.append("ai-incident-commander")
        steps.append({"agent": "ai-incident-commander", "goal": "Review and triage all security findings"})
    if any(kw in goal_lower for kw in ["compliance", "audit", "soc2", "pci", "iso"]):
        agents.append("ai-compliance-director")
        steps.append({"agent": "ai-compliance-director", "goal": "Assess compliance status against frameworks"})
    if any(kw in goal_lower for kw in ["executive", "board", "report", "summary", "risk score"]):
        agents.append("ai-chief-ciso")
        steps.append({"agent": "ai-chief-ciso", "goal": "Provide executive risk assessment"})
    if not agents:
        agents = ["ai-vuln-director", "ai-threat-hunter"]
        steps = [
            {"agent": "ai-vuln-director", "goal": "Run nmap scan, CISA KEV check, and security headers check"},
            {"agent": "ai-threat-hunter", "goal": "Run nmap and nuclei scan for threats and attack surface"}
        ]
    return {"agents": agents, "parallel": True, "steps": steps, "aggregator": "ai-chief-ciso", "rationale": "Fallback keyword-based"}

# ═══════════════════════════════════════════════════════════
# FEATURE 3: Agent-to-agent IPC through kernel memory
# ═══════════════════════════════════════════════════════════
def _store_shared_finding(mission_pid: str, agent_id: str, finding: str, importance: float = 0.6):
    """Store a finding in the shared mission context for other agents to read."""
    if not KERNEL_AVAILABLE:
        return
    try:
        kernel = get_kernel()
        mem = getattr(kernel, 'memory')
        mem.allocate(
            process_id=mission_pid,
            content="[FINDING from %s] %s" % (agent_id, finding[:2000]),
            segment_type=MemorySegmentType.TOOL_RESULT,
            importance=importance
        )
        logger.debug("Shared finding stored by %s in mission %s" % (agent_id, mission_pid))
    except Exception as e:
        logger.debug("Failed to store shared finding: %s" % e)

def _get_shared_findings(mission_pid: str, max_findings: int = 10) -> str:
    """Read shared findings from the mission context for an agent to use."""
    if not KERNEL_AVAILABLE:
        return ""
    try:
        kernel = get_kernel()
        mem = getattr(kernel, 'memory')
        stats = mem.get_memory_stats(mission_pid)
        if stats.get("error") or stats.get("segment_count", 0) <= 2:
            return ""  # Only system prompt + plan exist, no agent findings yet
        
        # Build context from mission memory
        cw = mem.context_windows.get(mission_pid)
        if not cw:
            return ""
        
        findings = []
        for seg in cw.segments.values():
            if seg.segment_type == MemorySegmentType.TOOL_RESULT and "[FINDING" in seg.content:
                findings.append(seg.content[:500])
        
        if findings:
            return "\n\n--- SHARED FINDINGS FROM OTHER AGENTS ---\n" + "\n".join(findings[:max_findings])
        return ""
    except Exception as e:
        logger.debug("Failed to get shared findings: %s" % e)
        return ""

# ═══════════════════════════════════════════════════════════
# Core mission execution
# ═══════════════════════════════════════════════════════════
async def execute_mission(
    goal: str,
    context: Optional[Dict[str, Any]] = None,
    model: str = "gpt-4.1",
    max_agents_parallel: int = 5,
    mission_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Execute a multi-agent mission (sync mode)."""
    start_time = time.time()
    if not mission_id:
        mission_id = "mission-%s" % uuid.uuid4().hex[:12]
    context = context or {}
    
    # Update mission status
    with _MISSIONS_LOCK:
        _MISSIONS[mission_id] = {
            "mission_id": mission_id,
            "goal": goal,
            "status": "planning",
            "started_at": time.time(),
            "agent_results": [],
        }
    
    logger.info("Mission %s started: %s" % (mission_id, goal[:100]))
    
    # Step 1: Plan
    plan = await plan_mission(goal, model)
    with _MISSIONS_LOCK:
        _MISSIONS[mission_id]["plan"] = plan
        _MISSIONS[mission_id]["status"] = "executing"
    
    # Step 2: Allocate shared mission context
    mission_pid = "mission-%s" % mission_id
    if KERNEL_AVAILABLE:
        try:
            kernel = get_kernel()
            mem = getattr(kernel, 'memory')
            mem.allocate(mission_pid, "Mission: %s" % goal, MemorySegmentType.SYSTEM_PROMPT, 1.0)
            mem.allocate(mission_pid, "Plan: %s" % json.dumps(plan), MemorySegmentType.WORKING, 0.8)
        except Exception as e:
            logger.warning("Mission context alloc failed: %s" % e)
    
    # Step 3: Execute agents
    agent_results = []
    steps = plan.get("steps", [])
    parallel = plan.get("parallel", False)
    
    if parallel and len(steps) > 1 and AGENT_RUNNER_AVAILABLE:
        # PARALLEL execution
        logger.info("Running %d agents in parallel" % len(steps))
        tasks = []
        for step in steps[:max_agents_parallel]:
            agent_context = dict(context)
            agent_context["mission_id"] = mission_id
            agent_context["mission_goal"] = goal
            tasks.append(run_kernel_agent_runner(
                agent_id=step.get("agent", ""),
                goal=step.get("goal", goal),
                context=agent_context,
                model=model,
                max_iterations=5
            ))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                agent_results.append({
                    "agent_id": steps[i].get("agent", "?"), "success": False,
                    "error": str(result), "tool_calls": [], "summary": "Agent failed"
                })
            else:
                agent_results.append(result)
                # FEATURE 3: Store findings in shared context
                if result.get("success") and result.get("summary"):
                    _store_shared_finding(mission_pid, result.get("agent_id", "?"), result.get("summary", ""))
    elif AGENT_RUNNER_AVAILABLE:
        # SEQUENTIAL execution with IPC
        logger.info("Running %d agents sequentially (with IPC)" % len(steps))
        for step in steps:
            agent_id = step.get("agent", "")
            agent_goal = step.get("goal", goal)
            agent_context = dict(context)
            agent_context["mission_id"] = mission_id
            agent_context["mission_goal"] = goal
            
            # FEATURE 3: Inject shared findings from previous agents
            shared_findings = _get_shared_findings(mission_pid)
            if shared_findings:
                agent_context["previous_agent_findings"] = shared_findings
            
            result = await run_kernel_agent_runner(
                agent_id=agent_id, goal=agent_goal, context=agent_context,
                model=model, max_iterations=5
            )
            agent_results.append(result)
            
            # Store this agent's findings in shared context
            if result.get("success") and result.get("summary"):
                _store_shared_finding(mission_pid, agent_id, result.get("summary", ""))
            
            with _MISSIONS_LOCK:
                _MISSIONS[mission_id]["agent_results"] = [
                    {
                        "agent_id": ar.get("agent_id", "?"),
                        "success": ar.get("success", False),
                        "pid": ar.get("pid", "?"),
                        "kernel_managed": ar.get("kernel_managed", False),
                        "iterations": ar.get("iterations", 0),
                        "tool_calls": len(ar.get("tool_calls", [])),
                        "duration_ms": ar.get("duration_ms", 0),
                        "summary": str(ar.get("summary", ""))[:500],
                        "error": ar.get("error")
                    }
                    for ar in agent_results
                ]
    
    # Step 4: Aggregate
    with _MISSIONS_LOCK:
        _MISSIONS[mission_id]["status"] = "aggregating"
    
    unified_report = await _aggregate_results(goal, agent_results, plan.get("aggregator", "ai-chief-ciso"), model)
    
    duration_ms = int((time.time() - start_time) * 1000)
    total_tool_calls = sum(len(ar.get("tool_calls", [])) for ar in agent_results)
    successful_agents = sum(1 for ar in agent_results if ar.get("success"))
    
    result = {
        "mission_id": mission_id,
        "goal": goal,
        "plan": plan,
        "agent_results": [
            {
                "agent_id": ar.get("agent_id", "?"),
                "success": ar.get("success", False),
                "pid": ar.get("pid", "?"),
                "kernel_managed": ar.get("kernel_managed", False),
                "iterations": ar.get("iterations", 0),
                "tool_calls": len(ar.get("tool_calls", [])),
                "duration_ms": ar.get("duration_ms", 0),
                "summary": str(ar.get("summary", ""))[:500],
                "error": ar.get("error")
            }
            for ar in agent_results
        ],
        "unified_report": unified_report,
        "duration_ms": duration_ms,
        "kernel_managed": KERNEL_AVAILABLE,
        "mission_pid": mission_pid,
        "total_tool_calls": total_tool_calls,
        "successful_agents": successful_agents,
        "total_agents": len(agent_results),
        "status": "completed",
        "completed_at": datetime.now().isoformat(),
    }
    
    # Update in-memory registry
    with _MISSIONS_LOCK:
        _MISSIONS[mission_id].update(result)
        _MISSIONS[mission_id]["status"] = "completed"
    
    # FEATURE 4: Persist to PostgreSQL
    _persist_mission(result)
    
    logger.info("Mission %s complete: %d agents, %d tool calls, %dms" % (mission_id, successful_agents, total_tool_calls, duration_ms))
    return result

# ═══════════════════════════════════════════════════════════
# FEATURE 2: Async mission execution
# ═══════════════════════════════════════════════════════════
async def start_mission_async(goal: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Start a mission in background, return mission_id immediately."""
    mission_id = "mission-%s" % uuid.uuid4().hex[:12]
    
    with _MISSIONS_LOCK:
        _MISSIONS[mission_id] = {
            "mission_id": mission_id,
            "goal": goal,
            "status": "queued",
            "started_at": time.time(),
            "agent_results": [],
        }
    
    # Persist initial state
    _persist_mission({
        "mission_id": mission_id,
        "goal": goal,
        "status": "running",
        "plan": {},
        "agent_results": [],
        "unified_report": "",
        "mission_pid": "",
        "total_tool_calls": 0,
        "successful_agents": 0,
        "total_agents": 0,
        "duration_ms": 0,
        "kernel_managed": KERNEL_AVAILABLE,
    })
    
    # Start background task
    async def _run():
        try:
            await execute_mission(goal, context, mission_id=mission_id)
        except Exception as e:
            logger.error("Async mission %s failed: %s" % (mission_id, e))
            with _MISSIONS_LOCK:
                _MISSIONS[mission_id]["status"] = "failed"
                _MISSIONS[mission_id]["error"] = str(e)
            _persist_mission({
                "mission_id": mission_id,
                "goal": goal,
                "status": "failed",
                "plan": {},
                "agent_results": [],
                "unified_report": "Mission failed: %s" % str(e),
                "mission_pid": "",
                "total_tool_calls": 0,
                "successful_agents": 0,
                "total_agents": 0,
                "duration_ms": 0,
                "kernel_managed": False,
            })
    
    asyncio.create_task(_run())
    
    logger.info("Async mission %s queued" % mission_id)
    return {
        "mission_id": mission_id,
        "status": "running",
        "goal": goal,
        "message": "Mission started. Poll GET /bridge/mission/%s for status." % mission_id
    }

def get_mission_status(mission_id: str) -> Dict[str, Any]:
    """Get mission status — checks in-memory first, then PostgreSQL."""
    # Check in-memory
    with _MISSIONS_LOCK:
        if mission_id in _MISSIONS:
            m = _MISSIONS[mission_id]
            return {
                "mission_id": mission_id,
                "status": m.get("status", "unknown"),
                "goal": m.get("goal", ""),
                "agent_results": m.get("agent_results", []),
                "unified_report": m.get("unified_report", ""),
                "duration_ms": m.get("duration_ms", 0),
                "total_tool_calls": m.get("total_tool_calls", 0),
                "successful_agents": m.get("successful_agents", 0),
                "total_agents": m.get("total_agents", 0),
                "kernel_managed": m.get("kernel_managed", False),
                "mission_pid": m.get("mission_pid", ""),
                "source": "memory"
            }
    
    # Check PostgreSQL
    db_result = _load_mission_from_db(mission_id)
    if db_result:
        return {
            "mission_id": mission_id,
            "status": db_result.get("status", "unknown"),
            "goal": db_result.get("goal", ""),
            "agent_results": db_result.get("agent_results", []),
            "unified_report": db_result.get("unified_report", ""),
            "duration_ms": db_result.get("duration_ms", 0),
            "total_tool_calls": db_result.get("total_tool_calls", 0),
            "successful_agents": db_result.get("successful_agents", 0),
            "total_agents": db_result.get("total_agents", 0),
            "kernel_managed": db_result.get("kernel_managed", False),
            "mission_pid": db_result.get("mission_pid", ""),
            "source": "postgresql"
        }
    
    return {"mission_id": mission_id, "status": "not_found"}

# ═══════════════════════════════════════════════════════════
# Result aggregation
# ═══════════════════════════════════════════════════════════
async def _aggregate_results(goal, agent_results, aggregator_agent, model="gpt-4.1") -> str:
    """GPT-4.1 synthesizes all agent results into a unified report."""
    agent_summaries = []
    for ar in agent_results:
        agent_summaries.append("Agent: %s [%s]\nTools used: %d\nSummary: %s" % (
            ar.get("agent_id", "?"),
            "SUCCESS" if ar.get("success") else "FAILED",
            len(ar.get("tool_calls", [])),
            str(ar.get("summary", "No summary"))[:500]
        ))
    
    context_text = "\n\n---\n\n".join(agent_summaries)
    
    synthesis_prompt = """You are the GDS OS Mission Aggregator. Multiple AI security agents completed tasks. Synthesize their findings into a unified security report.

MISSION GOAL: %s

AGENT RESULTS:
%s

Create a concise but comprehensive security report:
1. Executive Summary (2-3 sentences)
2. Key Findings (bullet points with severity)
3. Risk Assessment (overall risk level + trending)
4. Recommended Actions (prioritized list)

Format as clean text, no markdown headers.""" % (goal, context_text)
    
    try:
        import openai
        from dotenv import load_dotenv
        load_dotenv("/opt/.env")
        client = openai.OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": synthesis_prompt},
                {"role": "user", "content": "Generate the unified security report now."}
            ],
            temperature=0.2,
            max_tokens=2000
        )
        return response.choices[0].message.content or "No report generated"
    except Exception as e:
        logger.error("Aggregation failed: %s" % e)
        return "Mission Report (Fallback)\n\n" + "\n\n".join(agent_summaries)

# ═══════════════════════════════════════════════════════════
# Entry points
# ═══════════════════════════════════════════════════════════
async def run_mission(goal: str, context: Optional[Dict[str, Any]] = None, async_mode: bool = False) -> Dict[str, Any]:
    """Entry point — sync or async mode."""
    if async_mode:
        return await start_mission_async(goal, context)
    return await execute_mission(goal, context)
