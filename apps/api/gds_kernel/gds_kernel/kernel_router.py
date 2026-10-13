"""
GDS Agent Kernel — FastAPI Router
====================================
Exposes kernel syscalls as HTTP endpoints on the VPS API.
Allows the Base44 Co-Pilot to interact with the kernel via the bridge.

Endpoints:
  GET  /kernel/status           — Kernel status
  GET  /kernel/processes          — List all processes
  POST /kernel/process/create     — Create agent process
  POST /kernel/process/terminate  — Terminate process
  POST /kernel/memory/alloc       — Allocate memory
  GET  /kernel/memory/stats/{pid} — Memory stats
  POST /kernel/tool/execute      — Execute tool via sandbox
  GET  /kernel/tools             — List tool drivers
  POST /kernel/llm/request       — Request LLM compute
  POST /kernel/ipc/send          — Send IPC message
  GET  /kernel/ipc/recv/{pid}     — Receive IPC messages
  POST /kernel/approval/request  — Request human approval
  POST /kernel/approval/grant    — Grant/deny approval
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Dict, List, Optional, Any
import logging

logger = logging.getLogger("gds.kernel.router")
router = APIRouter(prefix="/kernel", tags=["GDS Agent Kernel"])

# Lazy kernel initialization
_kernel = None

def get_kernel():
    global _kernel
    if _kernel is None:
        from gds_kernel.unified_kernel import GDSUnifiedKernel
        _kernel = GDSUnifiedKernel()
        _kernel.boot()
        logger.info("Kernel initialized via router")
    return _kernel


# ===== Models =====

class CreateProcessRequest(BaseModel):
    agent_id: str
    task_name: str
    goal: str
    priority: int = 2
    depends_on: List[str] = []

class TerminateProcessRequest(BaseModel):
    pid: str
    reason: str = ""

class AllocMemoryRequest(BaseModel):
    pid: str
    content: str
    segment_type: str = "working"
    importance: float = 0.5

class ToolExecuteRequest(BaseModel):
    pid: str
    tool_id: str
    payload: Dict[str, Any] = {}

class LLMRequest(BaseModel):
    pid: str
    estimated_tokens: int = 5000

class IPCSendRequest(BaseModel):
    from_pid: str
    to_pid: str
    message: Dict[str, Any]

class ApprovalRequest(BaseModel):
    pid: str
    action: str
    risk_level: str
    description: str = ""

class ApprovalGrantRequest(BaseModel):
    approver_pid: str = "kernel"
    target_pid: str
    approved: bool
    reason: str = ""


# ===== Endpoints =====

@router.get("/status")
async def kernel_status():
    """Get kernel status — the /proc/kernel equivalent."""
    k = get_kernel()
    return k.get_status()

@router.get("/processes")
async def list_processes():
    """List all agent processes."""
    k = get_kernel()
    return k.syscall.sys_process_list("kernel").data

@router.post("/process/create")
async def create_process(req: CreateProcessRequest):
    """Create a new agent process."""
    k = get_kernel()
    result = k.syscall.sys_agent_create(
        "kernel", req.agent_id, req.task_name, req.goal,
        req.priority, req.depends_on
    )
    if not result.success:
        raise HTTPException(400, result.error)
    return result.data

@router.post("/process/terminate")
async def terminate_process(req: TerminateProcessRequest):
    """Terminate an agent process."""
    k = get_kernel()
    result = k.syscall.sys_agent_terminate("kernel", req.pid, req.reason)
    if not result.success:
        raise HTTPException(400, result.error)
    return result.data

@router.get("/memory/stats/{pid}")
async def memory_stats(pid: str):
    """Get memory stats for a process."""
    k = get_kernel()
    result = k.syscall.sys_mem_stats("kernel", pid)
    return result.data

@router.post("/memory/alloc")
async def alloc_memory(req: AllocMemoryRequest):
    """Allocate content into a process's context window."""
    k = get_kernel()
    result = k.syscall.sys_mem_alloc(req.pid, req.content, req.segment_type, req.importance)
    if not result.success:
        raise HTTPException(400, result.error)
    return result.data

@router.get("/tools")
async def list_tools():
    """List all registered tool drivers."""
    k = get_kernel()
    result = k.syscall.sys_tool_list("kernel")
    return result.data

@router.post("/tool/execute")
async def execute_tool(req: ToolExecuteRequest):
    """Execute a tool through the sandbox."""
    k = get_kernel()
    result = await k.syscall.sys_tool_call(req.pid, req.tool_id, req.payload)
    if not result.success:
        raise HTTPException(400, result.error)
    return result.data

@router.post("/llm/request")
async def llm_request(req: LLMRequest):
    """Request LLM compute allocation."""
    k = get_kernel()
    result = k.syscall.sys_llm_request(req.pid, req.estimated_tokens)
    return result.data

@router.post("/ipc/send")
async def ipc_send(req: IPCSendRequest):
    """Send an IPC message between agents."""
    k = get_kernel()
    result = k.syscall.sys_ipc_send(req.from_pid, req.to_pid, req.message)
    return result.data

@router.get("/ipc/recv/{pid}")
async def ipc_recv(pid: str):
    """Receive pending IPC messages for a process."""
    k = get_kernel()
    result = k.syscall.sys_ipc_recv(pid)
    return result.data

@router.post("/approval/request")
async def approval_request(req: ApprovalRequest):
    """Request human approval for a high-risk action."""
    k = get_kernel()
    result = k.syscall.sys_approval_request(req.pid, req.action, req.risk_level, req.description)
    return result.data

@router.post("/approval/grant")
async def approval_grant(req: ApprovalGrantRequest):
    """Grant or deny an approval."""
    k = get_kernel()
    result = k.syscall.sys_approval_grant(req.approver_pid, req.target_pid, req.approved, req.reason)
    return result.data

@router.get("/audit")
async def audit_log(last_n: int = 100):
    """Get the last N syscall audit entries."""
    k = get_kernel()
    return k.syscall.get_audit_log(last_n)

@router.get("/stats")
async def kernel_stats():
    """Get kernel syscall statistics."""
    k = get_kernel()
    return k.syscall.get_syscall_stats()
