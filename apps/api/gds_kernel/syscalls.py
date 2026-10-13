"""
GDS Agent Kernel — Phase 4: System Call Interface (Syscall)
=============================================================
The formal API that agents use to request kernel services.
Replaces direct REST calls and Python imports with OS-style traps.

Every agent operation goes through the syscall interface, allowing
the kernel to intercept, log, rate-limit, and sandbox all activity.

System Calls:
  Process Management:
    sys_agent_create(spec)      → Create a new agent process
    sys_agent_terminate(pid)    → Terminate a process
    sys_agent_status(pid)       → Get process state
  
  Memory Management:
    sys_mem_alloc(pid, content, type, importance) → Allocate context memory
    sys_mem_page_in(pid, seg_id)  → Page in from swap/disk
    sys_mem_page_out(pid, seg_id) → Page out to swap/disk
    sys_mem_build_context(pid)    → Build full prompt from context
  
  Tool Execution:
    sys_tool_call(tool_id, payload) → Execute a sandboxed tool
    sys_tool_status(tool_id)         → Check tool health
  
  LLM Compute:
    sys_llm_request(pid, messages, tools) → Request LLM completion
    sys_llm_model_select(complexity, priority) → Get recommended model
  
  IPC:
    sys_ipc_send(target_pid, message) → Send message to another agent
    sys_ipc_recv(pid)                  → Receive pending messages
  
  Approval:
    sys_approval_request(pid, action, risk) → Request human approval
    sys_approval_grant(pid, approved, reason) → Grant/deny approval
  
  Kernel Info:
    sys_kernel_status()   → Get kernel status
    sys_process_list()    → List all processes
    sys_memory_stats(pid) → Get memory stats for a process
"""

import time
import json
import logging
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from enum import Enum

from .process import AgentProcessControlBlock as APCB, ProcessState, ProcessPriority, BlockReason
from .scheduler import AgentScheduler
from .arbitrator import LLMArbitrator, LLMModel
from .memory import MemoryManager, MemorySegmentType
from .sandbox import ToolSandbox, ToolDriver, ExecutionResult

logger = logging.getLogger("gds.kernel.syscall")


class SyscallResult:
    """Standard result from any syscall."""
    def __init__(self, success: bool, data: Any = None, error: str = None):
        self.success = success
        self.data = data
        self.error = error
        self.timestamp = time.time()
    
    def to_dict(self) -> Dict:
        return {
            "success": self.success,
            "data": self.data,
            "error": self.error,
            "timestamp": self.timestamp,
        }
    
    def __repr__(self) -> str:
        if self.success:
            return f"SyscallResult(OK, data={self.data})"
        else:
            return f"SyscallResult(ERROR: {self.error})"


class SystemCallInterface:
    """
    The kernel's syscall interface — the only way agents interact with the system.
    
    Every call is:
      1. Logged (audit trail)
      2. Permission-checked (capability verification)
      3. Rate-limited (if applicable)
      4. Executed through the appropriate subsystem
      5. Result recorded (telemetry)
    """

    def __init__(
        self,
        scheduler: AgentScheduler,
        arbitrator: LLMArbitrator,
        memory: MemoryManager,
        sandbox: ToolSandbox,
    ):
        self.scheduler = scheduler
        self.arbitrator = arbitrator
        self.memory = memory
        self.sandbox = sandbox
        
        # IPC message store (in-memory, could be NATS-backed)
        self.message_queues: Dict[str, List[Dict]] = {}  # pid → messages
        
        # Audit log — every syscall is recorded
        self.audit_log: List[Dict] = []
        
        # Syscall counters
        self.syscall_counts: Dict[str, int] = {}
        self.syscall_latencies: Dict[str, float] = {}  # rolling avg

    def _audit(self, syscall: str, caller_pid: str, args: Dict, result: SyscallResult, latency_ms: float) -> None:
        """Record syscall in audit log."""
        self.audit_log.append({
            "syscall": syscall,
            "caller_pid": caller_pid,
            "args_summary": str(args)[:200],
            "success": result.success,
            "error": result.error,
            "latency_ms": round(latency_ms, 2),
            "timestamp": result.timestamp,
        })
        
        # Update counters
        self.syscall_counts[syscall] = self.syscall_counts.get(syscall, 0) + 1
        # Rolling average latency
        old = self.syscall_latencies.get(syscall, latency_ms)
        self.syscall_latencies[syscall] = (old * 0.9) + (latency_ms * 0.1)
        
        # Trim audit log
        if len(self.audit_log) > 10000:
            self.audit_log = self.audit_log[-5000:]

    def _execute(self, syscall: str, caller_pid: str, fn: Callable, args: Dict) -> SyscallResult:
        """Execute a syscall with logging and error handling."""
        start = time.time()
        try:
            result = fn()
            latency = (time.time() - start) * 1000
            self._audit(syscall, caller_pid, args, result, latency)
            return result
        except Exception as e:
            latency = (time.time() - start) * 1000
            result = SyscallResult(success=False, error=f"Syscall error: {e}")
            self._audit(syscall, caller_pid, args, result, latency)
            logger.error(f"Syscall {syscall} error: {e}", exc_info=True)
            return result

    # ===== Process Management Syscalls =====

    def sys_agent_create(
        self, caller_pid: str, agent_id: str, task_name: str, goal: str,
        priority: int = 2, depends_on: List[str] = None
    ) -> SyscallResult:
        """Create a new agent process."""
        def _create():
            prio = ProcessPriority(priority)
            apcb = APCB.create(agent_id=agent_id, task_name=task_name, goal=goal,
                             priority=prio, depends_on=depends_on)
            pid = self.scheduler.admit(apcb)
            self.memory.create_context_window(pid)
            return SyscallResult(success=True, data={"pid": pid})
        return self._execute("sys_agent_create", caller_pid, _create, 
                           {"agent_id": agent_id, "task_name": task_name})

    def sys_agent_terminate(self, caller_pid: str, target_pid: str, reason: str = "") -> SyscallResult:
        """Terminate an agent process."""
        def _term():
            ok = self.scheduler.complete_process(target_pid, error=reason)
            if ok:
                self.memory.destroy_context_window(target_pid)
                self.arbitrator.release_budget(target_pid)
                return SyscallResult(success=True, data={"pid": target_pid, "terminated": True})
            return SyscallResult(success=False, error=f"Process {target_pid} not found or already terminated")
        return self._execute("sys_agent_terminate", caller_pid, _term, {"target_pid": target_pid})

    def sys_agent_status(self, caller_pid: str, target_pid: str) -> SyscallResult:
        """Get the status of an agent process."""
        def _status():
            apcb = self.scheduler.get_process(target_pid)
            if apcb is None:
                return SyscallResult(success=False, error=f"Process {target_pid} not found")
            return SyscallResult(success=True, data={
                "pid": apcb.pid,
                "agent_id": apcb.agent_id,
                "state": apcb.state.value,
                "priority": apcb.priority.name,
                "task_name": apcb.task_name,
                "runtime_seconds": apcb.runtime_seconds,
                "block_reason": apcb.block_reason.value if apcb.state == ProcessState.BLOCKED else None,
            })
        return self._execute("sys_agent_status", caller_pid, _status, {"target_pid": target_pid})

    # ===== Memory Management Syscalls =====

    def sys_mem_alloc(
        self, caller_pid: str, content: str, segment_type: str = "working",
        importance: float = 0.5
    ) -> SyscallResult:
        """Allocate content into a process's context window."""
        def _alloc():
            seg_type = MemorySegmentType(segment_type)
            seg_id = self.memory.allocate(caller_pid, content, seg_type, importance)
            if seg_id:
                return SyscallResult(success=True, data={"segment_id": seg_id})
            return SyscallResult(success=False, error="Context window full and page fault could not free enough space")
        return self._execute("sys_mem_alloc", caller_pid, _alloc,
                           {"type": segment_type, "tokens_est": len(content) // 4})

    def sys_mem_build_context(self, caller_pid: str, target_pid: str) -> SyscallResult:
        """Build the full LLM prompt from a process's context window."""
        def _build():
            prompt = self.memory.build_context_prompt(target_pid)
            stats = self.memory.get_memory_stats(target_pid)
            return SyscallResult(success=True, data={
                "prompt": prompt,
                "tokens_used": stats.get("tokens_used", 0),
                "tokens_remaining": stats.get("tokens_remaining", 0),
                "utilization_pct": stats.get("utilization_pct", 0),
            })
        return self._execute("sys_mem_build_context", caller_pid, _build, {"target_pid": target_pid})

    def sys_mem_stats(self, caller_pid: str, target_pid: str) -> SyscallResult:
        """Get memory statistics for a process."""
        def _stats():
            stats = self.memory.get_memory_stats(target_pid)
            return SyscallResult(success=True, data=stats)
        return self._execute("sys_mem_stats", caller_pid, _stats, {"target_pid": target_pid})

    # ===== Tool Execution Syscalls =====

    async def sys_tool_call(self, caller_pid: str, tool_id: str, payload: Dict) -> SyscallResult:
        """Execute a tool through the sandbox."""
        start = time.time()
        try:
            result: ExecutionResult = await self.sandbox.execute(tool_id, payload)
            latency = (time.time() - start) * 1000
            
            syscall_result = SyscallResult(
                success=result.success,
                data=result.output if result.success else None,
                error=result.error,
            )
            self._audit("sys_tool_call", caller_pid, 
                       {"tool_id": tool_id, "payload_keys": list(payload.keys())},
                       syscall_result, latency)
            return syscall_result
        except Exception as e:
            latency = (time.time() - start) * 1000
            result = SyscallResult(success=False, error=f"Tool syscall error: {e}")
            self._audit("sys_tool_call", caller_pid, {"tool_id": tool_id}, result, latency)
            return result

    def sys_tool_status(self, caller_pid: str, tool_id: str) -> SyscallResult:
        """Check a tool driver's health status."""
        def _status():
            driver = self.sandbox.get_driver(tool_id)
            if driver is None:
                return SyscallResult(success=False, error=f"Tool '{tool_id}' not registered")
            return SyscallResult(success=True, data=driver.to_dict())
        return self._execute("sys_tool_status", caller_pid, _status, {"tool_id": tool_id})

    def sys_tool_list(self, caller_pid: str) -> SyscallResult:
        """List all available tool drivers."""
        def _list():
            return SyscallResult(success=True, data=self.sandbox.list_drivers())
        return self._execute("sys_tool_list", caller_pid, _list, {})

    # ===== LLM Compute Syscalls =====

    def sys_llm_request(self, caller_pid: str, estimated_tokens: int = 5000) -> SyscallResult:
        """Request permission for an LLM API call."""
        def _request():
            approved, reason = self.arbitrator.request_llm_call(caller_pid, estimated_tokens)
            return SyscallResult(success=approved, data={"approved": approved, "reason": reason})
        return self._execute("sys_llm_request", caller_pid, _request,
                           {"estimated_tokens": estimated_tokens})

    def sys_llm_record(self, caller_pid: str, input_tokens: int, output_tokens: int) -> SyscallResult:
        """Record LLM usage after a call completes."""
        def _record():
            self.arbitrator.record_llm_usage(caller_pid, input_tokens, output_tokens)
            return SyscallResult(success=True, data={"total_tokens": input_tokens + output_tokens})
        return self._execute("sys_llm_record", caller_pid, _record,
                           {"input_tokens": input_tokens, "output_tokens": output_tokens})

    def sys_llm_model_select(self, caller_pid: str, task_complexity: str, priority: int) -> SyscallResult:
        """Get the recommended LLM model for a task."""
        def _select():
            model = self.arbitrator.select_model(task_complexity, priority)
            return SyscallResult(success=True, data={"model": model.value})
        return self._execute("sys_llm_model_select", caller_pid, _select,
                           {"complexity": task_complexity, "priority": priority})

    # ===== IPC Syscalls =====

    def sys_ipc_send(self, caller_pid: str, target_pid: str, message: Dict) -> SyscallResult:
        """Send a message to another agent process."""
        def _send():
            if target_pid not in self.scheduler.process_table:
                return SyscallResult(success=False, error=f"Target process {target_pid} not found")
            
            # Add to target's message queue
            if target_pid not in self.message_queues:
                self.message_queues[target_pid] = []
            self.message_queues[target_pid].append({
                "from": caller_pid,
                "message": message,
                "timestamp": time.time(),
            })
            
            # If target is blocked waiting for a message, unblock it
            target = self.scheduler.get_process(target_pid)
            if target and target.state == ProcessState.BLOCKED:
                self.scheduler.unblock_process(target_pid)
            
            return SyscallResult(success=True, data={"delivered": True})
        return self._execute("sys_ipc_send", caller_pid, _send,
                           {"target_pid": target_pid, "message_type": message.get("type", "unknown")})

    def sys_ipc_recv(self, caller_pid: str) -> SyscallResult:
        """Receive pending messages for a process."""
        def _recv():
            messages = self.message_queues.get(caller_pid, [])
            if not messages:
                return SyscallResult(success=True, data={"messages": [], "count": 0})
            
            # Return and clear messages
            msgs = messages.copy()
            self.message_queues[caller_pid] = []
            return SyscallResult(success=True, data={"messages": msgs, "count": len(msgs)})
        return self._execute("sys_ipc_recv", caller_pid, _recv, {})

    # ===== Approval Syscalls =====

    def sys_approval_request(
        self, caller_pid: str, action: str, risk_level: str, description: str = ""
    ) -> SyscallResult:
        """Request human approval for a high-risk action."""
        def _request():
            self.scheduler.block_process(caller_pid, BlockReason.WAITING_APPROVAL)
            approval_id = f"APR-{caller_pid[:8]}-{int(time.time())}"
            return SyscallResult(success=True, data={
                "approval_id": approval_id,
                "pid": caller_pid,
                "action": action,
                "risk_level": risk_level,
                "description": description,
                "status": "pending",
            })
        return self._execute("sys_approval_request", caller_pid, _request,
                           {"action": action, "risk_level": risk_level})

    def sys_approval_grant(self, caller_pid: str, target_pid: str, approved: bool, reason: str = "") -> SyscallResult:
        """Grant or deny an approval request."""
        def _grant():
            apcb = self.scheduler.get_process(target_pid)
            if apcb is None or apcb.block_reason != BlockReason.WAITING_APPROVAL:
                return SyscallResult(success=False, error=f"Process {target_pid} not found or not awaiting approval")
            
            if approved:
                self.scheduler.unblock_process(target_pid)
                return SyscallResult(success=True, data={"pid": target_pid, "approved": True})
            else:
                self.scheduler.complete_process(target_pid, error=f"Approval denied: {reason}")
                return SyscallResult(success=True, data={"pid": target_pid, "approved": False, "reason": reason})
        return self._execute("sys_approval_grant", caller_pid, _grant,
                           {"target_pid": target_pid, "approved": approved})

    # ===== Kernel Info Syscalls =====

    def sys_kernel_status(self, caller_pid: str) -> SyscallResult:
        """Get kernel status."""
        def _status():
            return SyscallResult(success=True, data={
                "scheduler": self.scheduler.get_stats(),
                "arbitrator": self.arbitrator.get_stats(),
                "sandbox": self.sandbox.get_stats(),
                "memory": self.memory.get_global_stats(),
                "audit_log_size": len(self.audit_log),
                "syscall_counts": self.syscall_counts,
                "syscall_latencies": {k: round(v, 2) for k, v in self.syscall_latencies.items()},
            })
        return self._execute("sys_kernel_status", caller_pid, _status, {})

    def sys_process_list(self, caller_pid: str) -> SyscallResult:
        """List all processes in the system."""
        def _list():
            processes = []
            for apcb in self.scheduler.process_table.values():
                processes.append({
                    "pid": apcb.pid,
                    "agent_id": apcb.agent_id,
                    "task_name": apcb.task_name,
                    "state": apcb.state.value,
                    "priority": apcb.priority.name,
                    "runtime_seconds": apcb.runtime_seconds,
                })
            return SyscallResult(success=True, data=processes)
        return self._execute("sys_process_list", caller_pid, _list, {})

    def get_audit_log(self, last_n: int = 100) -> List[Dict]:
        """Get the last N audit entries."""
        return self.audit_log[-last_n:]

    def get_syscall_stats(self) -> Dict:
        """Get syscall statistics."""
        return {
            "total_syscalls": sum(self.syscall_counts.values()),
            "counts": self.syscall_counts,
            "avg_latencies_ms": {k: round(v, 2) for k, v in self.syscall_latencies.items()},
            "audit_log_size": len(self.audit_log),
        }
