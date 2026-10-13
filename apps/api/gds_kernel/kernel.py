"""
GDS Agent Kernel — Phase 1: Main Kernel Daemon
================================================
The central orchestrator that runs as a persistent process.
Manages agent processes, schedules LLM compute, and handles interrupts.

This replaces the passive gdsAIKernel entity with an active runtime.
"""

import time
import json
import logging
import asyncio
import signal
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field

from .process import AgentProcessControlBlock as APCB, ProcessState, ProcessPriority, BlockReason
from .scheduler import AgentScheduler
from .arbitrator import LLMArbitrator, LLMModel

logger = logging.getLogger("gds.kernel")

# Kernel version
KERNEL_VERSION = "1.0.0-phase1"

# Default configuration
DEFAULT_CONFIG = {
    "max_concurrent_agents": 3,
    "stale_timeout_seconds": 300,
    "global_tokens_per_minute": 1_000_000,
    "max_concurrent_llm_calls": 3,
    "scheduler_interval_ms": 100,  # How often the scheduler runs
    "checkpoint_interval_seconds": 30,  # How often to checkpoint running processes
    "cleanup_interval_seconds": 300,   # How often to clean terminated processes
}


class GDSAgentKernel:
    """
    The GDS Agent OS Kernel — a persistent process that manages agent execution.
    
    Lifecycle:
      1. boot() — Initialize kernel, load agents, restore state
      2. run()  — Main loop: schedule, dispatch, monitor, checkpoint
      3. shutdown() — Graceful shutdown: checkpoint all, terminate all
    
    The kernel maintains:
      - Process table (all APCBs)
      - Scheduler (ready/running/blocked queues)
      - LLM Arbitrator (token budgets)
      - Event hooks (callbacks for process state changes)
    
    It exposes a syscall interface (Phase 4 will formalize this) through
    methods that agents call to request resources.
    """

    def __init__(self, config: Optional[Dict] = None):
        self.config = {**DEFAULT_CONFIG, **(config or {})}
        
        # Core subsystems
        self.scheduler = AgentScheduler(
            max_concurrent=self.config["max_concurrent_agents"],
            stale_timeout=self.config["stale_timeout_seconds"],
        )
        self.arbitrator = LLMArbitrator(
            global_tokens_per_minute=self.config["global_tokens_per_minute"],
            max_concurrent_llm_calls=self.config["max_concurrent_llm_calls"],
        )
        
        # Kernel state
        self.boot_time: Optional[float] = None
        self.is_running: bool = False
        self.uptime_seconds: float = 0.0
        self.cycle_count: int = 0
        
        # Event hooks — external systems can register callbacks
        self.hooks: Dict[str, List[Callable]] = {
            "on_dispatch": [],      # When a process starts running
            "on_complete": [],      # When a process finishes
            "on_crash": [],         # When a process crashes
            "on_preempt": [],       # When a process is preempted
            "on_block": [],         # When a process blocks
            "on_unblock": [],       # When a process unblocks
        }
        
        # Registered agent factories — how to actually execute an agent
        self.agent_executors: Dict[str, Callable] = {}
        
        # Crash recovery journal
        self.journal: List[Dict] = []
        
        logger.info(f"GDS Agent Kernel v{KERNEL_VERSION} initialized")

    def boot(self) -> bool:
        """
        Kernel boot sequence:
        1. Verify infrastructure (LLM provider, databases)
        2. Restore process table from journal (crash recovery)
        3. Start scheduler loop
        """
        logger.info("=" * 60)
        logger.info(f"GDS Agent Kernel v{KERNEL_VERSION} — BOOTING")
        logger.info("=" * 60)
        
        self.boot_time = time.time()
        
        # TODO: Verify infrastructure connectivity
        # (LLM provider, PostgreSQL, Redis, Qdrant, etc.)
        logger.info("[1/3] Infrastructure check... (stub — Phase 2 will add real checks)")
        
        # Restore from journal if available
        if self.journal:
            logger.info(f"[2/3] Restoring {len(self.journal)} processes from journal...")
            for entry in self.journal:
                pid = entry.get("pid")
                if pid and pid in self.scheduler.process_table:
                    apcb = self.scheduler.process_table[pid]
                    if apcb.restore_from_checkpoint():
                        logger.info(f"  Restored {pid} ({apcb.agent_id})")
        else:
            logger.info("[2/3] No journal entries — fresh boot")
        
        logger.info("[3/3] Kernel ready")
        self.is_running = True
        logger.info(f"Kernel booted in {time.time() - self.boot_time:.2f}s")
        
        return True

    def register_agent_executor(self, agent_id: str, executor: Callable) -> None:
        """
        Register a function that executes a specific agent.
        The executor receives an APCB and returns a result dict.
        """
        self.agent_executors[agent_id] = executor
        logger.debug(f"Registered executor for agent: {agent_id}")

    def create_process(
        self,
        agent_id: str,
        task_name: str,
        goal: str,
        priority: ProcessPriority = ProcessPriority.P2_MEDIUM,
        depends_on: List[str] = None,
    ) -> str:
        """
        Create and admit a new agent process.
        This is the primary way work enters the system.
        """
        apcb = APCB.create(
            agent_id=agent_id,
            task_name=task_name,
            goal=goal,
            priority=priority,
            depends_on=depends_on,
        )
        pid = self.scheduler.admit(apcb)
        logger.info(f"Created process {pid} for agent '{agent_id}' task '{task_name}'")
        return pid

    async def run_cycle(self) -> List[APCB]:
        """
        Run one scheduling cycle:
        1. Dispatch ready processes to available slots
        2. Execute dispatched processes (call their executors)
        3. Check for stale processes
        4. Periodically checkpoint and cleanup
        """
        self.cycle_count += 1
        self.uptime_seconds = time.time() - (self.boot_time or time.time())
        
        # Dispatch ready processes
        dispatched = self.scheduler.dispatch()
        
        # Execute each dispatched process
        for apcb in dispatched:
            if apcb.state == ProcessState.RUNNING:
                # Allocate compute budget
                model = self.arbitrator.select_model("moderate", apcb.priority.value)
                self.arbitrator.allocate(apcb.pid, apcb.priority.value, model)
                
                # Fire on_dispatch hooks
                self._fire_hooks("on_dispatch", apcb)
                
                # Execute (async — non-blocking)
                executor = self.agent_executors.get(apcb.agent_id)
                if executor:
                    try:
                        # Don't await — let it run concurrently
                        asyncio.create_task(self._execute_process(apcb, executor))
                    except Exception as e:
                        logger.error(f"Failed to start execution for {apcb.pid}: {e}")
                        self.scheduler.complete_process(apcb.pid, error=str(e))
                        self._fire_hooks("on_crash", apcb)
                else:
                    logger.error(f"No executor registered for agent '{apcb.agent_id}'")
                    self.scheduler.complete_process(
                        apcb.pid, error=f"No executor for agent {apcb.agent_id}"
                    )
        
        # Periodic checkpoint
        if self.cycle_count % (self.config["checkpoint_interval_seconds"] * 10) == 0:
            self._checkpoint_all()
        
        # Periodic cleanup
        if self.cycle_count % (self.config["cleanup_interval_seconds"] * 10) == 0:
            removed = self.scheduler.cleanup_terminated()
            if removed:
                logger.info(f"Cleaned up {removed} terminated processes")
        
        return dispatched

    async def _execute_process(self, apcb: APCB, executor: Callable) -> None:
        """Execute an agent process and handle completion/failure."""
        try:
            # Update heartbeat
            self.scheduler.update_heartbeat(apcb.pid)
            
            # Call the executor
            result = await executor(apcb) if asyncio.iscoroutinefunction(executor) else executor(apcb)
            
            # Record LLM usage if available
            if isinstance(result, dict) and "llm_usage" in result:
                usage = result["llm_usage"]
                self.arbitrator.record_llm_usage(
                    apcb.pid,
                    usage.get("input_tokens", 0),
                    usage.get("output_tokens", 0),
                )
            
            # Complete the process
            self.scheduler.complete_process(apcb.pid, result=result)
            self._fire_hooks("on_complete", apcb)
            
            # Release compute budget
            self.arbitrator.release_budget(apcb.pid)
            
        except asyncio.CancelledError:
            logger.warning(f"Process {apcb.pid} was cancelled")
            self.scheduler.complete_process(apcb.pid, error="cancelled")
            self._fire_hooks("on_crash", apcb)
            
        except Exception as e:
            logger.error(f"Process {apcb.pid} crashed: {e}", exc_info=True)
            self.scheduler.complete_process(apcb.pid, error=str(e))
            self._fire_hooks("on_crash", apcb)
            self.arbitrator.release_budget(apcb.pid)

    def block_process(self, pid: str, reason: BlockReason) -> bool:
        """Block a process — it's waiting on something."""
        if self.scheduler.block_process(pid, reason):
            self._fire_hooks("on_block", self.scheduler.get_process(pid))
            return True
        return False

    def unblock_process(self, pid: str) -> bool:
        """Unblock a process — what it was waiting for arrived."""
        if self.scheduler.unblock_process(pid):
            self._fire_hooks("on_unblock", self.scheduler.get_process(pid))
            return True
        return False

    def request_approval(self, pid: str, action: str, risk_level: str) -> str:
        """
        Block a process pending human approval.
        Returns an approval ID that can be used to approve/deny.
        """
        approval_id = f"APR-{pid}-{int(time.time())}"
        self.block_process(pid, BlockReason.WAITING_APPROVAL)
        logger.warning(
            f"Process {pid} blocked for approval: {action} (risk: {risk_level}) "
            f"→ approval_id: {approval_id}"
        )
        return approval_id

    def grant_approval(self, pid: str, approved: bool, reason: str = "") -> bool:
        """Grant or deny an approval — unblocks the process."""
        apcb = self.scheduler.get_process(pid)
        if apcb and apcb.block_reason == BlockReason.WAITING_APPROVAL:
            if approved:
                self.unblock_process(pid)
                logger.info(f"Approval GRANTED for {pid}: {reason}")
                return True
            else:
                self.scheduler.complete_process(pid, error=f"Approval denied: {reason}")
                logger.info(f"Approval DENIED for {pid}: {reason}")
                return True
        return False

    def _checkpoint_all(self) -> None:
        """Save checkpoints for all running processes."""
        for apcb in self.scheduler.running.values():
            apcb.save_checkpoint()
        logger.debug(f"Checkpointed {len(self.scheduler.running)} running processes")

    def _fire_hooks(self, event: str, apcb: APCB) -> None:
        """Fire all registered hooks for an event."""
        for hook in self.hooks.get(event, []):
            try:
                hook(apcb)
            except Exception as e:
                logger.error(f"Hook error for event '{event}': {e}")

    def register_hook(self, event: str, callback: Callable) -> None:
        """Register a callback for a kernel event."""
        if event in self.hooks:
            self.hooks[event].append(callback)
            logger.debug(f"Registered hook for event: {event}")

    def get_kernel_status(self) -> Dict[str, Any]:
        """Return full kernel status — the /proc/kernel equivalent."""
        return {
            "version": KERNEL_VERSION,
            "uptime_seconds": self.uptime_seconds,
            "cycle_count": self.cycle_count,
            "is_running": self.is_running,
            "boot_time": self.boot_time,
            "scheduler": self.scheduler.get_stats(),
            "arbitrator": self.arbitrator.get_stats(),
            "process_table_size": len(self.scheduler.process_table),
            "registered_agents": len(self.agent_executors),
            "config": self.config,
        }

    def get_process_list(self) -> List[Dict]:
        """Return all processes — the /proc/agents equivalent."""
        processes = []
        for apcb in self.scheduler.process_table.values():
            processes.append({
                "pid": apcb.pid,
                "agent_id": apcb.agent_id,
                "task_name": apcb.task_name,
                "state": apcb.state.value,
                "priority": apcb.priority.name,
                "runtime_seconds": apcb.runtime_seconds,
                "tokens_used": apcb.llm_tokens_consumed,
                "llm_calls": apcb.llm_calls_made,
                "tools_called": apcb.tools_called,
                "current_tool": apcb.current_tool,
                "block_reason": apcb.block_reason.value if apcb.state == ProcessState.BLOCKED else None,
            })
        return processes

    async def shutdown(self) -> None:
        """Graceful shutdown — checkpoint all, terminate all."""
        logger.info("Kernel shutting down...")
        
        # Checkpoint all running processes
        self._checkpoint_all()
        
        # Terminate all running processes
        for pid in list(self.scheduler.running.keys()):
            self.scheduler.complete_process(pid, error="kernel_shutdown")
        
        # Write journal for recovery
        self.journal = [apcb.checkpoint for apcb in self.scheduler.process_table.values() 
                        if apcb.checkpoint]
        
        self.is_running = False
        logger.info(f"Kernel shutdown complete. {len(self.journal)} processes journaled.")


# Singleton kernel instance
_kernel_instance: Optional[GDSAgentKernel] = None


def get_kernel() -> GDSAgentKernel:
    """Get the singleton kernel instance."""
    global _kernel_instance
    if _kernel_instance is None:
        _kernel_instance = GDSAgentKernel()
    return _kernel_instance


def boot_kernel(config: Optional[Dict] = None) -> GDSAgentKernel:
    """Boot the kernel with optional config."""
    global _kernel_instance
    _kernel_instance = GDSAgentKernel(config)
    _kernel_instance.boot()
    return _kernel_instance
