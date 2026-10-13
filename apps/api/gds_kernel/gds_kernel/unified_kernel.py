"""
GDS Agent Kernel — Unified Kernel (All 4 Phases)
===================================================
Integrates Phase 1-4 into a single, cohesive Agentic OS kernel.

Phase 1: Active Kernel Runtime (process.py, scheduler.py, arbitrator.py, kernel.py)
Phase 2: Virtual Context Paging (memory.py)
Phase 3: Isolated Tool Sandbox (sandbox.py)
Phase 4: System Call Interface (syscalls.py)

Usage:
    from gds_kernel.unified_kernel import GDSUnifiedKernel
    
    kernel = GDSUnifiedKernel()
    kernel.boot()
    
    # Create an agent process
    pid = kernel.syscall.sys_agent_create("kernel", "ai-vuln-director", "nmap_scan", "Scan localhost")["data"]["pid"]
    
    # Allocate memory for system prompt
    kernel.syscall.sys_mem_alloc(pid, "You are AI Vuln Director...", "system_prompt", 1.0)
    
    # Execute a tool
    result = await kernel.syscall.sys_tool_call(pid, "nmap_scan", {"target": "localhost"})
"""

import asyncio
import logging
from typing import Dict, List, Optional, Any

from .process import AgentProcessControlBlock as APCB, ProcessState, ProcessPriority, BlockReason
from .scheduler import AgentScheduler
from .arbitrator import LLMArbitrator, LLMModel
from .memory import MemoryManager
from .sandbox import ToolSandbox, ToolDriver, ToolCapability, create_default_drivers
from .syscalls import SystemCallInterface, SyscallResult
from .kernel import KERNEL_VERSION

logger = logging.getLogger("gds.kernel.unified")


class GDSUnifiedKernel:
    """
    The complete GDS Agent OS Kernel — all 4 phases integrated.
    
    This is the runtime that transforms GDS OS from a platform into
    an operating system. It runs as a persistent process on the VPS
    alongside (but separate from) the FastAPI backend.
    """
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = {
            # Scheduler
            "max_concurrent_agents": 3,
            "stale_timeout_seconds": 300,
            # LLM Arbitrator
            "global_tokens_per_minute": 1_000_000,
            "max_concurrent_llm_calls": 3,
            # Memory
            "context_window_tokens": 128000,
            # Sandbox
            "max_concurrent_tools": 5,
            "default_tool_timeout": 120,
            # Misc
            "redis_url": None,
            "qdrant_url": None,
            **(config or {}),
        }
        
        # Phase 1: Scheduler + Arbitrator
        self.scheduler = AgentScheduler(
            max_concurrent=self.config["max_concurrent_agents"],
            stale_timeout=self.config["stale_timeout_seconds"],
        )
        self.arbitrator = LLMArbitrator(
            global_tokens_per_minute=self.config["global_tokens_per_minute"],
            max_concurrent_llm_calls=self.config["max_concurrent_llm_calls"],
        )
        
        # Phase 2: Memory Manager
        self.memory = MemoryManager()
        
        # Phase 3: Tool Sandbox
        self.sandbox = ToolSandbox(
            max_concurrent_tools=self.config["max_concurrent_tools"],
            default_timeout=self.config["default_tool_timeout"],
        )
        
        # Phase 4: Syscall Interface
        self.syscall = SystemCallInterface(
            scheduler=self.scheduler,
            arbitrator=self.arbitrator,
            memory=self.memory,
            sandbox=self.sandbox,
        )
        
        # Kernel state
        self.boot_time: Optional[float] = None
        self.is_running: bool = False
        self.cycle_count: int = 0
        
        # Agent executors (registered by external code)
        self.agent_executors: Dict[str, Any] = {}
        
        logger.info(f"GDS Unified Kernel v{KERNEL_VERSION} — All 4 phases initialized")

    def boot(self) -> bool:
        """Boot the kernel and register default tool drivers."""
        logger.info("=" * 60)
        logger.info(f"GDS UNIFIED KERNEL v{KERNEL_VERSION} — BOOTING")
        logger.info("=" * 60)
        
        self.boot_time = asyncio.get_event_loop().time() if asyncio.get_event_loop().is_running() else 0
        
        # Phase 3: Register default tool drivers
        drivers = create_default_drivers()
        for tid, driver in drivers.items():
            self.sandbox.register_driver(driver)
        logger.info(f"Registered {len(drivers)} tool drivers")
        
        logger.info("Kernel phases:")
        logger.info("  Phase 1: Active Kernel Runtime ✅ (scheduler + arbitrator)")
        logger.info("  Phase 2: Virtual Context Paging ✅ (memory manager)")
        logger.info("  Phase 3: Tool Driver Sandbox ✅ (10 drivers registered)")
        logger.info("  Phase 4: System Call Interface ✅ (18 syscalls available)")
        
        self.is_running = True
        logger.info(f"Kernel booted successfully")
        return True

    def register_agent_executor(self, agent_id: str, executor) -> None:
        """Register a function that executes an agent."""
        self.agent_executors[agent_id] = executor

    def register_tool_driver(self, driver: ToolDriver) -> bool:
        """Register a custom tool driver."""
        return self.sandbox.register_driver(driver)

    async def run_cycle(self) -> Dict[str, Any]:
        """Run one kernel cycle: schedule, dispatch, monitor."""
        self.cycle_count += 1
        
        # Dispatch ready processes
        dispatched = self.scheduler.dispatch()
        
        # Execute dispatched processes
        results = []
        for apcb in dispatched:
            if apcb.state == ProcessState.RUNNING:
                executor = self.agent_executors.get(apcb.agent_id)
                if executor:
                    # Allocate LLM budget
                    model = self.arbitrator.select_model("moderate", apcb.priority.value)
                    self.arbitrator.allocate(apcb.pid, apcb.priority.value, model)
                    
                    # Execute asynchronously
                    try:
                        result = await executor(apcb, self.syscall) if asyncio.iscoroutinefunction(executor) else executor(apcb, self.syscall)
                        self.scheduler.complete_process(apcb.pid, result=result)
                        results.append({"pid": apcb.pid, "status": "completed", "result": result})
                    except Exception as e:
                        self.scheduler.complete_process(apcb.pid, error=str(e))
                        results.append({"pid": apcb.pid, "status": "crashed", "error": str(e)})
                else:
                    self.scheduler.complete_process(apcb.pid, error=f"No executor for {apcb.agent_id}")
                    results.append({"pid": apcb.pid, "status": "no_executor"})
        
        return {
            "cycle": self.cycle_count,
            "dispatched": len(dispatched),
            "results": results,
            "scheduler": self.scheduler.get_stats(),
            "sandbox": self.sandbox.get_stats(),
            "memory": self.memory.get_global_stats(),
            "arbitrator": self.arbitrator.get_stats(),
        }

    def get_status(self) -> Dict[str, Any]:
        """Get full kernel status — the /proc/kernel equivalent."""
        return {
            "version": KERNEL_VERSION,
            "is_running": self.is_running,
            "cycle_count": self.cycle_count,
            "phases": {
                "phase_1_kernel": "active",
                "phase_2_memory": "active",
                "phase_3_sandbox": "active",
                "phase_4_syscalls": "active",
            },
            "scheduler": self.scheduler.get_stats(),
            "arbitrator": self.arbitrator.get_stats(),
            "sandbox": self.sandbox.get_stats(),
            "memory": self.memory.get_global_stats(),
            "syscalls": self.syscall.get_syscall_stats(),
            "registered_agents": len(self.agent_executors),
            "registered_tools": len(self.sandbox.drivers),
        }


# Singleton
_unified_kernel: Optional[GDSUnifiedKernel] = None

def get_unified_kernel(config: Optional[Dict] = None) -> GDSUnifiedKernel:
    """Get or create the singleton unified kernel."""
    global _unified_kernel
    if _unified_kernel is None:
        _unified_kernel = GDSUnifiedKernel(config)
    return _unified_kernel
