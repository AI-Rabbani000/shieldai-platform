"""
GDS Agent Kernel — Phase 1: Agent Process Control Block (APCB)
=============================================================
Each agent task is treated as a Process with a control block tracking:
  - State (NEW → READY → RUNNING → BLOCKED → TERMINATED)
  - Priority (P0 critical, P1 high, P2 medium, P3 low)
  - Context window budget (tokens allocated / used / remaining)
  - Dependencies (which steps must complete before this one starts)
  - Checkpoint state (for recovery after crash)
"""

import time
import uuid
import json
from enum import Enum
from dataclasses import dataclass, field, asdict
from typing import Optional, Dict, List, Any


class ProcessState(Enum):
    """Agent process lifecycle states — mirrors OS process states."""
    NEW = "new"           # Created but not yet admitted to scheduler
    READY = "ready"       # Admitted, waiting for LLM compute
    RUNNING = "running"   # Currently executing (LLM call in progress)
    BLOCKED = "blocked"   # Waiting on: tool I/O, human approval, or dependency
    SWAPPED = "swapped"   # Context paged out to Qdrant/Redis (Phase 2)
    TERMINATED = "terminated"  # Completed (success or failure)
    CRASHED = "crashed"   # Unexpected failure, awaiting recovery


class ProcessPriority(Enum):
    """Priority levels — P0 preempts P1, P1 preempts P2, etc."""
    P0_CRITICAL = 0    # Active incident, exploited vulnerability
    P1_HIGH = 1        # Critical finding remediation, new CVE
    P2_MEDIUM = 2      # Scheduled scan, compliance check
    P3_LOW = 3         # Report generation, metrics update
    P4_BACKGROUND = 4  # Telemetry, health checks, cleanup


class BlockReason(Enum):
    """Why a process is blocked — enables intelligent unblocking."""
    NONE = "none"
    WAITING_TOOL = "waiting_tool"           # Tool execution in progress
    WAITING_APPROVAL = "waiting_approval"   # Human-in-the-loop gate
    WAITING_DEPENDENCY = "waiting_dependency"  # Another APCB must finish
    WAITING_LLM = "waiting_llm"             # LLM rate limit / queue
    WAITING_MEMORY = "waiting_memory"       # Context page fault (Phase 2)


@dataclass
class AgentProcessControlBlock:
    """
    APCC — Agent Process Control Block.
    The kernel's primary data structure for managing agent processes.
    Analogous to a Linux task_struct.
    """
    pid: str                          # Process ID (unique)
    agent_id: str                     # Which agent (e.g., 'ai-vuln-director')
    task_name: str                    # What it's doing (e.g., 'nmap_scan')
    goal: str                         # The high-level goal from the user
    
    # State management
    state: ProcessState = ProcessState.NEW
    priority: ProcessPriority = ProcessPriority.P2_MEDIUM
    block_reason: BlockReason = BlockReason.NONE
    
    # Context budget (Phase 2 will add full paging)
    context_window_max: int = 128000  # GPT-4.1 context window
    context_tokens_used: int = 0
    context_tokens_remaining: int = 128000
    
    # LLM compute tracking
    llm_calls_made: int = 0
    llm_tokens_consumed: int = 0
    llm_cost_usd: float = 0.0
    
    # Tool tracking
    tools_called: List[str] = field(default_factory=list)
    current_tool: Optional[str] = None
    
    # Dependencies
    depends_on: List[str] = field(default_factory=list)  # PIDs that must finish first
    dependents: List[str] = field(default_factory=list)  # PIDs waiting on this one
    
    # Timing
    created_at: float = field(default_factory=time.time)
    started_at: Optional[float] = None
    completed_at: Optional[float] = None
    last_heartbeat: Optional[float] = None
    
    # Checkpoint (for crash recovery)
    checkpoint: Optional[Dict[str, Any]] = None
    
    # Result
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    
    # Session correlation
    session_id: Optional[str] = None
    correlation_id: Optional[str] = None

    def admit(self) -> bool:
        """Move from NEW to READY — kernel admits the process."""
        if self.state != ProcessState.NEW:
            return False
        self.state = ProcessState.READY
        return True

    def start(self) -> bool:
        """Move from READY to RUNNING — scheduler dispatches the process."""
        if self.state != ProcessState.READY:
            return False
        self.state = ProcessState.RUNNING
        self.started_at = time.time()
        self.last_heartbeat = time.time()
        return True

    def block(self, reason: BlockReason) -> bool:
        """Move from RUNNING to BLOCKED — process waits on something."""
        if self.state != ProcessState.RUNNING:
            return False
        self.state = ProcessState.BLOCKED
        self.block_reason = reason
        return True

    def unblock(self) -> bool:
        """Move from BLOCKED to READY — what we were waiting for arrived."""
        if self.state != ProcessState.BLOCKED:
            return False
        self.state = ProcessState.READY
        self.block_reason = BlockReason.NONE
        return True

    def terminate(self, result: Optional[Dict] = None, error: Optional[str] = None) -> bool:
        """Move to TERMINATED — process is done."""
        self.state = ProcessState.TERMINATED
        self.completed_at = time.time()
        self.result = result
        self.error = error
        # Notify dependents
        return True

    def crash(self, error: str) -> bool:
        """Move to CRASHED — unexpected failure, may be recoverable."""
        self.state = ProcessState.CRASHED
        self.error = error
        return True

    def save_checkpoint(self) -> Dict[str, Any]:
        """Save current state for crash recovery."""
        self.checkpoint = {
            "pid": self.pid,
            "agent_id": self.agent_id,
            "task_name": self.task_name,
            "state": self.state.value,
            "priority": self.priority.value,
            "llm_calls_made": self.llm_calls_made,
            "tools_called": self.tools_called.copy(),
            "current_tool": self.current_tool,
            "timestamp": time.time(),
        }
        return self.checkpoint

    def restore_from_checkpoint(self) -> bool:
        """Restore state after crash."""
        if not self.checkpoint:
            return False
        self.llm_calls_made = self.checkpoint.get("llm_calls_made", 0)
        self.tools_called = self.checkpoint.get("tools_called", [])
        self.current_tool = self.checkpoint.get("current_tool")
        self.state = ProcessState.READY  # Restart from ready
        return True

    def heartbeat(self) -> None:
        """Update heartbeat — kernel uses this to detect hung processes."""
        self.last_heartbeat = time.time()

    def is_stale(self, timeout_seconds: int = 300) -> bool:
        """Check if process hasn't sent heartbeat recently."""
        if self.last_heartbeat is None:
            return False
        return (time.time() - self.last_heartbeat) > timeout_seconds

    @property
    def age_seconds(self) -> float:
        """How long since creation."""
        return time.time() - self.created_at

    @property
    def runtime_seconds(self) -> float:
        """How long the process has been running."""
        if self.started_at is None:
            return 0.0
        end = self.completed_at or time.time()
        return end - self.started_at

    def to_dict(self) -> Dict[str, Any]:
        """Serialize for Redis persistence / Base44 entity sync."""
        d = asdict(self)
        d["state"] = self.state.value
        d["priority"] = self.priority.value
        d["block_reason"] = self.block_reason.value
        return d

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "AgentProcessControlBlock":
        """Deserialize from Redis / Base44."""
        d["state"] = ProcessState(d.get("state", "new"))
        d["priority"] = ProcessPriority(d.get("priority", 2))
        d["block_reason"] = BlockReason(d.get("block_reason", "none"))
        return cls(**d)

    @classmethod
    def create(cls, agent_id: str, task_name: str, goal: str,
               priority: ProcessPriority = ProcessPriority.P2_MEDIUM,
               depends_on: List[str] = None) -> "AgentProcessControlBlock":
        """Factory method to create a new agent process."""
        return cls(
            pid=f"APROC-{uuid.uuid4().hex[:12]}",
            agent_id=agent_id,
            task_name=task_name,
            goal=goal,
            priority=priority,
            depends_on=depends_on or [],
            context_tokens_remaining=128000,
        )
