"""
GDS Agent Kernel — Phase 1: Priority-Based Preemptive Scheduler
================================================================
Replaces the FIFO Redis queue with a real OS-style scheduler:
  - Priority-based dispatch (P0 preempts P1, etc.)
  - Token quantum allocation (each process gets a fair LLM time slice)
  - Preemption when higher-priority work arrives
  - Dependency resolution (blocked processes auto-unblock when deps complete)
  - Stale process detection (heartbeat-based crash detection)
"""

import time
import heapq
import logging
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from .process import AgentProcessControlBlock as APCB, ProcessState, ProcessPriority, BlockReason

logger = logging.getLogger("gds.kernel.scheduler")


@dataclass
class SchedulingStats:
    """Scheduler telemetry — tracked continuously."""
    total_dispatched: int = 0
    total_preemptions: int = 0
    total_completed: int = 0
    total_crashed: int = 0
    total_recovered: int = 0
    avg_wait_time: float = 0.0
    avg_runtime: float = 0.0
    max_concurrent: int = 0


class AgentScheduler:
    """
    The kernel's process scheduler.
    
    Maintains:
      - ready_queue: priority heap of READY processes
      - running: currently executing processes (up to max_concurrent)
      - blocked: processes waiting on I/O, approvals, or dependencies
      - terminated: completed processes (for stats)
    
    The scheduler runs in a continuous loop, dispatching ready processes
    to available compute slots and preempting when higher-priority work arrives.
    """

    def __init__(self, max_concurrent: int = 3, stale_timeout: int = 300):
        """
        Args:
            max_concurrent: Maximum simultaneously running agent processes.
                           This limits LLM API concurrency to avoid rate limits.
            stale_timeout: Seconds without heartbeat before a process is marked crashed.
        """
        self.max_concurrent = max_concurrent
        self.stale_timeout = stale_timeout
        
        # Process table — all APCBs by PID
        self.process_table: Dict[str, APCB] = {}
        
        # Ready queue — priority heap: (priority_value, created_at, pid)
        self.ready_queue: List[Tuple[int, float, str]] = []
        
        # Running processes — PID -> APCB
        self.running: Dict[str, APCB] = {}
        
        # Blocked processes — PID -> APCB
        self.blocked: Dict[str, APCB] = {}
        
        # Terminated (kept for stats, cleaned periodically)
        self.terminated: List[APCB] = []
        
        # Telemetry
        self.stats = SchedulingStats()
        
        # Token budget — global LLM token allocation per scheduling cycle
        self.global_token_budget: int = 500000  # tokens per cycle
        self.tokens_used_this_cycle: int = 0

    def admit(self, apcb: APCB) -> str:
        """
        Admit a new process to the system.
        NEW → READY (if dependencies are met) or stays NEW (if deps pending).
        Returns the PID.
        """
        self.process_table[apcb.pid] = apcb
        
        # Check dependencies
        if apcb.depends_on:
            unmet = [dep for dep in apcb.depends_on 
                     if dep not in self.process_table 
                     or self.process_table[dep].state != ProcessState.TERMINATED]
            if unmet:
                apcb.state = ProcessState.BLOCKED
                apcb.block_reason = BlockReason.WAITING_DEPENDENCY
                self.blocked[apcb.pid] = apcb
                logger.info(f"Admitted {apcb.pid} ({apcb.agent_id}) → BLOCKED (waiting on: {unmet})")
                return apcb.pid
        
        apcb.admit()
        heapq.heappush(self.ready_queue, (apcb.priority.value, apcb.created_at, apcb.pid))
        logger.info(f"Admitted {apcb.pid} ({apcb.agent_id}) → READY (priority: {apcb.priority.name})")
        return apcb.pid

    def dispatch(self) -> List[APCB]:
        """
        Dispatch ready processes to available compute slots.
        Preempts lower-priority running processes if needed.
        Returns list of processes that should start executing.
        """
        dispatched = []
        
        # First, detect and clean stale processes
        self._detect_stale_processes()
        
        # Check for dependencies that have been resolved
        self._check_blocked_dependencies()
        
        # Fill available slots from ready queue
        available_slots = self.max_concurrent - len(self.running)
        
        while available_slots > 0 and self.ready_queue:
            priority, created_at, pid = heapq.heappop(self.ready_queue)
            apcb = self.process_table.get(pid)
            
            if apcb is None or apcb.state != ProcessState.READY:
                continue  # Stale entry, skip
            
            if apcb.start():
                self.running[pid] = apcb
                dispatched.append(apcb)
                available_slots -= 1
                self.stats.total_dispatched += 1
                logger.info(f"Dispatched {pid} ({apcb.agent_id}) → RUNNING")
        
        # Preemption: if we have P0/P1 in ready queue but all slots full of P2/P3
        if self.ready_queue and len(self.running) >= self.max_concurrent:
            self._try_preempt()
        
        # Update max concurrent stat
        if len(self.running) > self.stats.max_concurrent:
            self.stats.max_concurrent = len(self.running)
        
        return dispatched

    def _try_preempt(self) -> None:
        """Preempt lowest-priority running process if a higher-priority one is waiting."""
        if not self.ready_queue:
            return
        
        # Find highest-priority waiting process
        waiting_priority = self.ready_queue[0][0]
        
        # Find lowest-priority running process
        running_by_priority = sorted(
            self.running.values(),
            key=lambda a: (-a.priority.value, a.started_at or 0)  # lowest priority, oldest
        )
        
        if not running_by_priority:
            return
        
        lowest_running = running_by_priority[0]
        
        if waiting_priority < lowest_running.priority.value:
            # Preempt: send the running process back to ready queue
            lowest_running.state = ProcessState.READY
            del self.running[lowest_running.pid]
            heapq.heappush(self.ready_queue, 
                          (lowest_running.priority.value, lowest_running.created_at, lowest_running.pid))
            
            # Dispatch the higher-priority process
            priority, _, pid = heapq.heappop(self.ready_queue)
            apcb = self.process_table.get(pid)
            if apcb and apcb.start():
                self.running[pid] = apcb
                self.stats.total_preemptions += 1
                logger.warning(
                    f"PREEMPTED {lowest_running.pid} ({lowest_running.agent_id}) "
                    f"for {pid} ({apcb.agent_id}) — priority {apcb.priority.name}"
                )

    def block_process(self, pid: str, reason: BlockReason) -> bool:
        """Block a running process — it's waiting on I/O, approval, etc."""
        apcb = self.running.get(pid)
        if apcb and apcb.block(reason):
            del self.running[pid]
            self.blocked[pid] = apcb
            apcb.save_checkpoint()
            logger.info(f"Blocked {pid} ({apcb.agent_id}) — reason: {reason.value}")
            return True
        return False

    def unblock_process(self, pid: str) -> bool:
        """Unblock a process — what it was waiting for has arrived."""
        apcb = self.blocked.get(pid)
        if apcb and apcb.unblock():
            del self.blocked[pid]
            heapq.heappush(self.ready_queue, 
                          (apcb.priority.value, apcb.created_at, apcb.pid))
            logger.info(f"Unblocked {pid} ({apcb.agent_id}) → READY")
            return True
        return False

    def complete_process(self, pid: str, result: Optional[Dict] = None, 
                         error: Optional[str] = None) -> bool:
        """Mark a process as terminated."""
        apcb = self.running.get(pid) or self.blocked.get(pid)
        if apcb is None:
            apcb = self.process_table.get(pid)
        
        if apcb and apcb.terminate(result, error):
            self.running.pop(pid, None)
            self.blocked.pop(pid, None)
            self.terminated.append(apcb)
            self.stats.total_completed += 1 if not error else 0
            self.stats.total_crashed += 1 if error else 0
            
            # Update dependents
            for dep_pid in apcb.dependents:
                self._check_blocked_dependencies()
            
            logger.info(f"Completed {pid} ({apcb.agent_id}) — "
                       f"{'SUCCESS' if not error else 'ERROR: ' + str(error)}")
            return True
        return False

    def _check_blocked_dependencies(self) -> None:
        """Unblock processes whose dependencies have completed."""
        to_unblock = []
        for pid, apcb in self.blocked.items():
            if apcb.block_reason == BlockReason.WAITING_DEPENDENCY:
                unmet = [dep for dep in apcb.depends_on
                         if dep not in self.process_table
                         or self.process_table[dep].state != ProcessState.TERMINATED]
                if not unmet:
                    to_unblock.append(pid)
        
        for pid in to_unblock:
            self.unblock_process(pid)

    def _detect_stale_processes(self) -> None:
        """Detect and crash processes that haven't sent a heartbeat."""
        stale_pids = []
        for pid, apcb in self.running.items():
            if apcb.is_stale(self.stale_timeout):
                stale_pids.append(pid)
        
        for pid in stale_pids:
            apcb = self.running.get(pid)
            if apcb:
                apcb.crash(f"Stale: no heartbeat for {self.stale_timeout}s")
                del self.running[pid]
                self.terminated.append(apcb)
                self.stats.total_crashed += 1
                logger.error(f"CRASHED {pid} ({apcb.agent_id}) — stale, no heartbeat")
                
                # Try recovery from checkpoint
                if apcb.checkpoint:
                    apcb.restore_from_checkpoint()
                    heapq.heappush(self.ready_queue,
                                  (apcb.priority.value, apcb.created_at, apcb.pid))
                    self.stats.total_recovered += 1
                    logger.info(f"RECOVERED {pid} from checkpoint → READY")

    def update_heartbeat(self, pid: str) -> None:
        """Update a process's heartbeat."""
        apcb = self.process_table.get(pid)
        if apcb:
            apcb.heartbeat()

    def get_process(self, pid: str) -> Optional[APCB]:
        """Get a process by PID."""
        return self.process_table.get(pid)

    def list_running(self) -> List[APCB]:
        """List all currently running processes."""
        return list(self.running.values())

    def list_ready(self) -> List[APCB]:
        """List all ready processes (in priority order)."""
        return sorted(
            [self.process_table[p] for _, _, p in self.ready_queue 
             if p in self.process_table],
            key=lambda a: a.priority.value
        )

    def list_blocked(self) -> List[APCB]:
        """List all blocked processes."""
        return list(self.blocked.values())

    def get_stats(self) -> Dict:
        """Return scheduler telemetry."""
        return {
            "total_dispatched": self.stats.total_dispatched,
            "total_preemptions": self.stats.total_preemptions,
            "total_completed": self.stats.total_completed,
            "total_crashed": self.stats.total_crashed,
            "total_recovered": self.stats.total_recovered,
            "currently_running": len(self.running),
            "currently_ready": len(self.ready_queue),
            "currently_blocked": len(self.blocked),
            "max_concurrent": self.stats.max_concurrent,
            "global_token_budget": self.global_token_budget,
            "tokens_used_this_cycle": self.tokens_used_this_cycle,
        }

    def cleanup_terminated(self, keep_last: int = 100) -> int:
        """Clean up old terminated processes to free memory."""
        if len(self.terminated) > keep_last:
            removed = len(self.terminated) - keep_last
            self.terminated = self.terminated[-keep_last:]
            return removed
        return 0
