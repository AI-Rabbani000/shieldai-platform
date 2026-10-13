"""
GDS Agent Kernel — Phase 1: LLM Compute Arbitrator
===================================================
Manages the global LLM token budget across all concurrent agent processes.
Prevents any single agent from monopolizing the LLM API.

Features:
  - Per-process token quota (based on priority)
  - Global rate limiting (tokens per minute)
  - Model selection routing (GPT-4.1 for reasoning, GPT-4.1-mini for simple tasks)
  - Cost tracking per process
  - Rate limit backoff handling
"""

import time
import logging
from typing import Dict, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger("gds.kernel.arbitrator")


class LLMModel(Enum):
    """Available LLM models, ordered by capability and cost."""
    GPT_41 = "gpt-4.1"              # Full reasoning, 128K context
    GPT_41_MINI = "gpt-4.1-mini"   # Fast, cheaper, 128K context
    GPT_41_NANO = "gpt-4.1-nano"   # Fastest, cheapest, for simple tasks


# Token quotas by priority — higher priority gets more tokens
PRIORITY_QUOTAS = {
    0: 200_000,  # P0_CRITICAL: 200K tokens per dispatch cycle
    1: 150_000,  # P1_HIGH: 150K tokens
    2: 100_000,  # P2_MEDIUM: 100K tokens
    3: 50_000,   # P3_LOW: 50K tokens
    4: 25_000,   # P4_BACKGROUND: 25K tokens
}

# Model costs per 1M tokens (USD) — OpenAI pricing
MODEL_COSTS = {
    LLMModel.GPT_41: {"input": 2.00, "output": 8.00},
    LLMModel.GPT_41_MINI: {"input": 0.40, "output": 1.60},
    LLMModel.GPT_41_NANO: {"input": 0.10, "output": 0.40},
}


@dataclass
class ComputeBudget:
    """Per-process compute allocation."""
    pid: str
    tokens_allocated: int
    tokens_used: int = 0
    llm_calls: int = 0
    cost_usd: float = 0.0
    model: LLMModel = LLMModel.GPT_41


class LLMArbitrator:
    """
    The kernel's LLM compute manager.
    
    Allocates token budgets to processes, tracks usage, and enforces
    rate limits. When global token budget is exhausted, processes are
    blocked until the next cycle.
    """

    def __init__(
        self,
        global_tokens_per_minute: int = 1_000_000,
        max_concurrent_llm_calls: int = 3,
    ):
        self.global_tokens_per_minute = global_tokens_per_minute
        self.max_concurrent_llm_calls = max_concurrent_llm_calls
        
        # Per-process budgets
        self.budgets: Dict[str, ComputeBudget] = {}
        
        # Rate limiting
        self.tokens_this_minute: int = 0
        self.minute_start: float = time.time()
        self.current_llm_calls: int = 0
        
        # Global stats
        self.total_tokens_consumed: int = 0
        self.total_cost_usd: float = 0.0
        self.total_llm_calls: int = 0

    def allocate(self, pid: str, priority: int, 
                 model: LLMModel = LLMModel.GPT_41) -> ComputeBudget:
        """
        Allocate a token budget for a process based on its priority.
        Called when a process is dispatched by the scheduler.
        """
        quota = PRIORITY_QUOTAS.get(priority, 50_000)
        budget = ComputeBudget(
            pid=pid,
            tokens_allocated=quota,
            model=model,
        )
        self.budgets[pid] = budget
        logger.debug(f"Allocated {quota} tokens for {pid} (priority {priority})")
        return budget

    def request_llm_call(self, pid: str, estimated_tokens: int) -> Tuple[bool, str]:
        """
        Request permission to make an LLM API call.
        Returns (approved, reason).
        """
        # Check rate limit
        self._check_rate_limit_reset()
        
        if self.current_llm_calls >= self.max_concurrent_llm_calls:
            return False, "max_concurrent_llm_calls_reached"
        
        if self.tokens_this_minute + estimated_tokens > self.global_tokens_per_minute:
            return False, "rate_limit_exceeded"
        
        budget = self.budgets.get(pid)
        if budget is None:
            return False, "no_budget_allocated"
        
        if budget.tokens_used + estimated_tokens > budget.tokens_allocated:
            return False, "process_quota_exceeded"
        
        # Approved
        self.current_llm_calls += 1
        self.tokens_this_minute += estimated_tokens
        return True, "approved"

    def record_llm_usage(self, pid: str, input_tokens: int, output_tokens: int) -> None:
        """
        Record actual LLM usage after a call completes.
        Updates token counts and cost tracking.
        """
        budget = self.budgets.get(pid)
        if budget is None:
            return
        
        total_tokens = input_tokens + output_tokens
        budget.tokens_used += total_tokens
        budget.llm_calls += 1
        
        # Calculate cost
        costs = MODEL_COSTS.get(budget.model, MODEL_COSTS[LLMModel.GPT_41])
        call_cost = (input_tokens / 1_000_000 * costs["input"] + 
                     output_tokens / 1_000_000 * costs["output"])
        budget.cost_usd += call_cost
        
        # Global stats
        self.total_tokens_consumed += total_tokens
        self.total_cost_usd += call_cost
        self.total_llm_calls += 1
        
        # Decrement concurrent counter
        if self.current_llm_calls > 0:
            self.current_llm_calls -= 1
        
        logger.debug(
            f"LLM usage recorded for {pid}: "
            f"{input_tokens} in + {output_tokens} out = {total_tokens} tokens, "
            f"${call_cost:.4f}"
        )

    def release_budget(self, pid: str) -> Optional[ComputeBudget]:
        """Release a process's budget when it terminates."""
        budget = self.budgets.pop(pid, None)
        if budget:
            logger.debug(
                f"Released budget for {pid}: "
                f"{budget.tokens_used}/{budget.tokens_allocated} tokens used, "
                f"${budget.cost_usd:.4f} spent"
            )
        return budget

    def select_model(self, task_complexity: str, priority: int) -> LLMModel:
        """
        Auto-select the appropriate model based on task complexity and priority.
        Saves cost by using cheaper models for simple tasks.
        """
        if priority <= 1:  # P0/P1 always get full GPT-4.1
            return LLMModel.GPT_41
        
        if task_complexity in ("simple", "classification", "extraction"):
            return LLMModel.GPT_41_NANO
        elif task_complexity in ("moderate", "summarization", "analysis"):
            return LLMModel.GPT_41_MINI
        else:  # "complex", "reasoning", "planning"
            return LLMModel.GPT_41

    def _check_rate_limit_reset(self) -> None:
        """Reset the per-minute token counter."""
        now = time.time()
        if now - self.minute_start >= 60:
            self.tokens_this_minute = 0
            self.minute_start = now

    def get_stats(self) -> Dict:
        """Return arbitrator telemetry."""
        return {
            "total_tokens_consumed": self.total_tokens_consumed,
            "total_cost_usd": round(self.total_cost_usd, 4),
            "total_llm_calls": self.total_llm_calls,
            "current_concurrent_llm_calls": self.current_llm_calls,
            "tokens_this_minute": self.tokens_this_minute,
            "active_budgets": len(self.budgets),
        }

    def get_process_budget(self, pid: str) -> Optional[ComputeBudget]:
        """Get the compute budget for a specific process."""
        return self.budgets.get(pid)
