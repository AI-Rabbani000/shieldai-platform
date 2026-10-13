"""
GDS Kernel-Mediated Agent Loop — Phase 3
=========================================
This module provides a drop-in replacement for the standard agent_loop
that uses the kernel's MemoryManager for automatic context management.

Instead of manually building messages arrays and hoping they fit in
the LLM's context window, this loop:
  - Creates a kernel APCB for each agent invocation
  - Allocates all content into the kernel's memory manager
  - Builds the prompt from context before each LLM call
  - Pages cold segments to Redis when context fills up
  - Can recall paged memory via semantic search

The agent NEVER runs out of context — it just pages.
"""

import logging
import os
import time
import json
import httpx
from typing import Dict, List, Optional, Any

logger = logging.getLogger("gds.kernel_agent_loop")

KERNEL_API = "http://127.0.0.1:8000/kernel"


class KernelAgentLoop:
    """
    Agent reasoning loop backed by the kernel's virtual memory system.
    
    Flow:
      1. start() — creates APCB, allocates system prompt + tools + goal
      2. reason() — builds prompt from context, calls GPT-4.1, allocates response
      3. execute_tool() — runs tool via kernel sandbox, allocates result
      4. recall() — searches Qdrant for relevant paged memory
      5. get_stats() — returns memory utilization + page fault stats
      6. finish() — terminates APCB, returns results
    """
    
    def __init__(
        self,
        agent_id: str,
        agent_definition: str,
        tools: List[Dict[str, Any]],
        kernel_api: str = KERNEL_API,
        openai_client = None,
        model: str = "gpt-4.1",
        max_iterations: int = 10,
        max_tokens: int = 4096,
    ):
        self.agent_id = agent_id
        self.agent_definition = agent_definition
        self.tools = tools
        self.api = kernel_api
        self.openai_client = openai_client
        self.model = model
        self.max_iterations = max_iterations
        self.max_tokens = max_tokens
        
        self.pid: Optional[str] = None
        bridge_key = os.environ.get("BRIDGE_API_KEY", "")
        if not bridge_key:
            raise RuntimeError("BRIDGE_API_KEY is required for kernel access")
        self._client = httpx.Client(timeout=120.0, headers={"Authorization": f"Bearer {bridge_key}"})
        self.iterations = 0
        self.tool_calls_made: List[Dict] = []
        self.start_time = 0
        self.page_faults_observed = 0
    
    def _kernel_post(self, path: str, data: dict) -> dict:
        """POST to kernel API. Always returns a dict, never None."""
        try:
            resp = self._client.post(f"{self.api}{path}", json=data)
            if resp.status_code == 200:
                result = resp.json()
                return result if isinstance(result, dict) else {}
            logger.warning(f"Kernel {path} returned {resp.status_code}: {resp.text[:200]}")
        except Exception as e:
            logger.warning(f"Kernel {path} failed: {e}")
        return {}
    
    def _kernel_get(self, path: str) -> dict:
        """GET from kernel API."""
        resp = self._client.get(f"{self.api}{path}")
        if resp.status_code == 200:
            return resp.json()
        return {}
    
    def start(self, goal: str) -> str:
        """
        Initialize the agent: create APCB, allocate system prompt + tools + goal.
        Returns the process PID.
        """
        self.start_time = time.time()
        
        # 1. Create kernel process (APCB)
        proc = self._kernel_post("/process/create", {
            "agent_id": self.agent_id,
            "task_name": goal[:60],
            "goal": goal,
            "priority": 2,
            "depends_on": [],
        })
        self.pid = proc.get("pid") or f"PROC-{int(time.time())}"
        logger.info(f"Agent {self.agent_id} started: PID={self.pid}")
        
        # 2. Allocate system prompt (importance=1.0 — NEVER paged out)
        tools_desc = self._format_tools()
        system_content = f"{self.agent_definition}\n\n{tools_desc}"
        self._kernel_post("/memory/alloc", {
            "pid": self.pid,
            "content": system_content,
            "segment_type": "system_prompt",
            "importance": 1.0,
        })
        
        # 3. Allocate user goal (importance=0.8 — high priority, rarely paged)
        self._kernel_post("/memory/alloc", {
            "pid": self.pid,
            "content": f"USER REQUEST: {goal}",
            "segment_type": "conversation",
            "importance": 0.8,
        })
        
        return self.pid
    
    def _format_tools(self) -> str:
        """Format tools as a description string for the system prompt."""
        if not self.tools:
            return "No tools available."
        
        lines = ["You have access to the following tools:"]
        for t in self.tools:
            name = t.get("name", t.get("function", {}).get("name", "unknown"))
            desc = t.get("description", t.get("function", {}).get("description", ""))
            params = t.get("parameters", t.get("function", {}).get("parameters", {}))
            param_str = ""
            if isinstance(params, dict):
                props = params.get("properties", {})
                param_str = ", ".join(f'{k}: {v.get("type","any")}' for k, v in props.items())
            lines.append(f"  - {name}({param_str}): {desc[:100]}")
        return "\n".join(lines)
    
    def build_prompt(self) -> str:
        """
        Build the full LLM prompt from the kernel's context window.
        This is where page fault magic happens — if context is full,
        cold segments are automatically paged to Redis.
        """
        result = self._kernel_post("/memory/build-context", {"pid": self.pid})
        prompt = result.get("prompt", "")
        stats = result.get("stats", {}) if isinstance(result.get("stats"), dict) else {}
        
        # Track page faults
        global_stats = self._kernel_get("/memory/global-stats")
        current_faults = global_stats.get("page_faults", 0)
        if current_faults > self.page_faults_observed:
            new_faults = current_faults - self.page_faults_observed
            self.page_faults_observed = current_faults
            logger.info(f"Page fault occurred during prompt build: {new_faults} segments paged to swap")
        
        if not prompt:
            # Fallback: use system prompt + goal directly
            logger.warning("Kernel context empty — using fallback prompt")
            prompt = f"{self.agent_definition}\n\nUSER REQUEST: Build the prompt from the conversation"
        
        return prompt
    
    async def reason(self) -> Dict[str, Any]:
        """
        One reasoning step: build prompt from context → call GPT-4.1 → allocate response.
        Returns the GPT-4.1 response.
        """
        self.iterations += 1
        
        # 1. Build prompt from kernel context window (auto page faults)
        prompt = self.build_prompt()
        
        # 2. Call GPT-4.1 with the kernel-managed prompt
        if self.openai_client is None:
            return {
                "content": f"[Stub mode] Prompt built from context ({len(prompt)} chars). "
                          f"Iteration {self.iterations}.",
                "tool_calls": [],
                "done": True,
            }
        
        # Format as OpenAI messages — single user message with full context
        # (The kernel's MemoryManager handles the context window, not OpenAI's API)
        messages = [{"role": "user", "content": prompt}]
        
        # Convert tools to OpenAI function calling format
        openai_tools = []
        for t in self.tools:
            if "function" in t:
                openai_tools.append(t)
            elif "name" in t:
                openai_tools.append({
                    "type": "function",
                    "function": {
                        "name": t["name"],
                        "description": t.get("description", ""),
                        "parameters": t.get("parameters", {"type": "object", "properties": {}}),
                    }
                })
        
        try:
            response = self.openai_client.chat.completions.create(
                model=self.model,
                messages=messages,
                tools=openai_tools if openai_tools else None,
                tool_choice="auto" if openai_tools else None,
                max_tokens=self.max_tokens,
                temperature=0.1,
            )
            
            choice = response.choices[0]
            content = choice.message.content or ""
            tool_calls = choice.message.tool_calls or []
            
            # 3. Allocate assistant response into context (importance=0.7)
            if content:
                self._kernel_post("/memory/alloc", {
                    "pid": self.pid,
                    "content": f"ASSISTANT: {content}",
                    "segment_type": "conversation",
                    "importance": 0.7,
                })
            
            # 4. Check if agent is done
            done = not tool_calls
            
            return {
                "content": content,
                "tool_calls": [
                    {
                        "id": tc.id,
                        "name": tc.function.name,
                        "arguments": tc.function.arguments,
                    }
                    for tc in tool_calls
                ],
                "done": done,
            }
            
        except Exception as e:
            logger.error(f"GPT-4.1 call failed: {e}")
            return {"content": f"Error: {e}", "tool_calls": [], "done": True}
    
    async def execute_tool(self, tool_name: str, tool_args: str) -> Dict[str, Any]:
        """
        Execute a tool through the kernel sandbox and allocate the result.
        Tool results have importance=0.5 — they're the FIRST segments paged out.
        """
        # Parse arguments
        try:
            args = json.loads(tool_args) if isinstance(tool_args, str) else tool_args
        except json.JSONDecodeError:
            args = {}
        
        # Execute through kernel sandbox
        result = self._kernel_post("/tool/execute", {
            "pid": self.pid,
            "tool_id": tool_name,
            "payload": args,
        })
        
        # Allocate tool result into context (importance=0.5 — paged first when full)
        result_str = json.dumps(result, default=str)[:5000]  # Truncate long results
        self._kernel_post("/memory/alloc", {
            "pid": self.pid,
            "content": f"TOOL_RESULT [{tool_name}]: {result_str}",
            "segment_type": "tool_result",
            "importance": 0.5,
        })
        
        self.tool_calls_made.append({
            "tool": tool_name,
            "arguments": args,
            "result": result,
        })
        
        return result
    
    def recall(self, query: str, limit: int = 3) -> List[Dict]:
        """
        Search Qdrant for relevant paged memory and page it back into context.
        This allows the agent to recall information that was paged to disk.
        """
        result = self._kernel_post("/memory/search", {
            "query": query,
            "pid": self.pid,
            "limit": limit,
        })
        memories = result.get("results", [])
        
        # Page any recalled memories back into context
        for mem in memories:
            self._kernel_post("/memory/alloc", {
                "pid": self.pid,
                "content": f"RECALLED: {mem.get('content', '')}",
                "segment_type": "knowledge",
                "importance": 0.6,
            })
        
        return memories
    
    def get_stats(self) -> Dict[str, Any]:
        """Get memory stats for this agent process."""
        stats = self._kernel_get(f"/memory/stats/{self.pid}")
        global_stats = self._kernel_get("/memory/global-stats")
        return {
            "process": stats,
            "global": global_stats,
            "iterations": self.iterations,
            "tool_calls": len(self.tool_calls_made),
            "page_faults": self.page_faults_observed,
        }
    
    def finish(self) -> Dict[str, Any]:
        """
        Terminate the agent process and return results.
        Does NOT destroy the memory — it stays in Redis/Qdrant for future recall.
        """
        duration = time.time() - self.start_time
        
        # Get final stats
        stats = self.get_stats()
        
        # Terminate the kernel process
        self._kernel_post("/process/terminate", {
            "pid": self.pid,
            "reason": "completed",
        })
        
        logger.info(
            f"Agent {self.agent_id} finished: {self.iterations} iterations, "
            f"{len(self.tool_calls_made)} tool calls, "
            f"{self.page_faults_observed} page faults, "
            f"{duration:.1f}s"
        )
        
        return {
            "agent_id": self.agent_id,
            "pid": self.pid,
            "iterations": self.iterations,
            "tool_calls": self.tool_calls_made,
            "duration_ms": int(duration * 1000),
            "page_faults": self.page_faults_observed,
            "memory_stats": stats,
        }
    
    async def run(self, goal: str) -> Dict[str, Any]:
        """
        Full autonomous agent run: start → reason → execute → finish.
        The agent loops until it's done or hits max_iterations.
        """
        self.start(goal)
        
        try:
            while self.iterations < self.max_iterations:
                # Reason
                result = await self.reason()
                
                # Check if done
                if result.get("done", True):
                    break
                
                # Execute tool calls
                for tc in result.get("tool_calls", []):
                    tool_result = await self.execute_tool(tc["name"], tc["arguments"])
                    
                    # Allocate tool result summary into context
                    # (Already done in execute_tool)
                
                # Log memory stats every 3 iterations
                if self.iterations % 3 == 0:
                    stats = self.get_stats()
                    proc_stats = stats.get("process", {})
                    logger.info(
                        f"Agent {self.agent_id} iter {self.iterations}: "
                        f"{proc_stats.get('tokens_used', 0)}/{proc_stats.get('max_tokens', 0)} tokens "
                        f"({proc_stats.get('utilization_pct', 0)}%), "
                        f"{proc_stats.get('segment_count', 0)} segments, "
                        f"{stats.get('page_faults', 0)} page faults"
                    )
        finally:
            return self.finish()


# Convenience function for the bridge to use
async def run_kernel_agent(
    agent_id: str,
    agent_definition: str,
    tools: List[Dict[str, Any]],
    goal: str,
    openai_client = None,
    model: str = "gpt-4.1",
    max_iterations: int = 10,
    kernel_api: str = KERNEL_API,
) -> Dict[str, Any]:
    """
    Run an agent with kernel-mediated memory management.
    
    This is the Phase 3 entry point — called by the bridge instead of
    the legacy agent_loop when kernel memory management is enabled.
    """
    loop = KernelAgentLoop(
        agent_id=agent_id,
        agent_definition=agent_definition,
        tools=tools,
        kernel_api=kernel_api,
        openai_client=openai_client,
        model=model,
        max_iterations=max_iterations,
    )
    return await loop.run(goal)
