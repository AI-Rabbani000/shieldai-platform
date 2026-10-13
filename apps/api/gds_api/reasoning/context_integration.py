"""
Context Builder Integration for agent_loop.py

This module provides a drop-in replacement for the manual context assembly
in agent_loop.py. Instead of manually building messages arrays, it uses
the kernel's MemoryManager to automatically handle context window management.

When the context window fills up:
  - Old tool results are paged to Redis (swap)
  - Old conversation turns are summarized and paged out
  - System prompts are never paged out (importance=1.0)
  - Agent can recall relevant memory from Qdrant via semantic search
"""

import logging
import time
from typing import Dict, List, Optional, Any
import httpx

logger = logging.getLogger("gds.context_integration")

KERNEL_API = "http://127.0.0.1:8000/kernel"


class RemoteContextBuilder:
    """
    Manages agent context through the kernel's MemoryManager via HTTP API.
    This is used by agent_loop.py since the reasoning engine runs in the
    gds-os process, not the kernel daemon process.
    """

    def __init__(self, kernel_api: str = KERNEL_API):
        self.api = kernel_api
        self._client = None

    @property
    def client(self):
        if self._client is None:
            self._client = httpx.Client(timeout=30.0)
        return self._client

    def init_context(
        self,
        pid: str,
        agent_definition: str,
        tools_description: str,
        max_tokens: int = 128000,
    ) -> Dict[str, Any]:
        """Initialize a context window with the system prompt."""
        system_content = f"{agent_definition}\n\n{tools_description}"
        resp = self.client.post(
            f"{self.api}/memory/alloc",
            json={
                "pid": pid,
                "content": system_content,
                "segment_type": "system_prompt",
                "importance": 1.0,
            },
        )
        if resp.status_code == 200:
            return resp.json()
        logger.warning(f"init_context failed: {resp.status_code} {resp.text[:100]}")
        return {"segment_id": None}

    def add_user_message(self, pid: str, message: str) -> Dict[str, Any]:
        """Add a user message to context."""
        resp = self.client.post(
            f"{self.api}/memory/alloc",
            json={
                "pid": pid,
                "content": f"USER: {message}",
                "segment_type": "conversation",
                "importance": 0.8,
            },
        )
        return resp.json() if resp.status_code == 200 else {"segment_id": None}

    def add_assistant_message(self, pid: str, message: str) -> Dict[str, Any]:
        """Add an assistant response to context."""
        resp = self.client.post(
            f"{self.api}/memory/alloc",
            json={
                "pid": pid,
                "content": f"ASSISTANT: {message}",
                "segment_type": "conversation",
                "importance": 0.7,
            },
        )
        return resp.json() if resp.status_code == 200 else {"segment_id": None}

    def add_tool_result(self, pid: str, tool_name: str, result: str) -> Dict[str, Any]:
        """Add a tool execution result to context. Auto-truncates long results."""
        if len(result) > 5000:
            result = result[:2500] + "\n[...truncated...]\n" + result[-2500:]

        resp = self.client.post(
            f"{self.api}/memory/alloc",
            json={
                "pid": pid,
                "content": f"TOOL_RESULT [{tool_name}]: {result}",
                "segment_type": "tool_result",
                "importance": 0.5,
            },
        )
        return resp.json() if resp.status_code == 200 else {"segment_id": None}

    def add_working_memory(self, pid: str, content: str) -> Dict[str, Any]:
        """Add scratch pad / intermediate reasoning."""
        resp = self.client.post(
            f"{self.api}/memory/alloc",
            json={
                "pid": pid,
                "content": content,
                "segment_type": "working",
                "importance": 0.3,
            },
        )
        return resp.json() if resp.status_code == 200 else {"segment_id": None}

    def build_prompt(self, pid: str) -> str:
        """Build the full LLM prompt from the context window."""
        resp = self.client.post(
            f"{self.api}/memory/build-context",
            json={"pid": pid},
        )
        if resp.status_code == 200:
            data = resp.json()
            prompt = data.get("prompt", "")
            stats = data.get("stats", {})
            util = stats.get("utilization_pct", 0)
            if util > 80:
                logger.info(f"Context utilization {util}% for {pid} — approaching limit")
            return prompt
        return ""

    def get_stats(self, pid: str) -> Dict[str, Any]:
        """Get memory stats for a process."""
        resp = self.client.get(f"{self.api}/memory/stats/{pid}")
        return resp.json() if resp.status_code == 200 else {}

    def recall_memory(self, query: str, pid: Optional[str] = None, limit: int = 3) -> List[Dict]:
        """Search Qdrant for relevant memory and page it back in."""
        resp = self.client.post(
            f"{self.api}/memory/search",
            json={"query": query, "pid": pid, "limit": limit},
        )
        if resp.status_code == 200:
            return resp.json().get("results", [])
        return []

    def get_global_stats(self) -> Dict[str, Any]:
        """Get global memory manager stats."""
        resp = self.client.get(f"{self.api}/memory/global-stats")
        return resp.json() if resp.status_code == 200 else {}

    def page_in(self, pid: str, segment_id: str) -> Dict[str, Any]:
        """Page a segment back from swap/disk into context."""
        resp = self.client.post(
            f"{self.api}/memory/page-in",
            json={"pid": pid, "segment_id": segment_id},
        )
        return resp.json() if resp.status_code == 200 else {}


# Singleton instance
_context_builder: Optional[RemoteContextBuilder] = None

def get_context_builder() -> RemoteContextBuilder:
    """Get the singleton RemoteContextBuilder instance."""
    global _context_builder
    if _context_builder is None:
        _context_builder = RemoteContextBuilder()
    return _context_builder


def build_agent_messages_with_memory(
    pid: str,
    agent_definition: str,
    tools_description: str,
    user_goal: str,
    conversation_history: List[Dict[str, str]],
    tool_results: List[Dict[str, str]],
) -> str:
    """
    Build a complete agent prompt using the kernel's memory manager.
    
    This replaces the manual message array assembly in agent_loop.py.
    The memory manager handles page faults automatically — if the context
    window fills up, cold segments are paged to Redis/Qdrant.
    
    Returns the full prompt string ready to send to GPT-4.1.
    """
    builder = get_context_builder()
    
    # Initialize context with system prompt (importance=1.0, never paged out)
    builder.init_context(pid, agent_definition, tools_description)
    
    # Add conversation history (importance=0.8/0.7, can be paged out)
    for msg in conversation_history:
        if msg.get("role") == "user":
            builder.add_user_message(pid, msg["content"])
        elif msg.get("role") == "assistant":
            builder.add_assistant_message(pid, msg["content"])
    
    # Add tool results (importance=0.5, first to be paged out)
    for tr in tool_results:
        builder.add_tool_result(pid, tr.get("tool", "unknown"), tr.get("result", ""))
    
    # Add the user's current goal
    builder.add_user_message(pid, user_goal)
    
    # Build the full prompt from all segments in context
    prompt = builder.build_prompt(pid)
    
    return prompt
