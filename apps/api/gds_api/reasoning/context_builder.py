"""
GDS Context Builder — Integrates MemoryManager with agent reasoning loop.

Instead of manually assembling prompts, the agent loop uses this module
to allocate content into the memory manager, which auto-handles page faults.

Usage in agent_loop.py:
    from gds_api.reasoning.context_builder import ContextBuilder
    
    builder = ContextBuilder(kernel_memory_manager)
    builder.set_system_prompt(pid, agent_definition)
    builder.add_conversation(pid, user_message)
    builder.add_tool_result(pid, tool_name, result)
    prompt = builder.build_prompt(pid)
"""

import logging
from typing import Optional, Dict, Any
from gds_kernel.memory import MemoryManager, MemorySegmentType

logger = logging.getLogger("gds.context_builder")


class ContextBuilder:
    """
    High-level interface for agent loops to manage context windows.
    Wraps MemoryManager with agent-specific semantics.
    """

    def __init__(self, memory_manager: MemoryManager):
        self.memory = memory_manager

    def init_agent_context(
        self,
        process_id: str,
        agent_definition: str,
        tools_description: str,
        max_tokens: int = 128000,
    ) -> str:
        """Initialize a context window for an agent with system prompt."""
        # Create context window
        self.memory.create_context_window(process_id, max_tokens)

        # System prompt (highest importance — never paged out)
        system_content = f"{agent_definition}\n\n{tools_description}"
        sid = self.memory.allocate(
            process_id=process_id,
            content=system_content,
            segment_type=MemorySegmentType.SYSTEM_PROMPT,
            importance=1.0,  # Never page out
        )
        logger.debug(f"Initialized context for {process_id}: system_prompt={sid}")
        return sid

    def add_user_message(self, process_id: str, message: str) -> Optional[str]:
        """Add a user message to context."""
        return self.memory.allocate(
            process_id=process_id,
            content=f"USER: {message}",
            segment_type=MemorySegmentType.CONVERSATION,
            importance=0.8,
        )

    def add_assistant_message(self, process_id: str, message: str) -> Optional[str]:
        """Add an assistant response to context."""
        return self.memory.allocate(
            process_id=process_id,
            content=f"ASSISTANT: {message}",
            segment_type=MemorySegmentType.CONVERSATION,
            importance=0.7,
        )

    def add_tool_result(self, process_id: str, tool_name: str, result: str) -> Optional[str]:
        """Add a tool execution result to context."""
        # Truncate very long tool results to avoid filling context
        if len(result) > 5000:
            result = result[:2500] + "\n[...truncated...]\n" + result[-2500:]

        return self.memory.allocate(
            process_id=process_id,
            content=f"TOOL_RESULT [{tool_name}]: {result}",
            segment_type=MemorySegmentType.TOOL_RESULT,
            importance=0.5,  # Medium — can be paged out
        )

    def add_working_memory(self, process_id: str, content: str) -> Optional[str]:
        """Add scratch pad / intermediate reasoning."""
        return self.memory.allocate(
            process_id=process_id,
            content=content,
            segment_type=MemorySegmentType.WORKING,
            importance=0.3,  # Low — first to be paged out
        )

    def add_knowledge(self, process_id: str, content: str, importance: float = 0.6) -> Optional[str]:
        """Add retrieved knowledge (from Qdrant search, findings, etc.)."""
        return self.memory.allocate(
            process_id=process_id,
            content=content,
            segment_type=MemorySegmentType.KNOWLEDGE,
            importance=importance,
        )

    def recall_from_disk(self, process_id: str, query: str, limit: int = 3) -> list:
        """Search Qdrant for relevant memory and page it back in."""
        results = self.memory.search_disk(query, process_id=process_id, limit=limit)
        paged_in = []
        for r in results:
            segment = self.memory.page_in(process_id, r["segment_id"])
            if segment:
                paged_in.append({
                    "segment_id": r["segment_id"],
                    "content": r["content"][:200],
                    "score": r["score"],
                })
        return paged_in

    def build_prompt(self, process_id: str) -> str:
        """Build the full LLM prompt from context window."""
        return self.memory.build_context_prompt(process_id)

    def get_stats(self, process_id: str) -> Dict[str, Any]:
        """Get memory stats for this process."""
        return self.memory.get_memory_stats(process_id)

    def cleanup(self, process_id: str) -> None:
        """Destroy context window and page remaining to disk."""
        self.memory.destroy_context_window(process_id)
