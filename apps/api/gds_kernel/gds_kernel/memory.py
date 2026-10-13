"""
GDS Agent Kernel — Phase 2: Virtual Context Paging Engine
============================================================
Treats the LLM context window as physical RAM and implements
automatic paging when context exceeds token limits.

Architecture (MemGPT-inspired):
  - Context Window = RAM (128K tokens for GPT-4.1)
  - Redis = Swap (recent working memory, fast access)
  - Qdrant = Disk (persistent semantic memory, vector search)
  - PostgreSQL = Archive (long-term findings, audit logs)

When a process's context window fills up:
  1. Kernel triggers a "page fault"
  2. Coldest context segments are paged out to Redis (swap)
  3. Oldest swap segments are evicted to Qdrant (disk)
  4. Relevant memory is paged in from Qdrant when needed
"""

import time
import json
import hashlib
import logging
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger("gds.kernel.memory")


class MemoryTier(Enum):
    """Memory hierarchy — mirrors CPU cache hierarchy."""
    CONTEXT = "context"    # LLM context window (RAM) — fastest, smallest
    SWAP = "swap"          # Redis (L2 cache) — fast, medium
    DISK = "disk"          # Qdrant (disk) — slow, large
    ARCHIVE = "archive"    # PostgreSQL (cold storage) — slowest, unlimited


class MemorySegmentType(Enum):
    """Types of memory segments that can be paged."""
    SYSTEM_PROMPT = "system_prompt"      # Agent identity, tools, instructions
    CONVERSATION = "conversation"        # Message history (user/assistant turns)
    TOOL_RESULT = "tool_result"          # Output from tool calls
    KNOWLEDGE = "knowledge"              # Retrieved from Qdrant (findings, threat intel)
    WORKING = "working"                  # Scratch pad, intermediate reasoning
    SUMMARY = "summary"                  # Compressed summary of older context


@dataclass
class MemorySegment:
    """A unit of agent memory — can be paged in/out."""
    segment_id: str
    process_id: str                      # Which APCB owns this memory
    segment_type: MemorySegmentType
    tier: MemoryTier                     # Where it currently lives
    content: str                         # The actual text
    token_count: int                     # Estimated tokens
    importance: float = 0.5             # 0-1, how important to keep in context
    access_count: int = 0               # How many times accessed
    last_accessed: float = field(default_factory=time.time)
    created_at: float = field(default_factory=time.time)
    embedding_id: Optional[str] = None  # Qdrant embedding reference (if paged to disk)
    summary: Optional[str] = None       # Compressed version (for page-out)

    def touch(self) -> None:
        """Mark as recently accessed (LRU tracking)."""
        self.last_accessed = time.time()
        self.access_count += 1

    def is_cold(self, threshold_seconds: int = 120) -> bool:
        """Check if this segment is cold enough to page out."""
        return (time.time() - self.last_accessed) > threshold_seconds

    def to_dict(self) -> Dict[str, Any]:
        return {
            "segment_id": self.segment_id,
            "process_id": self.process_id,
            "segment_type": self.segment_type.value,
            "tier": self.tier.value,
            "token_count": self.token_count,
            "importance": self.importance,
            "access_count": self.access_count,
            "last_accessed": self.last_accessed,
            "created_at": self.created_at,
            "summary": self.summary,
            "embedding_id": self.embedding_id,
        }


@dataclass
class ContextWindow:
    """
    A process's context window — the "RAM" for a single agent.
    Has a hard token limit. When full, page fault triggers.
    """
    process_id: str
    max_tokens: int = 128000
    segments: List[MemorySegment] = field(default_factory=list)
    
    @property
    def tokens_used(self) -> int:
        return sum(s.token_count for s in self.segments)
    
    @property
    def tokens_remaining(self) -> int:
        return self.max_tokens - self.tokens_used
    
    @property
    def utilization_pct(self) -> float:
        return (self.tokens_used / self.max_tokens) * 100

    def add_segment(self, segment: MemorySegment) -> bool:
        """Add a segment to context window. Returns False if would overflow."""
        if self.tokens_used + segment.token_count > self.max_tokens:
            return False  # Page fault needed
        self.segments.append(segment)
        segment.tier = MemoryTier.CONTEXT
        return True

    def remove_segment(self, segment_id: str) -> Optional[MemorySegment]:
        """Remove a segment from context (for page-out)."""
        for i, s in enumerate(self.segments):
            if s.segment_id == segment_id:
                return self.segments.pop(i)
        return None

    def get_coldest_segments(self, n: int = 3) -> List[MemorySegment]:
        """Get the n coldest/least-important segments for page-out."""
        sorted_segs = sorted(
            self.segments,
            key=lambda s: (s.importance, s.last_accessed)
        )
        # Never page out system_prompt
        return [s for s in sorted_segs if s.segment_type != MemorySegmentType.SYSTEM_PROMPT][:n]


class MemoryManager:
    """
    The kernel's virtual memory manager.
    
    Manages context windows for all processes and handles
    page faults automatically. When a process needs to add content
    but its context window is full, the manager:
      1. Identifies cold segments to evict
      2. Pages them to Redis (swap) or Qdrant (disk)
      3. Frees up context space
      4. Allows the new content to be paged in
    """

    def __init__(self, redis_client=None, qdrant_client=None):
        """
        Args:
            redis_client: Redis client for swap tier (optional — works without)
            qdrant_client: Qdrant client for disk tier (optional — works without)
        """
        self.redis = redis_client
        self.qdrant = qdrant_client
        
        # Context windows by process ID
        self.context_windows: Dict[str, ContextWindow] = {}
        
        # Swap storage (Redis-backed, falls back to in-memory dict)
        self.swap: Dict[str, MemorySegment] = {}  # segment_id → segment
        
        # Disk storage (Qdrant-backed, falls back to in-memory dict)
        self.disk: Dict[str, MemorySegment] = {}
        
        # Telemetry
        self.page_faults: int = 0
        self.page_ins: int = 0
        self.page_outs: int = 0
        self.swap_evictions: int = 0
        self.total_tokens_paged: int = 0

    def create_context_window(self, process_id: str, max_tokens: int = 128000) -> ContextWindow:
        """Create a context window for a new process."""
        cw = ContextWindow(process_id=process_id, max_tokens=max_tokens)
        self.context_windows[process_id] = cw
        logger.debug(f"Created context window for {process_id} ({max_tokens} tokens)")
        return cw

    def allocate(
        self,
        process_id: str,
        content: str,
        segment_type: MemorySegmentType,
        importance: float = 0.5,
    ) -> Optional[str]:
        """
        Allocate content into a process's context window.
        If the window is full, triggers page fault handling.
        Returns segment_id on success, None on failure.
        """
        cw = self.context_windows.get(process_id)
        if cw is None:
            cw = self.create_context_window(process_id)
        
        # Estimate token count (rough: 4 chars ≈ 1 token)
        token_count = max(1, len(content) // 4)
        
        segment = MemorySegment(
            segment_id=self._gen_segment_id(process_id),
            process_id=process_id,
            segment_type=segment_type,
            tier=MemoryTier.CONTEXT,
            content=content,
            token_count=token_count,
            importance=importance,
        )
        
        # Try to add directly
        if cw.add_segment(segment):
            logger.debug(f"Allocated {token_count} tokens for {process_id} ({segment_type.value})")
            return segment.segment_id
        
        # Page fault — context window is full
        self.page_faults += 1
        logger.info(f"PAGE FAULT for {process_id}: {cw.tokens_used}/{cw.max_tokens} tokens used, "
                    f"need {token_count} more")
        
        # Handle the page fault
        freed = self._handle_page_fault(process_id, token_count)
        
        if freed >= token_count:
            # Now we have space
            cw.add_segment(segment)
            logger.info(f"Page fault resolved: freed {freed} tokens, allocated {token_count}")
            return segment.segment_id
        else:
            logger.warning(f"Page fault unresolved: only freed {freed}/{token_count} tokens")
            return None

    def _handle_page_fault(self, process_id: str, needed_tokens: int) -> int:
        """
        Handle a page fault by evicting cold segments.
        Returns total tokens freed.
        """
        cw = self.context_windows.get(process_id)
        if cw is None:
            return 0
        
        freed = 0
        # Get coldest segments to evict
        cold_segments = cw.get_coldest_segments(n=10)
        
        for segment in cold_segments:
            if freed >= needed_tokens:
                break
            
            # Page out to swap (Redis) or disk (Qdrant)
            self._page_out(segment)
            
            # Remove from context window
            cw.remove_segment(segment.segment_id)
            freed += segment.token_count
        
        return freed

    def _page_out(self, segment: MemorySegment) -> None:
        """Page a segment from context to swap/disk."""
        self.page_outs += 1
        self.total_tokens_paged += segment.token_count
        
        # Generate a summary for future page-in (compression)
        if segment.token_count > 500 and segment.segment_type == MemorySegmentType.CONVERSATION:
            # Simple compression: keep first/last 200 chars
            if len(segment.content) > 400:
                segment.summary = segment.content[:200] + " [...] " + segment.content[-200:]
            else:
                segment.summary = segment.content
        
        # Store in swap (Redis or in-memory)
        if self.redis:
            self.redis.setex(
                f"mem:swap:{segment.segment_id}",
                3600,  # 1 hour TTL
                json.dumps({
                    "content": segment.content,
                    "summary": segment.summary,
                    "token_count": segment.token_count,
                    "segment_type": segment.segment_type.value,
                    "process_id": segment.process_id,
                })
            )
        else:
            self.swap[segment.segment_id] = segment
        
        segment.tier = MemoryTier.SWAP
        logger.debug(f"Paged out {segment.segment_id} ({segment.token_count} tokens) to swap")

    def page_in(self, process_id: str, segment_id: str) -> Optional[MemorySegment]:
        """Page a segment back from swap/disk into context."""
        self.page_ins += 1
        cw = self.context_windows.get(process_id)
        
        # Check swap first
        segment = self.swap.get(segment_id)
        if segment is None and self.redis:
            raw = self.redis.get(f"mem:swap:{segment_id}")
            if raw:
                data = json.loads(raw)
                segment = MemorySegment(
                    segment_id=segment_id,
                    process_id=data["process_id"],
                    segment_type=MemorySegmentType(data["segment_type"]),
                    tier=MemoryTier.SWAP,
                    content=data["content"],
                    token_count=data["token_count"],
                    summary=data.get("summary"),
                )
        
        if segment is None:
            # Check disk
            segment = self.disk.get(segment_id)
        
        if segment and cw:
            if cw.add_segment(segment):
                segment.tier = MemoryTier.CONTEXT
                segment.touch()
                logger.debug(f"Paged in {segment_id} ({segment.token_count} tokens) to context")
                return segment
            else:
                logger.warning(f"Cannot page in {segment_id} — context window full")
                return None
        
        return None

    def build_context_prompt(self, process_id: str) -> str:
        """
        Build the full prompt from all segments in the context window.
        This is what gets sent to the LLM.
        """
        cw = self.context_windows.get(process_id)
        if cw is None:
            return ""
        
        parts = []
        for segment in cw.segments:
            segment.touch()
            if segment.segment_type == MemorySegmentType.SYSTEM_PROMPT:
                parts.insert(0, segment.content)  # System prompt first
            else:
                parts.append(segment.content)
        
        return "\n\n".join(parts)

    def get_memory_stats(self, process_id: str) -> Dict[str, Any]:
        """Get memory stats for a process."""
        cw = self.context_windows.get(process_id)
        if cw is None:
            return {"error": "no context window"}
        
        return {
            "max_tokens": cw.max_tokens,
            "tokens_used": cw.tokens_used,
            "tokens_remaining": cw.tokens_remaining,
            "utilization_pct": round(cw.utilization_pct, 1),
            "segment_count": len(cw.segments),
            "segments": [s.to_dict() for s in cw.segments],
        }

    def get_global_stats(self) -> Dict[str, Any]:
        """Get global memory manager stats."""
        total_context = sum(cw.tokens_used for cw in self.context_windows.values())
        return {
            "active_context_windows": len(self.context_windows),
            "total_context_tokens": total_context,
            "swap_segments": len(self.swap),
            "disk_segments": len(self.disk),
            "page_faults": self.page_faults,
            "page_ins": self.page_ins,
            "page_outs": self.page_outs,
            "swap_evictions": self.swap_evictions,
            "total_tokens_paged": self.total_tokens_paged,
        }

    def destroy_context_window(self, process_id: str) -> None:
        """Clean up when a process terminates."""
        # Page remaining segments to disk for potential future reuse
        cw = self.context_windows.get(process_id)
        if cw:
            for segment in cw.segments:
                if segment.segment_type != MemorySegmentType.SYSTEM_PROMPT:
                    self._page_out(segment)
        
        self.context_windows.pop(process_id, None)
        logger.debug(f"Destroyed context window for {process_id}")

    def _gen_segment_id(self, process_id: str) -> str:
        """Generate a unique segment ID."""
        return f"MEM-{process_id[:8]}-{int(time.time()*1000)}-{hash(content) % 10000 if 'content' in dir() else hash(str(time.time())) % 10000}"
