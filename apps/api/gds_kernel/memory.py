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
import uuid
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
    process_id: str
    segment_type: MemorySegmentType
    tier: MemoryTier
    content: str
    token_count: int
    importance: float = 0.5
    access_count: int = 0
    last_accessed: float = field(default_factory=time.time)
    created_at: float = field(default_factory=time.time)
    embedding_id: Optional[str] = None
    summary: Optional[str] = None

    def touch(self) -> None:
        self.last_accessed = time.time()
        self.access_count += 1

    def is_cold(self, threshold_seconds: int = 120) -> bool:
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
    """A process's context window — the 'RAM' for a single agent."""
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
        if self.max_tokens == 0:
            return 0
        return (self.tokens_used / self.max_tokens) * 100

    def add_segment(self, segment: MemorySegment) -> bool:
        if self.tokens_used + segment.token_count > self.max_tokens:
            return False
        self.segments.append(segment)
        segment.tier = MemoryTier.CONTEXT
        return True

    def remove_segment(self, segment_id: str) -> Optional[MemorySegment]:
        for i, s in enumerate(self.segments):
            if s.segment_id == segment_id:
                return self.segments.pop(i)
        return None

    def get_coldest_segments(self, n: int = 3) -> List[MemorySegment]:
        sorted_segs = sorted(
            self.segments,
            key=lambda s: (s.importance, s.last_accessed)
        )
        return [s for s in sorted_segs if s.segment_type != MemorySegmentType.SYSTEM_PROMPT][:n]


class MemoryManager:
    """
    The kernel's virtual memory manager.
    
    Manages context windows for all processes with automatic page faults.
    Wired to real Redis (swap) and Qdrant (disk) on the VPS.
    """

    QDRANT_COLLECTION = "gds_agent_memory"
    SWAP_TTL = 3600  # 1 hour in Redis
    MAX_SWAP_SEGMENTS = 500  # Evict to Qdrant after this

    def __init__(self, redis_client=None, qdrant_client=None):
        self.redis = redis_client
        # Create a SYNCHRONOUS Redis client for swap operations
        # (the async client can't be used from sync methods like _page_out)
        self.redis_sync = None
        try:
            import redis as redis_sync_module
            self.redis_sync = redis_sync_module.Redis(
                host='localhost', port=6379, db=0, decode_responses=True
            )
            self.redis_sync.ping()
        except Exception as e:
            import logging
            logging.getLogger("gds.kernel.memory").warning(
                f"Sync Redis client for swap failed: {e} — using in-memory swap only"
            )
            self.redis_sync = None
        self.qdrant = qdrant_client
        
        self.context_windows: Dict[str, ContextWindow] = {}
        self.swap: Dict[str, MemorySegment] = {}  # Fallback if no Redis
        self.disk: Dict[str, MemorySegment] = {}  # Fallback if no Qdrant
        
        # Telemetry
        self.page_faults: int = 0
        self.page_ins: int = 0
        self.page_outs: int = 0
        self.swap_evictions: int = 0
        self.total_tokens_paged: int = 0

        # Initialize Qdrant collection if client available
        if self.qdrant:
            try:
                from qdrant_client.models import Distance, VectorParams
                collections = self.qdrant.get_collections()
                col_names = [c.name for c in collections.collections]
                if self.QDRANT_COLLECTION not in col_names:
                    self.qdrant.create_collection(
                        collection_name=self.QDRANT_COLLECTION,
                        vectors_config=VectorParams(size=1536, distance=Distance.COSINE),
                    )
                    logger.info(f"Created Qdrant collection: {self.QDRANT_COLLECTION}")
            except Exception as e:
                logger.warning(f"Qdrant init failed (non-fatal): {e}")
                self.qdrant = None

    def create_context_window(self, process_id: str, max_tokens: int = 128000) -> ContextWindow:
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
        """Allocate content into context window. Auto-handles page faults."""
        cw = self.context_windows.get(process_id)
        if cw is None:
            cw = self.create_context_window(process_id)

        token_count = max(1, len(content) // 4)
        segment_id = self._gen_segment_id(process_id)

        segment = MemorySegment(
            segment_id=segment_id,
            process_id=process_id,
            segment_type=segment_type,
            tier=MemoryTier.CONTEXT,
            content=content,
            token_count=token_count,
            importance=importance,
        )

        if cw.add_segment(segment):
            return segment.segment_id

        # Page fault
        self.page_faults += 1
        logger.info(f"PAGE FAULT for {process_id}: {cw.tokens_used}/{cw.max_tokens} tokens, "
                    f"need {token_count} more")

        freed = self._handle_page_fault(process_id, token_count)

        if freed >= token_count:
            cw.add_segment(segment)
            logger.info(f"Page fault resolved: freed {freed} tokens, allocated {token_count}")
            return segment.segment_id
        else:
            logger.warning(f"Page fault unresolved: only freed {freed}/{token_count} tokens")
            return None

    def _handle_page_fault(self, process_id: str, needed_tokens: int) -> int:
        """Evict cold segments to make room. Returns tokens freed."""
        cw = self.context_windows.get(process_id)
        if cw is None:
            return 0

        freed = 0
        cold_segments = cw.get_coldest_segments(n=10)

        for segment in cold_segments:
            if freed >= needed_tokens:
                break
            self._page_out(segment)
            cw.remove_segment(segment.segment_id)
            freed += segment.token_count

        return freed

    def _page_out(self, segment: MemorySegment) -> None:
        """Page a segment from context to swap/disk."""
        self.page_outs += 1
        self.total_tokens_paged += segment.token_count

        # Simple compression for large conversation segments
        if segment.token_count > 500 and segment.segment_type == MemorySegmentType.CONVERSATION:
            if len(segment.content) > 400:
                segment.summary = segment.content[:200] + " [...] " + segment.content[-200:]
            else:
                segment.summary = segment.content

        # Store in swap using SYNCHRONOUS Redis (async client can't be used from sync methods)
        stored = False
        if self.redis_sync:
            try:
                self.redis_sync.setex(
                    f"mem:swap:{segment.segment_id}",
                    getattr(self, 'SWAP_TTL', 3600),
                    json.dumps({
                        "content": segment.content,
                        "summary": segment.summary,
                        "token_count": segment.token_count,
                        "segment_type": segment.segment_type.value,
                        "process_id": segment.process_id,
                    })
                )
                stored = True
            except Exception as e:
                logger.warning(f"Redis sync swap failed for {segment.segment_id}: {e} — using in-memory")

        if not stored:
            self.swap[segment.segment_id] = segment

        segment.tier = MemoryTier.SWAP
        logger.debug(f"Paged out {segment.segment_id} ({segment.token_count} tokens) to swap")
    def _maybe_evict_swap(self) -> None:
        """Evict oldest swap segments to Qdrant (disk) if swap is too large."""
        if len(self.swap) < self.MAX_SWAP_SEGMENTS:
            return

        # Sort by last_accessed, evict oldest 10%
        sorted_swap = sorted(self.swap.values(), key=lambda s: s.last_accessed)
        to_evict = sorted_swap[:max(1, len(self.swap) // 10)]

        for segment in to_evict:
            self._evict_to_disk(segment)
            self.swap.pop(segment.segment_id, None)
            self.swap_evictions += 1

    def _evict_to_disk(self, segment: MemorySegment) -> None:
        """Evict a segment from swap to Qdrant (disk) with embedding."""
        if self.qdrant:
            try:
                # Store in Qdrant with a simple vector (hash-based placeholder)
                # In production, this would call an embedding model
                vector = self._simple_embedding(segment.content)
                self.qdrant.upsert(
                    collection_name=self.QDRANT_COLLECTION,
                    points=[{
                        "id": segment.segment_id,
                        "vector": vector,
                        "payload": {
                            "content": segment.content,
                            "summary": segment.summary,
                            "token_count": segment.token_count,
                            "segment_type": segment.segment_type.value,
                            "process_id": segment.process_id,
                            "importance": segment.importance,
                            "last_accessed": segment.last_accessed,
                        }
                    }]
                )
                segment.tier = MemoryTier.DISK
                segment.embedding_id = segment.segment_id
                logger.debug(f"Evicted {segment.segment_id} to Qdrant (disk)")
            except Exception as e:
                logger.warning(f"Qdrant eviction failed: {e}, keeping in memory")
                self.disk[segment.segment_id] = segment
        else:
            self.disk[segment.segment_id] = segment
            segment.tier = MemoryTier.DISK

    def page_in(self, process_id: str, segment_id: str) -> Optional[MemorySegment]:
        """Page a segment back from swap/disk into context."""
        self.page_ins += 1
        cw = self.context_windows.get(process_id)

        # Check swap first (in-memory fallback)
        segment = self.swap.get(segment_id)

        # Check Redis swap
        if segment is None and self.redis_sync:
            try:
                raw = self.redis_sync.get(f"mem:swap:{segment_id}")
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
                        importance=data.get("importance", 0.5),
                    )
            except Exception as e:
                logger.warning(f"Redis page_in failed: {e}")

        # Check disk (Qdrant or in-memory fallback)
        if segment is None:
            segment = self.disk.get(segment_id)
            if segment is None and self.qdrant:
                try:
                    result = self.qdrant.retrieve(
                        collection_name=self.QDRANT_COLLECTION,
                        ids=[segment_id],
                    )
                    if result:
                        payload = result[0].payload
                        segment = MemorySegment(
                            segment_id=segment_id,
                            process_id=payload.get("process_id", process_id),
                            segment_type=MemorySegmentType(payload.get("segment_type", "working")),
                            tier=MemoryTier.DISK,
                            content=payload.get("content", ""),
                            token_count=payload.get("token_count", 0),
                            summary=payload.get("summary"),
                            importance=payload.get("importance", 0.5),
                        )
                except Exception as e:
                    logger.warning(f"Qdrant page_in failed: {e}")

        if segment and cw:
            if cw.add_segment(segment):
                segment.tier = MemoryTier.CONTEXT
                segment.touch()
                logger.debug(f"Paged in {segment_id} ({segment.token_count} tokens)")
                return segment
            else:
                logger.warning(f"Cannot page in {segment_id} — context full")
                return None
        return None

    def search_disk(self, query: str, process_id: Optional[str] = None, limit: int = 5) -> List[Dict]:
        """Search Qdrant for relevant memory segments (semantic recall)."""
        if not self.qdrant:
            return []
        try:
            vector = self._simple_embedding(query)
            results = self.qdrant.search(
                collection_name=self.QDRANT_COLLECTION,
                query_vector=vector,
                limit=limit,
                query_filter={"must": [{"key": "process_id", "match": {"value": process_id}}]} if process_id else None,
            )
            return [
                {
                    "segment_id": r.id,
                    "content": r.payload.get("content", "")[:200],
                    "summary": r.payload.get("summary"),
                    "token_count": r.payload.get("token_count", 0),
                    "score": r.score,
                }
                for r in results
            ]
        except Exception as e:
            logger.warning(f"Qdrant search failed: {e}")
            return []

    def build_context_prompt(self, process_id: str) -> str:
        """Build the full prompt from all segments in context window."""
        cw = self.context_windows.get(process_id)
        if cw is None:
            return ""
        parts = []
        for segment in cw.segments:
            segment.touch()
            if segment.segment_type == MemorySegmentType.SYSTEM_PROMPT:
                parts.insert(0, segment.content)
            else:
                parts.append(segment.content)
        return "\n\n".join(parts)

    def get_memory_stats(self, process_id: str) -> Dict[str, Any]:
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


    def _count_redis_swap(self):
        """Safely count Redis swap segments."""
        try:
            if getattr(self, "redis_sync", None):
                keys = self.redis_sync.keys("mem:swap:*")
                return len(keys) if keys else 0
        except Exception:
            pass
        return 0

    def get_global_stats(self) -> Dict[str, Any]:
        total_context = sum(cw.tokens_used for cw in self.context_windows.values())
        return {
            "active_context_windows": len(self.context_windows),
            "total_context_tokens": total_context,
            "swap_segments": len(self.swap) + self._count_redis_swap(),
            "disk_segments": len(self.disk),
            "page_faults": self.page_faults,
            "page_ins": self.page_ins,
            "page_outs": self.page_outs,
            "swap_evictions": self.swap_evictions,
            "total_tokens_paged": self.total_tokens_paged,
        }

    def destroy_context_window(self, process_id: str) -> None:
        """Clean up when a process terminates — page remaining to disk."""
        cw = self.context_windows.get(process_id)
        if cw:
            for segment in cw.segments:
                if segment.segment_type != MemorySegmentType.SYSTEM_PROMPT:
                    self._page_out(segment)
        self.context_windows.pop(process_id, None)

    def _gen_segment_id(self, process_id: str) -> str:
        """Generate a unique segment ID."""
        return f"MEM-{process_id[:8]}-{uuid.uuid4().hex[:12]}"

    def _simple_embedding(self, text: str, dims: int = 1536) -> List[float]:
        """
        Simple hash-based embedding for dedup/search.
        In production, replace with OpenAI text-embedding-3-small.
        """
        import hashlib
        h = hashlib.sha256(text.encode()).hexdigest()
        vec = []
        for i in range(0, len(h), 2):
            vec.append(int(h[i:i+2], 16) / 255.0)
        # Pad or truncate to dims
        while len(vec) < dims:
            vec.extend(vec)
        return vec[:dims]
