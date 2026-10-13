#!/usr/bin/env python3
"""
Phase 4 Final Fix: The Redis client in MemoryManager is ASYNC (redis.asyncio.client.Redis).
_page_out calls self.redis.setex() synchronously, which returns a coroutine that
is never awaited — so data never reaches Redis.

Fix: Add a synchronous Redis client (self.redis_sync) for swap operations.
"""
import sys
sys.path.insert(0, "/opt/gds-os/apps/api")

# ============================================================
# Step 1: Diagnose
# ============================================================
print("=" * 60)
print("STEP 1: Diagnose Redis client type")
print("=" * 60)

from gds_kernel.kernel_router import get_kernel
k = get_kernel()
mm = k.memory

print(f"  Redis client type: {type(mm.redis)}")
print(f"  Is async: {'asyncio' in str(type(mm.redis))}")

# Check if redis sync module is available
try:
    import redis.sync
    print("  redis.sync available: YES")
except ImportError:
    try:
        import redis
        print(f"  redis version: {redis.__version__}")
        # In redis-py 4.x+, redis.Redis is synchronous by default
        print("  redis.Redis (sync) available: YES")
    except ImportError:
        print("  redis module: NOT FOUND")

# ============================================================
# Step 2: Fix MemoryManager to add sync Redis client
# ============================================================
print()
print("=" * 60)
print("STEP 2: Add synchronous Redis client for swap operations")
print("=" * 60)

f = "/opt/gds-os/apps/api/gds_kernel/memory.py"
content = open(f).read()

# 2a: Add sync Redis client in __init__ (after self.redis = redis_client)
if "self.redis_sync" not in content:
    # Find the __init__ and add sync client
    old_init_line = "        self.redis = redis_client"
    new_init_lines = """        self.redis = redis_client
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
            self.redis_sync = None"""
    
    if old_init_line in content:
        content = content.replace(old_init_line, new_init_lines)
        print("  Added redis_sync client to __init__")
    else:
        print("  WARNING: Could not find self.redis = redis_client in __init__")

# 2b: Fix _page_out to use redis_sync instead of async redis
# Find the current _page_out setex block and replace with sync version
if "self.redis_sync.setex" not in content:
    # The current code already has try/except and SWAP_TTL
    # Replace the async setex with sync setex
    import re
    
    # Match the existing setex block (already has try/except from earlier patches)
    old_pattern = r'if self\.redis:\s*\n\s*try:\s*\n\s*self\.redis\.setex\([^)]+\)\s*\n\s*stored = True\s*\n\s*except Exception as e:[^}]*?using in-memory"'
    
    # Simpler approach: find and replace the whole _page_out method
    page_out_match = re.search(
        r'(    def _page_out\(self, segment.*?)(?=\n    def |\Z)',
        content, re.DOTALL
    )
    
    if page_out_match:
        old_method = page_out_match.group(0)
        
        new_method = '''    def _page_out(self, segment: MemorySegment) -> None:
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
        logger.debug(f"Paged out {segment.segment_id} ({segment.token_count} tokens) to swap")'''
        
        content = content.replace(old_method, new_method)
        print("  Replaced _page_out with sync Redis version")
    else:
        print("  WARNING: Could not find _page_out method")
else:
    print("  _page_out already uses redis_sync")

# 2c: Fix page_in to use redis_sync
if "self.redis_sync.get" not in content and "self.redis_sync" in content:
    # Find page_in method and fix it too
    import re
    page_in_match = re.search(
        r'(    def page_in\(self.*?)(?=\n    def |\Z)',
        content, re.DOTALL
    )
    if page_in_match:
        old_page_in = page_in_match.group(0)
        # Replace async redis with sync
        new_page_in = old_page_in.replace(
            "if segment is None and self.redis:",
            "if segment is None and self.redis_sync:"
        ).replace(
            "raw = self.redis.get(f\"mem:swap:{segment_id}\")",
            "raw = self.redis_sync.get(f\"mem:swap:{segment_id}\")"
        )
        content = content.replace(old_page_in, new_page_in)
        print("  Fixed page_in to use redis_sync")
    else:
        print("  WARNING: Could not find page_in method")

# 2d: Fix _count_redis_swap to use redis_sync
if "self.redis_sync" in content:
    content = content.replace(
        "if self.redis:\n                keys = self.redis.keys(\"mem:swap:*\")",
        "if self.redis_sync:\n                keys = self.redis_sync.keys(\"mem:swap:*\")"
    )
    print("  Fixed _count_redis_swap to use redis_sync")

open(f, "w").write(content)
print("  All fixes applied to memory.py")

# ============================================================
# Step 3: Restart services
# ============================================================
print()
print("=" * 60)
print("STEP 3: Restart services")
print("=" * 60)

import subprocess
subprocess.run(["supervisorctl", "restart", "gds-kernel"], check=True)
import time
time.sleep(3)
subprocess.run(["supervisorctl", "restart", "gds-os"], check=True)
time.sleep(15)
print("  Services restarted")

# ============================================================
# Step 4: Verify sync Redis client is connected
# ============================================================
print()
print("=" * 60)
print("STEP 4: Verify sync Redis client")
print("=" * 60)

from gds_kernel.kernel_router import get_kernel
k = get_kernel()
mm = k.memory

print(f"  redis (async): {type(mm.redis).__name__}")
print(f"  redis_sync: {mm.redis_sync}")
if mm.redis_sync:
    try:
        print(f"  redis_sync ping: {mm.redis_sync.ping()}")
    except Exception as e:
        print(f"  redis_sync ping FAILED: {e}")
else:
    print("  redis_sync is None — swap will use in-memory only")

# ============================================================
# Step 5: Run overflow test
# ============================================================
print()
print("=" * 60)
print("STEP 5: Overflow test — fill 128K context window")
print("=" * 60)

import httpx

KERNEL_API = "http://127.0.0.1:8000/kernel"
PID = "sync-redis-swap-test"
client = httpx.Client(timeout=120.0)

def kpost(path, data):
    try:
        r = client.post(f"{KERNEL_API}{path}", json=data)
        if r.status_code == 200:
            result = r.json()
            return result if isinstance(result, dict) else {}
    except Exception:
        pass
    return {}

def kget(path):
    try:
        r = client.get(f"{KERNEL_API}{path}")
        return r.json() if r.status_code == 200 else {}
    except Exception:
        pass
    return {}

# Allocate system prompt + goal
kpost("/memory/alloc", {
    "pid": PID,
    "content": "You are a security analyst. Analyze all scan results.",
    "segment_type": "system_prompt",
    "importance": 1.0
})
kpost("/memory/alloc", {
    "pid": PID,
    "content": "Analyze 250 vulnerability scan results and provide a summary.",
    "segment_type": "conversation",
    "importance": 0.8
})

before = kget("/memory/global-stats")
print(f"  Before: faults={before.get('page_faults',0)}, swap={before.get('swap_segments',0)}")

# Fill context with 250 large results
for i in range(250):
    result_text = (
        f"TOOL_RESULT_{i}: nuclei_scan target=api.globaldigitalsecurity.io "
        f"template=CVE-2024-{10000+i} severity="
        f"{'critical' if i%5==0 else 'high' if i%3==0 else 'medium'} "
        f"description=RCE vulnerability payload={'A'*1500} "
        f"response=HTTP/1.1 {'500' if i%5==0 else '200'} "
        f"body={'B'*500} remediation=Update to latest version immediately"
    )
    kpost("/memory/alloc", {
        "pid": PID,
        "content": result_text,
        "segment_type": "tool_result",
        "importance": 0.5
    })

    if (i + 1) % 50 == 0:
        stats = kget(f"/memory/stats/{PID}")
        g = kget("/memory/global-stats")
        total_faults = g.get("page_faults", 0) - before.get("page_faults", 0)
        print(
            f"  [{i+1}/250] tokens: {stats.get('tokens_used',0)}/"
            f"{stats.get('max_tokens',0)} ({stats.get('utilization_pct',0)}%) | "
            f"segments: {stats.get('segment_count',0)} | "
            f"faults: {total_faults} | swap: {g.get('swap_segments',0)}"
        )

# Final results
g = kget("/memory/global-stats")
stats = kget(f"/memory/stats/{PID}")
total_faults = g.get("page_faults", 0) - before.get("page_faults", 0)

# Check Redis directly (sync)
redis_keys = []
if mm.redis_sync:
    try:
        redis_keys = mm.redis_sync.keys("mem:swap:*")
    except Exception:
        pass

print()
print("=" * 60)
print("FINAL RESULTS")
print("=" * 60)
print(f"  Tokens in context:   {stats.get('tokens_used',0)}/{stats.get('max_tokens',0)} ({stats.get('utilization_pct',0)}%)")
print(f"  Segments in context:  {stats.get('segment_count',0)}")
print(f"  Page faults:         {total_faults}")
print(f"  Page-outs:            {g.get('page_outs',0)}")
print(f"  Page-ins:             {g.get('page_ins',0)}")
print(f"  Swap (stats):         {g.get('swap_segments',0)}")
print(f"  Swap (Redis raw):     {len(redis_keys)} keys")
print(f"  Total tokens paged:   {g.get('total_tokens_paged',0)}")

if redis_keys:
    print(f"  Redis key samples:   {redis_keys[:3]}")

print()
if total_faults > 0 and (g.get("swap_segments", 0) > 0 or len(redis_keys) > 0):
    print("  [VERIFIED] PAGE FAULTS + REDIS SWAP WORKING — 3-tier memory hierarchy confirmed!")
elif total_faults > 0 and mm.redis_sync is None:
    print("  [PARTIAL] Page faults work, redis_sync is None — in-memory swap should have segments")
    # Check in-memory swap
    print(f"  In-memory swap: {len(mm.swap)} segments")
    if len(mm.swap) > 0:
        print(f"  Swap keys: {list(mm.swap.keys())[:3]}")
        print("  [VERIFIED] PAGE FAULTS + IN-MEMORY SWAP WORKING!")
elif total_faults > 0:
    print("  [PARTIAL] Page faults work but swap still empty")
else:
    print("  [FAIL] No page faults triggered")

client.close()
print()
print("Phase 4 final fix complete.")
