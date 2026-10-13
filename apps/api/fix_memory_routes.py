#!/usr/bin/env python3
"""
Fix memory API endpoints — ensure all endpoints are registered and use consistent paths
"""
import sys
sys.path.insert(0, "/opt/gds-os/apps/api")

f = "/opt/gds-os/apps/api/gds_kernel/kernel_router.py"
content = open(f).read()

# 1. Fix the stats endpoint to go through syscall (same path as alloc)
old_stats = '''@router.get("/memory/stats/{pid}")
async def memory_stats(pid: str):
    """Get memory stats for a process."""
    k = get_kernel()
    result = k.syscall.sys_mem_stats("kernel", pid)
    if not result.success:
        raise HTTPException(400, result.error)
    return result.data'''

old_stats_v2 = '''@router.get("/memory/stats/{pid}")
async def memory_stats(pid: str):
    k = get_kernel()
    return k.memory.get_memory_stats(pid)'''

new_stats = '''@router.get("/memory/stats/{pid}")
async def memory_stats(pid: str):
    """Get memory stats for a process via syscall."""
    k = get_kernel()
    result = k.syscall.sys_mem_stats("kernel", pid)
    if not result.success:
        return {"error": result.error or "no context window"}
    return result.data'''

# Try replacing either variant
replaced = False
if old_stats in content:
    content = content.replace(old_stats, new_stats)
    replaced = True
    print("Fixed stats endpoint (variant 1)")
elif old_stats_v2 in content:
    content = content.replace(old_stats_v2, new_stats)
    replaced = True
    print("Fixed stats endpoint (variant 2)")
else:
    print("Stats endpoint not found — checking for other patterns")
    # Try to find any memory_stats endpoint
    import re
    match = re.search(r'@router\.get\("/memory/stats/\{pid\}"\).*?(?=\n@|\Z)', content, re.DOTALL)
    if match:
        print(f"Found stats endpoint:\n  {match.group(0)[:300]}")
        content = content.replace(match.group(0), new_stats)
        replaced = True
        print("Fixed stats endpoint (regex match)")

# 2. Add global-stats endpoint if missing
if "global-stats" not in content:
    # Add at the end of the file
    global_stats_endpoint = '''

@router.get("/memory/global-stats")
async def global_memory_stats():
    """Get global memory manager stats."""
    k = get_kernel()
    return k.memory.get_global_stats()
'''
    content = content.rstrip() + "\n" + global_stats_endpoint
    print("Added global-stats endpoint")
else:
    print("global-stats already exists")

# 3. Add build-context endpoint if missing
if "build-context" not in content:
    build_context_endpoint = '''

class BuildContextRequest(BaseModel):
    pid: str

@router.post("/memory/build-context")
async def build_context(req: BuildContextRequest):
    """Build the full LLM prompt from context window."""
    k = get_kernel()
    result = k.syscall.sys_mem_build_context("kernel", req.pid)
    if not result.success:
        return {"prompt": "", "stats": {"error": result.error or "no context window"}}
    return result.data
'''
    content = content.rstrip() + "\n" + build_context_endpoint
    print("Added build-context endpoint")
else:
    print("build-context already exists")

# 4. Add page-in endpoint if missing
if "page-in" not in content:
    page_in_endpoint = '''

class PageInRequest(BaseModel):
    pid: str
    segment_id: str

@router.post("/memory/page-in")
async def page_in_memory(req: PageInRequest):
    """Page a segment back from swap/disk into context."""
    k = get_kernel()
    segment = k.memory.page_in(req.pid, req.segment_id)
    if segment:
        return segment.to_dict()
    raise HTTPException(404, "Segment not found or context full")
'''
    content = content.rstrip() + "\n" + page_in_endpoint
    print("Added page-in endpoint")
else:
    print("page-in already exists")

# 5. Add search endpoint if missing
if "/memory/search" not in content:
    search_endpoint = '''

class SearchMemoryRequest(BaseModel):
    query: str
    pid: str = None
    limit: int = 5

@router.post("/memory/search")
async def search_memory(req: SearchMemoryRequest):
    """Search Qdrant for relevant memory segments."""
    k = get_kernel()
    results = k.memory.search_disk(req.query, process_id=req.pid, limit=req.limit)
    return {"results": results, "count": len(results)}
'''
    content = content.rstrip() + "\n" + search_endpoint
    print("Added search endpoint")
else:
    print("search already exists")

# Write the fixed file
open(f, "w").write(content)
print(f"\nWrote: {f}")
print("Restart services to apply changes:")
print("  supervisorctl restart gds-kernel; sleep 3; supervisorctl restart gds-os; sleep 15")
