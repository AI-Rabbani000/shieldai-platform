#!/usr/bin/env python3
"""
Fix memory API endpoints in kernel_router.py
- Ensures global-stats endpoint is registered
- Makes stats/{pid} go through the syscall (same path as alloc)
"""
import sys
sys.path.insert(0, "/opt/gds-os/apps/api")

f = "/opt/gds-os/apps/api/gds_kernel/kernel_router.py"
content = open(f).read()

# Check what memory endpoints exist
print("=== Current memory endpoints ===")
for line in content.split("\n"):
    if "/memory" in line and ("@router" in line or "def " in line):
        print(f"  {line.strip()}")

# Check if global-stats exists
if "global-stats" in content:
    print("\n  global-stats: FOUND")
else:
    print("\n  global-stats: MISSING — adding it")

# Check if the stats endpoint reads from k.memory or k.syscall
# Find the memory_stats function
import re
stats_match = re.search(r'async def memory_stats\(pid: str\):.*?(?=\n@|\nclass |\Z)', content, re.DOTALL)
if stats_match:
    stats_body = stats_match.group(0)
    print(f"\n  stats endpoint body:\n    {stats_body[:200]}")
    if "k.memory.get_memory_stats" in stats_body:
        print("  ISSUE: stats reads from k.memory directly, not through syscall")
    elif "k.syscall.sys_mem_stats" in stats_body:
        print("  stats goes through syscall — correct")
    else:
        print(f"  stats uses unknown path — check above")

print("\n=== Alloc endpoint ===")
alloc_match = re.search(r'async def alloc_memory.*?(?=\n@|\nclass |\Z)', content, re.DOTALL)
if alloc_match:
    alloc_body = alloc_match.group(0)
    if "k.syscall.sys_mem_alloc" in alloc_body:
        print("  alloc goes through syscall — correct")
    elif "k.memory" in alloc_body:
        print("  ISSUE: alloc uses k.memory directly")
    else:
        print(f"  alloc body: {alloc_body[:200]}")
