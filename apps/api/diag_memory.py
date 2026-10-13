#!/usr/bin/env python3
"""
GDS Kernel Memory Diagnostic — checks syscall-to-MemoryManager wiring
"""
import sys
sys.path.insert(0, "/opt/gds-os/apps/api")

from gds_kernel.unified_kernel import GDSUnifiedKernel

k = GDSUnifiedKernel()
k.boot()

km = k.memory
sm = k.syscall.memory

print(f"kernel.memory id: {id(km)}")
print(f"syscall.memory id: {id(sm)}")
print(f"Same object? {km is sm}")

# Test allocate through syscall
result = k.syscall.sys_mem_alloc("diag-pid", "Test content for diagnostic", "system_prompt", 1.0)
print(f"\nSyscall alloc: success={result.success}, data={result.data}")

# Check memory stats directly on kernel.memory
stats_direct = km.get_memory_stats("diag-pid")
print(f"Direct stats (kernel.memory): tokens={stats_direct.get('tokens_used', 0)}, segments={stats_direct.get('segment_count', 0)}")

# Check through syscall
result2 = k.syscall.sys_mem_stats("kernel", "diag-pid")
print(f"Syscall stats: success={result2.success}, data={result2.data}")

# Check global stats
global_stats = km.get_global_stats()
print(f"\nGlobal stats: windows={global_stats.get('active_context_windows', 0)}, page_faults={global_stats.get('page_faults', 0)}")

# If they're not the same object, that's the bug
if km is not sm:
    print("\n*** BUG FOUND: kernel.memory and syscall.memory are DIFFERENT objects! ***")
    print("The syscall interface has its own MemoryManager separate from the kernel's.")
    print("Fix: pass kernel.memory to the syscall interface constructor.")
else:
    print("\n*** Objects are the same — stats should work. Checking if context window exists... ***")
    cw = km.context_windows.get("diag-pid")
    if cw:
        print(f"Context window exists: tokens_used={cw.tokens_used}, segments={len(cw.segments)}")
    else:
        print("*** BUG: Context window not found after allocation! ***")
        print("The allocate() method may have failed silently.")
        # Check if allocate returned a segment_id
        if result.success:
            seg_id = result.data.get("segment_id")
            print(f"Segment ID returned: {seg_id}")
            # Check all context windows
            print(f"All context windows: {list(km.context_windows.keys())}")
