#!/usr/bin/env python3
"""
Fix: Ensure get_kernel() returns the SAME kernel instance across all requests.

The bug: get_kernel() creates a new GDSUnifiedKernel each time because
the _kernel global is either not properly initialized or is being reset.

The fix: Use a class-level singleton pattern that persists across all
requests in the same process.
"""
import sys
sys.path.insert(0, "/opt/gds-os/apps/api")

f = "/opt/gds-os/apps/api/gds_kernel/kernel_router.py"
content = open(f).read()

# Replace the get_kernel function with a robust singleton
import re

# Find the existing get_kernel function
match = re.search(r'(def get_kernel\(\).*?)(?=\n@router|\nclass |\ndef [a-z]|\Z)', content, re.DOTALL)
if match:
    old_func = match.group(0)
    
    new_func = '''def get_kernel():
    """Get the singleton kernel instance. Created once, reused forever."""
    global _kernel
    if _kernel is None:
        from gds_kernel.unified_kernel import GDSUnifiedKernel
        _kernel = GDSUnifiedKernel()
        _kernel.boot()
        import logging
        logging.getLogger("gds.kernel.router").info(
            f"Kernel singleton created: id={id(_kernel)}, memory_id={id(_kernel.memory)}"
        )
    return _kernel'''

    content = content.replace(old_func, new_func)
    
    # Also ensure _kernel = None is at module level (before the function)
    if " _kernel = None" not in content and "_kernel = None" not in content:
        # Add it before the get_kernel function
        content = content.replace(
            "def get_kernel():",
            "_kernel = None  # Singleton kernel instance\n\ndef get_kernel():"
        )
    
    # Add kernel instance ID to the alloc endpoint for debugging
    if "kernel_id" not in content:
        # Add kernel_id to the alloc response
        content = content.replace(
            'return result.data',
            '''# Debug: include kernel instance ID
        result_data = result.data if result.success else {}
        result_data["kernel_instance"] = id(k)
        result_data["memory_instance"] = id(k.memory)
        return result_data
        
        # Original return for other endpoints
        return result.data''',
            1  # Only replace first occurrence (the alloc endpoint)
        )
    
    open(f, "w").write(content)
    print("Fixed: get_kernel() singleton strengthened")
    print("Added: _kernel = None at module level")
    print("Added: kernel_instance + memory_instance in alloc response for debugging")
else:
    print("Could not find get_kernel() function!")

# Also add instance IDs to stats endpoint
content = open(f).read()
if "kernel_instance" in content and "memory/stats" in content:
    # The stats endpoint should also include instance IDs
    # Find the stats endpoint and add instance IDs to its response
    stats_match = re.search(
        r'(async def memory_stats\(pid: str\):.*?)((?:\n@|\nclass |\Z))',
        content, re.DOTALL
    )
    if stats_match:
        stats_body = stats_match.group(1)
        if "kernel_instance" not in stats_body:
            new_stats_body = stats_body.replace(
                "return result.data",
                'data = result.data if result.success else {"error": result.error or "no context window"}\n    data["kernel_instance"] = id(k)\n    data["memory_instance"] = id(k.memory)\n    data["context_window_keys"] = list(k.memory.context_windows.keys())\n    return data'
            )
            content = content.replace(stats_body, new_stats_body)
            open(f, "w").write(content)
            print("Added: kernel_instance + memory_instance + context_window_keys to stats response")

# Also add to global-stats
content = open(f).read()
if "global_memory_stats" in content:
    global_match = re.search(
        r'(async def global_memory_stats\(\):.*?)((?:\n@|\nclass |\Z))',
        content, re.DOTALL
    )
    if global_match:
        global_body = global_match.group(1)
        if "kernel_instance" not in global_body:
            new_global = global_body.replace(
                "return k.memory.get_global_stats()",
                'data = k.memory.get_global_stats()\n    data["kernel_instance"] = id(k)\n    data["memory_instance"] = id(k.memory)\n    data["context_window_keys"] = list(k.memory.context_windows.keys())\n    return data'
            )
            content = content.replace(global_body, new_global)
            open(f, "w").write(content)
            print("Added: kernel_instance + memory_instance + context_window_keys to global-stats response")

print("\nDone. Restart services and test:")
print("  supervisorctl restart gds-kernel; sleep 3; supervisorctl restart gds-os; sleep 15")
print("  curl -s -X POST http://127.0.0.1:8000/kernel/memory/alloc -H 'Content-Type: application/json' -d '{\"pid\":\"test\",\"content\":\"test\",\"segment_type\":\"system_prompt\",\"importance\":1.0}' | python3 -m json.tool")
print("  curl -s http://127.0.0.1:8000/kernel/memory/stats/test | python3 -m json.tool")
print("  curl -s http://127.0.0.1:8000/kernel/memory/global-stats | python3 -m json.tool")
print("\nIf kernel_instance IDs differ between alloc and stats, the singleton is broken.")
print("If they're the same but context_window_keys shows [], the memory manager is losing state.")
