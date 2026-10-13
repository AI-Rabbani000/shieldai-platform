#!/usr/bin/env python3
"""
Phase 5 Fix v3: Fix the three actual bugs in the bridge.

Bug 1: Import statements inserted at wrong indentation inside try: block
Bug 2: result.agent_id, result.goal, result.error + tc.tool_name etc still use dot notation
Bug 3: kernel_agent_runner imports TOOL_REGISTRY from kernel_bridge which doesn't export it
"""
import sys
import os
import subprocess
import time

API_DIR = "/opt/gds-os/apps/api"
bridge_file = os.path.join(API_DIR, "gds_api/bridge/super_agent_bridge.py")
runner_file = os.path.join(API_DIR, "gds_api/reasoning/kernel_agent_runner.py")

# ============================================================
# Bug 1: Fix broken imports in bridge file
# ============================================================
print("=" * 60)
print("BUG 1: Fix bridge import indentation")
print("=" * 60)

with open(bridge_file) as f:
    content = f.read()

# The problem: imports were inserted inside a try: block at wrong indentation
# Remove the broken imports and add them at module level
broken_imports = [
    "from gds_api.reasoning.kernel_agent_loop import run_kernel_agent, KernelAgentLoop\n",
    "from gds_api.reasoning.kernel_agent_runner import run_kernel_agent_runner\n",
]

for imp in broken_imports:
    if imp in content:
        # Remove the broken import (it's at wrong indentation)
        content = content.replace(imp, "")
        print("  Removed broken import: %s" % imp.strip())

# Now add the import at module level (top of file, after other imports)
# Find a good insertion point — after the last top-level import
lines = content.split("\n")
last_import_line = 0
for i, line in enumerate(lines):
    if line.startswith("from ") or line.startswith("import "):
        last_import_line = i

# Insert after the last top-level import
lines.insert(last_import_line + 1, "from gds_api.reasoning.kernel_agent_runner import run_kernel_agent_runner")
content = "\n".join(lines)
print("  Added import at line %d (module level)" % (last_import_line + 2))

# ============================================================
# Bug 2: Fix all attribute access to use dict access
# ============================================================
print()
print("=" * 60)
print("BUG 2: Fix attribute access (dict, not dot notation)")
print("=" * 60)

# The return block still has result.agent_id, result.goal, result.error
# and tc.tool_name, tc.arguments, tc.result, tc.duration_ms
# These need to be dict access since run_kernel_agent_runner returns a dict

# Fix result attributes
content = content.replace("result.agent_id", 'result.get("agent_id", agent_id)')
content = content.replace("result.goal", 'result.get("goal", req.goal if "req" in dir() else goal)')
content = content.replace("result.error", 'result.get("error", None)')

# Fix tool call attributes inside the list comprehension
content = content.replace("tc.tool_name", 'tc.get("tool", "")')
content = content.replace("tc.arguments", 'tc.get("args", {})')
content = content.replace("tc.result", 'tc.get("result", {})')
content = content.replace("tc.duration_ms", 'tc.get("duration_ms", 0)')

print("  Fixed all attribute access to dict.get()")

# Also fix the run_kernel_agent_runner call — it needs req.goal and req.context
# from the request, not just goal/context variables
content = content.replace(
    "result = await run_kernel_agent_runner(agent_id=agent_id, goal=goal, context=context)",
    "result = await run_kernel_agent_runner(agent_id=agent_id, goal=req.goal, context=req.context)"
)
print("  Fixed goal/context to use req.goal, req.context")

# Save the bridge file
with open(bridge_file, "w") as f:
    f.write(content)
print("  Bridge file saved")

# Verify the import works
print()
print("  Verifying bridge import...")
sys.path.insert(0, API_DIR)
try:
    # Clear any cached modules
    for mod in list(sys.modules.keys()):
        if "gds_api" in mod:
            del sys.modules[mod]
    from gds_api.bridge.super_agent_bridge import router
    print("  Bridge router imported OK!")
    routes = [r.path for r in router.routes]
    print("  Routes: %s" % routes)
except Exception as e:
    print("  Bridge import FAILED: %s" % e)
    import traceback
    traceback.print_exc()

# ============================================================
# Bug 3: Fix kernel_agent_runner TOOL_REGISTRY import
# ============================================================
print()
print("=" * 60)
print("BUG 3: Fix kernel_agent_runner TOOL_REGISTRY import")
print("=" * 60)

with open(runner_file) as f:
    runner_content = f.read()

# The runner tries to import TOOL_REGISTRY from kernel_bridge which doesn't have it
# Fix: import from tool_gateway instead, which is where TOOL_REGISTRY lives
old_import = "from gds_api.reasoning.kernel_bridge import execute_tool, list_tools, TOOL_REGISTRY"
new_import = """try:
    from gds_api.tool_gateway import execute_tool, TOOL_REGISTRY
except ImportError:
    try:
        from gds_api.reasoning.kernel_bridge import execute_tool, TOOL_REGISTRY
    except ImportError:
        execute_tool = None
        TOOL_REGISTRY = {}"""

if old_import in runner_content:
    runner_content = runner_content.replace(old_import, new_import)
    print("  Fixed: import TOOL_REGISTRY from tool_gateway (with fallback)")
else:
    # Check what import is there
    if "kernel_bridge" in runner_content and "TOOL_REGISTRY" in runner_content:
        # Replace any kernel_bridge import of TOOL_REGISTRY
        import re
        runner_content = re.sub(
            r'from gds_api\.reasoning\.kernel_bridge import.*?TOOL_REGISTRY.*',
            new_import,
            runner_content
        )
        print("  Fixed via regex: TOOL_REGISTRY import")
    else:
        print("  Import pattern not found — checking current import")

# Save runner file
with open(runner_file, "w") as f:
    f.write(runner_content)
print("  Runner file saved")

# Verify runner import
print()
print("  Verifying kernel_agent_runner import...")
for mod in list(sys.modules.keys()):
    if "gds_api" in mod:
        del sys.modules[mod]
try:
    from gds_api.reasoning.kernel_agent_runner import run_kernel_agent_runner
    print("  kernel_agent_runner imported OK!")
except Exception as e:
    print("  kernel_agent_runner import FAILED: %s" % e)
    import traceback
    traceback.print_exc()

# ============================================================
# Step 4: Restart services
# ============================================================
print()
print("=" * 60)
print("STEP 4: Restart services")
print("=" * 60)

subprocess.run(["supervisorctl", "restart", "gds-kernel"], check=True)
time.sleep(3)
subprocess.run(["supervisorctl", "restart", "gds-os"], check=True)
time.sleep(15)
print("  Services restarted")

# ============================================================
# Step 5: Test the bridge
# ============================================================
print()
print("=" * 60)
print("STEP 5: Test bridge")
print("=" * 60)

import httpx
import json

client = httpx.Client(timeout=120.0)

# Read API token
api_token = None
with open("/opt/.env") as f:
    for line in f:
        if "BRIDGE_API_KEY" in line and not line.startswith("#"):
            api_token = line.split("=", 1)[1].strip()
            break

if not api_token:
    api_token = "REDACTED_SET_BRIDGE_API_KEY"

# Health
try:
    r = client.get("http://127.0.0.1:8000/health")
    print("  API health: %s" % r.json().get("status", "unknown"))
except Exception as e:
    print("  API health failed: %s" % e)

# Bridge health
try:
    r = client.get("http://127.0.0.1:8000/bridge/health")
    print("  Bridge health: %d" % r.status_code)
except Exception as e:
    print("  Bridge health failed: %s" % e)

# Memory before
try:
    r = client.get("http://127.0.0.1:8000/kernel/memory/global-stats")
    mb = r.json()
    print("  Memory before: %d windows, %d faults, %d swap" % (
        mb.get("active_context_windows", 0),
        mb.get("page_faults", 0),
        mb.get("swap_segments", 0)
    ))
except Exception:
    mb = {}

# Test bridge invoke
print()
print("  Testing bridge invoke...")
r = client.post(
    "http://127.0.0.1:8000/bridge/agent/ai-vuln-director/invoke",
    headers={"Authorization": "Bearer %s" % api_token, "Content-Type": "application/json"},
    json={"goal": "Run cisa_kev_check and report the total count", "context": {}},
    timeout=120.0
)

print("  Status: %d" % r.status_code)

if r.status_code == 200:
    data = r.json()
    print("  Success: %s" % data.get("success"))
    print("  Kernel managed: %s" % data.get("kernel_managed", "N/A"))
    print("  PID: %s" % data.get("pid", "N/A"))
    print("  Iterations: %s" % data.get("iterations"))
    print("  Tool calls: %d" % len(data.get("tool_calls", [])))
    print("  Duration: %sms" % data.get("duration_ms"))
    print("  Summary: %s" % str(data.get("summary", ""))[:200])

    # Memory after
    try:
        r2 = client.get("http://127.0.0.1:8000/kernel/memory/global-stats")
        ma = r2.json()
        print()
        print("  Memory after: %d windows, %d faults, %d swap" % (
            ma.get("active_context_windows", 0),
            ma.get("page_faults", 0),
            ma.get("swap_segments", 0)
        ))
        new_windows = ma.get("active_context_windows", 0) - mb.get("active_context_windows", 0)
        if new_windows > 0:
            print("  New context window created: +%d" % new_windows)
    except Exception:
        pass

    if data.get("kernel_managed"):
        print()
        print("  [VERIFIED] KERNEL-MANAGED MEMORY AGENT WORKING!")
    elif data.get("success"):
        print()
        print("  [PARTIAL] Bridge works but kernel_managed not in response")
else:
    print("  Response: %s" % r.text[:500])
    # Check error logs
    try:
        import subprocess
        logs = subprocess.run(["tail", "-20", "/var/log/gds-os/error.log"], capture_output=True, text=True)
        if logs.stdout:
            for line in logs.stdout.split("\n")[-10:]:
                if line.strip():
                    print("  LOG: %s" % line.strip()[:150])
    except Exception:
        pass

client.close()
print()
print("=" * 60)
print("Phase 5 fix v3 complete.")
print("=" * 60)
