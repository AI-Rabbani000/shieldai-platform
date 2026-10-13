#!/usr/bin/env python3
"""
Phase 5 Fix v2: Wire bridge to kernel_agent_runner.
Simple, direct patching — no complex regex.
"""
import sys
import os
import subprocess
import time

sys.path.insert(0, "/opt/gds-os/apps/api")
API_DIR = "/opt/gds-os/apps/api"

bridge_file = os.path.join(API_DIR, "gds_api/bridge/super_agent_bridge.py")

# ============================================================
# Step 1: Read bridge and show the invoke handler
# ============================================================
print("=" * 60)
print("STEP 1: Read bridge invoke handler")
print("=" * 60)

with open(bridge_file) as f:
    lines = f.readlines()

# Find and show lines around AgenticLoop
for i, line in enumerate(lines):
    if "AgenticLoop(" in line and "import" not in line:
        start = max(0, i - 3)
        end = min(len(lines), i + 30)
        print("Found AgenticLoop at line %d. Context:" % (i + 1))
        for j in range(start, end):
            marker = ">>>" if j == i else "   "
            print("  %s L%d: %s" % (marker, j + 1, lines[j].rstrip()[:100]))
        loop_line = i
        break
else:
    print("AgenticLoop not found — may already be patched")
    loop_line = None

# ============================================================
# Step 2: Patch — replace AgenticLoop block with run_kernel_agent_runner
# ============================================================
print()
print("=" * 60)
print("STEP 2: Patch bridge")
print("=" * 60)

with open(bridge_file) as f:
    content = f.read()

# Check if already patched
if "run_kernel_agent_runner" in content and "AgenticLoop(" not in content:
    print("Already patched — bridge uses run_kernel_agent_runner")
else:
    # 1. Add import if not present
    if "from gds_api.reasoning.kernel_agent_runner import run_kernel_agent_runner" not in content:
        content = content.replace(
            "from gds_api.reasoning.kernel_agent_loop import run_kernel_agent, KernelAgentLoop",
            "from gds_api.reasoning.kernel_agent_loop import run_kernel_agent, KernelAgentLoop\nfrom gds_api.reasoning.kernel_agent_runner import run_kernel_agent_runner"
        )
        print("Added import for run_kernel_agent_runner")
    else:
        print("Import already present")

    # 2. Replace "loop = AgenticLoop(agent_id=agent_id)" with a marker
    old_loop_line = "loop = AgenticLoop(agent_id=agent_id)"
    new_loop_line = "# Phase 5: kernel-managed memory (no AgenticLoop)"
    if old_loop_line in content:
        content = content.replace(old_loop_line, new_loop_line)
        print("Replaced AgenticLoop instantiation with marker")
    else:
        print("WARNING: could not find '%s'" % old_loop_line)

    # 3. Replace the .run() call with run_kernel_agent_runner
    # Common patterns:
    #   result = await loop.run(goal, context)
    #   result = await loop.run(goal=goal, context=context)
    #   result = loop.run(goal, context)
    replacements = [
        ("result = await loop.run(goal, context)", "result = await run_kernel_agent_runner(agent_id=agent_id, goal=goal, context=context)"),
        ("result = await loop.run(goal=goal, context=context)", "result = await run_kernel_agent_runner(agent_id=agent_id, goal=goal, context=context)"),
        ("result = loop.run(goal, context)", "result = await run_kernel_agent_runner(agent_id=agent_id, goal=goal, context=context)"),
        ("result = loop.run(goal=goal, context=context)", "result = await run_kernel_agent_runner(agent_id=agent_id, goal=goal, context=context)"),
        ("result = await loop.run(goal, **kwargs)", "result = await run_kernel_agent_runner(agent_id=agent_id, goal=goal, context=kwargs)"),
    ]

    patched_run = False
    for old, new in replacements:
        if old in content:
            content = content.replace(old, new)
            print("Replaced: %s -> run_kernel_agent_runner" % old[:50])
            patched_run = True
            break

    if not patched_run:
        # Try to find any loop.run pattern
        import re
        run_match = re.search(r'result\s*=\s*(?:await\s+)?loop\.run\([^)]*\)', content)
        if run_match:
            old = run_match.group(0)
            content = content.replace(old, "result = await run_kernel_agent_runner(agent_id=agent_id, goal=goal, context=context)")
            print("Replaced via regex: %s -> run_kernel_agent_runner" % old[:50])
            patched_run = True
        else:
            print("WARNING: could not find loop.run() call")

    # 4. Handle result attribute access differences
    # AgenticLoop returns AgentResult with .tool_calls, .summary, .iterations etc.
    # run_kernel_agent_runner returns dict with "tool_calls", "response", "iterations" etc.
    # The bridge may access result.tool_calls -> need result["tool_calls"]
    # But dict also supports .get() which is safer
    # Let's check if the bridge accesses result attributes

    # Common patterns:
    #   result.tool_calls -> result.get("tool_calls", [])
    #   result.summary -> result.get("response", "")
    #   result.iterations -> result.get("iterations", 0)
    #   result.success -> result.get("success", True)

    attr_replacements = [
        ("result.tool_calls", 'result.get("tool_calls", [])'),
        ("result.summary", 'result.get("response", "")'),
        ("result.iterations", 'result.get("iterations", 0)'),
        ("result.duration_ms", 'result.get("duration_ms", 0)'),
        ("result.success", 'result.get("success", True)'),
    ]

    for old, new in attr_replacements:
        if old in content:
            content = content.replace(old, new)
            print("Fixed attr access: %s -> %s" % (old, new))

    # Save
    with open(bridge_file, "w") as f:
        f.write(content)
    print("Bridge file saved")

# ============================================================
# Step 3: Find the correct bridge URL
# ============================================================
print()
print("=" * 60)
print("STEP 3: Find bridge routes")
print("=" * 60)

with open(bridge_file) as f:
    content = f.read()

import re
routes = re.findall(r'@router\.(get|post|put|delete)\("([^"]+)"', content)
print("Bridge routes:")
for method, path in routes:
    print("  %s %s" % (method.upper(), path))

prefix_match = re.search(r'APIRouter\([^)]*prefix\s*=\s*"([^"]*)"', content)
if prefix_match:
    print("Router prefix: %s" % prefix_match.group(1))

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
print("Services restarted")

# ============================================================
# Step 5: Test
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

# Check health
try:
    r = client.get("http://127.0.0.1:8000/health")
    print("API health: %s" % r.json().get("status", "unknown"))
except Exception as e:
    print("API health failed: %s" % e)

# Check kernel
try:
    r = client.get("http://127.0.0.1:8000/kernel/status")
    ks = r.json()
    print("Kernel: %s, Tools: %d/%d" % (
        ks.get("is_running"),
        ks.get("sandbox", {}).get("healthy_tools", 0),
        ks.get("sandbox", {}).get("registered_tools", 0)
    ))
except Exception as e:
    print("Kernel status failed: %s" % e)

# Memory before
try:
    r = client.get("http://127.0.0.1:8000/kernel/memory/global-stats")
    mb = r.json()
    print("Memory before: %d windows, %d faults, %d swap" % (
        mb.get("active_context_windows", 0),
        mb.get("page_faults", 0),
        mb.get("swap_segments", 0)
    ))
except Exception:
    mb = {}

# Try different bridge URLs
test_urls = [
    "http://127.0.0.1:8000/bridge/agent/ai-vuln-director/invoke",
    "http://127.0.0.1:8000/bridge/agents/ai-vuln-director/invoke",
    "http://127.0.0.1:8000/bridge/invoke",
]

test_payload = {"goal": "Run cisa_kev_check and report total count", "context": {}}

for url in test_urls:
    try:
        print("\nTrying: POST %s" % url)
        r = client.post(
            url,
            headers={"Authorization": "Bearer %s" % api_token, "Content-Type": "application/json"},
            json=test_payload,
            timeout=120.0
        )
        print("Status: %d" % r.status_code)

        if r.status_code == 200:
            data = r.json()
            print("Success: %s" % data.get("success"))
            print("Kernel managed: %s" % data.get("kernel_managed"))
            print("PID: %s" % data.get("pid"))
            print("Iterations: %s" % data.get("iterations"))
            tool_calls = data.get("tool_calls", [])
            print("Tool calls: %d" % len(tool_calls))
            print("Duration: %sms" % data.get("duration_ms"))
            response_text = str(data.get("response", ""))
            print("Response: %s" % response_text[:200])

            if data.get("kernel_managed"):
                print("\n  [VERIFIED] KERNEL-MANAGED MEMORY AGENT WORKING!")

            # Check memory after
            try:
                r2 = client.get("http://127.0.0.1:8000/kernel/memory/global-stats")
                ma = r2.json()
                print("\nMemory after: %d windows, %d faults, %d swap" % (
                    ma.get("active_context_windows", 0),
                    ma.get("page_faults", 0),
                    ma.get("swap_segments", 0)
                ))
            except Exception:
                pass

            break
        elif r.status_code == 404:
            print("  404 - not found")
        else:
            print("  Response: %s" % r.text[:300])
    except Exception as e:
        print("  Error: %s" % e)

client.close()
print()
print("=" * 60)
print("Phase 5 fix v2 complete.")
print("=" * 60)
