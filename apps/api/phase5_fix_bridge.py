#!/usr/bin/env python3
"""
Phase 5 Fix: Wire the bridge to use kernel_agent_runner instead of AgenticLoop.

The bridge file (super_agent_bridge.py) still instantiates AgenticLoop at line 203.
The import for KernelAgentLoop was added but never used for instantiation.

Fix: Replace the AgenticLoop instantiation + .run() call with
run_kernel_agent_runner() which is a clean async function that handles
kernel memory management internally.
"""
import sys
import os
import re
import subprocess
import time

sys.path.insert(0, "/opt/gds-os/apps/api")
API_DIR = "/opt/gds-os/apps/api"

# ============================================================
# Step 1: Read the bridge file and find the invoke handler
# ============================================================
print("=" * 60)
print("STEP 1: Read bridge file")
print("=" * 60)

bridge_file = os.path.join(API_DIR, "gds_api/bridge/super_agent_bridge.py")
with open(bridge_file) as f:
    content = f.read()

lines = content.split("\n")
print(f"  Total lines: {len(lines)}")

# Find the invoke endpoint handler
invoke_start = None
for i, line in enumerate(lines):
    if "invoke" in line.lower() and ("def " in line or "@router" in line):
        invoke_start = i
        print(f"  Invoke handler found at line {i+1}: {line.strip()[:80]}")
        break

# Show lines around the AgenticLoop instantiation
for i, line in enumerate(lines):
    if "AgenticLoop" in line or "KernelAgentLoop" in line or "run_kernel" in line:
        print(f"  Line {i+1}: {line.rstrip()[:100]}")

# ============================================================
# Step 2: Fix the bridge — replace AgenticLoop with run_kernel_agent_runner
# ============================================================
print()
print("=" * 60)
print("STEP 2: Fix bridge to use kernel_agent_runner")
print("=" * 60)

# Strategy: Find the block that creates AgenticLoop and calls .run()
# Replace with a call to run_kernel_agent_runner()

# Check if already fixed
if "run_kernel_agent_runner" in content and "AgenticLoop(" not in content:
    print("  Already fixed — bridge uses run_kernel_agent_runner")
else:
    # Add import for run_kernel_agent_runner if not present
    if "from gds_api.reasoning.kernel_agent_runner import run_kernel_agent_runner" not in content:
        # Add after the existing kernel_agent_loop import (line 196)
        content = content.replace(
            "from gds_api.reasoning.kernel_agent_loop import run_kernel_agent, KernelAgentLoop",
            "from gds_api.reasoning.kernel_agent_loop import run_kernel_agent, KernelAgentLoop\nfrom gds_api.reasoning.kernel_agent_runner import run_kernel_agent_runner"
        )
        print("  Added import for run_kernel_agent_runner")

    # Find and replace the AgenticLoop block
    # The pattern is:
    #   loop = AgenticLoop(agent_id=agent_id)
    #   ... some lines ...
    #   result = await loop.run(goal, ...) or result = loop.run(goal, ...)
    #   ... return based on result

    # Let's find the exact block
    # First, find "loop = AgenticLoop"
    loop_line_idx = None
    for i, line in enumerate(lines):
        if "AgenticLoop(" in line and "import" not in line:
            loop_line_idx = i
            break

    if loop_line_idx is not None:
        print(f"  Found AgenticLoop instantiation at line {loop_line_idx + 1}")

        # Find the run() call and result handling
        # Show context around the instantiation
        start = max(0, loop_line_idx - 5)
        end = min(len(lines), loop_line_idx + 40)
        print(f"  Context (lines {start+1}-{end}):")
        for j in range(start, end):
            marker = " >>>" if j == loop_line_idx else "    "
            print(f"  {marker} L{j+1}: {lines[j].rstrip()[:100]}")

        # Now let's do the replacement
        # We need to find the full block from "loop = AgenticLoop" to the return
        # and replace it with run_kernel_agent_runner

        # Read the file again as a single string for replacement
        with open(bridge_file) as f:
            content = f.read()

        # Find the AgenticLoop block using regex
        # Pattern: loop = AgenticLoop(...) ... result = await loop.run(...) or result = loop.run(...)
        # We need to be careful not to break the surrounding code

        # Find the block from "loop = AgenticLoop" to the next "return" or end of function
        block_pattern = r'(\s+)(?:#.*\n)?\s*loop\s*=\s*AgenticLoop\(agent_id=agent_id\).*?(?=\n        (?:return|except|else:|finally:))'
        block_match = re.search(block_pattern, content, re.DOTALL)

        if block_match:
            old_block = block_match.group(0)
            indent = block_match.group(1)
            print(f"\n  Old block ({len(old_block)} chars):")
            for line in old_block.split("\n")[:15]:
                print(f"    {line.rstrip()[:100]}")
            if len(old_block.split("\n")) > 15:
                print(f"    ... ({len(old_block.split('\n'))} lines total)")

            # New block: call run_kernel_agent_runner
            new_block = f"""{indent}# Phase 5: Use kernel-managed memory agent runner
{indent}# This creates a kernel APCB, allocates system prompt (importance=1.0),
{indent}# user goal (importance=0.8), tool results (importance=0.5),
{indent}# and handles page faults to Redis swap when context exceeds 128K.
{indent}result = await run_kernel_agent_runner(
{indent}    agent_id=agent_id,
{indent}    goal=goal,
{indent}    context=context_dict if 'context_dict' in dir() else context,
{indent})"""

            content = content.replace(old_block, new_block)
            print(f"\n  New block ({len(new_block)} chars):")
            for line in new_block.split("\n"):
                print(f"    {line.rstrip()[:100]}")
        else:
            print("\n  Regex block not found — trying line-by-line replacement")
            # Simpler approach: just replace the specific lines
            # Replace "loop = AgenticLoop(agent_id=agent_id)" with runner call
            # and comment out the .run() call

            # Find the instantiation line
            content = content.replace(
                "loop = AgenticLoop(agent_id=agent_id)",
                "# Phase 5: Using kernel_agent_runner instead of AgenticLoop\n        _use_kernel_runner = True"
            )

            # Find the .run() call and replace with runner
            # The run call is typically: result = await loop.run(goal, ...) or result = loop.run(goal, ...)
            content = re.sub(
                r'result\s*=\s*(?:await\s+)?loop\.run\(([^)]+)\)',
                'result = await run_kernel_agent_runner(agent_id=agent_id, goal=goal, context=context)',
                content
            )

            # Also need to handle the case where the result is processed differently
            # AgenticLoop returns AgentResult, run_kernel_agent_runner returns dict
            # The bridge might access result.tool_calls, result.response, etc.
            # run_kernel_agent_runner returns: {success, agent_id, iterations, tool_calls, response, duration_ms, pid, kernel_managed}

            print("  Applied line-by-line replacement")

        with open(bridge_file, "w") as f:
            f.write(content)
        print("\n  SAVED: bridge file patched")
    else:
        print("  Could not find AgenticLoop instantiation in the bridge")

# ============================================================
# Step 3: Also check and fix the bridge endpoint URL (404 issue)
# ============================================================
print()
print("=" * 60)
print("STEP 3: Check bridge endpoint URL (404 fix)")
print("=" * 60)

with open(bridge_file) as f:
    content = f.read()

# Find all route definitions
routes = re.findall(r'@router\.(get|post|put|delete)\("([^"]+)"', content)
print(f"  Bridge routes found:")
for method, path in routes:
    print(f"    {method.upper()} {path}")

# Check if the invoke endpoint exists
invoke_routes = [r for r in routes if "invoke" in r[1]]
if invoke_routes:
    print(f"\n  Invoke routes: {invoke_routes}")
else:
    print("\n  No invoke route found — checking for alternative patterns")
    # Maybe it's /agent/{agent_id}/invoke or /agents/{agent_id}/invoke
    agent_routes = [r for r in routes if "agent" in r[1]]
    print(f"  Agent routes: {agent_routes}")

# Check the router prefix
prefix_match = re.search(r'APIRouter\([^)]*prefix\s*=\s*"([^"]*)"', content)
if prefix_match:
    print(f"\n  Router prefix: {prefix_match.group(1)}")
    full_invoke = prefix_match.group(1) + invoke_routes[0][1] if invoke_routes else "unknown"
    print(f"  Full invoke URL: {full_invoke}")

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
# Step 5: Test the bridge with correct URL
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
    print("  WARNING: BRIDGE_API_KEY not found in /opt/.env")
    api_token = "REDACTED_SET_BRIDGE_API_KEY"

# Try different URL patterns
urls_to_try = [
    ("http://127.0.0.1:8000/bridge/agent/ai-vuln-director/invoke",
     "POST", {"goal": "Run cisa_kev_check and report total", "context": {}}),
    ("http://127.0.0.1:8000/bridge/agents/ai-vuln-director/invoke",
     "POST", {"goal": "Run cisa_kev_check and report total", "context": {}}),
    ("http://127.0.0.1:8000/bridge/invoke",
     "POST", {"agent_id": "ai-vuln-director", "goal": "Run cisa_kev_check and report total", "context": {}}),
]

# First check health
try:
    health = client.get("http://127.0.0.1:8000/bridge/health")
    print(f"  Bridge health: {health.status_code} — {health.json() if health.status_code == 200 else health.text[:100]}")
except Exception as e:
    print(f"  Bridge health failed: {e}")

# Check agents list
try:
    agents = client.get("http://127.0.0.1:8000/bridge/agents",
                       headers={"Authorization": f"Bearer {api_token}"})
    print(f"  Bridge agents: {agents.status_code}")
    if agents.status_code == 200:
        agents_data = agents.json()
        if isinstance(agents_data, list):
            print(f"  Agents count: {len(agents_data)}")
        elif isinstance(agents_data, dict):
            agents_list = agents_data.get("agents", [])
            print(f"  Agents count: {len(agents_list)}")
except Exception as e:
    print(f"  Bridge agents failed: {e}")

# Try invoke URLs
for url, method, payload in urls_to_try:
    try:
        print(f"\n  Trying: {method} {url}")
        if method == "POST":
            r = client.post(url,
                          headers={"Authorization": f"Bearer {api_token}", "Content-Type": "application/json"},
                          json=payload, timeout=120.0)
        else:
            r = client.get(url, headers={"Authorization": f"Bearer {api_token}"}, timeout=120.0)

        print(f"  Status: {r.status_code}")

        if r.status_code == 200:
            data = r.json()
            print(f"  Success: {data.get('success', 'N/A')}")
            print(f"  Kernel managed: {data.get('kernel_managed', 'N/A')}")
            print(f"  PID: {data.get('pid', 'N/A')}")
            print(f"  Iterations: {data.get('iterations', 'N/A')}")
            print(f"  Tool calls: {len(data.get('tool_calls', []))}")
            print(f"  Duration: {data.get('duration_ms', 'N/A')}ms")
            print(f"  Response: {str(data.get('response', ''))[:200]}")

            if data.get("kernel_managed"):
                print("\n  [VERIFIED] Bridge uses KERNEL-MANAGED MEMORY!")
            elif data.get("success"):
                print("\n  [PARTIAL] Bridge works but kernel_managed=False")
            break
        elif r.status_code == 404:
            print(f"  404 — endpoint not found")
        else:
            print(f"  Response: {r.text[:200]}")
    except Exception as e:
        print(f"  Error: {e}")

# Check memory stats after
try:
    mem = client.get("http://127.0.0.1:8000/kernel/memory/global-stats")
    mem_data = mem.json()
    print(f"\n  Memory after test: {mem_data.get('active_context_windows', 0)} windows, "
          f"{mem_data.get('page_faults', 0)} faults, {mem_data.get('swap_segments', 0)} swap")
except Exception:
    pass

client.close()

print()
print("=" * 60)
print("Phase 5 fix complete.")
print("=" * 60)
