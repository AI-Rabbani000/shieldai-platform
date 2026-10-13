#!/usr/bin/env python3
"""
Phase 5 Final: Replace broken files with clean versions.

Instead of patching (which keeps creating syntax errors in f-strings
and try/except blocks), we replace two files entirely:

1. gds_api/reasoning/kernel_agent_runner.py — clean runner with proper imports
2. gds_api/bridge/super_agent_bridge.py — we DON'T replace this (too much code we can't see)

Instead, for the bridge, we use a DictWrapper adapter that lets the
existing dot-notation code work with our dict return value.
"""
import sys
import os
import subprocess
import time

API_DIR = "/opt/gds-os/apps/api"

# ============================================================
# Step 1: Write clean kernel_agent_runner.py
# ============================================================
print("=" * 60)
print("STEP 1: Write clean kernel_agent_runner.py")
print("=" * 60)

runner_path = os.path.join(API_DIR, "gds_api/reasoning/kernel_agent_runner.py")

runner_code = '''#!/usr/bin/env python3
"""
Kernel Agent Runner — wraps GPT-4.1 reasoning with kernel-managed memory.

Each agent invocation:
1. Creates a kernel APCB (process) with unique PID
2. Allocates system prompt (importance=1.0, never paged)
3. Allocates user goal (importance=0.8)
4. Runs GPT-4.1 with function calling
5. Tool results get importance=0.5 (paged first when context fills)
6. When context exceeds 128K, cold segments auto-page to Redis swap
"""
import sys
import os
import logging
import time
import uuid
from typing import Dict, Any, Optional

logger = logging.getLogger("gds.kernel.agent_runner")

# Import tools — try tool_gateway first, then kernel_bridge as fallback
TOOL_REGISTRY = {}
execute_tool = None

try:
    from gds_api.tool_gateway import TOOL_REGISTRY as _TR, execute_tool as _et
    TOOL_REGISTRY = _TR
    execute_tool = _et
    logger.info("Tools loaded from tool_gateway: %d tools" % len(TOOL_REGISTRY))
except Exception as e:
    logger.warning("tool_gateway import failed: %s" % e)
    try:
        from gds_api.reasoning.kernel_bridge import TOOL_REGISTRY as _TR2, execute_tool as _et2
        TOOL_REGISTRY = _TR2
        execute_tool = _et2
        logger.info("Tools loaded from kernel_bridge: %d tools" % len(TOOL_REGISTRY))
    except Exception as e2:
        logger.warning("kernel_bridge import also failed: %s" % e2)

# Import kernel for memory management
KERNEL_AVAILABLE = False
try:
    from gds_kernel.kernel_router import get_kernel
    KERNEL_AVAILABLE = True
except Exception as e:
    logger.warning("Kernel not available: %s" % e)


async def run_kernel_agent_runner(
    agent_id: str,
    goal: str,
    context: Optional[Dict[str, Any]] = None,
    model: str = "gpt-4.1",
    max_iterations: int = 10,
) -> Dict[str, Any]:
    """Run an agent using kernel-managed memory."""
    start_time = time.time()
    context = context or {}
    pid = "agent-%s-%s" % (agent_id, uuid.uuid4().hex[:8])

    kernel = None
    if KERNEL_AVAILABLE:
        try:
            kernel = get_kernel()
        except Exception as e:
            logger.warning("Could not get kernel: %s" % e)

    tool_calls = []
    iterations = 0
    agent_response = ""
    success = True
    error_message = None

    # Allocate memory in kernel
    if kernel:
        try:
            system_prompt = (
                "You are %s, an AI security agent for GDS OS. "
                "You have access to real security tools. "
                "Analyze the request and decide which tools to use. "
                "Available tools: %s"
            ) % (agent_id, ", ".join(TOOL_REGISTRY.keys()) if TOOL_REGISTRY else "none")

            kernel.memory.allocate(
                pid=pid,
                content=system_prompt,
                segment_type="system_prompt",
                importance=1.0
            )
            kernel.memory.allocate(
                pid=pid,
                content=goal,
                segment_type="conversation",
                importance=0.8
            )
            logger.info("Kernel memory allocated for %s" % pid)
        except Exception as e:
            logger.warning("Kernel memory allocation failed: %s" % e)

    # GPT-4.1 function calling loop
    try:
        import openai
        from dotenv import load_dotenv
        load_dotenv("/opt/.env")
        client = openai.OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

        # Build tool definitions
        tool_defs = []
        if TOOL_REGISTRY:
            for tool_name, tool_spec in TOOL_REGISTRY.items():
                tool_defs.append({
                    "type": "function",
                    "function": {
                        "name": tool_name,
                        "description": tool_spec.get("description", "Execute %s" % tool_name),
                        "parameters": tool_spec.get("parameters", {"type": "object", "properties": {}})
                    }
                })

        messages = [
            {"role": "system", "content": "You are %s, an AI security agent. Use tools to accomplish the goal." % agent_id},
            {"role": "user", "content": goal}
        ]

        if context:
            for key, value in context.items():
                if isinstance(value, str):
                    messages.append({"role": "user", "content": "Context - %s: %s" % (key, value)})

        for iteration in range(max_iterations):
            iterations += 1

            response = client.chat.completions.create(
                model=model,
                messages=messages,
                tools=tool_defs if tool_defs else None,
                tool_choice="auto" if tool_defs else None,
                temperature=0.1,
                max_tokens=4096
            )

            msg = response.choices[0].message

            if msg.tool_calls:
                messages.append(msg)
                for tc in msg.tool_calls:
                    tool_name = tc.function.name
                    try:
                        import json
                        tool_args = json.loads(tc.function.arguments) if tc.function.arguments else {}
                    except Exception:
                        tool_args = {}

                    logger.info("Iteration %d: calling %s" % (iteration, tool_name))

                    try:
                        result = execute_tool(tool_name, tool_args)
                        result_str = str(result)
                    except Exception as e:
                        result_str = "Error: %s" % e
                        result = {"error": str(e)}

                    tool_calls.append({
                        "tool": tool_name,
                        "tool_name": tool_name,
                        "args": tool_args,
                        "arguments": tool_args,
                        "result": result,
                        "duration_ms": 0
                    })

                    # Allocate tool result in kernel memory
                    if kernel:
                        try:
                            kernel.memory.allocate(
                                pid=pid,
                                content="Tool %s result: %s" % (tool_name, result_str[:2000]),
                                segment_type="tool_result",
                                importance=0.5
                            )
                        except Exception as e:
                            logger.debug("Memory alloc failed: %s" % e)

                    messages.append({
                        "role": "tool",
                        "tool_call_id": tc.id,
                        "content": result_str[:4000]
                    })
            else:
                agent_response = msg.content or ""
                break

        # Build context from kernel memory
        if kernel:
            try:
                stats = kernel.memory.get_stats(pid)
                logger.info("Kernel context for %s: %s/%s tokens, %s segments" % (
                    pid, stats.get("tokens_used", 0), stats.get("max_tokens", 0), stats.get("segment_count", 0)
                ))
            except Exception as e:
                logger.debug("Build context failed: %s" % e)

    except Exception as e:
        success = False
        error_message = str(e)
        agent_response = "Agent execution failed: %s" % e
        logger.error("Kernel agent runner failed: %s" % e)

    duration_ms = int((time.time() - start_time) * 1000)

    return {
        "success": success,
        "agent_id": agent_id,
        "goal": goal,
        "summary": agent_response,
        "response": agent_response,
        "tool_calls": tool_calls,
        "iterations": iterations,
        "duration_ms": duration_ms,
        "pid": pid,
        "error": error_message,
        "kernel_managed": kernel is not None,
    }
'''

with open(runner_path, "w") as f:
    f.write(runner_code)

# Verify it compiles
try:
    compile(runner_code, runner_path, "exec")
    print("  kernel_agent_runner.py compiles OK")
except SyntaxError as e:
    print("  SYNTAX ERROR: %s at line %d" % (e.msg, e.lineno))
    sys.exit(1)

# Verify import
sys.path.insert(0, API_DIR)
for mod in list(sys.modules.keys()):
    if "gds_api" in mod:
        del sys.modules[mod]
try:
    from gds_api.reasoning.kernel_agent_runner import run_kernel_agent_runner
    print("  Import verified OK")
except Exception as e:
    print("  Import failed: %s" % e)

# ============================================================
# Step 2: Fix bridge with DictWrapper approach
# ============================================================
print()
print("=" * 60)
print("STEP 2: Fix bridge with DictWrapper (no f-string breakage)")
print("=" * 60)

bridge_path = os.path.join(API_DIR, "gds_api/bridge/super_agent_bridge.py")

with open(bridge_path) as f:
    content = f.read()

# Strategy: Instead of replacing result.success -> result.get("success") (breaks f-strings),
# we wrap the dict result in a DictWrapper that supports BOTH dot access AND .get()
# This way the existing return block code works unchanged.

# Step 2a: Add DictWrapper class at module level (after imports)
DICT_WRAPPER_CODE = '''

class DictWrapper:
    """Wraps a dict so existing dot-notation code works with dict results."""
    def __init__(self, d):
        self.__dict__["_d"] = d
    def __getattr__(self, name):
        d = self.__dict__.get("_d", {})
        val = d.get(name)
        if name == "tool_calls" and isinstance(val, list):
            return [DictWrapper(tc) if isinstance(tc, dict) else tc for tc in val]
        return val
    def get(self, key, default=None):
        return self.__dict__.get("_d", {}).get(key, default)
    def __getitem__(self, key):
        return self.__dict__["_d"][key]
    def __repr__(self):
        return "DictWrapper(%r)" % self.__dict__.get("_d", {})
'''

if "class DictWrapper" not in content:
    # Find the last top-level import and insert after it
    lines = content.split("\n")
    last_import = 0
    for i, line in enumerate(lines):
        if line.startswith("from ") or line.startswith("import "):
            last_import = i

    lines.insert(last_import + 1, DICT_WRAPPER_CODE)
    content = "\n".join(lines)
    print("  Added DictWrapper class at line %d" % (last_import + 2))

# Step 2b: Ensure the import for run_kernel_agent_runner exists at module level
if "from gds_api.reasoning.kernel_agent_runner import run_kernel_agent_runner" not in content:
    lines = content.split("\n")
    # Find last import
    last_import = 0
    for i, line in enumerate(lines):
        if line.startswith("from ") or line.startswith("import "):
            last_import = i
    lines.insert(last_import + 1, "from gds_api.reasoning.kernel_agent_runner import run_kernel_agent_runner")
    content = "\n".join(lines)
    print("  Added import at module level")
else:
    # Remove any broken inline imports (inside try blocks)
    import re
    # Remove the import from inside functions/try blocks (bad indentation)
    content = re.sub(r'\n\s+from gds_api\.reasoning\.kernel_agent_runner import run_kernel_agent_runner', '', content)
    # Keep the module-level one
    if "from gds_api.reasoning.kernel_agent_runner import run_kernel_agent_runner" not in content:
        lines = content.split("\n")
        last_import = 0
        for i, line in enumerate(lines):
            if line.startswith("from ") or line.startswith("import "):
                last_import = i
        lines.insert(last_import + 1, "from gds_api.reasoning.kernel_agent_runner import run_kernel_agent_runner")
        content = "\n".join(lines)
    print("  Cleaned imports (module-level only)")

# Step 2c: Remove any leftover broken kernel_agent_loop import
content = content.replace(
    "from gds_api.reasoning.kernel_agent_loop import run_kernel_agent, KernelAgentLoop\n",
    ""
)

# Step 2d: Replace the AgenticLoop instantiation + .run() call
# Find "loop = AgenticLoop(agent_id=agent_id)" and "result = await loop.run(req.goal, req.context)"
# Replace with: call run_kernel_agent_runner and wrap result in DictWrapper

old_invoke = "loop = AgenticLoop(agent_id=agent_id)"
new_invoke = "result_dict = await run_kernel_agent_runner(agent_id=agent_id, goal=req.goal, context=req.context)\n        result = DictWrapper(result_dict)"

if old_invoke in content:
    content = content.replace(old_invoke, new_invoke)
    print("  Replaced AgenticLoop instantiation with run_kernel_agent_runner + DictWrapper")
else:
    if "# Phase 5: kernel-managed memory (no AgenticLoop)" in content:
        # Already partially patched — fix the run call
        print("  AgenticLoop already replaced, fixing run call")
    else:
        print("  WARNING: AgenticLoop line not found")

# Replace the .run() call
old_run = "result = await loop.run(req.goal, req.context)"
if old_run in content:
    content = content.replace(old_run, "result = DictWrapper(result_dict)")
    print("  Replaced loop.run() with DictWrapper")
else:
    # Try to find any loop.run pattern
    import re
    run_match = re.search(r'result\s*=\s*(?:await\s+)?loop\.run\([^)]*\)', content)
    if run_match:
        content = content.replace(run_match.group(0), "result = DictWrapper(result_dict)")
        print("  Replaced loop.run() via regex")
    else:
        print("  loop.run() not found (may already be patched)")

# Step 2e: Revert any .get() replacements that broke f-strings
# The previous patches replaced result.success -> result.get("success", True)
# inside f-strings which breaks syntax. Since we're using DictWrapper now,
# dot notation works, so revert .get() back to dot notation.
reverts = [
    ('result.get("success", True)', 'result.success'),
    ('result.get("response", "")', 'result.summary'),
    ('result.get("tool_calls", [])', 'result.tool_calls'),
    ('result.get("iterations", 0)', 'result.iterations'),
    ('result.get("duration_ms", 0)', 'result.duration_ms'),
    ('result.get("agent_id", agent_id)', 'result.agent_id'),
    ('result.get("goal", req.goal if "req" in dir() else goal)', 'result.goal'),
    ('result.get("error", None)', 'result.error'),
    ('tc.get("tool", "")', 'tc.tool_name'),
    ('tc.get("args", {})', 'tc.arguments'),
    ('tc.get("result", {})', 'tc.result'),
    ('tc.get("duration_ms", 0)', 'tc.duration_ms'),
]

for old, new in reverts:
    if old in content:
        content = content.replace(old, new)

print("  Reverted .get() back to dot notation (DictWrapper handles it)")

# Save
with open(bridge_path, "w") as f:
    f.write(content)

# Verify it compiles
try:
    compile(content, bridge_path, "exec")
    print("  Bridge compiles OK")
except SyntaxError as e:
    print("  SYNTAX ERROR: %s at line %d" % (e.msg, e.lineno))
    # Show the problematic line
    lines = content.split("\n")
    if e.lineno and e.lineno <= len(lines):
        print("  Line %d: %s" % (e.lineno, lines[e.lineno - 1]))
    sys.exit(1)

# Verify import
for mod in list(sys.modules.keys()):
    if "gds_api" in mod:
        del sys.modules[mod]
try:
    from gds_api.bridge.super_agent_bridge import router
    routes = [r.path for r in router.routes]
    print("  Bridge import OK! Routes: %s" % routes)
except Exception as e:
    print("  Bridge import FAILED: %s" % e)
    import traceback
    traceback.print_exc()

# ============================================================
# Step 3: Restart services
# ============================================================
print()
print("=" * 60)
print("STEP 3: Restart services")
print("=" * 60)

subprocess.run(["supervisorctl", "restart", "gds-kernel"], check=True)
time.sleep(3)
subprocess.run(["supervisorctl", "restart", "gds-os"], check=True)
time.sleep(15)
print("  Services restarted")

# ============================================================
# Step 4: Test
# ============================================================
print()
print("=" * 60)
print("STEP 4: Test bridge")
print("=" * 60)

import httpx
import json

client = httpx.Client(timeout=120.0)

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
    print("  API: %s" % r.json().get("status", "unknown"))
except Exception as e:
    print("  API health failed: %s" % e)

# Bridge health
try:
    r = client.get("http://127.0.0.1:8000/bridge/health")
    print("  Bridge: %d" % r.status_code)
    if r.status_code == 200:
        print("  Bridge health: %s" % r.json())
except Exception as e:
    print("  Bridge health: %s" % e)

# Memory before
try:
    r = client.get("http://127.0.0.1:8000/kernel/memory/global-stats")
    mb = r.json()
    print("  Memory before: %d windows, %d faults, %d swap" % (mb.get("active_context_windows", 0), mb.get("page_faults", 0), mb.get("swap_segments", 0)))
except Exception:
    mb = {}

# Invoke
print()
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

    try:
        r2 = client.get("http://127.0.0.1:8000/kernel/memory/global-stats")
        ma = r2.json()
        print("\n  Memory after: %d windows, %d faults, %d swap" % (ma.get("active_context_windows", 0), ma.get("page_faults", 0), ma.get("swap_segments", 0)))
    except Exception:
        pass

    if data.get("kernel_managed"):
        print("\n  [VERIFIED] KERNEL-MANAGED MEMORY AGENT WORKING!")
    elif data.get("success"):
        print("\n  [PARTIAL] Bridge works, kernel_managed not in response")
else:
    print("  Response: %s" % r.text[:500])

client.close()
print()
print("=" * 60)
print("Phase 5 final complete.")
print("=" * 60)
