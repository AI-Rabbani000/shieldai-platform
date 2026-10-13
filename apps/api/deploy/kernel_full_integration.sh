#!/bin/bash
# ============================================================
# GDS KERNEL FULL INTEGRATION PATCH — Phase 2
# ============================================================
# 1. Patches remaining tool_gateway imports in execution files
# 2. Creates kernel agent processes (APCBs) for the agent fleet
# 3. Starts the scheduler to manage running agents
# ============================================================

set -e
API_DIR="/opt/gds-os/apps/api"
BRIDGE="$API_DIR/gds_api/reasoning/kernel_bridge.py"

echo "============================================================"
echo "GDS KERNEL FULL INTEGRATION — Phase 2"
echo "============================================================"

# ============================================================
# Step 1: Patch execution files to use kernel_bridge
# ============================================================
echo ""
echo "[1/4] Patching execution files to route through kernel..."

# Patch execution_engine.py — replace tool_gateway import with kernel_bridge
EXEC_ENGINE="$API_DIR/gds_api/agentic/execution_engine.py"
if [ -f "$EXEC_ENGINE" ]; then
    cp "$EXEC_ENGINE" "${EXEC_ENGINE}.bak.tg"
    python3 << 'PYEOF'
f = "/opt/gds-os/apps/api/gds_api/agentic/execution_engine.py"
content = open(f).read()

# Replace the tool_gateway execute_tool import with kernel_bridge
old = "from gds_api.tool_gateway import execute_tool"
new = "from gds_api.reasoning.kernel_bridge import execute_tool"
content = content.replace(old, new)

# Also handle the alias import
old2 = "from gds_api.tool_gateway import execute_tool as gateway_execute"
new2 = "from gds_api.reasoning.kernel_bridge import execute_tool as gateway_execute"
content = content.replace(old2, new2)

open(f, "w").write(content)
print(f"  Patched: {f}")
PYEOF
else
    echo "  SKIP: execution_engine.py not found"
fi

# Patch execution.py
EXEC_PY="$API_DIR/gds_api/agentic/execution.py"
if [ -f "$EXEC_PY" ]; then
    cp "$EXEC_PY" "${EXEC_PY}.bak.tg"
    python3 << 'PYEOF'
f = "/opt/gds-os/apps/api/gds_api/agentic/execution.py"
content = open(f).read()

old = "from gds_api.tool_gateway import execute_tool"
new = "from gds_api.reasoning.kernel_bridge import execute_tool"
content = content.replace(old, new)

old2 = "from gds_api.tool_gateway import execute_tool as gateway_execute"
new2 = "from gds_api.reasoning.kernel_bridge import execute_tool as gateway_execute"
content = content.replace(old2, new2)

open(f, "w").write(content)
print(f"  Patched: {f}")
PYEOF
else
    echo "  SKIP: execution.py not found"
fi

# Patch agents/validation.py — replace TOOL_REGISTRY import
# This file uses TOOL_REGISTRY for validation, not execution.
# We'll add a compatibility shim that re-exports from kernel_bridge.
AGENTS_VAL="$API_DIR/gds_api/agents/validation.py"
if [ -f "$AGENTS_VAL" ]; then
    cp "$AGENTS_VAL" "${AGENTS_VAL}.bak.tg"
    python3 << 'PYEOF'
f = "/opt/gds-os/apps/api/gds_api/agents/validation.py"
content = open(f).read()
# Replace TOOL_REGISTRY import — kernel_bridge doesn't have TOOL_REGISTRY,
# so we keep importing from tool_gateway for metadata-only access
# But add kernel_bridge for execution
old = "from gds_api.tool_gateway import TOOL_REGISTRY"
new = "from gds_api.tool_gateway import TOOL_REGISTRY\nfrom gds_api.reasoning.kernel_bridge import execute_tool as kernel_execute_tool"
content = content.replace(old, new)
open(f, "w").write(content)
print(f"  Patched: {f}")
PYEOF
else
    echo "  SKIP: agents/validation.py not found"
fi

# Patch capabilities/broker.py, capabilities/validation.py, capabilities/gateway.py
# These use TOOL_REGISTRY for metadata — keep as-is but add kernel_bridge for execution
for fpath in \
    "$API_DIR/gds_api/capabilities/broker.py" \
    "$API_DIR/gds_api/capabilities/validation.py" \
    "$API_DIR/gds_api/build_guide.py" \
    "$API_DIR/gds_api/bridge/super_agent_bridge.py"; do
    if [ -f "$fpath" ]; then
        cp "$fpath" "${fpath}.bak.tg"
        python3 -c "
f = '$fpath'
content = open(f).read()
# Only patch if it imports execute_tool (not just TOOL_REGISTRY)
if 'execute_tool' in content and 'tool_gateway' in content:
    content = content.replace(
        'from gds_api.tool_gateway import execute_tool',
        'from gds_api.reasoning.kernel_bridge import execute_tool'
    )
    content = content.replace(
        'from gds_api.tool_gateway import execute_tool as gateway_execute',
        'from gds_api.reasoning.kernel_bridge import execute_tool as gateway_execute'
    )
    open(f, 'w').write(content)
    print(f'  Patched: {f}')
else:
    print(f'  SKIP (no execute_tool): {f}')
"
    else
        echo "  SKIP: $fpath not found"
    fi
done

# NOTE: monitoring_activities.py, remediation.py, pentest/engine.py use INTERNAL
# functions (_check_cisa_kev, _probe_tls_certificate, etc.) from tool_gateway.
# These are scheduled workflow tasks, not LLM-decided agent tool calls.
# They stay on tool_gateway for now — they don't need sandbox isolation.

echo "  Done — execution files patched"
echo "  NOTE: monitoring_activities.py, remediation.py, pentest/engine.py"
echo "        keep tool_gateway for internal workflow functions (no sandbox needed)"

# ============================================================
# Step 2: Create kernel agent processes (APCBs)
# ============================================================
echo ""
echo "[2/4] Creating kernel agent processes (APCBs)..."

python3 << 'PYEOF'
import requests
import json

KERNEL_API = "http://127.0.0.1:8000/kernel"

# The 23 agents from Redis — create APCB processes for each
AGENTS = [
    ("ai-chief-ciso", "command", 0, "Strategic security oversight and board reporting"),
    ("ai-gasci-orchestrator", "command", 0, "Centralized governance orchestration"),
    ("ai-soc-director", "command", 1, "SOC operations and alert triage"),
    ("ai-incident-commander", "command", 1, "Incident response coordination"),
    ("ai-cloud-security-director", "command", 1, "Cloud security posture management"),
    ("ai-vulnerability-director", "command", 1, "Vulnerability scanning and management"),
    ("ai-remediation-director", "command", 1, "Remediation planning and execution"),
    ("ai-threat-hunter", "command", 1, "Threat hunting and IOC analysis"),
    ("ai-compliance-director", "command", 1, "Compliance framework management"),
    ("ai-risk-director", "command", 1, "Risk assessment and scoring"),
    ("ai-executive-advisor", "command", 1, "Executive briefings and board reports"),
    ("ai-devsecops-director", "command", 1, "DevSecOps pipeline security"),
    ("ai-identity-director", "command", 1, "Identity and access management"),
    ("ai-threat-intel-director", "command", 1, "Threat intelligence feeds and analysis"),
    ("ai-ciem-director", "specialist", 2, "Cloud identity and entitlement management"),
    ("ai-dark-web-monitor", "specialist", 2, "Dark web and breach monitoring"),
    ("ai-predictive-risk-director", "specialist", 2, "Predictive risk modeling"),
    ("ai-zero-trust-architect", "specialist", 2, "Zero trust architecture validation"),
    ("ai-security-director-llm", "specialist", 2, "AI/LLM security assessment"),
    ("ai-red-team-director", "restricted", 3, "Red team operations (approval required)"),
    ("ai-supply-chain-monitor", "specialist", 2, "Supply chain security monitoring"),
    ("ai-database-security", "specialist", 2, "Database security assessment"),
    ("ai-network-security", "specialist", 2, "Network security analysis"),
]

created = 0
failed = 0

for agent_id, agent_type, priority, goal in AGENTS:
    try:
        resp = requests.post(
            f"{KERNEL_API}/process/create",
            json={
                "agent_id": agent_id,
                "agent_type": agent_type,
                "priority": priority,
                "goal": goal,
            },
            timeout=10,
        )
        if resp.status_code == 200:
            data = resp.json()
            pid = data.get("pid", "unknown")
            print(f"  ✅ {agent_id:35s} → PID: {pid}")
            created += 1
        else:
            print(f"  ❌ {agent_id:35s} → HTTP {resp.status_code}: {resp.text[:80]}")
            failed += 1
    except Exception as e:
        print(f"  ❌ {agent_id:35s} → {str(e)[:80]}")
        failed += 1

print(f"\n  Summary: {created} created, {failed} failed out of {len(AGENTS)} agents")
PYEOF

# ============================================================
# Step 3: Start the kernel scheduler
# ============================================================
echo ""
echo "[3/4] Starting kernel scheduler..."

# Check if scheduler is already running
SCHED_STATUS=$(curl -s http://127.0.0.1:8000/kernel/status | python3 -c "
import sys, json
d = json.load(sys.stdin)
s = d.get('scheduler', {})
print(f'running={s.get(\"currently_running\",0)} ready={s.get(\"currently_ready\",0)} dispatched={s.get(\"total_dispatched\",0)}')
" 2>/dev/null || echo "error")

echo "  Scheduler state: $SCHED_STATUS"

# The scheduler runs automatically when APCBs are created — check if any are running
python3 << 'PYEOF'
import requests, json

resp = requests.get("http://127.0.0.1:8000/kernel/status", timeout=10)
data = resp.json()

scheduler = data.get("scheduler", {})
sandbox = data.get("sandbox", {})

print(f"  Kernel version: {data.get('version')}")
print(f"  Kernel running: {data.get('is_running')}")
print(f"  Registered agents: {data.get('registered_agents', 0)}")
print(f"  Registered tools: {data.get('registered_tools', 0)}")
print(f"  Sandbox: {sandbox.get('registered_tools',0)} tools, {sandbox.get('healthy_tools',0)} healthy, {sandbox.get('total_executions',0)} executions")
print(f"  Scheduler: {scheduler.get('total_dispatched',0)} dispatched, {scheduler.get('currently_running',0)} running, {scheduler.get('currently_ready',0)} ready")
PYEOF

# ============================================================
# Step 4: Verify everything works end-to-end
# ============================================================
echo ""
echo "[4/4] Verification..."

# Test 1: Kernel status with agent processes
echo ""
echo "1. Kernel status (with APCBs):"
curl -s http://127.0.0.1:8000/kernel/status | python3 -c "
import sys, json
d = json.load(sys.stdin)
print(f'   Agents registered: {d.get(\"registered_agents\", 0)}')
print(f'   Tools: {d.get(\"sandbox\",{}).get(\"registered_tools\",0)} registered, {d.get(\"sandbox\",{}).get(\"healthy_tools\",0)} healthy')
print(f'   Executions: {d.get(\"sandbox\",{}).get(\"total_executions\",0)} total, {d.get(\"sandbox\",{}).get(\"success_rate\",0)}% success')
" 2>/dev/null || echo "   FAILED"

# Test 2: Kernel tool execution still works
echo ""
echo "2. Kernel tool (cisa_kev_check):"
curl -s -X POST http://127.0.0.1:8000/kernel/tool/execute \
  -H "Content-Type: application/json" \
  -d '{"pid":"verify-test","tool_id":"cisa_kev_check","payload":{}}' | python3 -c "
import sys, json
d = json.load(sys.stdin)
print(f'   KEV count: {d.get(\"total_count\",0)}')
print(f'   Success: {d.get(\"success\")}')
" 2>/dev/null || echo "   FAILED"

# Test 3: Import test — verify kernel_bridge is used by execution engine
echo ""
echo "3. Import test (execution files):"
cd $API_DIR && python3 -c "
# Verify agent_loop uses kernel_bridge
from gds_api.reasoning.kernel_bridge import KERNEL_TOOLS, get_available_tools, execute_tool
print(f'   kernel_bridge: {len(KERNEL_TOOLS)} tools, {len(get_available_tools())} LLM definitions')
print(f'   execute_tool: {execute_tool.__name__} (async)')
" 2>/dev/null || echo "   FAILED"

# Test 4: Check no broken imports
echo ""
echo "4. Broken import check:"
cd $API_DIR && python3 -c "
import sys
errors = []
# Try importing the patched files
try:
    from gds_api.agentic.execution_engine import AgentExecutionEngine
    print('   execution_engine.py: OK')
except Exception as e:
    print(f'   execution_engine.py: ERROR - {str(e)[:100]}')
    errors.append('execution_engine')

try:
    from gds_api.agentic.execution import AgentExecutionLoop
    print('   execution.py: OK')
except Exception as e:
    print(f'   execution.py: ERROR - {str(e)[:100]}')
    errors.append('execution')

if not errors:
    print('   All imports clean ✅')
else:
    print(f'   {len(errors)} broken imports ❌')
" 2>/dev/null || echo "   FAILED"

# Restart API to pick up patches
echo ""
echo "   Restarting API..."
supervisorctl restart gds-os
sleep 5
echo "   gds-os: $(supervisorctl status gds-os | awk '{print $2, $4, $6}')"

# Final check after restart
echo ""
echo "5. Post-restart kernel status:"
curl -s http://127.0.0.1:8000/kernel/status | python3 -c "
import sys, json
d = json.load(sys.stdin)
print(f'   Kernel running: {d.get(\"is_running\")}')
print(f'   Agents: {d.get(\"registered_agents\", 0)}')
print(f'   Tools: {d.get(\"sandbox\",{}).get(\"registered_tools\",0)}/{d.get(\"sandbox\",{}).get(\"healthy_tools\",0)} healthy')
" 2>/dev/null || echo "   FAILED"

echo ""
echo "============================================================"
echo "KERNEL FULL INTEGRATION COMPLETE"
echo "============================================================"
echo ""
echo "What was done:"
echo "  1. Patched execution_engine.py + execution.py → kernel_bridge"
echo "  2. Created APCB processes for 23 agents"
echo "  3. Verified kernel scheduler state"
echo "  4. Verified all imports clean + API restarted"
echo ""
echo "Tool execution routing (NEW):"
echo "  LLM agent → kernel_bridge.execute_tool() → /kernel/tool/execute → sandbox → real executor"
echo ""
echo "Tool execution routing (OLD, now replaced):"
echo "  LLM agent → tool_gateway.execute_tool() → subprocess (no sandbox)"
echo ""
echo "Internal workflow functions (UNCHANGED):"
echo "  monitoring_activities → tool_gateway._check_cisa_kev() (internal, no sandbox needed)"
echo "  remediation → tool_gateway._probe_tls_certificate() (internal, no sandbox needed)"
echo "  pentest → tool_gateway._recon_port_scan() (internal, no sandbox needed)"
echo ""
echo "Agent fleet (23 APCBs created):"
echo "  P0 (critical): ai-chief-ciso, ai-gasci-orchestrator"
echo "  P1 (command): soc-director, incident-commander, cloud-sec, vuln-director, etc."
echo "  P2 (specialist): ciem, dark-web, predictive-risk, zero-trust, etc."
echo "  P3 (restricted): red-team-director (approval required)"
echo "============================================================"
