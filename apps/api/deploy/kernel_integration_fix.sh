#!/bin/bash
# ============================================================
# GDS KERNEL INTEGRATION FIX — Fixes APCB creation + broken import
# ============================================================

set -e
API_DIR="/opt/gds-os/apps/api"

echo "============================================================"
echo "GDS KERNEL INTEGRATION FIX"
echo "============================================================"

# ============================================================
# Fix 1: Restore execution_engine.py with try/except fallback
# ============================================================
echo ""
echo "[1/3] Fixing execution_engine.py import..."

EXEC_ENGINE="$API_DIR/gds_api/agentic/execution_engine.py"

# Check if the backup exists
if [ -f "${EXEC_ENGINE}.bak.tg" ]; then
    # Restore from backup first, then apply a safer patch
    cp "${EXEC_ENGINE}.bak.tg" "$EXEC_ENGINE"
    echo "  Restored from backup"
fi

# Apply a safer patch — try kernel_bridge first, fall back to tool_gateway
python3 << 'PYEOF'
f = "/opt/gds-os/apps/api/gds_api/agentic/execution_engine.py"
content = open(f).read()

# Check what imports exist
if "from gds_api.tool_gateway import execute_tool" in content:
    # Replace with try/except fallback
    old = "from gds_api.tool_gateway import execute_tool"
    new = """try:
    from gds_api.reasoning.kernel_bridge import execute_tool as execute_tool
except ImportError:
    from gds_api.tool_gateway import execute_tool"""
    content = content.replace(old, new)
    open(f, "w").write(content)
    print(f"  Patched with try/except fallback: {f}")
elif "from gds_api.reasoning.kernel_bridge import execute_tool" in content:
    # Already patched but failed — add fallback
    old = "from gds_api.reasoning.kernel_bridge import execute_tool"
    new = """try:
    from gds_api.reasoning.kernel_bridge import execute_tool as execute_tool
except ImportError:
    from gds_api.tool_gateway import execute_tool"""
    content = content.replace(old, new)
    open(f, "w").write(content)
    print(f"  Added fallback to existing patch: {f}")
else:
    print(f"  No execute_tool import found — skipping")

# Also fix the alias import if present
if "from gds_api.tool_gateway import execute_tool as gateway_execute" in content:
    old = "from gds_api.tool_gateway import execute_tool as gateway_execute"
    new = """try:
    from gds_api.reasoning.kernel_bridge import execute_tool as gateway_execute
except ImportError:
    from gds_api.tool_gateway import execute_tool as gateway_execute"""
    content = content.replace(old, new)
    open(f, "w").write(content)
    print(f"  Also patched alias import")
elif "from gds_api.reasoning.kernel_bridge import execute_tool as gateway_execute" in content:
    old = "from gds_api.reasoning.kernel_bridge import execute_tool as gateway_execute"
    new = """try:
    from gds_api.reasoning.kernel_bridge import execute_tool as gateway_execute
except ImportError:
    from gds_api.tool_gateway import execute_tool as gateway_execute"""
    content = content.replace(old, new)
    open(f, "w").write(content)
    print(f"  Added fallback to alias import")
PYEOF

# Same fix for execution.py
EXEC_PY="$API_DIR/gds_api/agentic/execution.py"
if [ -f "${EXEC_PY}.bak.tg" ]; then
    cp "${EXEC_PY}.bak.tg" "$EXEC_PY"
    echo "  Restored execution.py from backup"
fi

python3 << 'PYEOF'
f = "/opt/gds-os/apps/api/gds_api/agentic/execution.py"
content = open(f).read()

if "from gds_api.tool_gateway import execute_tool" in content:
    old = "from gds_api.tool_gateway import execute_tool"
    new = """try:
    from gds_api.reasoning.kernel_bridge import execute_tool as execute_tool
except ImportError:
    from gds_api.tool_gateway import execute_tool"""
    content = content.replace(old, new)
    open(f, "w").write(content)
    print(f"  Patched execution.py with fallback")

if "from gds_api.tool_gateway import execute_tool as gateway_execute" in content:
    old = "from gds_api.tool_gateway import execute_tool as gateway_execute"
    new = """try:
    from gds_api.reasoning.kernel_bridge import execute_tool as gateway_execute
except ImportError:
    from gds_api.tool_gateway import execute_tool as gateway_execute"""
    content = content.replace(old, new)
    open(f, "w").write(content)
    print(f"  Also patched execution.py alias import")
PYEOF

# Verify imports work
echo ""
echo "  Verifying imports..."
cd $API_DIR && python3 -c "
try:
    from gds_api.agentic.execution_engine import AgentExecutionEngine
    print('   execution_engine.py: OK ✅')
except Exception as e:
    print(f'   execution_engine.py: ERROR - {str(e)[:120]}')

try:
    from gds_api.agentic.execution import AgentExecutionLoop
    print('   execution.py: OK ✅')
except Exception as e:
    print(f'   execution.py: ERROR - {str(e)[:120]}')
" 2>/dev/null || echo "   Import check failed"

# ============================================================
# Fix 2: Create APCBs with correct task_name field
# ============================================================
echo ""
echo "[2/3] Creating kernel agent processes (APCBs) with task_name..."

python3 << 'PYEOF'
import requests
import json

KERNEL_API = "http://127.0.0.1:8000/kernel"

# The 23 agents — now with task_name field
AGENTS = [
    ("ai-chief-ciso", "strategic_oversight", 0, "Strategic security oversight and board reporting"),
    ("ai-gasci-orchestrator", "governance_orchestration", 0, "Centralized governance orchestration"),
    ("ai-soc-director", "soc_operations", 1, "SOC operations and alert triage"),
    ("ai-incident-commander", "incident_response", 1, "Incident response coordination"),
    ("ai-cloud-security-director", "cloud_security", 1, "Cloud security posture management"),
    ("ai-vulnerability-director", "vulnerability_management", 1, "Vulnerability scanning and management"),
    ("ai-remediation-director", "remediation_planning", 1, "Remediation planning and execution"),
    ("ai-threat-hunter", "threat_hunting", 1, "Threat hunting and IOC analysis"),
    ("ai-compliance-director", "compliance_management", 1, "Compliance framework management"),
    ("ai-risk-director", "risk_assessment", 1, "Risk assessment and scoring"),
    ("ai-executive-advisor", "executive_briefing", 1, "Executive briefings and board reports"),
    ("ai-devsecops-director", "devsecops_pipeline", 1, "DevSecOps pipeline security"),
    ("ai-identity-director", "identity_management", 1, "Identity and access management"),
    ("ai-threat-intel-director", "threat_intelligence", 1, "Threat intelligence feeds and analysis"),
    ("ai-ciem-director", "ciem_analysis", 2, "Cloud identity and entitlement management"),
    ("ai-dark-web-monitor", "dark_web_monitoring", 2, "Dark web and breach monitoring"),
    ("ai-predictive-risk-director", "predictive_risk", 2, "Predictive risk modeling"),
    ("ai-zero-trust-architect", "zero_trust_validation", 2, "Zero trust architecture validation"),
    ("ai-security-director-llm", "ai_llm_security", 2, "AI/LLM security assessment"),
    ("ai-red-team-director", "red_team_operations", 3, "Red team operations (approval required)"),
    ("ai-supply-chain-monitor", "supply_chain_monitoring", 2, "Supply chain security monitoring"),
    ("ai-database-security", "database_security", 2, "Database security assessment"),
    ("ai-network-security", "network_security", 2, "Network security analysis"),
]

created = 0
failed = 0

for agent_id, task_name, priority, goal in AGENTS:
    try:
        resp = requests.post(
            f"{KERNEL_API}/process/create",
            json={
                "agent_id": agent_id,
                "task_name": task_name,
                "goal": goal,
                "priority": priority,
                "depends_on": [],
            },
            timeout=10,
        )
        if resp.status_code == 200:
            data = resp.json()
            pid = data.get("pid", "unknown")
            state = data.get("state", "unknown")
            print(f"  ✅ {agent_id:35s} → PID: {pid}, State: {state}")
            created += 1
        else:
            err = resp.text[:100]
            print(f"  ❌ {agent_id:35s} → HTTP {resp.status_code}: {err}")
            failed += 1
    except Exception as e:
        print(f"  ❌ {agent_id:35s} → {str(e)[:80]}")
        failed += 1

print(f"\n  Summary: {created} created, {failed} failed out of {len(AGENTS)} agents")
PYEOF

# ============================================================
# Fix 3: Restart and verify
# ============================================================
echo ""
echo "[3/3] Restarting and verifying..."

supervisorctl restart gds-os
sleep 5
echo "  gds-os: $(supervisorctl status gds-os | awk '{print $2, $4, $6}')"

# Kernel status
echo ""
echo "Kernel status:"
curl -s http://127.0.0.1:8000/kernel/status | python3 -c "
import sys, json
d = json.load(sys.stdin)
print(f'  Version: {d.get(\"version\")}')
print(f'  Running: {d.get(\"is_running\")}')
print(f'  Agents: {d.get(\"registered_agents\", 0)}')
print(f'  Tools: {d.get(\"sandbox\",{}).get(\"registered_tools\",0)} registered, {d.get(\"sandbox\",{}).get(\"healthy_tools\",0)} healthy')
print(f'  Executions: {d.get(\"sandbox\",{}).get(\"total_executions\",0)} total, {d.get(\"sandbox\",{}).get(\"success_rate\",0)}% success')
print(f'  Scheduler: {d.get(\"scheduler\",{}).get(\"total_dispatched\",0)} dispatched, {d.get(\"scheduler\",{}).get(\"currently_running\",0)} running')
" 2>/dev/null || echo "  FAILED"

# Tool test
echo ""
echo "Kernel tool test (cisa_kev_check):"
curl -s -X POST http://127.0.0.1:8000/kernel/tool/execute \
  -H "Content-Type: application/json" \
  -d '{"pid":"fix-test","tool_id":"cisa_kev_check","payload":{}}' | python3 -c "
import sys, json
d = json.load(sys.stdin)
print(f'  KEV: {d.get(\"total_count\",0)} vulns, Success: {d.get(\"success\")}')
" 2>/dev/null || echo "  FAILED"

# Import test
echo ""
echo "Import test:"
cd $API_DIR && python3 -c "
try:
    from gds_api.agentic.execution_engine import AgentExecutionEngine
    print('  execution_engine.py: OK ✅')
except Exception as e:
    print(f'  execution_engine.py: ERROR - {str(e)[:100]}')
try:
    from gds_api.agentic.execution import AgentExecutionLoop
    print('  execution.py: OK ✅')
except Exception as e:
    print(f'  execution.py: ERROR - {str(e)[:100]}')
from gds_api.reasoning.kernel_bridge import KERNEL_TOOLS, get_available_tools
print(f'  kernel_bridge: {len(KERNEL_TOOLS)} tools ✅')
" 2>/dev/null || echo "  FAILED"

echo ""
echo "============================================================"
echo "FIX COMPLETE"
echo "============================================================"
