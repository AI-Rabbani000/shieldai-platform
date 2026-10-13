#!/bin/bash
# ============================================================
# GDS Kernel Bridge Wiring Patch
# ============================================================
# Updates the VPS reasoning engine to route tool execution
# through the GDS Unified Kernel (/kernel/tool/execute) instead
# of calling tool_gateway.py functions directly.
#
# This gives every agent tool call:
#   - Sandbox isolation (timeout, panic protection)
#   - Health tracking (auto-disable unhealthy tools)
#   - Audit trail (every syscall logged)
#   - Resource limits (max concurrent, memory)
#
# Run this ON the VPS.
# ============================================================

set -e
API_DIR="/opt/gds-os/apps/api"

echo "============================================================"
echo "GDS KERNEL BRIDGE WIRING PATCH"
echo "============================================================"

# ============================================================
# Step 1: Create kernel_bridge.py — a thin wrapper that the
# reasoning engine uses instead of calling tool_gateway directly.
# It calls the kernel API on localhost (same process, no network
# overhead since it's 127.0.0.1).
# ============================================================
echo "[1/3] Creating kernel_bridge.py..."

cat > $API_DIR/gds_api/reasoning/kernel_bridge.py << 'PYEOF'
"""
Kernel Bridge — Routes tool execution through the GDS Unified Kernel
====================================================================
Replaces direct tool_gateway.py calls with kernel syscall calls.
Every tool execution goes through the sandbox with:
  - Timeout enforcement
  - Panic isolation
  - Health tracking
  - Audit trail
"""

import logging
import asyncio
from typing import Dict, Any, Optional, List

logger = logging.getLogger("gds.kernel.bridge")

# Kernel API endpoint (same process, localhost)
KERNEL_API = "http://127.0.0.1:8000/kernel"


async def execute_tool(tool_id: str, payload: Dict[str, Any], pid: str = "agent") -> Dict[str, Any]:
    """
    Execute a tool through the kernel sandbox.
    
    Args:
        tool_id: Tool to execute (nmap_scan, cisa_kev_check, etc.)
        payload: Tool input parameters
        pid: Calling process ID for audit trail
    
    Returns:
        Tool execution result dict
    """
    import aiohttp
    
    async with aiohttp.ClientSession() as session:
        async with session.post(
            f"{KERNEL_API}/tool/execute",
            json={"pid": pid, "tool_id": tool_id, "payload": payload},
            timeout=aiohttp.ClientTimeout(total=600),
        ) as resp:
            if resp.status == 200:
                result = await resp.json()
                logger.info(f"Kernel tool {tool_id} executed (pid={pid})")
                return result
            else:
                error_text = await resp.text()
                logger.error(f"Kernel tool {tool_id} failed: {resp.status} {error_text}")
                return {"success": False, "error": f"Kernel API {resp.status}: {error_text}"}


async def get_kernel_status() -> Dict[str, Any]:
    """Get kernel status including sandbox health."""
    import aiohttp
    
    async with aiohttp.ClientSession() as session:
        async with session.get(f"{KERNEL_API}/status", timeout=aiohttp.ClientTimeout(total=10)) as resp:
            return await resp.json()


async def create_process(agent_id: str, agent_type: str = "security", priority: int = 2, goal: str = "") -> Dict[str, Any]:
    """Create an agent process in the kernel."""
    import aiohttp
    
    async with aiohttp.ClientSession() as session:
        async with session.post(
            f"{KERNEL_API}/process/create",
            json={"agent_id": agent_id, "agent_type": agent_type, "priority": priority, "goal": goal},
            timeout=aiohttp.ClientTimeout(total=10),
        ) as resp:
            return await resp.json()


async def list_tools() -> List[Dict[str, Any]]:
    """List all registered kernel tools."""
    import aiohttp
    
    async with aiohttp.ClientSession() as session:
        async with session.get(f"{KERNEL_API}/tools", timeout=aiohttp.ClientTimeout(total=10)) as resp:
            return await resp.json()


# ============================================================
# Tool function wrappers — same interface as tool_gateway but
# routes through the kernel sandbox.
# These match the function names the reasoning engine expects.
# ============================================================

async def nmap_scan(payload: Dict) -> Dict:
    """Nmap port scan through kernel."""
    return await execute_tool("nmap_scan", payload, pid="reasoning-engine")

async def nuclei_scan(payload: Dict) -> Dict:
    """Nuclei vulnerability scan through kernel."""
    return await execute_tool("nuclei_scan", payload, pid="reasoning-engine")

async def semgrep_scan(payload: Dict) -> Dict:
    """Semgrep SAST scan through kernel."""
    return await execute_tool("semgrep_scan", payload, pid="reasoning-engine")

async def trivy_scan(payload: Dict) -> Dict:
    """Trivy vulnerability scan through kernel."""
    return await execute_tool("trivy_scan", payload, pid="reasoning-engine")

async def cisa_kev_check(payload: Dict) -> Dict:
    """CISA KEV check through kernel."""
    return await execute_tool("cisa_kev_check", payload, pid="reasoning-engine")

async def osv_check(payload: Dict) -> Dict:
    """OSV vulnerability check through kernel."""
    return await execute_tool("osv_check", payload, pid="reasoning-engine")

async def security_headers_check(payload: Dict) -> Dict:
    """Security headers check through kernel."""
    return await execute_tool("security_headers_check", payload, pid="reasoning-engine")

async def aws_iam_scan(payload: Dict) -> Dict:
    """AWS IAM scan through kernel."""
    return await execute_tool("aws_iam_scan", payload, pid="reasoning-engine")

async def get_findings(payload: Dict) -> Dict:
    """Get security findings from PostgreSQL through kernel."""
    return await execute_tool("get_findings", payload, pid="reasoning-engine")

async def store_finding(payload: Dict) -> Dict:
    """Store a security finding in PostgreSQL through kernel."""
    return await execute_tool("store_finding", payload, pid="reasoning-engine")


# ============================================================
# Tool registry — maps tool names to kernel-bridged functions.
# The reasoning engine uses this to dispatch LLM function calls.
# ============================================================

KERNEL_TOOLS = {
    "nmap_scan": nmap_scan,
    "nuclei_scan": nuclei_scan,
    "semgrep_scan": semgrep_scan,
    "trivy_scan": trivy_scan,
    "cisa_kev_check": cisa_kev_check,
    "osv_check": osv_check,
    "security_headers_check": security_headers_check,
    "aws_iam_scan": aws_iam_scan,
    "get_findings": get_findings,
    "store_finding": store_finding,
}


def get_available_tools() -> List[Dict[str, Any]]:
    """Return tool definitions for LLM function calling."""
    return [
        {
            "type": "function",
            "function": {
                "name": "nmap_scan",
                "description": "Scan target for open ports and services. Use for network reconnaissance.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "target": {"type": "string", "description": "Target host or IP (e.g., localhost, 127.0.0.1)"},
                        "scan_type": {"type": "string", "description": "Nmap scan type flag", "default": "-sV"},
                    },
                    "required": ["target"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "nuclei_scan",
                "description": "Run template-based vulnerability scanner against a target URL.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "target": {"type": "string", "description": "Target URL (e.g., https://example.com)"},
                    },
                    "required": ["target"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "cisa_kev_check",
                "description": "Check CISA Known Exploited Vulnerabilities catalog. Optionally query a specific CVE.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "cve_id": {"type": "string", "description": "Specific CVE ID to check (optional)"},
                    },
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "security_headers_check",
                "description": "Check HTTP security headers on a URL (HSTS, CSP, X-Frame-Options, etc.).",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "target": {"type": "string", "description": "URL to check (e.g., https://api.example.com)"},
                    },
                    "required": ["target"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "osv_check",
                "description": "Check packages against OSV.dev vulnerability database.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "target": {"type": "string", "description": "Package name to check"},
                        "ecosystem": {"type": "string", "description": "Package ecosystem (pypi, npm, etc.)", "default": "pypi"},
                    },
                    "required": ["target"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "semgrep_scan",
                "description": "Run static analysis (SAST) on a code repository.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "target": {"type": "string", "description": "Repository path or URL"},
                    },
                    "required": ["target"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "trivy_scan",
                "description": "Run Trivy vulnerability scanner on filesystem or container image.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "target": {"type": "string", "description": "Path to scan"},
                        "scan_type": {"type": "string", "description": "Scan type (fs, image)", "default": "fs"},
                    },
                    "required": ["target"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "aws_iam_scan",
                "description": "Scan AWS IAM users, roles, and policies for misconfigurations.",
                "parameters": {"type": "object", "properties": {}},
            },
        },
        {
            "type": "function",
            "function": {
                "name": "get_findings",
                "description": "Retrieve stored security findings from the database.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "severity": {"type": "string", "description": "Filter by severity (CRITICAL, HIGH, MEDIUM, LOW)"},
                        "limit": {"type": "integer", "description": "Max findings to return", "default": 50},
                    },
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "store_finding",
                "description": "Store a new security finding in the database.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "title": {"type": "string", "description": "Finding title"},
                        "severity": {"type": "string", "description": "CRITICAL, HIGH, MEDIUM, or LOW"},
                        "source": {"type": "string", "description": "Tool that found it"},
                        "description": {"type": "string", "description": "Finding description"},
                        "cve_id": {"type": "string", "description": "CVE ID if applicable"},
                    },
                    "required": ["title", "severity"],
                },
            },
        },
    ]
PYEOF
echo "  OK — kernel_bridge.py created"

# ============================================================
# Step 2: Patch the reasoning engine to use kernel_bridge
# instead of tool_gateway for tool execution.
# ============================================================
echo ""
echo "[2/3] Patching reasoning engine to use kernel_bridge..."

REASONING_DIR="$API_DIR/gds_api/reasoning"
AGENT_LOOP="$REASONING_DIR/agent_loop.py"

if [ -f "$AGENT_LOOP" ]; then
    # Backup the original
    cp "$AGENT_LOOP" "${AGENT_LOOP}.bak.tool_gateway"
    
    # Patch: replace tool_gateway imports with kernel_bridge
    python3 << 'PYEOF'
import re

f = "/opt/gds-os/apps/api/gds_api/reasoning/agent_loop.py"
content = open(f).read()

# Replace tool_gateway imports with kernel_bridge
content = content.replace(
    "from gds_api.agentic.tool_gateway import",
    "from gds_api.reasoning.kernel_bridge import"
)

# Replace tool_gateway. function calls with kernel_bridge. calls
content = content.replace("tool_gateway.", "kernel_bridge.")

# If there's a TOOLS dict or function registry, replace it with kernel_bridge.get_available_tools()
# Look for patterns like: "nmap_scan": tool_gateway.nmap_scan
content = re.sub(
    r'"(nmap_scan|nuclei_scan|semgrep_scan|trivy_scan|cisa_kev_check|osv_check|security_headers_check|aws_iam_scan|get_findings|store_finding)"\s*:\s*(?:tool_gateway\.|kernel_bridge\.)\1',
    r'"\1": kernel_bridge.\1',
    content
)

# If the code has a hardcoded tools list, replace with kernel_bridge import
if "def get_tools" in content or "TOOLS =" in content or "tools_list" in content:
    content = content.replace(
        "from gds_api.reasoning.kernel_bridge import",
        "from gds_api.reasoning.kernel_bridge import\nfrom gds_api.reasoning.kernel_bridge import KERNEL_TOOLS, get_available_tools"
    )

open(f, "w").write(content)
print(f"Patched {f}")
PYEOF
    echo "  OK — agent_loop.py patched"
else
    echo "  WARNING: agent_loop.py not found at $AGENT_LOOP"
    echo "  Checking for other reasoning files..."
    ls -la $REASONING_DIR/*.py 2>/dev/null || echo "  No reasoning files found"
fi

# Also check for other files that import tool_gateway
echo ""
echo "  Checking for other files that import tool_gateway..."
grep -rn "from.*tool_gateway import\|import tool_gateway" $API_DIR/gds_api/ --include="*.py" 2>/dev/null | grep -v __pycache__ | grep -v .bak || echo "  No other imports found"

echo ""
echo "[3/3] Restarting services..."

# Install aiohttp if not already installed
pip install aiohttp 2>/dev/null || echo "  aiohttp already installed"

# Restart the API to pick up the changes
supervisorctl restart gds-os
sleep 5
echo "  gds-os: $(supervisorctl status gds-os | awk '{print $2, $4, $6}')"

# Also restart the kernel daemon
supervisorctl restart gds-kernel 2>/dev/null || echo "  gds-kernel: not managed by supervisor (ok)"

echo ""
echo "============================================================"
echo "VERIFICATION"
echo "============================================================"

# Test 1: Kernel status
echo "1. Kernel status:"
curl -s http://localhost:8000/kernel/status | python3 -c "
import sys, json
d = json.load(sys.stdin)
print(f'   Version: {d.get(\"version\")}')
print(f'   Running: {d.get(\"is_running\")}')
print(f'   Tools: {d.get(\"sandbox\",{}).get(\"registered_tools\",0)} registered, {d.get(\"sandbox\",{}).get(\"healthy_tools\",0)} healthy')
print(f'   Executions: {d.get(\"sandbox\",{}).get(\"total_executions\",0)}')
" 2>/dev/null || echo "   FAILED"

# Test 2: Direct kernel tool call (CISA KEV)
echo ""
echo "2. Direct kernel tool call (cisa_kev_check):"
curl -s -X POST http://localhost:8000/kernel/tool/execute \
  -H "Content-Type: application/json" \
  -d '{"pid":"bridge-test","tool_id":"cisa_kev_check","payload":{}}' | python3 -c "
import sys, json
d = json.load(sys.stdin)
print(f'   Tool: {d.get(\"tool\")}')
print(f'   KEV count: {d.get(\"total_count\")}')
print(f'   Success: {d.get(\"success\")}')
" 2>/dev/null || echo "   FAILED"

# Test 3: Kernel tool via the reasoning engine path
echo ""
echo "3. Kernel bridge import test:"
cd $API_DIR && python3 -c "
from gds_api.reasoning.kernel_bridge import KERNEL_TOOLS, get_available_tools
print(f'   Registered tools: {len(KERNEL_TOOLS)}')
print(f'   Tool names: {list(KERNEL_TOOLS.keys())}')
tools = get_available_tools()
print(f'   LLM function definitions: {len(tools)}')
print(f'   First tool: {tools[0][\"function\"][\"name\"]}')
" 2>/dev/null || echo "   FAILED — import error"

# Test 4: Nmap through kernel (quick scan)
echo ""
echo "4. Nmap through kernel (localhost, fast):"
curl -s -X POST http://localhost:8000/kernel/tool/execute \
  -H "Content-Type: application/json" \
  -d '{"pid":"bridge-test","tool_id":"nmap_scan","payload":{"target":"127.0.0.1","scan_type":"-sV"}}' | python3 -c "
import sys, json
d = json.load(sys.stdin)
print(f'   Ports found: {d.get(\"port_count\",0)}')
print(f'   Success: {d.get(\"success\")}')
for p in d.get('open_ports', [])[:5]:
    print(f'     {p.get(\"port\")} {p.get(\"state\")} {p.get(\"service\")}')
" 2>/dev/null || echo "   FAILED"

echo ""
echo "============================================================"
echo "KERNEL BRIDGE WIRING COMPLETE"
echo "============================================================"
echo ""
echo "Tool execution flow (NEW):"
echo "  Base44 → gdsRabbaniBridge → VPS /bridge/* → reasoning engine"
echo "  → kernel_bridge.execute_tool() → /kernel/tool/execute"
echo "  → sandbox.execute() → real executor → subprocess/API → result"
echo ""
echo "Tool execution flow (OLD, now replaced):"
echo "  Base44 → gdsRabbaniBridge → VPS /bridge/* → reasoning engine"
echo "  → tool_gateway.nmap_scan() → subprocess → result"
echo ""
echo "Benefits:"
echo "  + Sandbox isolation (timeout, panic protection)"
echo "  + Health tracking (auto-disable unhealthy tools)"
echo "  + Audit trail (every syscall logged)"
echo "  + Resource limits (max concurrent, memory)"
echo "  + Unified API (all tools go through one interface)"
echo ""
echo "Next: Redeploy gdsRabbaniBridge on Base44 with kernel_tool action"
echo "============================================================"
