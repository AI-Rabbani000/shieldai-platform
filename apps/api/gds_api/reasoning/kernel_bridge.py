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
import os
import asyncio
from typing import Dict, Any, Optional, List
from gds_api.reasoning.kernel_agent_loop import run_kernel_agent

logger = logging.getLogger("gds.kernel.bridge")

# Kernel API endpoint (same process, localhost)
KERNEL_API = "http://127.0.0.1:8000/kernel"


def _kernel_headers() -> Dict[str, str]:
    key = os.environ.get("BRIDGE_API_KEY", "")
    if not key:
        raise RuntimeError("BRIDGE_API_KEY is required for kernel access")
    return {"Authorization": f"Bearer {key}"}


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
    
    headers = _kernel_headers()
    async with aiohttp.ClientSession(headers=headers) as session:
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
    
    headers = _kernel_headers()
    async with aiohttp.ClientSession(headers=headers) as session:
        async with session.get(f"{KERNEL_API}/status", timeout=aiohttp.ClientTimeout(total=10)) as resp:
            return await resp.json()


async def create_process(agent_id: str, agent_type: str = "security", priority: int = 2, goal: str = "", task_name: Optional[str] = None) -> Dict[str, Any]:
    """Create an agent process in the kernel."""
    import aiohttp
    
    headers = _kernel_headers()
    async with aiohttp.ClientSession(headers=headers) as session:
        async with session.post(
            f"{KERNEL_API}/process/create",
            json={"agent_id": agent_id, "task_name": task_name or agent_id, "priority": priority, "goal": goal},
            timeout=aiohttp.ClientTimeout(total=10),
        ) as resp:
            return await resp.json()


async def list_tools() -> List[Dict[str, Any]]:
    """List all registered kernel tools."""
    import aiohttp
    
    headers = _kernel_headers()
    async with aiohttp.ClientSession(headers=headers) as session:
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
