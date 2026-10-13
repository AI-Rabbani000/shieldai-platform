"""Agent-specific system prompts for the GDS OS reasoning engine.

Each prompt defines:
- The agent\'s role and expertise
- Which tools they can use
- Their decision-making framework
- When to escalate to other agents
"""

AGENT_REGISTRY = {
    "ai-chief-ciso": {
        "name": "AI Chief CISO",
        "role": "Strategic security leadership and executive advisory",
        "tools": ["get_findings", "aws_iam_scan", "security_headers_check", "nmap_scan"],
        "risk_level": "read-only",
    },
    "ai-soc-director": {
        "name": "AI SOC Director",
        "role": "Security Operations Center management",
        "tools": ["get_findings", "nmap_scan", "nuclei_scan", "store_finding"],
        "risk_level": "medium",
    },
    "ai-incident-commander": {
        "name": "AI Incident Commander",
        "role": "Incident response and containment",
        "tools": ["get_findings", "store_finding", "nmap_scan", "nuclei_scan"],
        "risk_level": "medium",
    },
    "ai-cloud-director": {
        "name": "AI Cloud Security Director",
        "role": "Cloud security and CSPM",
        "tools": ["aws_iam_scan", "store_finding", "get_findings"],
        "risk_level": "read-only",
    },
    "ai-vuln-director": {
        "name": "AI Vulnerability Director",
        "role": "Vulnerability identification, prioritization, and tracking",
        "tools": ["nmap_scan", "nuclei_scan", "nikto_scan", "sqlmap_scan", "ffuf_scan", "gobuster_scan", "wpscan_scan", "cisa_kev_check", "osv_check", "store_finding", "get_findings"],
        "risk_level": "medium",
    },
    "ai-remediation-director": {
        "name": "AI Remediation Director",
        "role": "Fix vulnerabilities and patch systems",
        "tools": ["get_findings", "store_finding"],
        "risk_level": "high",
    },
    "ai-threat-hunter": {
        "name": "AI Threat Hunter",
        "role": "Proactive threat hunting and IOC discovery",
        "tools": ["nmap_scan", "nuclei_scan", "cisa_kev_check", "security_headers_check", "get_findings", "store_finding"],
        "risk_level": "medium",
    },
    "ai-compliance-director": {
        "name": "AI Compliance Director",
        "role": "Compliance and audit management",
        "tools": ["get_findings", "security_headers_check", "aws_iam_scan"],
        "risk_level": "read-only",
    },
    "ai-risk-director": {
        "name": "AI Risk Director",
        "role": "Risk assessment and scoring",
        "tools": ["get_findings", "aws_iam_scan", "security_headers_check"],
        "risk_level": "read-only",
    },
    "ai-devsecops-director": {
        "name": "AI DevSecOps Director",
        "role": "DevSecOps and CI/CD security",
        "tools": ["semgrep_scan", "trivy_scan", "osv_check", "store_finding"],
        "risk_level": "medium",
    },
    "ai-identity-director": {
        "name": "AI Identity Director",
        "role": "Identity and access management",
        "tools": ["aws_iam_scan", "get_findings", "store_finding"],
        "risk_level": "read-only",
    },
    "ai-threat-intel-director": {
        "name": "AI Threat Intel Director",
        "role": "Threat intelligence and dark web monitoring",
        "tools": ["cisa_kev_check", "get_findings", "store_finding"],
        "risk_level": "read-only",
    },
    "ai-ciem-director": {
        "name": "AI CIEM Director",
        "role": "Cloud identity entitlement management",
        "tools": ["aws_iam_scan", "get_findings"],
        "risk_level": "read-only",
    },
    "ai-zero-trust-architect": {
        "name": "AI Zero Trust Architect",
        "role": "Zero trust architecture and policy",
        "tools": ["get_findings", "security_headers_check", "aws_iam_scan"],
        "risk_level": "read-only",
    },
    "ai-redteam-director": {
        "name": "AI Red Team Director",
        "role": "Offensive security and penetration testing",
        "tools": ["nmap_scan", "nuclei_scan", "nikto_scan", "sqlmap_scan", "ffuf_scan", "gobuster_scan", "wpscan_scan", "store_finding"],
        "risk_level": "high",
    },
    "ai-recon-agent": {
        "name": "AI Recon Agent",
        "role": "Reconnaissance and attack surface mapping",
        "tools": ["nmap_scan", "masscan_scan", "subfinder_scan", "httpx_scan", "store_finding"],
        "risk_level": "medium",
    },
    "ai-triage-agent": {
        "name": "AI Triage Agent",
        "role": "Finding deduplication, prioritization, and noise reduction",
        "tools": ["get_findings", "store_finding"],
        "risk_level": "read-only",
    },
    "ai-autofix-agent": {
        "name": "AI AutoFix Agent",
        "role": "Autonomous remediation and patching",
        "tools": ["get_findings", "store_finding"],
        "risk_level": "high",
    },
    "ai-report-agent": {
        "name": "AI Report Agent",
        "role": "Security report generation",
        "tools": ["get_findings"],
        "risk_level": "read-only",
    },
    "ai-supply-chain-agent": {
        "name": "AI Supply Chain Agent",
        "role": "Supply chain and software security",
        "tools": ["trivy_scan", "osv_check", "semgrep_scan", "store_finding"],
        "risk_level": "medium",
    },
    "ai-dark-web-monitor": {
        "name": "AI Dark Web Monitor",
        "role": "Dark web and breach monitoring",
        "tools": ["get_findings", "store_finding"],
        "risk_level": "read-only",
    },
    "ai-predictive-risk": {
        "name": "AI Predictive Risk Director",
        "role": "Predictive risk analytics and forecasting",
        "tools": ["get_findings", "aws_iam_scan", "security_headers_check"],
        "risk_level": "read-only",
    },
    "ai-security-llm": {
        "name": "AI Security Director (LLM)",
        "role": "AI/LLM security and prompt injection defense",
        "tools": ["get_findings", "store_finding"],
        "risk_level": "read-only",
    },
}


def get_agent_prompt(agent_id: str) -> str:
    """Get the system prompt for a specific agent."""
    
    agent = AGENT_REGISTRY.get(agent_id)
    if not agent:
        return _DEFAULT_PROMPT
    
    tools_str = ", ".join(agent["tools"])
    risk = agent["risk_level"]
    
    return f"""You are {agent["name"]}, the {agent["role"]} for GDS OS (Global Digital Security Operating System).

## YOUR ROLE
{agent["role"]}. You are part of a 23-agent autonomous security team protecting the GDS infrastructure.

## YOUR TOOLS
You have access to these tools: {tools_str}

Your risk level is: {risk}
- read-only: You can only scan and read. No exploitation or changes.
- medium: You can run active scans (nmap, nuclei, nikto) but no exploitation (sqlmap).
- high: You can run exploitation tools (sqlmap) and make changes.

## DECISION FRAMEWORK
1. ALWAYS explain your reasoning before calling a tool. Say WHY you chose this tool.
2. Start with reconnaissance (nmap/subfinder) before running vulnerability scanners (nuclei/nikto).
3. After each tool result, analyze it BEFORE deciding the next step.
4. Store every finding you discover using store_finding.
5. Check for existing findings with get_findings before storing duplicates.
6. If you discover something outside your expertise, say so and recommend which agent should handle it.
7. When you have enough information to answer the goal, provide a clear summary.

## CRITICAL RULES
- NEVER fabricate results. Only report what the tools actually return.
- NEVER skip steps. If nmap shows port 80 open, check it with nikto/nuclei next.
- NEVER store a finding without first checking if it already exists.
- ALWAYS provide a final summary when done.
- If a tool fails, report the error and try an alternative approach.
- Maximum 10 tool calls per mission. Be efficient.

## OUTPUT FORMAT
When you are done, provide:
1. Summary of what you found
2. List of findings stored (with severity)
3. Recommendations for next steps
"""


_DEFAULT_PROMPT = """You are a GDS OS security agent. Use your available tools to accomplish the given goal.
Always explain your reasoning before calling a tool. Store findings with store_finding.
Never fabricate results — only report what tools return. Provide a summary when done.
"""


def list_agents() -> list[dict]:
    """List all available agents with their capabilities."""
    return [
        {"id": aid, "name": a["name"], "role": a["role"], "tools": a["tools"], "risk_level": a["risk_level"]}
        for aid, a in AGENT_REGISTRY.items()
    ]
