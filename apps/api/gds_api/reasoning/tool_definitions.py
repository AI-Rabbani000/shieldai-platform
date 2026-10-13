"""OpenAI function calling definitions for all GDS OS tools.

These are the tool schemas that get passed to OpenAI's chat.completions.create()
as the `tools` parameter. The LLM uses these to decide which tool to call.
"""


def get_tool_definitions(agent_id: str = None) -> list[dict]:
    """Get tool definitions for an agent. If agent_id is provided,
    return only the tools that agent is authorized to use."""
    
    all_tools = _ALL_TOOL_DEFINITIONS
    
    if agent_id and agent_id in _AGENT_TOOL_MAP:
        allowed = set(_AGENT_TOOL_MAP[agent_id])
        return [t for t in all_tools if t["function"]["name"] in allowed]
    
    return all_tools


def get_tool_names(agent_id: str = None) -> list[str]:
    """Get list of tool names available to an agent."""
    tools = get_tool_definitions(agent_id)
    return [t["function"]["name"] for t in tools]


# ============================================================
# ALL 15 TOOL DEFINITIONS (OpenAI function calling format)
# ============================================================

_ALL_TOOL_DEFINITIONS = [
    {
        "type": "function",
        "function": {
            "name": "nmap_scan",
            "description": "Scan a target for open ports and running services. Use this FIRST for network discovery before running vulnerability scanners. Returns list of open ports with service names.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "IP address or hostname to scan"},
                    "scan_type": {"type": "string", "enum": ["quick", "full", "stealth"], "description": "quick=fast top ports, full=all 65535 ports, stealth=stealth SYN scan. Default: quick"}
                },
                "required": ["target"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "nuclei_scan",
            "description": "Run Nuclei vulnerability templates against a target. Use AFTER nmap to check for known CVEs, misconfigurations, and exposures on discovered ports. Returns list of vulnerabilities found.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "URL or hostname to scan"},
                    "templates": {"type": "string", "enum": ["cve", "exposures", "misconfiguration", "all"], "description": "Template category. Default: all"}
                },
                "required": ["target"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "semgrep_scan",
            "description": "Run static analysis (SAST) on source code. Use when source code is available to find security issues like SQL injection, XSS, hardcoded secrets. Returns list of code findings with file/line references.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Path to source code directory or file"},
                    "ruleset": {"type": "string", "enum": ["security", "owasp", "auto"], "description": "Ruleset to use. Default: auto"}
                },
                "required": ["target"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "trivy_scan",
            "description": "Scan container images, filesystems, or IaC files for vulnerabilities. Use for container security and dependency scanning. Returns vulnerabilities with CVSS scores and fixed versions.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Container image (e.g. nginx:1.21) or filesystem path"},
                    "scan_type": {"type": "string", "enum": ["image", "fs", "repo"], "description": "Type of scan. Default: image"}
                },
                "required": ["target"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "nikto_scan",
            "description": "Run Nikto web server scanner against a URL. Use for web server misconfiguration, outdated software, and dangerous files. Returns list of web vulnerabilities.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "URL to scan (e.g. https://example.com)"}
                },
                "required": ["target"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "sqlmap_scan",
            "description": "Test a URL for SQL injection vulnerabilities. HIGH RISK — active exploitation testing. Requires approval. Returns injection points and database info if vulnerable.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "URL with parameters to test (e.g. https://example.com/page?id=1)"},
                    "level": {"type": "integer", "description": "Test level 1-5. Default: 1. Higher = more tests but slower."}
                },
                "required": ["target"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "masscan_scan",
            "description": "Fast port scanner for scanning large networks. Use for quick port discovery across many IPs. Returns list of open ports per IP.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "IP or CIDR range (e.g. 192.168.1.0/24)"},
                    "ports": {"type": "string", "description": "Ports to scan (e.g. 1-65535 or 22,80,443)"}
                },
                "required": ["target"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "subfinder_scan",
            "description": "Discover subdomains for a domain. Use for attack surface mapping and recon. Returns list of discovered subdomains.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Domain name (e.g. example.com)"}
                },
                "required": ["target"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "httpx_scan",
            "description": "Probe HTTP/HTTPS services on discovered hosts. Use AFTER subfinder to check which subdomains are live web servers. Returns live URLs with status codes and titles.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Domain or list of subdomains"}
                },
                "required": ["target"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "ffuf_scan",
            "description": "Fuzz directories and files on a web server. Use for content discovery — find hidden paths, admin panels, config files. Returns discovered URLs with status codes.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "URL to fuzz (e.g. https://example.com/FUZZ)"},
                    "wordlist": {"type": "string", "description": "Wordlist path. Default: common.txt"}
                },
                "required": ["target"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "gobuster_scan",
            "description": "Directory/file brute-forcing on web servers. Similar to ffuf but with different approach. Use for discovering hidden content. Returns discovered paths.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "URL to scan"},
                    "mode": {"type": "string", "enum": ["dir", "dns", "vhost"], "description": "Scan mode. Default: dir"}
                },
                "required": ["target"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "wpscan_scan",
            "description": "WordPress security scanner. Use when target is a WordPress site. Returns WordPress version, plugins, themes, and vulnerabilities.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "WordPress URL"}
                },
                "required": ["target"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "cisa_kev_check",
            "description": "Check CISA Known Exploited Vulnerabilities catalog. Use to check if specific CVEs are being actively exploited in the wild. Returns matching KEV entries.",
            "parameters": {
                "type": "object",
                "properties": {
                    "cve_id": {"type": "string", "description": "Specific CVE ID to check (e.g. CVE-2025-62718). If omitted, returns full KEV count."}
                }
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "osv_check",
            "description": "Check OSV.dev for vulnerabilities in a specific package. Use for dependency vulnerability scanning. Returns list of CVEs with severity and fixed versions.",
            "parameters": {
                "type": "object",
                "properties": {
                    "package": {"type": "string", "description": "Package name (e.g. axios, lodash)"},
                    "ecosystem": {"type": "string", "description": "Package ecosystem (e.g. npm, pypi, go)"},
                    "version": {"type": "string", "description": "Package version (optional)"}
                },
                "required": ["package"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "security_headers_check",
            "description": "Check HTTP security headers on a URL. Use for web security posture assessment. Returns which security headers are present/missing (HSTS, CSP, X-Frame-Options, etc).",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "URL to check (e.g. https://example.com)"}
                },
                "required": ["target"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "aws_iam_scan",
            "description": "Scan AWS IAM for security issues — users without MFA, old access keys, missing password policy. Use for cloud security assessment. Returns IAM findings.",
            "parameters": {
                "type": "object",
                "properties": {
                    "check_type": {"type": "string", "enum": ["users", "mfa", "keys", "policy", "all"], "description": "What to check. Default: all"}
                }
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "store_finding",
            "description": "Store a security finding in the PostgreSQL database. Use after discovering a vulnerability or security issue during a scan. Required for tracking and compliance.",
            "parameters": {
                "type": "object",
                "properties": {
                    "scanner": {"type": "string", "description": "Name of the scanner that found it (e.g. nmap, nuclei)"},
                    "title": {"type": "string", "description": "Short title of the finding"},
                    "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"], "description": "Severity level"},
                    "target": {"type": "string", "description": "Affected target (IP, URL, resource)"},
                    "details": {"type": "string", "description": "JSON string with finding details"},
                    "remediation": {"type": "string", "description": "How to fix the issue"}
                },
                "required": ["scanner", "title", "severity", "target"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_findings",
            "description": "Retrieve stored security findings from the database. Use to review past findings, check for duplicates before storing new ones, or assess overall security posture.",
            "parameters": {
                "type": "object",
                "properties": {
                    "status": {"type": "string", "enum": ["open", "resolved", "all"], "description": "Filter by status. Default: open"},
                    "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"], "description": "Filter by severity (optional)"}
                }
            }
        }
    },
]


# ============================================================
# AGENT → TOOL MAPPING (which tools each agent can use)
# ============================================================

_AGENT_TOOL_MAP = {
    "ai-recon-agent": ["nmap_scan", "masscan_scan", "subfinder_scan", "httpx_scan", "store_finding"],
    "ai-vuln-director": ["nmap_scan", "nuclei_scan", "nikto_scan", "sqlmap_scan", "ffuf_scan", "gobuster_scan", "wpscan_scan", "cisa_kev_check", "osv_check", "store_finding", "get_findings"],
    "ai-cloud-director": ["aws_iam_scan", "store_finding", "get_findings"],
    "ai-threat-hunter": ["nmap_scan", "nuclei_scan", "cisa_kev_check", "security_headers_check", "get_findings", "store_finding"],
    "ai-redteam-director": ["nmap_scan", "nuclei_scan", "nikto_scan", "sqlmap_scan", "ffuf_scan", "gobuster_scan", "wpscan_scan", "store_finding"],
    "ai-triage-agent": ["get_findings", "store_finding"],
    "ai-compliance-director": ["get_findings", "security_headers_check", "aws_iam_scan"],
    "ai-incident-commander": ["get_findings", "store_finding", "nmap_scan", "nuclei_scan"],
    "ai-autofix-agent": ["get_findings", "store_finding"],
    "ai-supply-chain-agent": ["trivy_scan", "osv_check", "semgrep_scan", "store_finding"],
    "ai-devsecops-director": ["semgrep_scan", "trivy_scan", "osv_check", "store_finding"],
    "ai-report-agent": ["get_findings"],
    "ai-chief-ciso": ["get_findings", "aws_iam_scan", "security_headers_check", "nmap_scan"],
    "ai-soc-director": ["get_findings", "nmap_scan", "nuclei_scan", "store_finding"],
    "ai-risk-director": ["get_findings", "aws_iam_scan", "security_headers_check"],
}
