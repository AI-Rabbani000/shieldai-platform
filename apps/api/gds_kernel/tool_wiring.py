"""
GDS Agent Kernel — Tool Wiring Layer
======================================
Connects the kernel's sandbox drivers to the REAL tool_gateway.py
functions on the VPS. This replaces the placeholder executors
(lambda p: None) with actual tool execution functions.

Usage (called from kernel_executor.py or kernel_daemon.py):
    from gds_kernel.tool_wiring import wire_real_tools
    wire_real_tools(kernel)
"""

import asyncio
import json
import logging
import os
import sys
import subprocess
import time
from typing import Dict, Any, Optional, Callable
from pathlib import Path

logger = logging.getLogger("gds.kernel.wiring")

VPS_API_DIR = "/opt/gds-os/apps/api"
TOOLS_BIN = "/opt/tools/bin"


def _ensure_path():
    if TOOLS_BIN not in os.environ.get("PATH", ""):
        os.environ["PATH"] = f"{TOOLS_BIN}:{os.environ.get('PATH', '')}"


def _run_subprocess(cmd: list, timeout: int = 120) -> Dict[str, Any]:
    _ensure_path()
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return {
            "exit_code": result.returncode,
            "stdout": result.stdout[:10000] if result.stdout else "",
            "stderr": result.stderr[:5000] if result.stderr else "",
            "success": result.returncode == 0,
        }
    except subprocess.TimeoutExpired:
        return {"exit_code": -1, "stdout": "", "stderr": f"Timeout after {timeout}s", "success": False, "timed_out": True}
    except FileNotFoundError:
        return {"exit_code": -1, "stdout": "", "stderr": f"Command not found: {cmd[0]}", "success": False}
    except Exception as e:
        return {"exit_code": -1, "stdout": "", "stderr": str(e), "success": False}


def _run_python(code: str, timeout: int = 30) -> Dict[str, Any]:
    _ensure_path()
    try:
        result = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True, text=True, timeout=timeout,
            env={**os.environ, "PYTHONPATH": VPS_API_DIR},
        )
        if result.returncode == 0 and result.stdout.strip():
            try:
                return json.loads(result.stdout.strip())
            except json.JSONDecodeError:
                return {"success": True, "output": result.stdout.strip()[:10000]}
        else:
            return {"success": False, "error": result.stderr[:5000] if result.stderr else "Unknown error"}
    except Exception as e:
        return {"success": False, "error": str(e)}


# ============================================================
# REAL TOOL EXECUTORS
# ============================================================

def exec_nmap_scan(payload: Dict) -> Dict:
    target = payload.get("target", "localhost")
    scan_type = payload.get("scan_type", "-sV")
    logger.info(f"[nmap_scan] target={target}")
    result = _run_subprocess(["nmap", scan_type, "-p", "1-10000", target], timeout=300)
    open_ports = []
    for line in result.get("stdout", "").split("\n"):
        if "/tcp" in line or "/udp" in line:
            parts = line.split()
            if len(parts) >= 3:
                open_ports.append({"port": parts[0], "state": parts[1], "service": parts[2] if len(parts) > 2 else "unknown"})
    return {"tool": "nmap_scan", "target": target, "open_ports": open_ports, "port_count": len(open_ports), "raw_output": result.get("stdout", ""), "success": result.get("success", False)}


def exec_nuclei_scan(payload: Dict) -> Dict:
    target = payload.get("target", "localhost")
    if not target.startswith("http"):
        target = f"https://{target}"
    logger.info(f"[nuclei_scan] target={target}")
    result = _run_subprocess(["nuclei", "-u", target, "-j", "-severity", "low,medium,high,critical", "-silent"], timeout=600)
    findings = []
    for line in result.get("stdout", "").split("\n"):
        line = line.strip()
        if line.startswith("{"):
            try:
                findings.append(json.loads(line))
            except:
                pass
    return {"tool": "nuclei_scan", "target": target, "findings": findings, "finding_count": len(findings), "success": result.get("success", False)}


def exec_semgrep_scan(payload: Dict) -> Dict:
    repo_path = payload.get("target", payload.get("repo_path", "."))
    config = payload.get("config", "p/default")
    logger.info(f"[semgrep_scan] target={repo_path}")
    result = _run_subprocess(["semgrep", "--config", config, "--metrics=off", "--json", repo_path], timeout=300)
    findings = []
    stdout = result.get("stdout", "")
    if stdout:
        try:
            data = json.loads(stdout)
            findings = data.get("results", [])
        except:
            pass
    return {"tool": "semgrep_scan", "target": repo_path, "findings": findings, "finding_count": len(findings), "success": result.get("success", False)}


def exec_trivy_scan(payload: Dict) -> Dict:
    target = payload.get("target", ".")
    scan_type = payload.get("scan_type", "fs")
    logger.info(f"[trivy_scan] target={target} type={scan_type}")
    result = _run_subprocess(["trivy", scan_type, "--format", "json", "--quiet", target], timeout=300)
    vulns = []
    stdout = result.get("stdout", "")
    if stdout:
        try:
            data = json.loads(stdout)
            for res in data.get("Results", []):
                for vuln in res.get("Vulnerabilities", []):
                    vulns.append({
                        "cve_id": vuln.get("VulnerabilityID"),
                        "package": vuln.get("PkgName"),
                        "installed_version": vuln.get("InstalledVersion"),
                        "fixed_version": vuln.get("FixedVersion"),
                        "severity": vuln.get("Severity"),
                        "title": vuln.get("Title", ""),
                    })
        except:
            pass
    return {"tool": "trivy_scan", "target": target, "vulnerabilities": vulns, "vuln_count": len(vulns), "success": result.get("success", False)}


def exec_cisa_kev_check(payload: Dict) -> Dict:
    import urllib.request
    logger.info("[cisa_kev_check] Fetching CISA KEV catalog")
    try:
        url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        req = urllib.request.Request(url, headers={"User-Agent": "GDS-OS-Kernel/1.0"})
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = json.loads(resp.read().decode())
        vulns = data.get("vulnerabilities", [])
        catalog_version = data.get("catalogVersion", "unknown")
        count = data.get("count", len(vulns))
        target_cve = payload.get("cve_id", "").upper()
        if target_cve:
            matches = [v for v in vulns if target_cve in v.get("cveID", "").upper()]
            return {"tool": "cisa_kev_check", "catalog_version": catalog_version, "total_count": count, "query_cve": target_cve, "matched": matches, "is_kev": len(matches) > 0, "success": True}
        return {"tool": "cisa_kev_check", "catalog_version": catalog_version, "total_count": count, "success": True}
    except Exception as e:
        return {"tool": "cisa_kev_check", "error": str(e), "success": False}


def exec_osv_check(payload: Dict) -> Dict:
    import urllib.request
    packages = payload.get("packages", [])
    if not packages and payload.get("target"):
        packages = [{"package": {"name": payload["target"], "ecosystem": payload.get("ecosystem", "pypi")}}]
    logger.info(f"[osv_check] checking {len(packages)} packages")
    results = []
    try:
        for pkg in packages[:20]:
            osv_payload = json.dumps(pkg).encode()
            req = urllib.request.Request("https://api.osv.dev/v1/query", data=osv_payload, headers={"Content-Type": "application/json"}, method="POST")
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode())
                vulns = data.get("vulns", [])
                results.append({
                    "package": pkg.get("package", {}).get("name", "unknown"),
                    "vuln_count": len(vulns),
                    "vulns": [{"id": v.get("id"), "severity": v.get("severity", ["unknown"])[0] if v.get("severity") else "unknown"} for v in vulns[:10]],
                })
        return {"tool": "osv_check", "packages_checked": len(results), "results": results, "total_vulns": sum(r["vuln_count"] for r in results), "success": True}
    except Exception as e:
        return {"tool": "osv_check", "error": str(e), "success": False}


def exec_security_headers_check(payload: Dict) -> Dict:
    import urllib.request
    target = payload.get("target", "https://api.globaldigitalsecurity.io")
    if not target.startswith("http"):
        target = f"https://{target}"
    logger.info(f"[security_headers_check] target={target}")
    headers_to_check = ["strict-transport-security", "content-security-policy", "x-frame-options", "x-content-type-options", "referrer-policy", "permissions-policy"]
    resp_headers = None
    try:
        req = urllib.request.Request(target, headers={"User-Agent": "GDS-OS-Kernel/1.0"}, method="HEAD")
        with urllib.request.urlopen(req, timeout=10) as resp:
            resp_headers = dict(resp.headers)
        status_code = resp.status if hasattr(resp, "status") else 200
    except urllib.error.HTTPError as e:
        # 4xx/5xx still carries the server headers — capture them
        resp_headers = dict(e.headers or {})
        status_code = e.code
    except Exception as e:
        return {"tool": "security_headers_check", "target": target, "error": str(e), "success": False}
    try:
        results = {}
        for header in headers_to_check:
            value = resp_headers.get(header, resp_headers.get(header.title(), ""))
            results[header] = {"present": bool(value), "value": value if value else "MISSING"}
        present_count = sum(1 for h in results.values() if h["present"])
        return {"tool": "security_headers_check", "target": target, "headers": results, "present_count": present_count, "total_checked": len(headers_to_check), "score": f"{present_count}/{len(headers_to_check)}", "status_code": status_code, "success": True}
    except Exception as e:
        return {"tool": "security_headers_check", "target": target, "error": str(e), "success": False}


def exec_aws_iam_scan(payload: Dict) -> Dict:
    logger.info("[aws_iam_scan] Starting IAM scan")
    code = '''
import json, os, sys
sys.path.insert(0, "/opt/gds-os/apps/api")
os.environ["PATH"] = "/opt/tools/bin:" + os.environ.get("PATH", "")

try:
    import boto3
    session = boto3.Session(
        aws_access_key_id=os.environ.get("AWS_ACCESS_KEY_ID"),
        aws_secret_access_key=os.environ.get("AWS_SECRET_ACCESS_KEY"),
        region_name=os.environ.get("AWS_REGION", "eu-west-2"),
    )
    iam = session.client("iam")
    users = iam.list_users()["Users"]
    findings = []

    for user in users:
        username = user["UserName"]
        mfa_devices = iam.list_mfa_devices(UserName=username)["MFADevices"]
        if not mfa_devices:
            findings.append({"severity": "HIGH", "title": "IAM user " + username + " has no MFA", "user": username, "type": "no_mfa"})
        keys = iam.list_access_keys(UserName=username)["AccessKeyMetadata"]
        for key in keys:
            if key["Status"] == "Active":
                import datetime
                age = (datetime.datetime.now(key["CreateDate"].tzinfo) - key["CreateDate"]).days
                if age > 90:
                    findings.append({"severity": "MEDIUM", "title": "IAM access key " + key["AccessKeyId"] + " is " + str(age) + " days old", "user": username, "type": "old_access_key"})
        attached = iam.list_attached_user_policies(UserName=username)["AttachedPolicies"]
        for policy in attached:
            if "Admin" in policy["PolicyName"] or "admin" in policy["PolicyName"].lower():
                findings.append({"severity": "HIGH", "title": "IAM user " + username + " has admin policy: " + policy["PolicyName"], "user": username, "type": "admin_policy"})

    print(json.dumps({"users_scanned": len(users), "findings": findings, "finding_count": len(findings), "usernames": [u["UserName"] for u in users]}))
except Exception as e:
    print(json.dumps({"error": str(e), "success": False}))
'''
    result = _run_python(code, timeout=60)
    if "error" in result:
        return {"tool": "aws_iam_scan", "error": result["error"], "success": False}
    return {"tool": "aws_iam_scan", **result, "success": True}


def exec_get_findings(payload: Dict) -> Dict:
    severity = payload.get("severity", "")
    limit = payload.get("limit", 100)
    logger.info(f"[get_findings] severity={severity} limit={limit}")
    code = '''
import json, sys, os
sys.path.insert(0, "/opt/gds-os/apps/api")

db_url = None
env_path = "/opt/.env"
if os.path.exists(env_path):
    with open(env_path) as f:
        for line in f:
            if line.startswith("DATABASE_URL="):
                db_url = line.strip().split("=", 1)[1].strip().strip("'").strip('"')
                break

if not db_url:
    db_pass = os.environ.get("POSTGRES_PASSWORD", "")
    db_user = os.environ.get("POSTGRES_USER", "gds")
    db_url = "postgresql://" + db_user + ":" + db_pass + "@127.0.0.1:5432/gds_os"

try:
    import psycopg2
    conn = psycopg2.connect(db_url)
    cur = conn.cursor()
    severity = "''' + str(severity) + '''"
    limit = ''' + str(limit) + '''
    if severity:
        cur.execute("SELECT id, title, severity, status, scanner, detected_at FROM security_findings WHERE severity = %s ORDER BY detected_at DESC LIMIT %s", (severity, limit))
    else:
        cur.execute("SELECT id, title, severity, status, scanner, detected_at FROM security_findings ORDER BY detected_at DESC LIMIT %s", (limit,))
    rows = cur.fetchall()
    findings = [{"id": str(r[0]), "title": r[1], "severity": r[2], "status": r[3], "scanner": r[4], "detected_at": str(r[5])} for r in rows]
    print(json.dumps({"findings": findings, "count": len(findings)}))
    cur.close()
    conn.close()
except Exception as e:
    print(json.dumps({"error": str(e)}))
'''
    result = _run_python(code, timeout=15)
    if "error" in result:
        return {"tool": "get_findings", "error": result["error"], "success": False}
    return {"tool": "get_findings", **result, "success": True}


def exec_store_finding(payload: Dict) -> Dict:
    title = payload.get("title", "Unknown finding")
    target = str(payload.get("target", payload.get("asset", "")))
    severity = payload.get("severity", "MEDIUM")
    source = payload.get("source", "kernel")
    description = payload.get("description", "")
    cve_id = payload.get("cve_id", "")
    logger.info(f"[store_finding] title={title} severity={severity}")
    
    code = '''
import json, sys, os
sys.path.insert(0, "/opt/gds-os/apps/api")

db_url = os.environ.get("DATABASE_URL", "")
if not db_url:
    try:
        with open("/opt/.env") as f:
            for line in f:
                if line.startswith("DATABASE_URL="):
                    db_url = line.strip().split("=", 1)[1].strip().strip("'").strip('"')
                    break
    except OSError:
        pass
if not db_url:
    db_pass = os.environ.get("POSTGRES_PASSWORD", "")
    db_user = os.environ.get("POSTGRES_USER", "gds")
    db_url = "postgresql://" + db_user + ":" + db_pass + "@127.0.0.1:5432/gds_os"

title = "''' + title.replace("'", "''") + '''"
severity = "''' + severity.replace("'", "''") + '''"
source = "''' + source.replace("'", "''") + '''"
description = "''' + description.replace("'", "''")[:2000] + '''"
cve_id = "''' + cve_id.replace("'", "''") + '''"
target = "''' + target.replace("'", "''") + '''"

try:
    import psycopg2
    conn = psycopg2.connect(db_url)
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO security_findings (scanner, title, severity, target, details, status) VALUES (%s, %s, %s, %s, %s, 'open') RETURNING id",
        (source, title, severity, target, json.dumps({"description": description, "cve_id": cve_id}))
    )
    finding_id = cur.fetchone()[0]
    conn.commit()
    print(json.dumps({"success": True, "finding_id": str(finding_id)}))
    cur.close()
    conn.close()
except Exception as e:
    print(json.dumps({"error": str(e)}))
'''
    result = _run_python(code, timeout=10)
    if "error" in result:
        return {"tool": "store_finding", "error": result["error"], "success": False}
    return {"tool": "store_finding", **result, "success": True}


# ============================================================
# WIRING FUNCTION
# ============================================================

REAL_EXECUTORS: Dict[str, Callable] = {
    "nmap_scan": exec_nmap_scan,
    "nuclei_scan": exec_nuclei_scan,
    "semgrep_scan": exec_semgrep_scan,
    "trivy_scan": exec_trivy_scan,
    "cisa_kev_check": exec_cisa_kev_check,
    "osv_check": exec_osv_check,
    "security_headers_check": exec_security_headers_check,
    "aws_iam_scan": exec_aws_iam_scan,
    "get_findings": exec_get_findings,
    "store_finding": exec_store_finding,
}


def wire_real_tools(kernel) -> int:
    _ensure_path()
    wired_count = 0
    for tool_id, real_executor in REAL_EXECUTORS.items():
        driver = kernel.sandbox.drivers.get(tool_id)
        if driver is None:
            logger.warning(f"Cannot wire {tool_id} - driver not registered")
            continue
        driver.executor = real_executor
        driver.state = 2  # ToolState.OPEN
        wired_count += 1
        logger.info(f"Wired {tool_id} -> {real_executor.__name__}")
    logger.info(f"Tool wiring complete: {wired_count}/{len(REAL_EXECUTORS)} tools wired to real executors")
    return wired_count


async def test_wired_tools(kernel) -> Dict[str, Any]:
    import asyncio

    async def _run_tests():
        results = {}
        test_payloads = {
            "cisa_kev_check": {},
            "security_headers_check": {"target": "https://api.globaldigitalsecurity.io"},
            "get_findings": {"limit": 5},
            "nmap_scan": {"target": "localhost", "scan_type": "-sV"},
        }
        for tool_id, payload in test_payloads.items():
            driver = kernel.sandbox.drivers.get(tool_id)
            if driver is None or driver.executor is None:
                results[tool_id] = {"status": "not_registered"}
                continue
            try:
                result = await kernel.sandbox.execute(tool_id, payload)
                results[tool_id] = {
                    "status": "ok" if result.success else "failed",
                    "duration_ms": result.duration_ms,
                    "error": result.error if not result.success else None,
                }
            except Exception as e:
                results[tool_id] = {"status": "error", "error": str(e)}
        return results

    return await _run_tests()
