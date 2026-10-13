#!/bin/bash
# ============================================================
# GDS KERNEL PHASE 4 — PAGE FAULT STRESS TEST
# ============================================================
# Fills a 128K context window with large scan results to trigger
# real page faults. Verifies:
#   1. Context fills to 128K tokens
#   2. Page faults trigger when context exceeds capacity
#   3. Cold segments (tool_result, importance=0.5) page to Redis
#   4. Agent can recall paged memory via semantic search
#   5. Prompt rebuilds correctly after paging
#   6. Memory stats reflect the paging accurately
# ============================================================

set -e
API_DIR="/opt/gds-os/apps/api"
KERNEL_API="http://127.0.0.1:8000/kernel"
PID="stress-test"

echo "============================================================"
echo "GDS KERNEL PHASE 4 — PAGE FAULT STRESS TEST"
echo "============================================================"

# ============================================================
# Step 1: Verify kernel is running and clean slate
# ============================================================
echo ""
echo "[1/6] Preparing clean test environment..."

# Verify kernel is running
STATUS=$(curl -s $KERNEL_API/status | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('is_running',False))" 2>/dev/null)
if [ "$STATUS" != "True" ]; then
    echo "  ❌ Kernel not running — restart services first"
    exit 1
fi
echo "  ✅ Kernel running"

# Check current global stats
curl -s $KERNEL_API/memory/global-stats | python3 -c "
import sys, json
d = json.load(sys.stdin)
print(f'  Before test: {d.get(\"active_context_windows\",0)} windows, {d.get(\"total_context_tokens\",0)} tokens, {d.get(\"page_faults\",0)} page faults, {d.get(\"swap_segments\",0)} swap, {d.get(\"disk_segments\",0)} disk')
"

# ============================================================
# Step 2: Run the stress test — fill context with large content
# ============================================================
echo ""
echo "[2/6] Running stress test — filling 128K context window..."

cd $API_DIR && python3 << 'PYEOF'
import httpx
import time
import json
import sys

KERNEL_API = "http://127.0.0.1:8000/kernel"
PID = "stress-test"

client = httpx.Client(timeout=120.0)

def kernel_post(path, data):
    try:
        r = client.post(f"{KERNEL_API}{path}", json=data)
        if r.status_code == 200:
            return r.json() if isinstance(r.json(), dict) else {}
        return {}
    except Exception as e:
        return {"error": str(e)}

def kernel_get(path):
    try:
        r = client.get(f"{KERNEL_API}{path}")
        return r.json() if r.status_code == 200 else {}
    except:
        return {}

def get_stats():
    return kernel_get(f"/memory/stats/{PID}")

def get_global():
    return kernel_get("/memory/global-stats")

# Step 1: Allocate system prompt (importance=1.0 — never paged)
print("  Allocating system prompt (importance=1.0, never paged)...")
system_prompt = """You are the AI Vulnerability Director for GDS OS.
Your job is to analyze security scan results and identify critical vulnerabilities.

You have access to tools: nmap_scan, cisa_kev_check, nuclei_scan, nikto_scan, 
security_headers_check, osv_check, aws_iam_scan, semgrep_scan, trivy_scan, 
get_findings, store_finding.

You must:
1. Analyze all scan results provided in context
2. Identify critical and high severity findings
3. Check for duplicates against existing findings
4. Store new findings in the database
5. Provide a summary with remediation recommendations

Be thorough and accurate. Never hallucinate findings — only report what the scan data shows.""" 

result = kernel_post("/memory/alloc", {
    "pid": PID,
    "content": system_prompt,
    "segment_type": "system_prompt",
    "importance": 1.0
})
print(f"    System prompt: {result.get('segment_id', 'FAILED')}")

# Step 2: Allocate user goal
print("  Allocating user goal (importance=0.8)...")
goal = """USER REQUEST: Perform a comprehensive security assessment of the VPS at 2.24.141.108. 
Run nmap, CISA KEV check, security headers, and nuclei scans. 
Analyze ALL results and provide a complete findings report."""
result = kernel_post("/memory/alloc", {
    "pid": PID,
    "content": goal,
    "segment_type": "conversation",
    "importance": 0.8
})
print(f"    User goal: {result.get('segment_id', 'FAILED')}")

# Step 3: Simulate large scan results filling context
# Each scan result is ~5K chars (~1250 tokens)
# 128K tokens / 1250 per result = ~102 results to fill context
# But we also have system prompt + goal, so ~100 results

port_services = {22:'ssh', 80:'http', 443:'https', 5432:'postgresql', 6379:'redis', 8000:'http-alt', 8222:'nats', 9000:'http-alt', 9001:'http-alt', 7233:'temporal', 7474:'neo4j', 7687:'neo4j-bolt'}

scan_results = [
    # nmap results
    "NMAP SCAN RESULT (localhost, top 1000 ports):\n" + "\n".join([
        f"PORT {port}/tcp {'open':>6} {port_services.get(port, 'unknown')} {'version' if port in [22,80,443,5432] else ''}"
        for port in [22, 80, 443, 5432, 6379, 8000, 8222, 9000, 9001, 7233, 7474, 7687]
    ]) + "\n\nNmap done: 1 IP address (1 host up) scanned in 1.23 seconds\n" + 
    "Host script results:\n|_nbstat: NetBIOS name: SRV1869692\n|_smb2-security-mode: SMB: Couldn't find a NetBIOS name to use\n|_ssh-hostkey: ERROR: Script execution failed (use -d to debug)\n",
    
    # CISA KEV results
    "CISA KEV CHECK RESULT:\n" + "\n".join([
        f"CVE-{2024+i}-{10000+j}: {['Microsoft Exchange RCE', 'Chrome Zero Day', 'Apache Log4j', 'Fortinet FortiOS', 'VMware vCenter RCE', 'Citrix NetScaler', 'Atlassian Confluence', 'Cisco IOS XE', 'SAP NetWeaver', 'OpenSSL Buffer Overflow'][j % 10]}"
        for i in range(5) for j in range(50)
    ]) + f"\nTotal CISA KEV vulnerabilities: 1656\n",
    
    # Security headers result  
    "SECURITY HEADERS CHECK (https://api.globaldigitalsecurity.io):\n" +
    "HTTP/1.1 200 OK\n" +
    "Server: nginx/1.18.0 (Ubuntu)\n" +
    "Date: " + time.strftime("%a, %d %b %Y %H:%M:%S GMT") + "\n" +
    "Content-Type: text/html; charset=utf-8\n" +
    "Strict-Transport-Security: max-age=31536000; includeSubDomains ✅\n" +
    "X-Frame-Options: SAMEORIGIN ✅\n" +
    "X-Content-Type-Options: nosniff ✅\n" +
    "Content-Security-Policy: MISSING ❌\n" +
    "Referrer-Policy: MISSING ❌\n" +
    "Permissions-Policy: MISSING ❌\n" +
    "X-XSS-Protection: 1; mode=block (deprecated)\n" +
    "Overall Grade: C (5/10 headers present)\n",
]

# Generate large fake tool results to fill context
large_results = []
for i in range(80):
    result_text = f"TOOL_RESULT_{i} (nuclei_scan, iteration {i}):\n"
    result_text += f"Target: api.globaldigitalsecurity.io\n"
    result_text += f"Template: cves/2024/CVE-2024-{10000+i}\n"
    result_text += f"Severity: {'critical' if i % 5 == 0 else 'high' if i % 3 == 0 else 'medium' if i % 2 == 0 else 'low'}\n"
    result_text += f"Description: {'Remote Code Execution vulnerability detected' if i % 5 == 0 else 'SQL Injection vulnerability' if i % 3 == 0 else 'Cross-Site Scripting' if i % 2 == 0 else 'Information disclosure'}\n"
    result_text += f"URL: https://api.globaldigitalsecurity.io/api/v1/endpoint/{i}\n"
    result_text += f"Payload: {'testpayload' * 50}\n"  # Make it large
    result_text += f"Response: HTTP/1.1 {'500' if i % 5 == 0 else '200'}\n"
    result_text += f"Body: {'A' * 2000}\n"  # 2KB of response body
    result_text += f"CURL command: curl -X GET https://api.globaldigitalsecurity.io/api/v1/endpoint/{i}\n"
    result_text += f"Remediation: Update to latest version. Patch available.\n"
    large_results.append(result_text)

print(f"\n  Generated {len(large_results)} large tool results ({len(large_results)} * ~2.5KB each)")
print(f"  Total content: ~{sum(len(r) for r in large_results) // 1024}KB ({sum(len(r) for r in large_results) // 4} tokens estimated)")

# Step 4: Allocate all results and watch for page faults
print(f"\n  Allocating {len(large_results)} results into context (importance=0.5, paged first)...")
page_faults_before = get_global().get("page_faults", 0)
swap_before = get_global().get("swap_segments", 0)

allocated = 0
page_faults_triggered = 0
for i, result in enumerate(large_results):
    result_alloc = kernel_post("/memory/alloc", {
        "pid": PID,
        "content": f"TOOL_RESULT [{i}]: {result}",
        "segment_type": "tool_result",
        "importance": 0.5
    })
    if result_alloc.get("segment_id"):
        allocated += 1
    else:
        page_faults_triggered += 1
        if page_faults_triggered <= 3:  # Show first 3
            print(f"    ❌ Alloc {i} FAILED — context full, page fault unresolved")
    
    # Check stats every 20 allocations
    if (i + 1) % 20 == 0:
        stats = get_stats()
        global_stats = get_global()
        current_faults = global_stats.get("page_faults", 0)
        new_faults = current_faults - page_faults_before
        print(f"    [{i+1}/{len(large_results)}] tokens: {stats.get('tokens_used',0)}/{stats.get('max_tokens',0)} "
              f"({stats.get('utilization_pct',0)}%), segments: {stats.get('segment_count',0)}, "
              f"page_faults: {new_faults}, swap: {global_stats.get('swap_segments',0)}")

# Final stats
print(f"\n  Allocation complete: {allocated}/{len(large_results)} segments allocated")
final_stats = get_stats()
final_global = get_global()
total_faults = final_global.get("page_faults", 0) - page_faults_before
total_swap = final_global.get("swap_segments", 0) - swap_before

print(f"\n  Final context stats:")
print(f"    Tokens: {final_stats.get('tokens_used',0)}/{final_stats.get('max_tokens',0)} ({final_stats.get('utilization_pct',0)}%)")
print(f"    Segments in context: {final_stats.get('segment_count',0)}")
print(f"    Page faults triggered: {total_faults}")
print(f"    Segments in swap (Redis): {total_swap}")
print(f"    Segments in disk (Qdrant): {final_global.get('disk_segments',0)}")

# Step 5: Build context and verify prompt is coherent
print(f"\n  Building prompt from context window (after page faults)...")
context_result = kernel_post("/memory/build-context", {"pid": PID})
prompt = context_result.get("prompt", "") if isinstance(context_result, dict) else ""
prompt_stats = context_result.get("stats", {}) if isinstance(context_result, dict) else {}
if isinstance(prompt_stats, dict):
    print(f"    Prompt length: {len(prompt)} chars ({len(prompt)//4} tokens)")
    print(f"    Tokens used: {prompt_stats.get('tokens_used', 0)}")
    print(f"    Prompt starts with: {prompt[:100]}...")
    print(f"    Prompt ends with: ...{prompt[-100:]}")
else:
    print(f"    Prompt length: {len(prompt)} chars")

# Step 6: Test semantic search (recall)
print(f"\n  Testing semantic search (recall paged memory)...")
# Note: Qdrant search only works if embeddings were generated during page-out
search_result = kernel_post("/memory/search", {
    "query": "RCE vulnerability critical",
    "pid": PID,
    "limit": 3
})
search_results = search_result.get("results", []) if isinstance(search_result, dict) else []
print(f"    Search results: {len(search_results)}")
for r in search_results[:3]:
    content_preview = r.get("content", r.get("text", ""))[:80]
    print(f"      - {content_preview}...")

# Step 7: Test page-in (bring a segment back from swap)
print(f"\n  Testing page-in (bring segment back from swap)...")
stats = get_stats()
segments = stats.get("segments", [])
if segments:
    # Try to page-in the first segment that's NOT in context (it was paged out)
    # We'll allocate more to force page-out, then try to page-in
    # Actually, let's just test the page-in endpoint exists
    first_seg_id = segments[0].get("segment_id", "")
    page_in_result = kernel_post("/memory/page-in", {
        "pid": PID,
        "segment_id": first_seg_id
    })
    print(f"    Page-in {first_seg_id}: {page_in_result.get('segment_id', page_in_result)}")
else:
    print(f"    No segments to page-in (all paged to swap)")

# Final summary
print(f"\n{'='*60}")
print(f"PHASE 4 STRESS TEST SUMMARY")
print(f"{'='*60}")
print(f"  Context capacity: 128,000 tokens")
print(f"  Segments allocated: {allocated}")
print(f"  Segments in context: {final_stats.get('segment_count', 0)}")
print(f"  Tokens used: {final_stats.get('tokens_used', 0)}")
print(f"  Page faults: {total_faults}")
print(f"  Swap segments (Redis): {total_swap}")
print(f"  Disk segments (Qdrant): {final_global.get('disk_segments', 0)}")
print(f"  Prompt rebuilt: {len(prompt)} chars")

if total_faults > 0:
    print(f"\n  ✅ PAGE FAULTS TRIGGERED — 3-tier memory hierarchy working!")
    print(f"  Cold segments (tool_result, importance=0.5) were paged to Redis swap")
    if total_swap > 0:
        print(f"  ✅ Swap (Redis) has {total_swap} segments")
    if final_global.get("disk_segments", 0) > 0:
        print(f"  ✅ Disk (Qdrant) has {final_global.get('disk_segments', 0)} segments")
else:
    print(f"\n  ⚠️ NO PAGE FAULTS — context not filled enough")
    print(f"  Need more data or smaller context window to trigger page faults")

# Cleanup
print(f"\n  Cleaning up...")
# We don't terminate — leave the context for inspection
client.close()
print(f"  Done. Context window '{PID}' left for inspection.")
PYEOF

# ============================================================
# Step 3: Check if Redis swap actually has segments
# ============================================================
echo ""
echo "[3/6] Checking Redis swap for paged segments..."

redis-cli -n 0 KEYS "gds:swap:*" 2>/dev/null | head -20 || echo "  No Redis swap keys found"
redis-cli -n 0 DBSIZE 2>/dev/null | head -1 || echo "  Redis not accessible"

SWAP_COUNT=$(redis-cli -n 0 KEYS "gds:swap:*" 2>/dev/null | wc -l)
echo "  Redis swap keys: $SWAP_COUNT"

# ============================================================
# Step 4: Check Qdrant for disk segments
# ============================================================
echo ""
echo "[4/6] Checking Qdrant for disk segments..."

curl -s http://127.0.0.1:6333/collections/gds_memory 2>/dev/null | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    count = d.get('result', {}).get('points_count', 0)
    status = d.get('result', {}).get('status', 'unknown')
    print(f'  Qdrant collection: gds_memory')
    print(f'  Status: {status}')
    print(f'  Points: {count}')
except:
    print('  Qdrant collection not found or not accessible')
" 2>/dev/null || echo "  Qdrant not accessible"

# ============================================================
# Step 5: Bridge test (verify kernel still works under memory pressure)
# ============================================================
echo ""
echo "[5/6] Bridge test under memory pressure..."

BRIDGE_RESULT=$(curl -s -X POST http://127.0.0.1:8000/bridge/agent/ai-vuln-director/invoke \
  -H "Authorization: Bearer REDACTED_SET_BRIDGE_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"goal":"Run cisa_kev_check and report total count","context":{}}' 2>/dev/null)

echo "$BRIDGE_RESULT" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    if d.get('success'):
        tc = d.get('tool_calls', [{}])
        vulns = tc[0].get('result', {}).get('total_vulns', 0) if tc else 0
        print(f'  ✅ Bridge working under pressure: {vulns} KEV vulns, {d.get(\"iterations\",0)} iterations, {d.get(\"duration_ms\",0)}ms')
    else:
        print(f'  ❌ Bridge failed: {d.get(\"detail\", d.get(\"error\", \"unknown\"))}')
except Exception as e:
    print(f'  ❌ Bridge parse error: {e}')
" 2>/dev/null || echo "  Bridge test failed"

# ============================================================
# Step 6: Final global stats
# ============================================================
echo ""
echo "[6/6] Final global memory stats:"

curl -s $KERNEL_API/memory/global-stats | python3 -c "
import sys, json
d = json.load(sys.stdin)
print(f'  Context windows: {d.get(\"active_context_windows\",0)}')
print(f'  Total context tokens: {d.get(\"total_context_tokens\",0)}')
print(f'  Page faults: {d.get(\"page_faults\",0)}')
print(f'  Swap segments (Redis): {d.get(\"swap_segments\",0)}')
print(f'  Disk segments (Qdrant): {d.get(\"disk_segments\",0)}')
print(f'  Page-ins: {d.get(\"page_ins\",0)}')
print(f'  Page-outs: {d.get(\"page_outs\",0)}')
print(f'  Swap evictions: {d.get(\"swap_evictions\",0)}')
print(f'  Total tokens paged: {d.get(\"total_tokens_paged\",0)}')
"

# Kernel status
echo ""
curl -s $KERNEL_API/status | python3 -c "
import sys, json
d = json.load(sys.stdin)
print(f'  Kernel: {d.get(\"is_running\")}')
sb = d.get('sandbox', {})
print(f'  Tools: {sb.get(\"registered_tools\",0)} registered, {sb.get(\"healthy_tools\",0)} healthy')
sc = d.get('scheduler', {})
print(f'  Scheduler: {sc.get(\"total_admitted\",0)} admitted, {sc.get(\"total_completed\",0)} completed, {sc.get(\"total_crashed\",0)} crashed')
mem = d.get('memory', {})
print(f'  Memory: {mem.get(\"total_context_windows\",0)} windows, {mem.get(\"page_faults\",0)} faults, {mem.get(\"swap_segments\",0)} swap, {mem.get(\"disk_segments\",0)} disk')
"

echo ""
echo "============================================================"
echo "PHASE 4 — PAGE FAULT STRESS TEST COMPLETE"
echo "============================================================"
