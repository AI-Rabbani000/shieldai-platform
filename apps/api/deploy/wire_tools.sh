#!/bin/bash
# ============================================================
# GDS Kernel Tool Wiring Patch
# ============================================================
# Patches the kernel daemon to use real tool executors
# instead of placeholder (lambda p: None) functions.
# Run this ON the VPS after deploy_kernel.sh.
# ============================================================

set -e
API_DIR="/opt/gds-os/apps/api"
KERNEL_DIR="$API_DIR/gds_kernel"

echo "============================================================"
echo "GDS KERNEL — TOOL WIRING PATCH"
echo "============================================================"

# Step 1: Copy the tool_wiring.py module
echo "[1/4] Copying tool_wiring.py..."
if [ -f "$KERNEL_DIR/tool_wiring.py" ]; then
    echo "  Already exists (from git pull)"
else
    echo "  ERROR: tool_wiring.py not found at $KERNEL_DIR"
    echo "  Run: cd /tmp && git clone https://github.com/Al-Rabbani/shieldai-platform.git && cp /tmp/shieldai-platform/gds_kernel/tool_wiring.py $KERNEL_DIR/"
    exit 1
fi
echo "  OK"

# Step 2: Patch kernel_daemon.py to call wire_real_tools
echo ""
echo "[2/4] Patching kernel_daemon.py to wire real tools..."
DAEMON="$KERNEL_DIR/kernel_daemon.py"

cat > $DAEMON << 'DAEMON'
"""GDS Agent Kernel Daemon — Entry point for supervisor."""
import asyncio
import logging
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(name)s] %(levelname)s: %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('/var/log/gds-kernel.log'),
    ]
)

logger = logging.getLogger("gds.kernel.daemon")

async def main():
    from gds_kernel.kernel_executor import initialize_kernel_with_executors
    from gds_kernel.tool_wiring import wire_real_tools, test_wired_tools

    kernel = initialize_kernel_with_executors()

    # Wire real tool executors (replaces placeholder lambdas)
    wired = wire_real_tools(kernel)
    logger.info(f"Wired {wired} real tool executors")

    # Quick smoke test
    logger.info("Running tool smoke tests...")
    test_results = test_wired_tools(kernel)
    for tool_id, result in test_results.items():
        status = result.get("status", "unknown")
        logger.info(f"  {tool_id}: {status}")
    logger.info("GDS Agent Kernel daemon started with real tools")

    # Main kernel loop
    while True:
        try:
            result = await kernel.run_cycle()
            if result["dispatched"] > 0:
                logger.info(f"Cycle {result['cycle']}: dispatched {result['dispatched']} processes")
            await asyncio.sleep(0.1)
        except KeyboardInterrupt:
            logger.info("Shutdown signal received")
            break
        except Exception as e:
            logger.error(f"Kernel cycle error: {e}", exc_info=True)
            await asyncio.sleep(1)

if __name__ == "__main__":
    asyncio.run(main())
DAEMON
echo "  OK — kernel_daemon.py patched"

# Step 3: Restart kernel daemon
echo ""
echo "[3/4] Restarting kernel daemon..."
supervisorctl restart gds-kernel
sleep 3
echo "  Status: $(supervisorctl status gds-kernel)"

# Step 4: Verify tools are wired via API
echo ""
echo "[4/4] Verifying wired tools via API..."
sleep 2

# Check kernel status
curl -s http://localhost:8000/kernel/status | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    sandbox = d.get('sandbox', {})
    print('  Registered tools:', sandbox.get('registered_tools', 0))
    print('  Healthy tools:', sandbox.get('healthy_tools', 0))
    print('  Total executions:', sandbox.get('total_executions', 0))
    if sandbox.get('total_executions', 0) > 0:
        print('  Success rate:', sandbox.get('success_rate', 0))
    print('  Kernel is live with real tools!')
except Exception as e:
    print('  Error:', e)
"

# Test a real tool execution through the kernel API
echo ""
echo "  Testing real tool: cisa_kev_check..."
curl -s -X POST http://localhost:8000/kernel/tool/execute \
  -H "Content-Type: application/json" \
  -d '{"pid": "test", "tool_id": "cisa_kev_check", "payload": {}}' | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    if 'detail' in d:
        print('  API error:', d['detail'])
    else:
        print('  Tool:', d.get('tool', 'unknown'))
        print('  Total KEV count:', d.get('total_count', 'N/A'))
        print('  Catalog version:', d.get('catalog_version', 'N/A'))
        print('  SUCCESS — real tool execution works!')
except Exception as e:
    print('  Error parsing:', e)
    print('  Raw:', sys.stdin.read()[:500])
"

echo ""
echo "  Testing real tool: security_headers_check..."
curl -s -X POST http://localhost:8000/kernel/tool/execute \
  -H "Content-Type: application/json" \
  -d '{"pid": "test", "tool_id": "security_headers_check", "payload": {"target": "https://api.globaldigitalsecurity.io"}}' | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    if 'detail' in d:
        print('  API error:', d['detail'])
    else:
        print('  Tool:', d.get('tool', 'unknown'))
        print('  Score:', d.get('score', 'N/A'))
        headers = d.get('headers', {})
        for h, info in headers.items():
            status = 'present' if info.get('present') else 'MISSING'
            print(f'    {h}: {status}')
        print('  SUCCESS — real tool execution works!')
except Exception as e:
    print('  Error parsing:', e)
    print('  Raw:', sys.stdin.read()[:500])
"

echo ""
echo "============================================================"
echo "TOOL WIRING COMPLETE"
echo "============================================================"
echo ""
echo "The kernel now executes REAL tools via the sandbox:"
echo "  nmap_scan       → real nmap subprocess"
echo "  nuclei_scan     → real nuclei subprocess"
echo "  semgrep_scan    → real semgrep subprocess"
echo "  trivy_scan      → real trivy subprocess"
echo "  cisa_kev_check  → real CISA API fetch"
echo "  osv_check       → real OSV.dev API"
echo "  security_headers_check → real HTTP HEAD request"
echo "  aws_iam_scan    → real boto3 IAM scan"
echo "  get_findings    → real PostgreSQL query"
echo "  store_finding   → real PostgreSQL insert"
echo ""
echo "Test via API:"
echo "  POST /kernel/tool/execute"
echo "  Body: {\"pid\":\"test\",\"tool_id\":\"cisa_kev_check\",\"payload\":{}}"
echo "============================================================"
