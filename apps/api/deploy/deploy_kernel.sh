#!/bin/bash
set -e

API_DIR="/opt/gds-os/apps/api"
KERNEL_DIR="$API_DIR/gds_kernel"
SUPERVISOR_CONF="/etc/supervisor/conf.d/gds-kernel.conf"

echo "============================================================"
echo "GDS AGENT OS KERNEL — VPS DEPLOYMENT"
echo "============================================================"
echo "Target: $API_DIR"
echo "Time: $(date)"
echo ""

if [ ! -d "/opt/gds-os" ]; then
    echo "ERROR: This script must be run on the GDS VPS (2.24.141.108)"
    exit 1
fi

echo "[1/6] Pulling latest code from GitHub..."
cd $API_DIR
if [ -d ".git" ]; then
    git fetch origin main
    git checkout main
    git pull origin main
    echo "  Code pulled from GitHub"
else
    echo "  Not a git repo. Cloning from GitHub..."
    git clone https://github.com/Al-Rabbani/shieldai-platform.git /tmp/shieldai-clone
    cp -r /tmp/shieldai-clone/gds_kernel $KERNEL_DIR
    cp -r /tmp/shieldai-clone/deploy $API_DIR/deploy
    echo "  Code cloned and copied"
fi

echo ""
echo "[2/6] Verifying kernel files..."
for f in process.py scheduler.py arbitrator.py kernel.py memory.py sandbox.py syscalls.py unified_kernel.py kernel_router.py kernel_executor.py; do
    if [ -f "$KERNEL_DIR/$f" ]; then
        echo "  OK $f"
    else
        echo "  MISSING $f"
    fi
done

echo ""
echo "[3/6] Creating kernel daemon entry point..."
cat > $API_DIR/gds_kernel/kernel_daemon.py << 'DAEMON'
import asyncio, logging, sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(name)s] %(levelname)s: %(message)s')
logger = logging.getLogger("gds.kernel.daemon")

async def main():
    from gds_kernel.kernel_executor import initialize_kernel_with_executors
    kernel = initialize_kernel_with_executors()
    logger.info("GDS Agent Kernel daemon started")
    while True:
        try:
            result = await kernel.run_cycle()
            if result["dispatched"] > 0:
                logger.info(f"Cycle {result['cycle']}: dispatched {result['dispatched']} processes")
            await asyncio.sleep(0.1)
        except KeyboardInterrupt:
            await kernel.shutdown()
            break
        except Exception as e:
            logger.error(f"Kernel cycle error: {e}", exc_info=True)
            await asyncio.sleep(1)

if __name__ == "__main__":
    asyncio.run(main())
DAEMON
echo "  Kernel daemon created"

echo ""
echo "[4/6] Wiring kernel router into FastAPI main.py..."
MAIN_PY="$API_DIR/gds_api/main.py"
if [ -f "$MAIN_PY" ]; then
    if grep -q "kernel_router" "$MAIN_PY"; then
        echo "  Kernel router already wired"
    else
        python3 -c "
content = open('$MAIN_PY').read()
if 'kernel_router' not in content:
    lines = content.split('\n')
    last_import = max(i for i, l in enumerate(lines) if l.startswith(('from ', 'import ')))
    lines.insert(last_import + 1, 'from gds_kernel.kernel_router import router as kernel_router')
    last_router = max(i for i, l in enumerate(lines) if 'app.include_router' in l)
    lines.insert(last_router + 1, 'app.include_router(kernel_router)')
    open('$MAIN_PY', 'w').write('\n'.join(lines))
    print('  Kernel router wired into main.py')
"
    fi
else
    echo "  main.py not found — manual wiring needed"
fi

echo ""
echo "[5/6] Creating supervisor config..."
cat > $SUPERVISOR_CONF << 'SUPCONF'
[program:gds-kernel]
command=python3 /opt/gds-os/apps/api/gds_kernel/kernel_daemon.py
directory=/opt/gds-os/apps/api
autostart=true
autorestart=true
startsecs=5
startretries=3
stopwaitsecs=30
stdout_logfile=/var/log/gds-kernel-stdout.log
stderr_logfile=/var/log/gds-kernel-stderr.log
environment=PYTHONPATH="/opt/gds-os/apps/api"
priority=10
SUPCONF
echo "  Supervisor config created"

echo ""
echo "[6/6] Restarting services..."
supervisorctl reread 2>/dev/null || true
supervisorctl update 2>/dev/null || true
supervisorctl restart gds-api 2>/dev/null || true
supervisorctl start gds-kernel 2>/dev/null || true
sleep 3

echo ""
echo "=== Service Status ==="
supervisorctl status gds-api 2>/dev/null || echo "  gds-api: check manually"
supervisorctl status gds-kernel 2>/dev/null || echo "  gds-kernel: check manually"

echo ""
echo "=== Kernel Health Check ==="
sleep 2
curl -s http://localhost:8000/kernel/status 2>/dev/null | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    print('  Version:', d.get('version', 'unknown'))
    print('  Running:', d.get('is_running', False))
    for phase, state in d.get('phases', {}).items():
        print(f'    {phase}: {state}')
    print('  Tools:', d.get('registered_tools', 0))
    print('  Kernel is live!')
except:
    print('  Kernel endpoint not yet available — check logs')
" 2>/dev/null || echo "  Kernel endpoint not yet available"

echo ""
echo "============================================================"
echo "DEPLOYMENT COMPLETE"
echo "============================================================"
echo ""
echo "Kernel API endpoints:"
echo "  GET  https://api.globaldigitalsecurity.io/kernel/status"
echo "  GET  https://api.globaldigitalsecurity.io/kernel/processes"
echo "  POST https://api.globaldigitalsecurity.io/kernel/process/create"
echo "  POST https://api.globaldigitalsecurity.io/kernel/tool/execute"
echo "  GET  https://api.globaldigitalsecurity.io/kernel/tools"
echo ""
echo "Logs: /var/log/gds-kernel*.log"
echo "============================================================"
