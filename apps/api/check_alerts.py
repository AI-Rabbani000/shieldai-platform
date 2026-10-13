#!/usr/bin/env python3
"""Check for critical findings and create alerts."""
import os, sys, uuid
sys.path.insert(0, '/opt/gds-os/apps/api')
for line in open('/opt/.env').read().split('\n'):
    if '=' in line and not line.startswith('#'):
        k, v = line.split('=', 1)
        os.environ[k.strip()] = v.strip()

from sqlalchemy import create_engine, text
from datetime import datetime, timezone

DB_URL = os.getenv("DATABASE_URL", "")
if not DB_URL:
    try:
        with open("/opt/.env") as f:
            for line in f:
                if line.startswith("DATABASE_URL="):
                    DB_URL = line.strip().split("=", 1)[1].strip().strip("'").strip('"')
                    break
    except OSError:
        pass
if not DB_URL:
    raise SystemExit("DATABASE_URL not configured (env or /opt/.env)")
engine = create_engine(DB_URL)

with engine.connect() as conn:
    tid = conn.execute(text("SELECT id FROM tenants LIMIT 1")).scalar()
    uid = conn.execute(text("SELECT id FROM users LIMIT 1")).scalar()
    
    result = conn.execute(text("SELECT severity, COUNT(*) FROM security_findings WHERE detected_at > NOW() - INTERVAL '1 hour' AND severity IN ('critical', 'high') GROUP BY severity"))
    for row in result:
        severity, count = row[0], row[1]
        conn.execute(text("INSERT INTO notifications (id, tenant_id, user_id, type, message, read_at, created_at) VALUES (:id, :tid, :uid, 'alert', :msg, NULL, NOW()) ON CONFLICT DO NOTHING"),
                     {"id": str(uuid.uuid4()), "tid": tid, "uid": uid, "msg": f"{count} {severity} findings in last hour"})
        print(f"[{datetime.now(timezone.utc).isoformat()}] Alert: {count} {severity}")
    conn.commit()
    total = conn.execute(text("SELECT COUNT(*) FROM security_findings WHERE status = 'open'")).scalar()
    print(f"[{datetime.now(timezone.utc).isoformat()}] Open findings: {total}")
