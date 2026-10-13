#!/bin/bash
set -a
source /opt/.env
set +a
cd /opt/gds-os/apps/api
exec /opt/gds-os/apps/api/venv/bin/uvicorn gds_api.main:app --host 0.0.0.0 --port 8000 --workers 1
