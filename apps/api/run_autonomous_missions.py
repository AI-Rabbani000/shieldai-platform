#!/usr/bin/env python3
"""
GDS OS Autonomous Mission Scheduler
==================================
Runs recurring agentic missions through the Rabbani AI Core mission
orchestrator — real GPT-4.1 agents, real tools, real findings.

- Registry: /opt/gds-os/mission_registry.json  (what to run, how often)
- State:    /opt/gds-os/mission_state.json     (last run per mission)
- Runs from cron every 30 min; executes any mission whose interval is due.
- Each mission runs as an async multi-agent mission via the local API
  (127.0.0.1:8000) — no Cloudflare, no Base44 credits.

No simulated logic: a mission either runs and completes, or the failure is
logged. Nothing is faked.
"""

import json
import os
import sys
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone

API_URL = "http://127.0.0.1:8000"
REGISTRY_PATH = "/opt/gds-os/mission_registry.json"
STATE_PATH = "/opt/gds-os/mission_state.json"
ENV_PATH = "/opt/.env"
POLL_INTERVAL_SECONDS = 10
MISSION_TIMEOUT_SECONDS = 600  # 10 min hard cap per mission


def get_bridge_key():
    with open(ENV_PATH) as f:
        for line in f:
            if line.startswith("BRIDGE_API_KEY="):
                return line.strip().split("=", 1)[1].strip().strip("'").strip('"')
    return None


def http_json(method, path, body=None, key=None):
    req = urllib.request.Request(
        API_URL + path,
        data=json.dumps(body).encode() if body is not None else None,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {key}",
        },
        method=method,
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode() or "null")
    except urllib.error.HTTPError as e:
        try:
            detail = e.read().decode()[:300]
        except Exception:
            detail = ""
        return {"__http_error__": e.code, "detail": detail}
    except Exception as e:
        return {"__error__": str(e)}


def load_json(path, default):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return default


def save_json(path, data):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, path)


def run_mission(entry, key):
    """Launch an async mission and poll until complete. Returns summary dict."""
    goal = entry["goal"]
    agents = entry.get("agents", [])
    label = entry.get("name", "unnamed")

    launch = http_json("POST", "/bridge/mission", {
        "goal": goal,
        "agents": agents,
        "async": True,
        "context": entry.get("context", {}),
    }, key)

    mission_id = launch.get("mission_id")
    if not mission_id:
        return {"mission": label, "ok": False, "error": f"launch failed: {launch}"}

    print(f"[{label}] mission {mission_id} launched", flush=True)

    deadline = time.time() + MISSION_TIMEOUT_SECONDS
    result = None
    while time.time() < deadline:
        time.sleep(POLL_INTERVAL_SECONDS)
        result = http_json("GET", f"/bridge/mission/{mission_id}", key=key)
        status = result.get("status") if isinstance(result, dict) else None
        if status in ("completed", "failed"):
            break
    else:
        return {"mission": label, "ok": False, "error": "timeout waiting for mission"}

    if not isinstance(result, dict) or result.get("status") != "completed":
        return {"mission": label, "ok": False, "error": f"final status: {result.get('status') if isinstance(result, dict) else result}"}

    agent_results = result.get("agent_results") or []
    tool_calls = sum(a.get("tool_calls", 0) for a in agent_results if isinstance(a, dict))
    succeeded = sum(1 for a in agent_results if isinstance(a, dict) and a.get("success"))
    duration = result.get("duration_ms", 0)

    print(f"[{label}] completed: {succeeded}/{len(agent_results)} agents, "
          f"{tool_calls} tool calls, {duration}ms", flush=True)
    return {
        "mission": label,
        "ok": True,
        "mission_id": mission_id,
        "agents": len(agent_results),
        "agents_succeeded": succeeded,
        "tool_calls": tool_calls,
        "duration_ms": duration,
    }


def main():
    key = get_bridge_key()
    if not key:
        print("ERROR: BRIDGE_API_KEY not found in /opt/.env", flush=True)
        sys.exit(1)

    registry = load_json(REGISTRY_PATH, {"missions": []})
    state = load_json(STATE_PATH, {})
    now = time.time()
    changed = False
    failures = 0

    for entry in registry.get("missions", []):
        name = entry.get("name", "unnamed")
        interval = int(entry.get("interval_seconds", 21600))
        last = state.get(name, {}).get("last_run_ts", 0)

        if interval <= 0:  # disabled
            continue
        if now - last < interval:
            continue

        print(f"[{datetime.now(timezone.utc).isoformat()}] running mission: {name}", flush=True)
        summary = run_mission(entry, key)

        state.setdefault(name, {})
        state[name]["last_run_ts"] = int(now)
        state[name]["last_run_iso"] = datetime.now(timezone.utc).isoformat()
        state[name]["last_result"] = summary
        changed = True

        if not summary.get("ok"):
            failures += 1

    if changed:
        save_json(STATE_PATH, state)

    if failures:
        sys.exit(1)


if __name__ == "__main__":
    main()
