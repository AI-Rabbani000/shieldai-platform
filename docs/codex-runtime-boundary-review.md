# Runtime boundary review and deployment handoff

Baseline: `3184ed44ab7ac3fca5a1d02bf9964cb7eaef3b69` from PR #6.

## Changes ready for review

- Tool dispatch uses `payload=` for both supported adapters and never retries after an internal TypeError. Custom awaitables are awaited.
- Both kernel HTTP client implementations send the configured Bearer credential and reject missing configuration before opening a network client.
- The bridge supplies the required process `task_name`; the router returns a successful process result instead of falling through to null.
- Kernel initialization publishes the singleton only after successful boot and complete default-driver wiring. Failed initialization can be retried by a later request.
- Kernel key comparison uses constant-time comparison. Authentication remains required on the router.
- Finding arguments cross the subprocess boundary as JSON stdin, never interpolated Python source. SQL uses bound values, including an optional target filter. Limits are bounded to 1–1000. Database failure cannot become successful tool output. Environment configuration takes precedence; password fallback uses psycopg connection arguments so reserved password characters are supported.

## Offline validation

Run `python3 -m unittest discover -s tests -p test_runtime_boundaries.py -v`.

The suite exercises the actual dependency-light functions using AST loading and mock transport/database dependencies. It does not start the whole API, connect to PostgreSQL, use real credentials, run scanners, or prove tenant isolation. A separate GitHub Actions workflow runs the same checks on Python 3.11.

## Co-Pilot deployment verification

Deploy only the reviewed commit after recording the deployed SHA and preserving a restorable release. Keep uvicorn at one worker. Confirm the bridge key is available in both service processes, without printing its value.

1. Run the offline test suite on the deployment Python version and compile the five changed Python modules before restarting.
2. Confirm missing and incorrect credentials receive 401 on kernel routes; an authorized status request must succeed. Do not log token values.
3. Call the authenticated kernel bridge client for status and tool listing; verify it no longer receives 401.
4. Create a bounded test process through the bridge and verify a non-null process ID is returned; terminate it afterward.
5. Run a read-only kernel tool canary, such as CISA KEV retrieval, and confirm a real result and execution trace.
6. Use a dedicated test finding with quotes and newlines. Store it, read it using its target filter, verify exact text preservation, and clean it up through an authorized mechanism.
7. Submit a bounded asynchronous mission and poll its actual result. Report mission ID, status, tool outcome and deployed full SHA.

If any step fails, roll back the reviewed files to the baseline release and report the failed check. Do not claim live verification from offline tests.

## Follow-up issues from source review

- `run_autonomous_missions.py` silently converts malformed or unreadable registry/state files into empty defaults. Lost state can trigger duplicate missions; invalid registries can silently disable monitoring. Persisted in-flight mission IDs and recovery are still needed.
- Scheduler polling only recognizes completed/failed, and a local timeout does not cancel or reconcile the remote mission. Per-host flock is not distributed deduplication.
- Tenant-scoped authority is not carried from the runner through the current gateway dispatch; a shared bridge key is not tenant authorization. Finding tools are not made tenant-safe by the target filter in this PR.
- Direct scanner drivers still need enforceable authorization/resource scope and argument allowlists. This PR does not enable broader scanning.
- Temporal functionality is unverified and reported broken by the Co-Pilot. Do not migrate schedules to it until persistence, authenticated connectivity, workflow execution and recovery tests pass.
- The snapshot has duplicate kernel paths. Verify the actual import/deployment layout before consolidating them.

The live Superagent API remains unconfigured from Codex. Coordination uses PR comments and the owner relay; no VPS source edits, merge, or deployment were performed by Codex.
