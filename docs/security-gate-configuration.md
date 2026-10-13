# ShieldAI CI gate configuration and verification

Tracks issue #9; client in PR #10; VPS backend in PR #11. This client change
reconciles the new production contract. It does not configure GitHub secrets
or certify the backend's scan coverage.

## Required secrets

- `SHIELDAI_GATE_URL`: `https://api.globaldigitalsecurity.io/ci/gate`
- `CI_GATE_API_KEY`: the dedicated CI credential supplied securely by the owner.

The client creates `Authorization: Bearer <CI_GATE_API_KEY>`. Do not set the
former SHIELDAI_GATE_AUTHORIZATION secret for this route. Do not copy key
values into chat, PR comments, repository files, or logs. The caller also sends
the read-only workflow GitHub token required by the backend to read the commit.

## Response validation

Successful assessments require `status: ok`, `verdict: pass|blocked`, the
consistent boolean `pass`, string-list `block_reasons`, and nonnegative integer
counts `critical`, `high`, `new_critical`, `secrets_found` and positive
`files_scanned` in `summary`.
Repository and commit must match the request. A passing response cannot contain
critical, new-critical or secret findings under this workflow's policy.

`status: integration_error`, HTML, malformed JSON, missing configuration,
timeout, redirects, wrong credentials and non-success HTTP statuses are
integration failures, never a validated security block or pass. No raw response
or external reason is interpolated into shell commands or logged. JSON body
validation tolerates the older Base44 text/plain media type but never HTML.

## AutoFix remains opt-in

AutoFix requires a validated blocked verdict AND repository variable
`SHIELDAI_AUTOFIX_ENABLED=true`. Keep it unset initially. Confirm repository and
tenant scoping and approved automation policy before enabling it. The separate
AutoFix service still needs SHIELDAI_AUTOFIX_URL and the complete-header secret
SHIELDAI_AUTOFIX_AUTHORIZATION after its own authentication contract is reviewed.
A request acknowledgement does not prove every generated PR succeeded.

Fork PRs use pull_request with withheld secrets and receive an explicit
integration error. Do not switch to pull_request_target to execute fork code
with credentials. Use an approved internal review branch for authenticated
assessment of reviewed fork changes. Keep the existing gate check name for
branch protection.

## Acceptance checks

Run `python -m unittest discover -s tests -p 'test_security_gate_client.py' -v`.
Then Co-Pilot verifies a bounded real CI round-trip: valid passing verdict,
valid blocking verdict, wrong credentials, unavailable endpoint, HTML response,
wrong repo/commit, and no AutoFix on integration failures. Report only status,
coverage and schema; never headers or tokens.

PR #11's latest revision 190e245a addresses the four review findings:
full unified-diff retrieval with a size cap, SQL severity normalization,
requested severity policy enforcement and a synchronous threadpool handler.
Codex performed six offline mock review checks; Co-Pilot reports separate live
verification. The client now rejects missing/zero diff coverage. The scan is
limited to supported high-confidence patterns on added text lines; it is not
full-tree SAST or binary secret inspection. Dedicated persisted backend tests,
precise repository-target identity and binary coverage remain follow-up work.

The authenticated PR #10 rerun passed before the final coverage revision.
Require that revision's CI to pass before merging; then verify push-to-main CI.
