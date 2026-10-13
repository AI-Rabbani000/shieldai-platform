# ShieldAI CI gate configuration and verification

Tracks issue #9. This change repairs client/workflow handling; it does not
configure the live endpoint or certify the endpoint's underlying assessment.

## Co-Pilot configuration required before merge

Confirm the callable function URL and authentication contract. Configure
`SHIELDAI_GATE_URL` to the actual HTTPS API endpoint, never an editor/login page.
The new `SHIELDAI_GATE_AUTHORIZATION` secret holds the complete Authorization
header value supported by that endpoint. If the endpoint uses a different
header, reconcile the client contract before merge; do not guess a credential
scheme or paste credentials into PR comments. This client does not follow
redirects or allow missing endpoint authorization.

The request preserves the existing shieldCICDGate input fields. The response
must include boolean `pass` and opposite boolean `blocked`, a list of strings
`block_reasons`, and a nonnegative integer `summary.critical`. An error object,
HTML, malformed JSON, timeout, missing configuration or HTTP failure means
`integration_error`, never passed or a finding-based block. Existing Base44
responses may use text/plain for valid JSON; body/schema validation handles
this without treating HTML as a verdict.

The GitHub token sent to the existing endpoint is reduced to read-only
permissions. The workflow itself provides the CI verdict; any server-side
GitHub comments/statuses must use a separate scoped provider integration or
report their permissions failure honestly. No raw response or block reason is
written into a shell command or log.

AutoFix requires a validated `blocked` verdict AND repository variable
`SHIELDAI_AUTOFIX_ENABLED=true`. Keep it unset initially. Before enabling,
confirm repository/tenant scoping and approved automation policy. Configure
`SHIELDAI_AUTOFIX_URL` and complete-header secret
`SHIELDAI_AUTOFIX_AUTHORIZATION` separately. An acknowledged request is not proof
that every generated PR succeeded.

Fork PRs continue using pull_request with withheld secrets; they receive an
explicit integration error. Do not switch to pull_request_target to execute
fork code with credentials. An approved internal review branch is needed for
authenticated assessment of such changes.

## Acceptance checks

Run `python -m unittest discover -s tests -p 'test_security_gate_client.py' -v`.
Then verify the authenticated endpoint on a bounded review commit: valid
passing verdict, valid blocking verdict, wrong credential, unavailable
endpoint, HTML/login response, and AutoFix withheld for integration failures.
Report statuses and schema only; never print header values or tokens.

## Backend follow-up

The current shieldCICDGate source reads stored findings rather than performing
a commit-specific scan, suppresses failed data reads into empty lists, and
does not visibly filter the retrieved findings by repository in that function.
Those gaps require a separate server change with confirmed entity schemas,
tenant authorization, commit-bound scan evidence, freshness and failure
handling. A structurally valid response alone is not proof of scan coverage.

This PR remains review-only until endpoint/auth configuration and a real CI
round-trip are verified by Co-Pilot. Production runtime source is unchanged.
