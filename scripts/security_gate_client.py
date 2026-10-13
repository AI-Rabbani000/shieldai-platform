"""Bounded CI gate client. Never print tokens or external response bodies."""
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

MAX_RESPONSE_BYTES = 1024 * 1024


class IntegrationError(Exception):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise IntegrationError("Gate endpoint redirected; configure its callable HTTPS URL")


def request_json(url, body, authorization=""):
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        raise IntegrationError("Gate endpoint must be a configured HTTPS URL without embedded credentials")
    if not authorization:
        raise IntegrationError("Gate endpoint authorization is not configured")
    headers = {"Content-Type": "application/json", "Accept": "application/json", "Authorization": authorization}
    request = urllib.request.Request(url, data=json.dumps(body).encode(), headers=headers, method="POST")
    try:
        with urllib.request.build_opener(NoRedirect()).open(request, timeout=30) as response:
            if not 200 <= response.status < 300:
                raise IntegrationError("Gate endpoint did not return a successful HTTP status")
            raw = response.read(MAX_RESPONSE_BYTES + 1)
    except IntegrationError:
        raise
    except urllib.error.HTTPError as exc:
        raise IntegrationError(f"Gate endpoint returned HTTP {exc.code}") from None
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        raise IntegrationError("Gate endpoint request failed") from None
    if len(raw) > MAX_RESPONSE_BYTES:
        raise IntegrationError("Gate response exceeded its size limit")
    # Existing Base44 functions may send valid JSON with text/plain media type.
    try:
        return json.loads(raw)
    except (ValueError, UnicodeError):
        raise IntegrationError("Gate endpoint returned invalid JSON (possibly an HTML/login page)") from None


def gate_verdict(data, *, expected_repo=None, expected_commit=None):
    if not isinstance(data, dict) or data.get("status") != "ok" or data.get("error"):
        raise IntegrationError("Gate response has no completed security assessment")
    if type(data.get("pass")) is not bool:
        raise IntegrationError("Gate response has no valid security verdict")
    verdict = data.get("verdict")
    if verdict not in ("pass", "blocked") or (verdict == "pass") != data["pass"]:
        raise IntegrationError("Gate response has inconsistent pass/verdict fields")
    if expected_repo is not None and data.get("repo") != expected_repo:
        raise IntegrationError("Gate response is for a different repository")
    if expected_commit is not None and data.get("commit") != expected_commit:
        raise IntegrationError("Gate response is for a different commit")
    reasons = data.get("block_reasons")
    summary = data.get("summary")
    if not isinstance(reasons, list) or not all(isinstance(r, str) for r in reasons):
        raise IntegrationError("Gate response has invalid block reasons")
    fields = ("critical", "high", "new_critical", "secrets_found", "files_scanned")
    if not isinstance(summary, dict) or any(type(summary.get(k)) is not int or summary[k] < 0 for k in fields):
        raise IntegrationError("Gate response has invalid finding counts")
    if summary["files_scanned"] < 1:
        raise IntegrationError("Gate response has no diff coverage")
    if data["pass"] and (reasons or any(summary[k] > 0 for k in ("critical", "new_critical", "secrets_found"))):
        raise IntegrationError("Passing response contains blocking findings or reasons")
    return ("passed" if data["pass"] else "blocked"), summary["critical"]


def write_outputs(verdict, critical=0):
    output = os.environ.get("GITHUB_OUTPUT")
    if output:
        with open(output, "a") as stream:
            stream.write(f"verdict={verdict}\ncritical={critical}\n")


def main(mode="gate"):
    try:
        if mode == "gate":
            token = os.environ.get("GITHUB_TOKEN", "")
            if not token:
                raise IntegrationError("GitHub read credential is not configured")
            pr = os.environ.get("PR_NUMBER", "")
            body = {
                "repo_full_name": os.environ.get("GITHUB_REPOSITORY", ""),
                "commit_sha": os.environ.get("GITHUB_SHA", ""),
                "branch": os.environ.get("GITHUB_REF_NAME", ""),
                "pr_number": int(pr) if pr else 0,
                "github_token": token,
                "block_on": ["critical"], "fail_on_secrets": True, "fail_on_new_critical": True,
            }
            gate_key = os.environ.get("CI_GATE_API_KEY", "")
            if not gate_key or any(c.isspace() for c in gate_key):
                raise IntegrationError("Dedicated CI gate credential is not configured or invalid")
            data = request_json(os.environ.get("SHIELDAI_GATE_URL", ""), body,
                                "Bearer " + gate_key)
            verdict, critical = gate_verdict(data, expected_repo=body["repo_full_name"],
                                            expected_commit=body["commit_sha"])
            write_outputs(verdict, critical)
            print(f"ShieldAI gate verdict: {verdict}; critical findings: {critical}")
            return 0 if verdict == "passed" else 1
        if mode == "autofix":
            if os.environ.get("GATE_VERDICT") != "blocked" or os.environ.get("AUTOFIX_ENABLED") != "true":
                raise IntegrationError("AutoFix requires an explicit policy and validated blocking verdict")
            data = request_json(os.environ.get("SHIELDAI_AUTOFIX_URL", ""), {
                "action": "bulk_fix", "repo_full_name": os.environ.get("GITHUB_REPOSITORY", ""), "max_prs": 5,
            }, os.environ.get("SHIELDAI_AUTOFIX_AUTHORIZATION", ""))
            if not isinstance(data, dict) or data.get("success") is not True or data.get("error"):
                raise IntegrationError("AutoFix did not return a successful response")
            print("AutoFix request acknowledged; verify individual PR outcomes separately")
            return 0
        raise IntegrationError("Unsupported client mode")
    except (IntegrationError, ValueError) as exc:
        write_outputs("integration_error")
        message = str(exc) if isinstance(exc, IntegrationError) else "Invalid client configuration"
        print(f"ShieldAI integration error: {message}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "gate"))
