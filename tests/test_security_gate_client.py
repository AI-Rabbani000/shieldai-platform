import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("gate_client", Path(__file__).resolve().parents[1] / "scripts/security_gate_client.py")
client = importlib.util.module_from_spec(spec)
spec.loader.exec_module(client)


class GateClientTests(unittest.TestCase):
    def valid(self, passed=True):
        return {"status": "ok", "verdict": "pass" if passed else "blocked", "pass": passed, "repo": "Al-Rabbani/shieldai-platform", "commit": "a" * 40, "block_reasons": [] if passed else ["critical finding"], "summary": {"critical": 0 if passed else 1, "high": 0, "new_critical": 0, "secrets_found": 0}}

    def response(self, body, status=200):
        class Response:
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def read(self, limit): return body[:limit]
        response = Response()
        response.status = status
        return response

    def test_passing_and_blocking_verdicts(self):
        self.assertEqual(client.gate_verdict(self.valid()), ("passed", 0))
        self.assertEqual(client.gate_verdict(self.valid(False)), ("blocked", 1))

    def test_invalid_verdicts_fail_closed(self):
        for value in (None, [], {}, {"pass": "true"}, {**self.valid(), "verdict": "blocked"}, {**self.valid(), "error": "data unavailable"}, {**self.valid(), "summary": {"critical": True}}, {**self.valid(), "block_reasons": ["must block"]}):
            with self.subTest(value=value), self.assertRaises(client.IntegrationError):
                client.gate_verdict(value)

    def test_html_response_is_integration_error(self):
        with patch.object(client.urllib.request, "build_opener") as opener:
            opener.return_value.open.return_value = self.response(b"<!doctype html><html>login</html>")
            with self.assertRaisesRegex(client.IntegrationError, "invalid JSON"):
                client.request_json("https://gate.invalid/api", {}, "Bearer test-only")

    def test_critical_findings_cannot_receive_passing_verdict(self):
        with self.assertRaises(client.IntegrationError):
            client.gate_verdict({**self.valid(), "summary": {"critical": 1}})

    def test_integration_status_never_becomes_security_block(self):
        with self.assertRaises(client.IntegrationError):
            client.gate_verdict({"status": "integration_error", "pass": False, "block_reasons": ["database unavailable"]})

    def test_assessment_binds_repo_and_commit(self):
        for kwargs in ({"expected_repo": "other/repo"}, {"expected_commit": "b" * 40}):
            with self.subTest(kwargs=kwargs), self.assertRaises(client.IntegrationError):
                client.gate_verdict(self.valid(), **kwargs)

    def test_missing_ci_key_prevents_network(self):
        with patch.dict(os.environ, {"GITHUB_TOKEN": "test-only", "CI_GATE_API_KEY": ""}), patch.object(client, "request_json") as request, contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(client.main(), 2)
            request.assert_not_called()

    def test_new_key_is_sent_as_bearer_and_assessment_matches(self):
        data = self.valid()
        with patch.dict(os.environ, {"GITHUB_TOKEN": "test-gh-token", "CI_GATE_API_KEY": "test-ci-key", "GITHUB_REPOSITORY": data["repo"], "GITHUB_SHA": data["commit"]}), patch.object(client, "request_json", return_value=data) as request, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(client.main(), 0)
            self.assertEqual(request.call_args.args[2], "Bearer test-ci-key")

    def test_json_body_works_without_media_type_assumptions(self):
        with patch.object(client.urllib.request, "build_opener") as opener:
            opener.return_value.open.return_value = self.response(json.dumps(self.valid()).encode())
            result = client.request_json("https://gate.invalid/api", {"branch": 'quote"\n'}, "Bearer test-only")
            self.assertTrue(result["pass"])
            request = opener.return_value.open.call_args.args[0]
            self.assertEqual(json.loads(request.data)["branch"], 'quote"\n')
            self.assertEqual(opener.return_value.open.call_args.kwargs["timeout"], 30)

    def test_bad_url_or_missing_auth_prevents_request(self):
        with patch.object(client.urllib.request, "build_opener") as opener:
            for url, auth in (("", "Bearer test-only"), ("http://gate.invalid", "Bearer test-only"), ("https://user:secret@gate.invalid", "Bearer test-only"), ("https://gate.invalid", "")):
                with self.subTest(url=url), self.assertRaises(client.IntegrationError):
                    client.request_json(url, {}, auth)
            opener.assert_not_called()

    def test_redirect_is_rejected(self):
        with self.assertRaises(client.IntegrationError):
            client.NoRedirect().redirect_request(None, None, 302, "", {}, "https://other.invalid")

    def test_non_success_and_oversized_responses_rejected(self):
        with patch.object(client.urllib.request, "build_opener") as opener:
            for response in (self.response(b"{}", 302), self.response(b"x" * (client.MAX_RESPONSE_BYTES + 1))):
                opener.return_value.open.return_value = response
                with self.assertRaises(client.IntegrationError):
                    client.request_json("https://gate.invalid", {}, "Bearer test-only")

    def test_integration_failure_has_controlled_output_and_no_secrets(self):
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / "output"
            logs = io.StringIO()
            with patch.dict(os.environ, {"GITHUB_OUTPUT": str(output), "GITHUB_TOKEN": "test-secret", "CI_GATE_API_KEY": "test-only-key"}), patch.object(client, "request_json", side_effect=client.IntegrationError("Gate endpoint returned invalid JSON")), contextlib.redirect_stderr(logs):
                self.assertEqual(client.main(), 2)
            self.assertEqual(output.read_text(), "verdict=integration_error\ncritical=0\n")
            self.assertNotIn("test-secret", logs.getvalue())

    def test_external_reasons_never_enter_outputs_or_logs(self):
        hostile = "$(touch /tmp/should-never-run)\nverdict=passed"
        data = self.valid(False)
        data["block_reasons"] = [hostile]
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / "output"
            logs = io.StringIO()
            with patch.dict(os.environ, {"GITHUB_OUTPUT": str(output), "GITHUB_TOKEN": "test-only", "CI_GATE_API_KEY": "test-only-key", "GITHUB_REPOSITORY": "Al-Rabbani/shieldai-platform", "GITHUB_SHA": "a" * 40}), patch.object(client, "request_json", return_value=data), contextlib.redirect_stdout(logs):
                self.assertEqual(client.main(), 1)
            self.assertEqual(output.read_text(), "verdict=blocked\ncritical=1\n")
            self.assertNotIn(hostile, logs.getvalue())

    def test_autofix_requires_both_policy_and_valid_block(self):
        with patch.object(client, "request_json") as request, contextlib.redirect_stderr(io.StringIO()), patch.dict(os.environ, {"GATE_VERDICT": "integration_error", "AUTOFIX_ENABLED": "true"}):
            self.assertEqual(client.main("autofix"), 2)
            request.assert_not_called()


if __name__ == "__main__":
    unittest.main()
