"""Exercise the local HTTP boundary without external services or model calls."""

from __future__ import annotations

import copy
import http.client
import json
import threading
import unittest
from unittest.mock import patch

from autoreviewer.web import LocalWebServer


JOB_ID = "a" * 32


class ConfigurationConflict(ValueError):
    status_code = 409


class FakeService:
    """A deliberately small service double: routing must not execute commands."""

    def __init__(self):
        self.calls = []
        self.error = None
        self.config = {"version": 1}
        self.config_revision = 0
        self.job = {
            "id": JOB_ID,
            "target": "/tmp/example",
            "status": "completed",
            "runs": [],
            "events": [],
            "report": None,
        }
        self.report = {
            "schema_version": 1,
            "target": "<script>alert('untrusted target')</script>",
            "status": "completed",
            "runs": [],
            "findings": [],
        }

    def bootstrap(self):
        return {
            "version": "0.1.0",
            "config": copy.deepcopy(self.config),
            "config_revision": self.config_revision,
            "credentials": [{"name": "TEST_KEY", "configured": False, "source": "missing"}],
            "agents": [],
            "jobs": [copy.deepcopy(self.job)],
        }

    def list_jobs(self):
        if self.error:
            raise self.error
        return [copy.deepcopy(self.job)]

    def get_job(self, job_id):
        self.calls.append(("get_job", job_id))
        return copy.deepcopy(self.job)

    def save_config(self, config, *, expected_revision=None):
        self.calls.append(("save_config", config, expected_revision))
        if expected_revision != self.config_revision:
            raise ConfigurationConflict("Configuration changed; reload before saving")
        self.config = copy.deepcopy(config)
        self.config_revision += 1
        return {"config": config, "config_revision": self.config_revision, "credentials": [], "agents": []}

    def set_credential(self, name, value):
        self.calls.append(("set_credential", name, value))
        return {"credentials": [{"name": name, "configured": bool(value), "source": "session"}]}

    def start_job(self, payload):
        self.calls.append(("start_job", payload))
        return {**self.job, "status": "queued"}

    def cancel_job(self, job_id):
        self.calls.append(("cancel_job", job_id))
        return {**self.job, "status": "cancelling"}

    def retry_job(self, job_id, payload):
        self.calls.append(("retry_job", job_id, payload))
        return {**self.job, "id": "b" * 32, "parent_job_id": job_id, "status": "queued"}

    def import_report(self, payload):
        self.calls.append(("import_report", payload))
        return {**self.job, "origin": "imported", "report": payload["report"]}

    def export_config(self):
        self.calls.append(("export_config",))
        return 'version = 1\n[providers.fixture]\napi_key_env = "TEST_KEY"\n'

    def get_report(self, job_id):
        self.calls.append(("get_report", job_id))
        return copy.deepcopy(self.report)

    def preview_issues(self, job_id, payload):
        self.calls.append(("preview_issues", job_id, payload))
        return {"repository": "owner/repo", "issues": [], "preview_id": "preview-opaque"}

    def publish_issues(self, job_id, payload):
        self.calls.append(("publish_issues", job_id, payload))
        return {"repository": "owner/repo", "issues": []}

    def close(self):
        pass


class LocalWebTests(unittest.TestCase):
    def setUp(self):
        self.service = FakeService()
        self.server = LocalWebServer(("127.0.0.1", 0), self.service)
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        self.thread.start()
        self.addCleanup(self.stop_server)
        self.host = f"127.0.0.1:{self.server.server_address[1]}"
        self.origin = f"http://{self.host}"
        status, _, body = self.request("GET", "/api/bootstrap", authenticated=False)
        self.assertEqual(status, 200)
        self.token = json.loads(body)["csrf_token"]

    def stop_server(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)
        self.assertFalse(self.thread.is_alive())

    def request(self, method, path, *, payload=None, raw=None, headers=None, authenticated=True):
        supplied = dict(headers or {})
        if authenticated:
            supplied.setdefault("X-Autoreviewer-Token", self.token)
        if payload is not None:
            raw = json.dumps(payload).encode("utf-8")
        if raw is not None:
            supplied.setdefault("Content-Type", "application/json")
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_address[1], timeout=3)
        try:
            connection.request(method, path, body=raw, headers=supplied)
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            connection.close()

    def test_bootstrap_provides_session_token_without_credentials(self):
        status, headers, body = self.request("GET", "/api/bootstrap", authenticated=False)
        data = json.loads(body)
        self.assertEqual(status, 200)
        self.assertIsInstance(data["csrf_token"], str)
        self.assertGreaterEqual(len(data["csrf_token"]), 32)
        self.assertEqual(data["csrf_token"], self.token)
        self.assertEqual(data["config_revision"], 0)
        self.assertEqual(data["credentials"], self.service.bootstrap()["credentials"])
        self.assertIn("no-store", headers["Cache-Control"])
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
        self.assertNotIn("Access-Control-Allow-Origin", headers)

    def test_every_sensitive_get_requires_the_session_token(self):
        for path in ("/api/jobs", f"/api/jobs/{JOB_ID}", f"/api/jobs/{JOB_ID}/report?format=json", "/api/config/export"):
            with self.subTest(path=path):
                status, _, body = self.request("GET", path, authenticated=False)
                self.assertEqual(status, 403)
                self.assertIn("error", json.loads(body))
                status, _, _ = self.request("GET", path, headers={"X-Autoreviewer-Token": "wrong-session"})
                self.assertEqual(status, 403)
        self.assertEqual(self.service.calls, [])

    def test_mutations_cannot_use_missing_or_other_session_tokens(self):
        for path, method in (("/api/jobs", "POST"), ("/api/config", "PUT"), ("/api/credentials", "PUT"),
                             ("/api/reports/import", "POST"), (f"/api/jobs/{JOB_ID}/retry", "POST")):
            with self.subTest(path=path):
                status, _, _ = self.request(method, path, payload={}, authenticated=False)
                self.assertEqual(status, 403)
        self.assertEqual(self.service.calls, [])

    def test_non_ascii_session_token_is_an_authentication_failure(self):
        status, _, body = self.request("GET", "/api/jobs", headers={"X-Autoreviewer-Token": "\u00e9-not-a-token"})
        self.assertEqual(status, 403)
        self.assertIn("error", json.loads(body))

    def test_server_rejects_non_loopback_binding(self):
        for address in ("0.0.0.0", "::", "192.0.2.1"):
            with self.subTest(address=address), self.assertRaises(ValueError):
                LocalWebServer((address, 0), self.service)

    def test_duplicate_security_headers_and_lengths_are_rejected(self):
        for header, values, method, path, status in (
            ("Host", [self.host, "attacker.example"], "GET", "/api/bootstrap", 403),
            ("Origin", [self.origin, self.origin], "GET", "/api/bootstrap", 403),
            ("X-Autoreviewer-Token", [self.token, self.token], "GET", "/api/jobs", 403),
            ("Content-Length", ["2", "2"], "POST", "/api/jobs", 400),
        ):
            with self.subTest(header=header):
                connection = http.client.HTTPConnection("127.0.0.1", self.server.server_address[1], timeout=3)
                try:
                    connection.putrequest(method, path, skip_host=True)
                    if header != "Host":
                        connection.putheader("Host", self.host)
                    if header != "X-Autoreviewer-Token":
                        connection.putheader("X-Autoreviewer-Token", self.token)
                    if method == "POST":
                        connection.putheader("Content-Type", "application/json")
                    for value in values:
                        connection.putheader(header, value)
                    connection.endheaders(b"{}" if method == "POST" else None)
                    response = connection.getresponse()
                    self.assertEqual(response.status, status)
                    self.assertIn("error", json.loads(response.read()))
                finally:
                    connection.close()
        self.assertEqual(self.service.calls, [])

    def test_host_validation_blocks_dns_rebinding_including_bootstrap(self):
        for host in ("attacker.example", "127.0.0.1.attacker.example", "localhost.attacker.example", "127.0.0.1:1"):
            with self.subTest(host=host):
                for path in ("/", "/api/bootstrap", "/api/jobs"):
                    status, _, _ = self.request("GET", path, headers={"Host": host})
                    self.assertIn(status, (400, 403))

    def test_cross_origin_and_cross_site_requests_are_rejected_even_with_token(self):
        for headers in (
            {"Origin": "https://attacker.example"},
            {"Origin": "null"},
            {"Origin": "http://127.0.0.1:1"},
            {"Sec-Fetch-Site": "cross-site"},
        ):
            with self.subTest(headers=headers):
                status, _, _ = self.request("GET", "/api/bootstrap", headers=headers, authenticated=False)
                self.assertEqual(status, 403)
                status, _, _ = self.request("POST", "/api/jobs", payload={}, headers=headers)
                self.assertEqual(status, 403)
        self.assertEqual(self.service.calls, [])

    def test_localhost_alias_and_matching_origin_work(self):
        host = f"localhost:{self.server.server_address[1]}"
        status, _, body = self.request("GET", "/api/jobs", headers={"Host": host, "Origin": f"http://{host}"})
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["jobs"][0]["id"], JOB_ID)

    def test_static_assets_have_security_headers_and_do_not_require_token(self):
        for path, media_type in (("/", "text/html"), ("/app.js", "javascript"), ("/styles.css", "text/css")):
            with self.subTest(path=path):
                status, headers, body = self.request("GET", path, authenticated=False)
                self.assertEqual(status, 200)
                self.assertTrue(body)
                self.assertIn(media_type, headers["Content-Type"])
                self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
                self.assertEqual(headers["X-Frame-Options"], "DENY")
                csp = headers["Content-Security-Policy"]
                self.assertIn("script-src 'self'", csp)
                self.assertIn("style-src 'self'", csp)
                self.assertIn("frame-ancestors 'none'", csp)
                self.assertNotIn("'unsafe-inline'", csp)
                self.assertNotIn("Access-Control-Allow-Origin", headers)

    def test_static_allowlist_does_not_expose_python_config_or_path_traversal(self):
        for path in ("/web.py", "/autoreviewer.toml", "/../webservice.py", "/%2e%2e/webservice.py", "/static/../web.py"):
            with self.subTest(path=path):
                status, _, _ = self.request("GET", path, authenticated=False)
                self.assertEqual(status, 404)

    def test_json_routes_delegate_exact_objects_without_executing_shell_text(self):
        config = {"version": 1, "models": [{"model": "model; $(not-a-shell-command)"}]}
        status, _, body = self.request("PUT", "/api/config", payload={"config": config, "revision": 0})
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["config"], config)
        self.assertEqual(json.loads(body)["config_revision"], 1)
        self.assertEqual(self.service.calls[-1], ("save_config", config, 0))

        payload = {"target": "/tmp/a folder;$(no-execution)", "models": ["one"], "concurrency": 1}
        status, _, body = self.request("POST", "/api/jobs", payload=payload, headers={"Origin": self.origin})
        self.assertEqual(status, 202)
        self.assertEqual(json.loads(body)["status"], "queued")
        self.assertEqual(self.service.calls[-1], ("start_job", payload))

        status, _, body = self.request("GET", f"/api/jobs/{JOB_ID}")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["id"], JOB_ID)
        self.assertEqual(self.service.calls[-1], ("get_job", JOB_ID))

        status, _, body = self.request("POST", f"/api/jobs/{JOB_ID}/cancel", payload={})
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["status"], "cancelling")
        self.assertEqual(self.service.calls[-1], ("cancel_job", JOB_ID))

    def test_configuration_save_requires_an_explicit_valid_revision(self):
        for payload in (
            {"config": {"version": 1}},
            {"config": {"version": 1}, "revision": None},
            {"config": {"version": 1}, "revision": True},
            {"config": {"version": 1}, "revision": -1},
            {"config": {"version": 1}, "revision": 0.0},
            {"config": {"version": 1}, "revision": "0"},
            {"config": {"version": 1}, "revision": 0, "extra": "value"},
            {"config": [], "revision": 0},
        ):
            with self.subTest(payload=payload):
                status, _, body = self.request("PUT", "/api/config", payload=payload)
                self.assertEqual(status, 400)
                self.assertIn("error", json.loads(body))
        self.assertEqual(self.service.calls, [])

    def test_stale_configuration_save_returns_conflict_without_overwriting(self):
        first = {"version": 1, "providers": {"new-provider": {"base_url": "https://example.invalid/v1"}}}
        status, _, body = self.request("PUT", "/api/config", payload={"config": first, "revision": 0})
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["config_revision"], 1)
        stale = {"version": 1, "models": [{"model": "edit-in-stale-tab"}]}
        status, _, body = self.request("PUT", "/api/config", payload={"config": stale, "revision": 0})
        self.assertEqual(status, 409)
        self.assertIn("error", json.loads(body))
        self.assertEqual(self.service.config, first)
        self.assertEqual(self.service.calls[-1], ("save_config", stale, 0))
        status, _, body = self.request("GET", "/api/bootstrap", authenticated=False)
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["config_revision"], 1)
        self.assertEqual(json.loads(body)["config"], first)

    def test_credential_entry_does_not_echo_secret_in_response(self):
        secret = "session-only-test-secret-123456"
        status, _, body = self.request("PUT", "/api/credentials", payload={"name": "TEST_KEY", "value": secret})
        self.assertEqual(status, 200)
        self.assertNotIn(secret.encode(), body)
        self.assertTrue(json.loads(body)["credentials"][0]["configured"])
        self.assertEqual(self.service.calls[-1], ("set_credential", "TEST_KEY", secret))

    def test_report_import_only_delegates_to_import_and_keeps_source_text_inert(self):
        report = {**self.service.report, "target": "https://github.com/owner/repo;$(not-a-command)"}
        payload = {"name": "<script>report.json</script>", "report": report}
        status, headers, body = self.request("POST", "/api/reports/import", payload=payload)
        self.assertEqual(status, 201)
        self.assertEqual(json.loads(body)["report"], report)
        self.assertEqual(json.loads(body)["origin"], "imported")
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(self.service.calls, [("import_report", payload)])

    def test_retry_uses_explicit_new_job_route_and_retains_parent(self):
        for mode in ("failed", "all"):
            with self.subTest(mode=mode):
                payload = {"mode": mode}
                status, _, body = self.request("POST", f"/api/jobs/{JOB_ID}/retry", payload=payload)
                self.assertEqual(status, 202)
                job = json.loads(body)
                self.assertEqual(job["parent_job_id"], JOB_ID)
                self.assertNotEqual(job["id"], JOB_ID)
                self.assertEqual(self.service.calls[-1], ("retry_job", JOB_ID, payload))
        self.assertNotIn("start_job", [call[0] for call in self.service.calls])

    def test_config_export_is_private_toml_attachment(self):
        status, headers, body = self.request("GET", "/api/config/export")
        self.assertEqual(status, 200)
        self.assertIn("text/toml", headers["Content-Type"])
        self.assertEqual(headers["Content-Disposition"], 'attachment; filename="autoreviewer.toml"')
        self.assertIn("no-store", headers["Cache-Control"])
        self.assertIn(b'api_key_env = "TEST_KEY"', body)
        self.assertEqual(self.service.calls, [("export_config",)])

    def test_import_large_body_allowance_does_not_expand_other_mutation_limits(self):
        payload = {"report": {"description": "x" * 180}}
        with patch("autoreviewer.web.MAX_BODY_BYTES", 128), patch("autoreviewer.web.MAX_IMPORT_BODY_BYTES", 256):
            status, _, _ = self.request("POST", "/api/reports/import", payload=payload)
            self.assertEqual(status, 201)
            for path in ("/api/jobs", f"/api/jobs/{JOB_ID}/retry", "/api/reports/import-extra"):
                with self.subTest(path=path):
                    status, _, _ = self.request("POST", path, payload=payload)
                    self.assertEqual(status, 413)
            status, _, _ = self.request("POST", "/api/reports/import", payload={"report": {"description": "x" * 300}})
            self.assertEqual(status, 413)
        self.assertEqual(self.service.calls, [("import_report", payload)])

    def test_new_routes_reject_cross_origin_requests_even_with_a_valid_token(self):
        for method, path, payload in (("POST", "/api/reports/import", {"report": {}}),
                                      ("POST", f"/api/jobs/{JOB_ID}/retry", {"mode": "failed"}),
                                      ("GET", "/api/config/export", None)):
            with self.subTest(path=path):
                for headers in ({"Origin": "https://attacker.example"}, {"Sec-Fetch-Site": "cross-site"}):
                    status, _, _ = self.request(method, path, payload=payload, headers=headers)
                    self.assertEqual(status, 403)
        self.assertEqual(self.service.calls, [])

    def test_import_json_validation_occurs_before_service_calls(self):
        for body in (b"[]", b"null", b'{"report":{},"report":{}}', b'{"report":{"value":NaN}}', b"not JSON"):
            with self.subTest(body=body):
                status, _, response = self.request("POST", "/api/reports/import", raw=body)
                self.assertEqual(status, 400)
                self.assertIn("error", json.loads(response))
        self.assertEqual(self.service.calls, [])

    def test_new_routes_reject_wrong_http_methods_without_side_effects(self):
        for method, path, payload in (("GET", "/api/reports/import", None),
                                      ("PUT", "/api/reports/import", {"report": {}}),
                                      ("GET", f"/api/jobs/{JOB_ID}/retry", None),
                                      ("PUT", f"/api/jobs/{JOB_ID}/retry", {"mode": "failed"}),
                                      ("POST", "/api/config/export", {})):
            with self.subTest(method=method, path=path):
                status, _, _ = self.request(method, path, payload=payload)
                self.assertEqual(status, 405)
        self.assertEqual(self.service.calls, [])

    def test_publish_requires_its_own_explicit_route_after_preview(self):
        payload = {"fingerprints": ["f" * 64], "allow_partial": True}
        status, _, body = self.request("POST", f"/api/jobs/{JOB_ID}/issues/preview", payload=payload)
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["preview_id"], "preview-opaque")
        self.assertEqual(self.service.calls, [("preview_issues", JOB_ID, payload)])
        confirmation = {"preview_id": "preview-opaque", "confirmation": "owner/repo"}
        status, _, _ = self.request("POST", f"/api/jobs/{JOB_ID}/issues/publish", payload=confirmation)
        self.assertEqual(status, 200)
        self.assertEqual(self.service.calls[-1], ("publish_issues", JOB_ID, confirmation))

    def test_report_downloads_are_attachments_and_model_content_stays_inert(self):
        status, headers, body = self.request("GET", f"/api/jobs/{JOB_ID}/report?format=json")
        self.assertEqual(status, 200)
        self.assertIn("application/json", headers["Content-Type"])
        self.assertIn("attachment", headers["Content-Disposition"])
        self.assertIn(".json", headers["Content-Disposition"])
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(json.loads(body)["target"], self.service.report["target"])
        status, headers, body = self.request("GET", f"/api/jobs/{JOB_ID}/report?format=markdown")
        self.assertEqual(status, 200)
        self.assertIn("attachment", headers["Content-Disposition"])
        self.assertIn(".md", headers["Content-Disposition"])
        self.assertIn(b"autoreviewer security review", body)
        self.assertNotIn(b"<script>", body)
        status, _, _ = self.request("GET", f"/api/jobs/{JOB_ID}/report?format=html")
        self.assertEqual(status, 400)

    def test_body_parser_rejects_malformed_ambiguous_and_non_object_json(self):
        for body in (
            b"{",
            b'{"target": "a", "target": "b"}',
            b'{"nested": {"same": 1, "same": 2}}',
            b'{"concurrency": NaN}',
            b'{"timeout_seconds": Infinity}',
            b"[]",
            b"null",
            b'"a string"',
            b'{"target": "\xff"}',
        ):
            with self.subTest(body=body):
                status, _, response = self.request("POST", "/api/jobs", raw=body)
                self.assertEqual(status, 400)
                self.assertIn("error", json.loads(response))
        self.assertEqual(self.service.calls, [])

    def test_mutation_media_type_and_body_size_are_bounded_before_dispatch(self):
        status, _, _ = self.request("POST", "/api/jobs", raw=b"{}", headers={"Content-Type": "text/plain"})
        self.assertEqual(status, 415)
        status, _, _ = self.request("POST", "/api/jobs", raw=b"{}", headers={"Content-Length": str(1024 * 1024 + 1)})
        self.assertEqual(status, 413)
        status, _, _ = self.request("POST", "/api/jobs", raw=b"{}", headers={"Transfer-Encoding": "chunked"})
        self.assertIn(status, (400, 411))
        self.assertEqual(self.service.calls, [])

    def test_errors_do_not_expose_unhandled_exception_details(self):
        self.service.error = RuntimeError("internal-file-path and SECRET-DO-NOT-RETURN")
        status, headers, body = self.request("GET", "/api/jobs")
        self.assertEqual(status, 500)
        self.assertIn("error", json.loads(body))
        self.assertNotIn(b"SECRET", body)
        self.assertNotIn(b"internal-file-path", body)
        self.assertIn("no-store", headers["Cache-Control"])

    def test_validation_errors_are_json_and_unsupported_methods_have_no_side_effects(self):
        self.service.error = ValueError("Invalid model selection")
        status, _, body = self.request("GET", "/api/jobs")
        self.assertEqual(status, 400)
        self.assertIn("error", json.loads(body))
        status, _, _ = self.request("DELETE", "/api/jobs", payload={})
        self.assertEqual(status, 405)
        status, _, _ = self.request("GET", "/api/unknown")
        self.assertEqual(status, 404)
        self.assertEqual(self.service.calls, [])

    def test_service_conflicts_keep_their_status_code(self):
        class Conflict(ValueError):
            status_code = 409

        self.service.error = Conflict("Another scan is already active")
        status, _, body = self.request("GET", "/api/jobs")
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(body)["error"], "Another scan is already active")


if __name__ == "__main__":
    unittest.main()
