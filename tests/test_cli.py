from __future__ import annotations

import contextlib
import io
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from autoreviewer.cli import main
from autoreviewer.findings import finding_fingerprint
from autoreviewer.github import plan_issues
from autoreviewer.reportio import validate_report
from autoreviewer.snapshot import snapshot_repository


def finding():
    return {
        "title": "Input reaches SQL execution",
        "severity": "high",
        "file": "source.py",
        "line": 1,
        "cwe": "CWE-89",
        "description": "Request input enters a query without binding.",
        "evidence": "query(user_input)",
        "recommendation": "Use query parameters.",
        "confidence": "medium",
    }


SCRIPT = '''import json, os, pathlib, sys
model = os.environ["AUTOREVIEWER_MODEL"]
with open(sys.argv[1], "a", encoding="utf-8") as events:
    events.write(model + "\\n")
assert pathlib.Path("source.py").read_text() == "query(user_input)\\n"
assert not pathlib.Path(".env").exists()
if model == "fail":
    print("provider unavailable", file=sys.stderr)
    raise SystemExit(3)
item = FINDING
if model == "secret":
    item["title"] += " " + os.environ["AUTOREVIEWER_API_KEY"]
    item["description"] += " " + os.environ["AUTOREVIEWER_API_KEY"]
print(json.dumps({"findings": [item]}))
'''.replace("FINDING", repr(finding()))


class CliTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / "source"
        self.source.mkdir()
        (self.source / "source.py").write_text("query(user_input)\n", encoding="utf-8")
        (self.source / ".env").write_text("NOT_FOR_A_MODEL=private\n", encoding="utf-8")
        self.script = self.root / "fake_cli.py"
        self.script.write_text(SCRIPT, encoding="utf-8")
        self.events = self.root / "events.txt"
        self.config = self.root / "autoreviewer.toml"
        self.output = self.root / "report"
        self.env_patch = patch.dict(os.environ, {"CLI_MODEL_KEY": "selected-model-key-123456"})
        self.env_patch.start()
        self.addCleanup(self.env_patch.stop)

    def write_config(self, models=("one", "two"), *, agent="fake", command=None, protocol="openai-chat", key=True):
        command = command or [sys.executable, str(self.script), str(self.events)]
        text = [
            "version = 1",
            "[providers.test]",
            'base_url = "https://provider.example/v1"',
            f"api_format = {json.dumps(protocol)}",
        ]
        if key:
            text.append('api_key_env = "CLI_MODEL_KEY"')
        text += [
            f"[agents.{agent}]",
            f"command = {json.dumps(command)}",
            "[scan]",
            "concurrency = 2",
            "timeout_seconds = 5",
            "[github]",
            'repository = "owner/repo"',
            'token_env = "CLI_GITHUB_TOKEN"',
        ]
        for model in models:
            text += [
                "[[models]]",
                f"id = {json.dumps(model)}",
                'provider = "test"',
                f"model = {json.dumps(model)}",
                f"agent = {json.dumps(agent)}",
            ]
        self.config.write_text("\n".join(text) + "\n", encoding="utf-8")

    def invoke(self, args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            status = main(args)
        return status, out.getvalue(), err.getvalue()

    def scan(self, *extra):
        return self.invoke(["scan", str(self.source), "--config", str(self.config), "--output", str(self.output), *extra])

    def load_report(self):
        return json.loads((self.output / "report.json").read_text(encoding="utf-8"))

    def test_init_creates_private_config_and_preserves_existing_file(self):
        status, _, error = self.invoke(["init", "--output", str(self.config)])
        self.assertEqual(status, 0, error)
        original = self.config.read_bytes()
        self.assertIn(b"version = 1", original)
        if os.name == "posix":
            self.assertEqual(stat.S_IMODE(self.config.stat().st_mode), 0o600)
        status, _, error = self.invoke(["init", "--output", str(self.config)])
        self.assertEqual(status, 2)
        self.assertIn("exists", error)
        self.assertEqual(self.config.read_bytes(), original)

    def test_doctor_is_offline_and_reports_missing_executable_and_key(self):
        self.write_config(models=("one",), command=["autoreviewer-command-that-does-not-exist"])
        with patch.dict(os.environ, {"CLI_MODEL_KEY": ""}), patch("autoreviewer.cli.run_models") as run:
            status, output, _ = self.invoke(["doctor", "--config", str(self.config)])
        self.assertEqual(status, 2)
        self.assertIn("executable not found", output)
        self.assertIn("CLI_MODEL_KEY", output)
        run.assert_not_called()
        self.assertFalse(self.events.exists())

    def test_doctor_identifies_incompatible_api_protocol(self):
        self.write_config(models=("one",), agent="codex", command=[sys.executable], protocol="openai-chat")
        status, output, _ = self.invoke(["doctor", "--config", str(self.config)])
        self.assertEqual(status, 2)
        self.assertIn("requires api_format=openai-responses", output)
        self.assertFalse(self.events.exists())

    def test_doctor_checks_valid_custom_agent_without_running_it(self):
        self.write_config()
        status, output, error = self.invoke(["doctor", "--config", str(self.config)])
        self.assertEqual(status, 0, error)
        self.assertEqual(output.count(": ready"), 2)
        self.assertFalse(self.events.exists())

    def test_scan_runs_multiple_real_processes_and_merges_provenance(self):
        self.write_config()
        status, output, error = self.scan()
        self.assertEqual(status, 0, error)
        data = self.load_report()
        self.assertEqual(data["status"], "completed")
        self.assertEqual(len(data["runs"]), 2)
        self.assertEqual(len(data["findings"]), 1)
        self.assertEqual(data["findings"][0]["models"], ["one", "two"])
        self.assertEqual(data["findings"][0]["fingerprint"], finding_fingerprint(data["findings"][0]))
        self.assertCountEqual(self.events.read_text().splitlines(), ["one", "two"])
        self.assertEqual(len(plan_issues(data)), 1)
        self.assertIn("1 unverified finding(s)", output)
        self.assertIn("unverified hypotheses", (self.output / "report.md").read_text())
        self.assertEqual((self.source / "source.py").read_text(), "query(user_input)\n")
        self.assertGreaterEqual(data["scope"]["skipped"]["excluded"], 1)

    def test_model_filter_only_launches_the_selected_model(self):
        self.write_config(models=("one", "two", "fail"))
        status, _, error = self.scan("--model", "two", "--model", "two")
        self.assertEqual(status, 0, error)
        data = self.load_report()
        self.assertEqual([run["model"] for run in data["runs"]], ["two"])
        self.assertEqual(self.events.read_text().splitlines(), ["two"])

    def test_unknown_model_and_existing_output_fail_before_launch(self):
        self.write_config()
        status, _, error = self.scan("--model", "unknown")
        self.assertEqual(status, 2)
        self.assertIn("Unknown model", error)
        self.assertFalse(self.events.exists())
        self.output.mkdir()
        existing = self.output / "report.json"
        existing.write_text("keep this", encoding="utf-8")
        status, _, error = self.scan()
        self.assertEqual(status, 2)
        self.assertIn("already exists", error)
        self.assertEqual(existing.read_text(), "keep this")
        self.assertFalse(self.events.exists())

    def test_output_created_during_scan_is_not_overwritten(self):
        self.write_config(models=("one",))

        def competing_writer(*args, **kwargs):
            self.output.mkdir()
            (self.output / "report.json").write_text("existing report")
            return snapshot_repository(*args, **kwargs)

        with patch("autoreviewer.cli.snapshot_repository", side_effect=competing_writer):
            status, _, error = self.scan()
        self.assertEqual(status, 2)
        self.assertIn("File exists", error)
        self.assertEqual((self.output / "report.json").read_text(), "existing report")
        self.assertFalse((self.output / "report.md").exists())

    def test_partial_failure_keeps_findings_and_returns_failure_status(self):
        self.write_config(models=("one", "fail"))
        status, output, error = self.scan()
        self.assertEqual(status, 2, error)
        data = self.load_report()
        self.assertEqual(data["status"], "partial")
        self.assertEqual([run["status"] for run in data["runs"]], ["completed", "failed"])
        self.assertEqual(len(data["findings"]), 1)
        self.assertIn("provider unavailable", data["runs"][1]["error"])
        self.assertIn("partial", output)
        with self.assertRaises(ValueError):
            plan_issues(data)
        self.assertEqual(len(plan_issues(data, allow_partial=True)), 1)

    def test_all_failed_scan_does_not_claim_a_clean_audit(self):
        self.write_config(models=("fail",))
        status, _, _ = self.scan()
        self.assertEqual(status, 2)
        data = self.load_report()
        self.assertEqual(data["status"], "failed")
        self.assertEqual(data["findings"], [])
        self.assertIn("not clean audit results", (self.output / "report.md").read_text())

    @unittest.skipUnless(os.name == "posix", "Real SIGINT regression uses POSIX process groups")
    def test_sigint_saves_completed_results_and_cleans_up_active_models(self):
        self.write_config(models=("one", "slow", "queued"))
        self.config.write_text(self.config.read_text().replace("concurrency = 2", "concurrency = 1"))
        marker = self.root / "slow-model.json"
        pause = ("if model == 'slow':\n"
                 "    import time\n"
                 f"    pathlib.Path({str(marker)!r}).write_text(json.dumps(dict(pid=os.getpid(), workspace=str(pathlib.Path.cwd()))))\n"
                 "    time.sleep(60)\n")
        self.script.write_text(SCRIPT.replace("item = ", pause + "item = ", 1))
        env = {**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src")}
        process = subprocess.Popen(
            [sys.executable, "-m", "autoreviewer", "scan", str(self.source),
             "--config", str(self.config), "--output", str(self.output)],
            env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        child = None
        try:
            deadline = time.monotonic() + 10
            while not marker.exists():
                if process.poll() is not None or time.monotonic() > deadline:
                    self.fail("Slow fixture did not start after the first model completed")
                time.sleep(0.02)
            # Concurrency=1 guarantees the first model's terminal event arrived
            # before the slow fixture started. The third model remains queued.
            child = json.loads(marker.read_text())
            process.send_signal(signal.SIGINT)
            output, error = process.communicate(timeout=10)
            self.assertEqual(process.returncode, 130, output + error)
            self.assertIn("completed results were saved", error)
            report = validate_report(self.load_report())
            self.assertTrue(report["cancelled"])
            self.assertEqual(report["status"], "partial")
            self.assertEqual([run["status"] for run in report["runs"]], ["completed", "cancelled", "cancelled"])
            self.assertEqual(len(report["findings"]), 1)
            self.assertEqual(report["findings"][0]["models"], ["one"])
            self.assertEqual(report["target"], str(self.source))
            self.assertIsNotNone(report["scope"])
            self.assertFalse(Path(child["workspace"]).exists())
            with self.assertRaises(ProcessLookupError):
                os.kill(child["pid"], 0)
        finally:
            if process.poll() is None:
                process.kill()
            process.communicate()
            if child:
                try:
                    os.killpg(child["pid"], signal.SIGKILL)
                except ProcessLookupError:
                    pass

    def test_interrupt_before_preparation_records_cancelled_models_without_clean_result(self):
        self.write_config()
        with patch("autoreviewer.cli.prepare_target", side_effect=KeyboardInterrupt):
            status, _, error = self.scan()
        self.assertEqual(status, 130, error)
        report = validate_report(self.load_report())
        self.assertTrue(report["cancelled"])
        self.assertEqual(report["status"], "failed")
        self.assertEqual([run["status"] for run in report["runs"]], ["cancelled", "cancelled"])
        self.assertEqual(report["findings"], [])
        self.assertIsNone(report["scope"])
        self.assertFalse(self.events.exists())

    def test_secret_redaction_preserves_publishable_fingerprints(self):
        self.write_config(models=("secret",))
        secret = 'model-secret-with-quote"and-slash\\'
        with patch.dict(os.environ, {"CLI_MODEL_KEY": secret}):
            status, _, error = self.scan()
        self.assertEqual(status, 0, error)
        data = self.load_report()
        item = data["findings"][0]
        self.assertIn("[REDACTED]", item["title"])
        self.assertNotIn(secret, json.dumps(data))
        self.assertEqual(item["fingerprint"], finding_fingerprint(item))
        self.assertEqual(len(plan_issues(data)), 1)

    def test_secret_matching_digest_does_not_corrupt_derived_fingerprint(self):
        self.write_config(models=("one",))
        digest = finding_fingerprint(finding())
        with patch.dict(os.environ, {"CLI_MODEL_KEY": digest[:8]}):
            status, _, error = self.scan()
        self.assertEqual(status, 0, error)
        data = self.load_report()
        for item in [data["findings"][0], data["runs"][0]["findings"][0]]:
            self.assertEqual(item["fingerprint"], finding_fingerprint(item))
        self.assertEqual(len(plan_issues(data)), 1)

    def test_publish_preview_needs_no_credentials_or_network(self):
        self.write_config(models=("one",))
        self.assertEqual(self.scan()[0], 0)
        with patch.dict(os.environ, {}, clear=True), patch("autoreviewer.cli.publish_issues") as publish, patch("autoreviewer.github.build_opener") as opener:
            status, output, error = self.invoke(["publish", str(self.output / "report.json"), "--config", str(self.config)])
        self.assertEqual(status, 0, error)
        result = json.loads(output)
        self.assertTrue(result["dry_run"])
        self.assertEqual(result["repository"], "owner/repo")
        self.assertEqual(len(result["issues"]), 1)
        publish.assert_not_called()
        opener.assert_not_called()
        self.assertFalse((self.output / "github-publications.json").exists())

    def test_publish_yes_invokes_explicit_write_path(self):
        self.write_config(models=("one",))
        self.assertEqual(self.scan()[0], 0)
        with patch("autoreviewer.cli.publish_issues", return_value=[{"status": "created", "url": "https://github.com/owner/repo/issues/1"}]) as publish:
            status, output, error = self.invoke(["publish", str(self.output / "report.json"), "--config", str(self.config), "--yes", "--allow-partial"])
        self.assertEqual(status, 0, error)
        self.assertEqual(json.loads(output)["issues"][0]["status"], "created")
        publish.assert_called_once()
        self.assertEqual(publish.call_args.args[1].repository, "owner/repo")
        self.assertTrue(publish.call_args.kwargs["allow_partial"])
        self.assertEqual(publish.call_args.kwargs["receipt_path"], self.output / "github-publications.json")

    def test_repeat_publish_uses_saved_receipt_when_issue_list_is_empty(self):
        self.write_config(models=("one",))
        self.assertEqual(self.scan()[0], 0)
        remote = {}
        posts = []

        def request(method, path, payload=None):
            if method == "GET" and path == "/repos/owner/repo":
                return {"has_issues": True, "archived": False}
            if method == "GET" and path.startswith("/repos/owner/repo/issues?"):
                return []
            if method == "POST" and path == "/repos/owner/repo/issues":
                posts.append(payload)
                remote.update({**payload, "number": 7, "state": "open"})
                return dict(remote)
            if method == "GET" and path == "/repos/owner/repo/issues/7":
                return dict(remote)
            self.fail(f"Unexpected GitHub request: {method} {path}")

        command = ["publish", str(self.output / "report.json"), "--config", str(self.config), "--yes"]
        with patch.dict(os.environ, {"CLI_GITHUB_TOKEN": "fixture-token"}), patch("autoreviewer.github._Client.request", side_effect=request):
            first_status, first_output, first_error = self.invoke(command)
            self.assertEqual(first_status, 0, first_error)
            self.assertTrue((self.output / "github-publications.json").is_file())
            remote["state"] = "closed"
            second_status, second_output, second_error = self.invoke(command)
        self.assertEqual(second_status, 0, second_error)
        first = json.loads(first_output)["issues"][0]
        second = json.loads(second_output)["issues"][0]
        self.assertEqual(first["status"], "created")
        self.assertEqual(second["status"], "existing")
        self.assertEqual(first["url"], second["url"])
        self.assertEqual(len(posts), 1)
        self.assertEqual(remote["state"], "closed")

    def test_publish_rejects_contradictory_status_and_aggregate_before_preview_or_write(self):
        self.write_config(models=("one",))
        self.assertEqual(self.scan()[0], 0)
        path = self.output / "report.json"
        original = path.read_text()
        for contradiction in ("failed_model", "changed_evidence", "checkpoint"):
            for publish_args in ([], ["--yes"]):
                with self.subTest(contradiction=contradiction, publish_args=publish_args):
                    report = json.loads(original)
                    if contradiction == "failed_model":
                        report["runs"][0]["status"] = "failed"
                        report["runs"][0]["findings"] = []
                    elif contradiction == "changed_evidence":
                        report["findings"][0]["evidence"] = "Evidence not produced by any recorded model"
                    else:
                        report["checkpoint"] = True
                    path.write_text(json.dumps(report))
                    with patch("autoreviewer.cli.plan_issues") as preview, patch("autoreviewer.cli.publish_issues") as publish:
                        status, _, error = self.invoke(["publish", str(path), "--config", str(self.config), *publish_args])
                    self.assertEqual(status, 2)
                    self.assertIn("Invalid saved report", error)
                    preview.assert_not_called()
                    publish.assert_not_called()

    def test_invalid_reports_fail_gracefully_without_publication(self):
        self.write_config()
        invalid = self.root / "invalid.json"
        for contents in (b"not JSON", b"\xff", b"[]", b'{"schema_version":1,"schema_version":2}', b"[" * 2000 + b"]" * 2000):
            with self.subTest(contents=contents[:40]), patch("autoreviewer.cli.publish_issues") as publish:
                invalid.write_bytes(contents)
                status, _, error = self.invoke(["publish", str(invalid), "--config", str(self.config)])
                self.assertEqual(status, 2)
                self.assertIn("autoreviewer:", error)
                self.assertNotIn("Traceback", error)
                publish.assert_not_called()

    def test_invalid_finding_types_fail_gracefully(self):
        self.write_config(models=("one",))
        self.assertEqual(self.scan()[0], 0)
        path = self.output / "report.json"
        original = path.read_text(encoding="utf-8")
        for field, value in (("severity", []), ("confidence", {}), ("models", {}), ("line", "1")):
            with self.subTest(field=field):
                data = json.loads(original)
                data["findings"][0][field] = value
                path.write_text(json.dumps(data), encoding="utf-8")
                status, _, error = self.invoke(["publish", str(path), "--config", str(self.config)])
                self.assertEqual(status, 2)
                self.assertIn("autoreviewer:", error)
                self.assertNotIn("Traceback", error)


if __name__ == "__main__":
    unittest.main()
