from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, patch

from autoreviewer.findings import finding_fingerprint
from autoreviewer.guidance import build_audit_prompt
from autoreviewer.reportio import validate_report
from autoreviewer.runner import AUDIT_PROMPT
from autoreviewer.webservice import ServiceError, WebService, _Worker


AGENT = r'''
import json, os, pathlib, sys, time
model = sys.argv[1]
if model == "slow":
    time.sleep(30)
if model == "bad":
    sys.stderr.write("provider failed " + os.environ.get("UI_TEST_KEY", ""))
    sys.exit(2)
finding = {"title":"Input reaches SQL", "severity":"high", "file":"app.py", "line":1,
           "cwe":"CWE-89", "description":"Files: " + ",".join(sorted(str(p) for p in pathlib.Path('.').rglob('*'))) + " Key: " + os.environ.get("UI_TEST_KEY", ""),
           "evidence":"query(user_input)", "recommendation":"Use parameters", "confidence":"medium"}
print(json.dumps({"findings":[finding]}))
'''


class WebServiceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        (self.repo / "app.py").write_text("query(user_input)\n")
        self.script = self.root / "agent.py"
        self.script.write_text(AGENT)
        self.config_path = self.repo / "settings.toml"
        self.data_dir = self.repo / "interface-state"
        self.environ = patch.dict(os.environ, {"UI_TEST_KEY": "environment-test-key", "UI_GITHUB_TOKEN": "environment-github-token"})
        self.environ.start()
        self.addCleanup(self.environ.stop)
        self.service = WebService(self.config_path, self.data_dir)
        self.addCleanup(self.service.close)
        self.config = {
            "version": 1,
            "providers": {"test": {"base_url": "https://example.test/v1", "api_key_env": "UI_TEST_KEY", "api_format": "openai-chat"}},
            "agents": {"fixture": {"command": [sys.executable, str(self.script)], "args": ["{model}"]}},
            "models": [{"id": "first", "provider": "test", "model": "ok", "agent": "fixture"}],
            "scan": {"concurrency": 2, "timeout_seconds": 10},
            "github": {"repository": "owner/repo", "token_env": "UI_GITHUB_TOKEN", "labels": ["security"]},
        }
        self.service.save_config(self.config)

    def wait_for(self, job_id, predicate=None):
        predicate = predicate or (lambda job: job["status"] not in {"queued", "preparing", "running", "cancelling"})
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            job = self.service.get_job(job_id)
            if predicate(job):
                return job
            time.sleep(0.01)
        self.fail("Review did not reach its expected state")

    def start(self):
        return self.service.start_job({"target": str(self.repo), "models": [item["id"] for item in self.config["models"]]})

    def complete(self):
        return self.wait_for(self.start()["id"])

    def test_bootstrap_has_normalized_config_and_no_secret_values(self):
        state = self.service.bootstrap()
        self.assertEqual({agent["id"] for agent in state["agents"]}, {"opencode", "codex", "claude", "gemini", "fixture"})
        self.assertTrue(next(agent for agent in state["agents"] if agent["id"] == "fixture")["available"])
        self.assertEqual(state["jobs"], [])
        self.assertEqual(state["config"]["scan"]["max_output_bytes"], 4194304)
        self.assertNotIn("environment-test-key", json.dumps(state))
        state["config"]["models"][0]["id"] = "tampered"
        self.assertEqual(self.service.bootstrap()["config"]["models"][0]["id"], "first")

    def test_session_credentials_override_without_environment_or_disk_changes(self):
        status = self.service.set_credential("UI_TEST_KEY", "session-only-credential")
        self.assertEqual(next(item for item in status["credentials"] if item["name"] == "UI_TEST_KEY")["source"], "session")
        self.assertEqual(os.environ["UI_TEST_KEY"], "environment-test-key")
        job = self.complete()
        self.assertEqual(job["status"], "completed")
        self.assertIn("[REDACTED]", job["report"]["findings"][0]["description"])
        self.assertNotIn("session-only-credential", json.dumps(job))
        for path in self.repo.rglob("*"):
            if path.is_file():
                self.assertNotIn(b"session-only-credential", path.read_bytes())
        status = self.service.set_credential("UI_TEST_KEY", "")
        self.assertEqual(next(item for item in status["credentials"] if item["name"] == "UI_TEST_KEY")["source"], "environment")
        with self.assertRaises(ServiceError):
            self.service.set_credential("PATH", "oops")

    def test_config_validation_does_not_overwrite_file_or_allow_raw_keys(self):
        original = self.config_path.read_bytes()
        for replacement in ({**self.config, "api_key": "not-written"}, {**self.config, "models": []}):
            with self.assertRaises(ServiceError):
                self.service.save_config(replacement)
            self.assertEqual(self.config_path.read_bytes(), original)
        with self.assertRaises(ServiceError):
            self.service.save_config({**self.config, "providers": {"test": {"base_url": "https://x.test", "api_key": "not-written"}}})
        self.service.set_credential("UI_TEST_KEY", 'secret-with-"quote\\slash')
        raw = copy.deepcopy(self.config)
        raw["models"][0]["model"] = 'secret-with-"quote\\slash'
        with self.assertRaisesRegex(ServiceError, "credential values"):
            self.service.save_config(raw)
        self.assertEqual(self.config_path.read_bytes(), original)

    def test_config_revision_rejects_stale_saves_without_mutating_session_state(self):
        first_tab = self.service.bootstrap()
        second_tab = copy.deepcopy(first_tab)
        updated = copy.deepcopy(first_tab["config"])
        updated["scan"]["concurrency"] = 3
        saved = self.service.save_config(updated, expected_revision=first_tab["config_revision"])
        self.assertEqual(saved["config_revision"], first_tab["config_revision"] + 1)
        self.service.set_credential("UI_TEST_KEY", "retained-session-credential")
        completed = self.complete()
        preview = self.service.preview_issues(completed["id"], {"fingerprints": [completed["report"]["findings"][0]["fingerprint"]]})
        before = self.config_path.read_bytes()
        stale = second_tab["config"]
        stale.pop("github")
        stale["providers"]["test"]["api_key_env"] = "CHANGED_KEY"
        with self.assertRaises(ServiceError) as conflict:
            self.service.save_config(stale, expected_revision=second_tab["config_revision"])
        self.assertEqual(conflict.exception.status_code, 409)
        self.assertEqual(self.config_path.read_bytes(), before)
        self.assertEqual(self.service.bootstrap()["config_revision"], saved["config_revision"])
        self.assertEqual(self.service.bootstrap()["config"]["scan"]["concurrency"], 3)
        self.assertEqual(self.service._credentials["UI_TEST_KEY"], "retained-session-credential")
        self.assertIn(preview["preview_id"], self.service._previews)
        for invalid in (True, -1, "1", 1.5):
            with self.subTest(revision=invalid), self.assertRaises(ServiceError):
                self.service.save_config(updated, expected_revision=invalid)
        self.assertEqual(self.config_path.read_bytes(), before)
        self.assertIn(preview["preview_id"], self.service._previews)

    def test_live_fixture_scan_excludes_config_and_history_and_preserves_report(self):
        (self.data_dir / "private.txt").write_text("must never become a scan input")
        job = self.complete()
        self.assertEqual(job["status"], "completed")
        self.assertEqual(job["report"]["scope"]["files"], 1)
        self.assertNotIn("settings.toml", job["report"]["findings"][0]["description"])
        self.assertNotIn("private.txt", job["report"]["findings"][0]["description"])
        self.assertEqual({event["status"] for event in job["events"]}, {"queued", "preparing", "running", "completed"})
        self.assertEqual(job["finding_count"], 1)
        saved = self.data_dir / "jobs" / job["id"]
        self.assertTrue((saved / "report.md").is_file())
        self.assertEqual(json.loads((saved / "report.json").read_text())["status"], "completed")
        metadata = json.loads((saved / "job.json").read_text())
        self.assertNotIn("report", metadata)
        self.assertNotIn("findings", metadata["runs"][0])
        self.service.close()
        reloaded = WebService(self.config_path, self.data_dir)
        self.addCleanup(reloaded.close)
        self.assertEqual(reloaded.get_report(job["id"])["findings"], job["report"]["findings"])
        self.assertEqual(reloaded.list_jobs()[0]["finding_count"], 1)
        if os.name == "posix":
            self.assertEqual(self.config_path.stat().st_mode & 0o777, 0o600)
            self.assertEqual((saved / "job.json").stat().st_mode & 0o777, 0o600)

    def test_local_guidance_survives_short_credential_redaction_and_reload(self):
        _, expected = build_audit_prompt(AUDIT_PROMPT)
        # This public commit prefix is deliberately also a configured secret.
        self.service.set_credential("UI_TEST_KEY", expected["commit"][:2])
        checkpoints = []
        save_progress = self.service._save_progress

        def capture_checkpoint(job, *, checkpoint=False):
            if checkpoint:
                checkpoints.append(copy.deepcopy(job["report"]))
            return save_progress(job, checkpoint=checkpoint)

        with patch.object(self.service, "_save_progress", side_effect=capture_checkpoint):
            job = self.complete()
        self.assertEqual(job["status"], "completed", job)
        self.assertTrue(checkpoints)
        for checkpoint in checkpoints:
            validate_report(checkpoint, allow_checkpoint=True)
            self.assertEqual(checkpoint["runs"][0]["audit_guidance"], expected)
        self.assertEqual(job["runs"][0]["audit_guidance"], expected)
        self.assertEqual(job["report"]["runs"][0]["audit_guidance"], expected)
        self.assertIn("Key: [REDACTED]", job["report"]["findings"][0]["description"])
        validate_report(job["report"])
        saved = self.data_dir / "jobs" / job["id"] / "report.json"
        self.assertEqual(json.loads(saved.read_text())["runs"][0]["audit_guidance"], expected)
        self.service.close()
        reloaded = WebService(self.config_path, self.data_dir)
        self.addCleanup(reloaded.close)
        self.assertEqual(reloaded.get_report(job["id"])["runs"][0]["audit_guidance"], expected)

    def test_partial_results_keep_model_errors_separate(self):
        self.config["models"].append({"id": "second", "provider": "test", "model": "bad", "agent": "fixture"})
        self.service.save_config(self.config)
        job = self.complete()
        self.assertEqual(job["status"], "partial")
        self.assertEqual([run["status"] for run in job["runs"]], ["completed", "failed"])
        self.assertEqual(len(job["report"]["findings"]), 1)
        self.assertIn("[REDACTED]", job["runs"][1]["error"])
        self.assertEqual(self.service.list_jobs()[0]["completed_models"], 1)

    def test_repeated_cancel_preserves_completed_results_and_rejects_concurrent_scan(self):
        self.config["models"].append({"id": "second", "provider": "test", "model": "slow", "agent": "fixture"})
        self.service.save_config(self.config)
        job = self.start()
        self.wait_for(job["id"], lambda value: value["runs"][0]["status"] == "completed" and value["runs"][1]["status"] == "running")
        with self.assertRaises(ServiceError) as blocked:
            self.start()
        self.assertEqual(blocked.exception.status_code, 409)
        self.service.cancel_job(job["id"])
        self.service.cancel_job(job["id"])
        result = self.wait_for(job["id"])
        self.assertEqual(result["status"], "cancelled")
        self.assertEqual(result["report"]["status"], "partial")
        self.assertEqual(result["runs"][1]["status"], "cancelled")
        self.assertEqual(len(result["report"]["findings"]), 1)
        self.assertEqual(sum(event["status"] == "cancelling" for event in result["events"]), 1)

    def test_start_validation_never_persists_credentials_or_invalid_refs(self):
        invalid = [
            {"target": "https://environment-test-key@github.com/owner/repo"},
            {"target": str(self.repo / "environment-test-key")},
            {"target": "https://github.com/owner/repo", "ref": "environment-test-key"},
            {"target": "https://github.com/owner/repo", "ref": "bad\nref"},
            {"target": "https://github.com/owner/repo", "ref": "x" * 201},
            {"target": "https://github.com/owner/repo", "ref": False},
            {"target": str(self.repo), "models": []},
            {"target": str(self.repo), "models": ["missing"]},
            {"target": str(self.repo), "concurrency": True},
        ]
        for payload in invalid:
            with self.subTest(payload=payload):
                with self.assertRaises(ServiceError):
                    self.service.start_job(payload)
        self.assertEqual(self.service.list_jobs(), [])

    def test_failed_task_creation_rolls_back_and_allows_retry(self):
        with patch.object(self.service, "_persist", side_effect=OSError("disk full")):
            with self.assertRaises(ServiceError):
                self.start()
        self.assertEqual(self.service.list_jobs(), [])
        with patch("autoreviewer.webservice.threading.Thread.start", side_effect=RuntimeError("thread unavailable")):
            with self.assertRaises(ServiceError):
                self.start()
        self.assertEqual(self.service.list_jobs(), [])
        self.assertEqual(self.complete()["status"], "completed")

    def test_data_directory_descendants_cannot_be_scanned(self):
        nested = self.data_dir / "jobs" / "data"
        nested.mkdir(parents=True)
        (nested / "app.py").write_text("private_report_data()\n")
        job = self.service.start_job({"target": str(nested)})
        result = self.wait_for(job["id"])
        self.assertEqual(result["status"], "failed")
        self.assertIn("data directory", result["error"])
        self.assertIsNone(result["report"]["scope"])

    def test_history_marks_interrupted_and_ignores_corrupt_runs(self):
        completed = self.complete()
        metadata_path = self.data_dir / "jobs" / completed["id"] / "job.json"
        self.service.close()
        metadata = json.loads(metadata_path.read_text())
        metadata["status"] = "running"
        metadata["runs"][0]["status"] = "running"
        metadata_path.write_text(json.dumps(metadata))
        (metadata_path.parent / "report.json").unlink()
        reloaded = WebService(self.config_path, self.data_dir)
        self.addCleanup(reloaded.close)
        self.assertEqual(reloaded.get_job(completed["id"])["status"], "interrupted")
        reloaded.close()
        metadata["runs"] = [None]
        metadata_path.write_text(json.dumps(metadata))
        corrupt = WebService(self.config_path, self.data_dir)
        self.addCleanup(corrupt.close)
        self.assertEqual(corrupt.list_jobs(), [])

    def test_corrupt_saved_report_does_not_break_task_history(self):
        completed = self.complete()
        self.service.close()
        path = self.data_dir / "jobs" / completed["id"] / "report.json"
        for changes in ({"runs": [None]}, {"findings": [None]}, {"duration": float("nan")}):
            with self.subTest(changes=changes):
                report = {**completed["report"], **changes}
                path.write_text(json.dumps(report))
                reloaded = WebService(self.config_path, self.data_dir)
                self.addCleanup(reloaded.close)
                self.assertEqual(len(reloaded.list_jobs()), 1)
                self.assertIsNone(reloaded.get_job(completed["id"])["report"])
                self.assertIn("No readable saved report", reloaded.get_job(completed["id"])["persistence_error"])
                with self.assertRaises(ServiceError):
                    reloaded.get_report(completed["id"])
                reloaded.close()

    def test_corrupt_final_report_falls_back_to_valid_checkpoint(self):
        completed = self.complete()
        self.service.close()
        checkpoint = copy.deepcopy(completed["report"])
        checkpoint["checkpoint"] = True
        checkpoint["status"] = "partial"
        checkpoint["runs"].append({**copy.deepcopy(checkpoint["runs"][0]), "model": "unfinished", "status": "running", "findings": []})
        original_folder = self.data_dir / "jobs" / completed["id"]
        metadata = json.loads((original_folder / "job.json").read_text())
        metadata["status"] = "running"
        metadata["runs"].append({"model": "unfinished", "status": "running"})
        corrupt_reports = ["{broken", json.dumps({**completed["report"], "findings": []})]
        for index, corrupt in enumerate(corrupt_reports):
            with self.subTest(corruption=index):
                history = self.root / f"recovery-{index}"
                shutil.copytree(self.data_dir, history)
                folder = history / "jobs" / completed["id"]
                (folder / "report.json").write_text(corrupt)
                (folder / "checkpoint.json").write_text(json.dumps(checkpoint))
                (folder / "job.json").write_text(json.dumps(metadata))
                with patch("autoreviewer.webservice.run_models") as run:
                    recovered = WebService(self.config_path, history)
                self.addCleanup(recovered.close)
                run.assert_not_called()
                job = recovered.get_job(completed["id"])
                self.assertEqual(job["status"], "interrupted")
                self.assertEqual([item["status"] for item in job["runs"]], ["completed", "interrupted"])
                self.assertEqual(job["report"]["findings"], completed["report"]["findings"])
                self.assertIn("recovered from a saved checkpoint", job["persistence_error"])
                validate_report(job["report"])
                backups = list(folder.glob("report.unreadable-*.json"))
                self.assertEqual(len(backups), 1)
                self.assertEqual(backups[0].read_text(), corrupt)
                self.assertFalse((folder / "checkpoint.json").exists())
                recovered.close()
                restarted = WebService(self.config_path, history)
                self.addCleanup(restarted.close)
                self.assertEqual(restarted.get_report(completed["id"])["findings"], completed["report"]["findings"])
                restarted.close()

    def test_unusable_final_and_checkpoint_show_warning_without_rewriting_evidence(self):
        completed = self.complete()
        self.service.close()
        folder = self.data_dir / "jobs" / completed["id"]
        metadata = json.loads((folder / "job.json").read_text())
        metadata["status"] = "running"
        (folder / "job.json").write_text(json.dumps(metadata))
        (folder / "report.json").write_text("{broken final")
        (folder / "checkpoint.json").write_text("{broken checkpoint")
        recovered = WebService(self.config_path, self.data_dir)
        self.addCleanup(recovered.close)
        job = recovered.get_job(completed["id"])
        self.assertEqual(job["status"], "interrupted")
        self.assertIsNone(job["report"])
        self.assertIn("No readable saved report", job["persistence_error"])
        self.assertEqual((folder / "report.json").read_text(), "{broken final")
        self.assertEqual((folder / "checkpoint.json").read_text(), "{broken checkpoint")

    def test_checkpoint_exposes_findings_and_recovers_after_interruption(self):
        self.config["models"].append({"id": "second", "provider": "test", "model": "slow", "agent": "fixture"})
        self.service.save_config(self.config)
        job = self.start()
        active = self.wait_for(job["id"], lambda value: value["runs"][0]["status"] == "completed" and value["runs"][1]["status"] == "running")
        self.assertEqual(active["status"], "running")
        self.assertTrue(active["report"]["checkpoint"])
        self.assertEqual(self.service.get_report(job["id"])["status"], "partial")
        self.assertEqual(len(active["finding_groups"]), 1)
        fingerprint = active["report"]["findings"][0]["fingerprint"]
        with self.assertRaises(ServiceError):
            self.service.preview_issues(job["id"], {"fingerprints": [fingerprint], "allow_partial": True})
        checkpoint = self.data_dir / "jobs" / job["id"] / "checkpoint.json"
        self.assertEqual(json.loads(checkpoint.read_text())["findings"], active["report"]["findings"])
        recovered_dir = self.root / "recovered-history"
        shutil.copytree(self.data_dir, recovered_dir)
        with patch("autoreviewer.webservice.run_models") as run:
            recovered = WebService(self.config_path, recovered_dir)
            self.addCleanup(recovered.close)
            result = recovered.get_job(job["id"])
        run.assert_not_called()
        self.assertEqual(result["status"], "interrupted")
        self.assertEqual([item["status"] for item in result["runs"]], ["completed", "interrupted"])
        self.assertEqual(result["report"]["status"], "partial")
        self.assertEqual(result["report"]["findings"], active["report"]["findings"])
        self.assertTrue(result["report"]["interrupted"])
        self.assertNotIn("checkpoint", result["report"])
        validate_report(result["report"])
        recovered.close()
        reopened = WebService(self.config_path, recovered_dir)
        self.addCleanup(reopened.close)
        self.assertEqual(reopened.get_report(job["id"])["findings"], result["report"]["findings"])
        self.service.cancel_job(job["id"])
        self.wait_for(job["id"])

    def test_checkpoint_write_failure_keeps_results_and_surfaces_warning(self):
        self.config["models"].append({"id": "second", "provider": "test", "model": "slow", "agent": "fixture"})
        self.service.save_config(self.config)
        from autoreviewer import webservice
        original = webservice._atomic_write

        def write(path, text):
            if path.name == "checkpoint.json":
                raise OSError("disk full")
            return original(path, text)

        with patch("autoreviewer.webservice._atomic_write", side_effect=write):
            job = self.start()
            active = self.wait_for(job["id"], lambda value: value["runs"][0]["status"] == "completed")
            self.assertIn("checkpoint", active["persistence_error"])
            self.assertEqual(len(active["report"]["findings"]), 1)
        self.service.cancel_job(job["id"])
        result = self.wait_for(job["id"])
        self.assertNotIn("persistence_error", result)
        self.assertEqual(len(result["report"]["findings"]), 1)

    def test_final_save_failure_retains_checkpoint_and_session_results(self):
        with patch("autoreviewer.webservice.write_reports", side_effect=OSError("disk full")):
            result = self.complete()
        self.assertEqual(result["status"], "completed")
        self.assertIn("could not be saved", result["persistence_error"])
        self.assertEqual(len(self.service.get_report(result["id"])["findings"]), 1)
        folder = self.data_dir / "jobs" / result["id"]
        self.assertTrue((folder / "checkpoint.json").is_file())
        self.service.close()
        recovered = WebService(self.config_path, self.data_dir)
        self.addCleanup(recovered.close)
        self.assertEqual(recovered.get_report(result["id"])["findings"], result["report"]["findings"])

    def test_retry_creates_new_lineage_and_preserves_original_report(self):
        self.config["models"].append({"id": "second", "provider": "test", "model": "bad", "agent": "fixture"})
        self.service.save_config(self.config)
        original = self.complete()
        contents = self.service.get_report(original["id"])
        new = self.service.retry_job(original["id"], {"mode": "failed"})
        self.assertNotEqual(new["id"], original["id"])
        self.assertEqual(new["parent_job_id"], original["id"])
        self.assertEqual(new["retry_mode"], "failed")
        self.assertEqual([run["model"] for run in new["runs"]], ["second"])
        self.wait_for(new["id"])
        self.assertEqual(self.service.get_report(original["id"]), contents)
        all_models = self.service.retry_job(original["id"], {"mode": "all"})
        self.assertEqual([run["model"] for run in all_models["runs"]], ["first", "second"])
        self.wait_for(all_models["id"])
        self.config["models"][1]["model"] = "replacement"
        self.service.save_config(self.config)
        with self.assertRaisesRegex(ServiceError, "removed or changed"):
            self.service.retry_job(original["id"], {"mode": "failed"})
        with self.assertRaises(ServiceError):
            self.service.retry_job(original["id"], {"mode": []})

    def test_import_is_read_only_and_cannot_start_a_retry(self):
        report = self.complete()["report"]
        report["target"] = "/path/that/does/not/exist"
        original = copy.deepcopy(report)
        with patch("autoreviewer.webservice.run_models") as run, patch("autoreviewer.webservice.prepare_target") as prepare:
            imported = self.service.import_report({"report": report, "name": "existing.json"})
            with self.assertRaisesRegex(ServiceError, "Imported"):
                self.service.retry_job(imported["id"], {"mode": "all"})
        run.assert_not_called()
        prepare.assert_not_called()
        self.assertEqual(report, original)
        self.assertTrue(imported["imported"])
        self.assertEqual(imported["origin"], "imported")
        self.assertEqual(imported["source_name"], "existing.json")
        self.assertEqual(imported["report"], original)
        self.assertEqual(len(imported["finding_groups"]), 1)
        self.service.close()
        reloaded = WebService(self.config_path, self.data_dir)
        self.addCleanup(reloaded.close)
        self.assertEqual(reloaded.get_report(imported["id"]), original)
        self.assertTrue(reloaded.get_job(imported["id"])["imported"])

    def test_import_redacts_credentials_and_repairs_fingerprints(self):
        report = self.complete()["report"]
        secret = "environment-test-key"
        report["target"] += "/" + secret
        for finding in report["runs"][0]["findings"] + report["findings"]:
            finding["title"] += " " + secret
            finding["fingerprint"] = finding_fingerprint(finding)
        imported = self.service.import_report({"report": report, "name": secret + ".json"})
        validate_report(imported["report"])
        self.assertNotIn(secret, json.dumps(imported))
        self.assertIn("[REDACTED]", imported["report"]["findings"][0]["title"])
        for path in (self.data_dir / "jobs" / imported["id"]).iterdir():
            self.assertNotIn(secret.encode(), path.read_bytes())
        invalid = copy.deepcopy(report)
        invalid[secret] = "untrusted field"
        with self.assertRaises(ServiceError):
            self.service.import_report({"report": invalid})

    def test_imported_guidance_never_bypasses_credential_redaction(self):
        report = self.complete()["report"]
        secret = "d" * 64
        report["runs"][0]["audit_guidance"]["prompt_sha256"] = secret
        validate_report(report)
        self.service.set_credential("UI_TEST_KEY", secret)
        before = self.service.list_jobs()
        with self.assertRaisesRegex(ServiceError, "after credential redaction") as failure:
            self.service.import_report({"report": report})
        self.assertNotIn(secret, str(failure.exception))
        self.assertEqual(self.service.list_jobs(), before)

    def test_import_checkpoint_preserves_results_without_resuming_models(self):
        report = self.complete()["report"]
        report["checkpoint"] = True
        report["status"] = "partial"
        pending = {**copy.deepcopy(report["runs"][0]), "model": "unfinished", "status": "running", "findings": []}
        report["runs"].append(pending)
        original = copy.deepcopy(report)
        with patch("autoreviewer.webservice.run_models") as run, patch("autoreviewer.webservice.prepare_target") as prepare:
            imported = self.service.import_report({"report": report, "name": "phase.json"})
        run.assert_not_called()
        prepare.assert_not_called()
        self.assertEqual(report, original)
        self.assertEqual(imported["status"], "partial")
        self.assertTrue(imported["report"]["interrupted"])
        self.assertNotIn("checkpoint", imported["report"])
        self.assertEqual(imported["runs"][1]["status"], "interrupted")
        self.assertEqual(imported["report"]["findings"], report["findings"])
        validate_report(imported["report"])

    def test_import_invalid_data_and_failed_persistence_leave_no_task(self):
        report = self.complete()["report"]
        before = self.service.list_jobs()
        for payload in ({"report": None}, {"report": []}, {"report": {**report, "runs": [None]}},
                        {"report": {**report, "findings": [None]}}, {"report": report, "name": "../private.json"},
                        {"report": {**report, "status": "failed"}}):
            with self.assertRaises(ServiceError):
                self.service.import_report(payload)
        with patch.object(self.service, "_persist", side_effect=OSError("disk full")):
            with self.assertRaises(ServiceError):
                self.service.import_report({"report": report})
        self.assertEqual(self.service.list_jobs(), before)

    def test_export_contains_only_nonsecret_configuration(self):
        self.service.set_credential("UI_TEST_KEY", "session-private-value")
        text = self.service.export_config()
        self.assertIn("UI_TEST_KEY", text)
        self.assertNotIn("session-private-value", text)
        self.assertNotIn("environment-test-key", text)

    def test_data_directory_lock_prevents_second_service_and_releases_on_failure(self):
        with self.assertRaises(ValueError):
            WebService(self.config_path, self.data_dir)
        self.service.close()
        self.config_path.write_text("not valid TOML")
        with self.assertRaises(ValueError):
            WebService(self.config_path, self.data_dir)
        self.config_path.unlink()
        fresh = WebService(self.config_path, self.data_dir)
        fresh.close()

    def test_close_keeps_data_lock_until_delayed_worker_has_finished(self):
        entered, release = threading.Event(), threading.Event()

        def prepare(*args, **kwargs):
            entered.set()
            release.wait(5)
            return self.repo

        with patch("autoreviewer.webservice.prepare_target", side_effect=prepare):
            job = self.start()
            self.assertTrue(entered.wait(3))
            thread = self.service._workers[job["id"]].thread
            try:
                with patch.object(thread, "join"):
                    self.service.close()
                with self.assertRaises(ValueError):
                    WebService(self.config_path, self.data_dir)
            finally:
                release.set()
                thread.join(3)
        self.assertFalse(thread.is_alive())
        reloaded = WebService(self.config_path, self.data_dir)
        self.addCleanup(reloaded.close)
        self.assertEqual(reloaded.get_job(job["id"])["status"], "cancelled")

    def test_preview_requires_selection_and_explicit_partial_option(self):
        self.config["models"].append({"id": "second", "provider": "test", "model": "bad", "agent": "fixture"})
        self.service.save_config(self.config)
        job = self.complete()
        fingerprint = job["report"]["findings"][0]["fingerprint"]
        with self.assertRaises(ValueError):
            self.service.preview_issues(job["id"], {"fingerprints": [fingerprint]})
        with self.assertRaises(ServiceError):
            self.service.preview_issues(job["id"], {"fingerprints": []})
        with patch("autoreviewer.webservice.publish_to_github") as network:
            preview = self.service.preview_issues(job["id"], {"fingerprints": [fingerprint], "allow_partial": True})
        network.assert_not_called()
        self.assertEqual(preview["repository"], "owner/repo")
        self.assertEqual(len(preview["issues"]), 1)
        self.assertFalse((self.data_dir / "github-publications.json").exists())

    def test_oversized_issue_selection_has_actionable_limit_error(self):
        job = self.complete()
        with self.assertRaisesRegex(ServiceError, "at most 1000.*reduce the selection"):
            self.service.preview_issues(job["id"], {"fingerprints": [str(index) for index in range(1002)]})
        self.assertEqual(self.service._previews, {})

    def test_close_holds_data_lock_until_publication_and_history_write_finish(self):
        job = self.complete()
        self.service.close()
        for outcome in ("success", "network-error", "history-error"):
            with self.subTest(outcome=outcome):
                service = WebService(self.config_path, self.data_dir)
                self.addCleanup(service.close)
                preview = service.preview_issues(job["id"], {"fingerprints": [job["report"]["findings"][0]["fingerprint"]]})
                entered, release = threading.Event(), threading.Event()
                replies = []

                def publish(*args, **kwargs):
                    entered.set()
                    self.assertTrue(release.wait(5))
                    if outcome == "network-error":
                        raise ValueError("fixture publication failed")
                    return [{"status": "existing", "url": "https://github.com/owner/repo/issues/1"}]

                def submit():
                    try:
                        replies.append(service.publish_issues(job["id"], {"preview_id": preview["preview_id"], "confirmation": "owner/repo"}))
                    except Exception as error:
                        replies.append(error)

                with patch("autoreviewer.webservice.publish_to_github", side_effect=publish):
                    thread = threading.Thread(target=submit)
                    thread.start()
                    try:
                        self.assertTrue(entered.wait(3))
                        service.close()
                        with self.assertRaises(ValueError):
                            WebService(self.config_path, self.data_dir)
                        if outcome == "history-error":
                            with patch.object(service, "_persist", side_effect=OSError("fixture write failed")):
                                release.set()
                                thread.join(3)
                        else:
                            release.set()
                            thread.join(3)
                    finally:
                        release.set()
                        thread.join(3)
                self.assertFalse(thread.is_alive())
                self.assertEqual(len(replies), 1)
                self.assertEqual(isinstance(replies[0], dict), outcome == "success")
                restarted = WebService(self.config_path, self.data_dir)
                restarted.close()

    def test_publication_uses_reviewed_selection_and_consumes_preview(self):
        job = self.complete()
        fingerprint = job["report"]["findings"][0]["fingerprint"]
        preview = self.service.preview_issues(job["id"], {"fingerprints": [fingerprint]})
        payload = {"preview_id": preview["preview_id"], "confirmation": "owner/repo"}
        self.service.set_credential("UI_GITHUB_TOKEN", "session-github-token")
        with patch("autoreviewer.webservice.publish_to_github", return_value=[{"fingerprint": fingerprint, "status": "created", "url": "https://github.com/owner/repo/issues/1"}]) as publish:
            with self.assertRaises(ServiceError):
                self.service.publish_issues(job["id"], {**payload, "confirmation": "wrong/repo"})
            publish.assert_not_called()
            response = self.service.publish_issues(job["id"], payload)
            self.assertEqual(response["issues"][0]["status"], "created")
            self.assertEqual(publish.call_args.kwargs["token"], "session-github-token")
            self.assertEqual(publish.call_args.kwargs["receipt_path"], self.data_dir / "github-publications.json")
            self.assertEqual(len(publish.call_args.args[0]["findings"]), 1)
            with self.assertRaises(ServiceError) as duplicate:
                self.service.publish_issues(job["id"], payload)
            self.assertEqual(duplicate.exception.status_code, 409)
            self.assertEqual(publish.call_count, 1)

    def test_publication_receipt_survives_restart_with_empty_issue_list(self):
        job = self.complete()
        selection = {"fingerprints": [job["report"]["findings"][0]["fingerprint"]]}
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

        with patch("autoreviewer.github._Client.request", side_effect=request):
            preview = self.service.preview_issues(job["id"], selection)
            first = self.service.publish_issues(job["id"], {"preview_id": preview["preview_id"], "confirmation": "owner/repo"})
            self.assertTrue((self.data_dir / "github-publications.json").is_file())
            self.service.close()
            self.service = WebService(self.config_path, self.data_dir)
            self.addCleanup(self.service.close)
            remote["state"] = "closed"
            preview = self.service.preview_issues(job["id"], selection)
            second = self.service.publish_issues(job["id"], {"preview_id": preview["preview_id"], "confirmation": "owner/repo"})
        self.assertEqual(first["issues"][0]["status"], "created")
        self.assertEqual(second["issues"][0]["status"], "existing")
        self.assertEqual(first["issues"][0]["url"], second["issues"][0]["url"])
        self.assertEqual(len(posts), 1)
        self.assertEqual(remote["state"], "closed")

    def test_config_change_invalidates_preview_and_failed_publish_redacts_token(self):
        job = self.complete()
        selection = {"fingerprints": [job["report"]["findings"][0]["fingerprint"]]}
        preview = self.service.preview_issues(job["id"], selection)
        self.service.save_config(self.config)
        with self.assertRaises(ServiceError):
            self.service.publish_issues(job["id"], {"preview_id": preview["preview_id"], "confirmation": "owner/repo"})
        preview = self.service.preview_issues(job["id"], selection)
        self.service.set_credential("UI_GITHUB_TOKEN", "private-github-token")
        with patch("autoreviewer.webservice.publish_to_github", side_effect=ValueError("response includes private-github-token")):
            with self.assertRaises(ServiceError) as failed:
                self.service.publish_issues(job["id"], {"preview_id": preview["preview_id"], "confirmation": "owner/repo"})
        self.assertNotIn("private-github-token", str(failed.exception))
        self.assertIn("[REDACTED]", str(failed.exception))

    def test_two_previews_cannot_publish_concurrently(self):
        job = self.complete()
        selection = {"fingerprints": [job["report"]["findings"][0]["fingerprint"]]}
        previews = [self.service.preview_issues(job["id"], selection) for _ in range(2)]
        entered, release = threading.Event(), threading.Event()
        result = []

        def network(*args, **kwargs):
            entered.set()
            release.wait(5)
            return []

        def submit():
            result.append(self.service.publish_issues(job["id"], {"preview_id": previews[0]["preview_id"], "confirmation": "owner/repo"}))

        with patch("autoreviewer.webservice.publish_to_github", side_effect=network) as publish:
            worker = threading.Thread(target=submit)
            worker.start()
            try:
                self.assertTrue(entered.wait(3))
                with self.assertRaises(ServiceError) as conflict:
                    self.service.publish_issues(job["id"], {"preview_id": previews[1]["preview_id"], "confirmation": "owner/repo"})
                self.assertEqual(conflict.exception.status_code, 409)
            finally:
                release.set()
                worker.join(3)
            self.assertEqual(publish.call_count, 1)
        self.assertEqual(len(result), 1)

    def test_not_found_and_close_are_explicit(self):
        with self.assertRaises(ServiceError) as missing:
            self.service.get_job("../report")
        self.assertEqual(missing.exception.status_code, 404)
        self.service.close()
        with self.assertRaises(ServiceError):
            self.start()

    def test_close_joins_workers_and_clears_credentials_when_status_save_fails(self):
        job = self.complete()
        worker = _Worker(threading.Event(), thread=Mock())
        self.service._jobs[job["id"]]["status"] = "running"
        self.service._workers[job["id"]] = worker
        self.service.set_credential("UI_TEST_KEY", "session-to-clear")
        with patch.object(self.service, "_persist", side_effect=OSError("disk unavailable")):
            self.service.close()
        worker.thread.join.assert_called_once_with(timeout=10)
        self.assertTrue(worker.cancel.is_set())
        self.assertEqual(self.service._credentials, {})
        self.assertEqual(self.service._previews, {})
        self.service._workers.clear()


if __name__ == "__main__":
    unittest.main()
