from __future__ import annotations

import asyncio
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from autoreviewer.runner import run_models
from autoreviewer.guidance import GuidanceError, build_audit_prompt


SCRIPT = r'''
import json, os, pathlib, subprocess, sys, time
mode, model, events, sentinel = sys.argv[1:]
def finding(description="A potential issue"):
    return {"title":"Potential injection", "severity":"high", "file":"source.py",
            "line":1, "cwe":"CWE-89", "description":description,
            "evidence":"Input reaches a sensitive operation", "recommendation":"Validate input",
            "confidence":"medium"}
def event(kind):
    with open(events, "a") as f:
        f.write(json.dumps({"kind":kind, "model":model, "time":time.monotonic()}) + "\n")
event("start")
if mode == "fail":
    sys.stderr.write("provider failed " + os.environ.get("MODEL_KEY", ""))
    sys.exit(2)
if mode == "malformed":
    print("I could not audit this repository")
    sys.exit(0)
if mode == "overflow":
    sys.stdout.write("x" * 100000)
    sys.exit(0)
if mode == "stress-overflow":
    for _ in range(128):
        os.write(sys.stdout.fileno(), b"x" * 65536)
        os.write(sys.stderr.fileno(), b"x" * 65536)
    sys.exit(0)
if mode == "secret-title":
    item = finding()
    item["title"] = "Potential issue " + os.environ["MODEL_KEY"]
    print(json.dumps({"findings": [item]}))
    sys.exit(0)
if mode == "timeout":
    child = "import pathlib,time; time.sleep(0.6); pathlib.Path(" + repr(sentinel) + ").touch()"
    subprocess.Popen([sys.executable, "-c", child])
    pathlib.Path(events + ".ready").touch()
    time.sleep(10)
if mode == "environment":
    original = pathlib.Path("source.py").read_text()
    pathlib.Path("source.py").write_text(original + "# changed copy\n")
    description = json.dumps({"selected":os.environ.get("MODEL_KEY"),
          "other":os.environ.get("OTHER_MODEL_KEY"), "github":os.environ.get("GITHUB_TOKEN"),
          "unrelated":os.environ.get("UNRELATED_SECRET"), "home":os.environ.get("HOME"),
          "cwd":os.getcwd(), "proxy":os.environ.get("HTTPS_PROXY")})
    print(json.dumps({"findings":[finding(description)]}))
else:
    time.sleep(0.12)
    print(json.dumps({"findings":[finding()]}))
event("end")
'''


class RunnerTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.source = self.root / "source"
        self.source.mkdir()
        (self.source / "source.py").write_text("query(user_input)\n")
        self.script = self.root / "fake_agent.py"
        self.script.write_text(SCRIPT)
        self.events = self.root / "events.jsonl"
        self.sentinel = self.root / "child-survived"
        self.work = self.root / "work"
        self.mode: dict[str, str] = {}
        self.received_keys = []
        self.received_prompts = []
        self.environ = patch.dict(os.environ, {
            "MODEL_KEY": "test-selected-secret-654321",
            "OTHER_MODEL_KEY": "test-other-secret-123456",
            "GITHUB_TOKEN": "test-github-secret-987654",
            "UNRELATED_SECRET": "test-unrelated-secret-112233",
            "HTTPS_PROXY": "http://example.test:8080",
        })
        self.environ.start()

        def snapshot(source, destination, excludes):
            shutil.copytree(source, destination)
            return {"files": 1}

        def build(model, provider, agent, workspace, state, prompt, key):
            self.assertIn("untrusted data", prompt)
            self.received_keys.append((model.id, key))
            self.received_prompts.append(prompt)
            return SimpleNamespace(
                argv=[sys.executable, str(self.script), self.mode.get(model.id, "ok"),
                      model.id, str(self.events), str(self.sentinel)],
                env={}, output_path=None, output_format="text",
            )

        self.patches = [
            patch("autoreviewer.runner.snapshot_repository", side_effect=snapshot),
            patch("autoreviewer.runner.build_command", side_effect=build),
            patch("autoreviewer.runner.extract_output", side_effect=lambda spec, text: text),
        ]
        for patcher in self.patches:
            patcher.start()

    def tearDown(self):
        for patcher in reversed(self.patches):
            patcher.stop()
        self.environ.stop()
        self.temp.cleanup()

    def config(self, ids=("one",), *, concurrency=2, timeout=3, limit=65536):
        return SimpleNamespace(
            models=tuple(SimpleNamespace(id=value, provider="selected", model=value, agent="fake")
                         for value in ids),
            providers={
                "selected": SimpleNamespace(api_key_env="MODEL_KEY", api_format="openai-chat"),
                "other": SimpleNamespace(api_key_env="OTHER_MODEL_KEY", api_format="openai-chat"),
            },
            agents={"fake": SimpleNamespace()},
            scan=SimpleNamespace(concurrency=concurrency, timeout_seconds=timeout,
                                 max_output_bytes=limit, excludes=()),
            github=SimpleNamespace(token_env="GITHUB_TOKEN"),
        )

    async def test_parallel_runs_are_bounded_and_keep_successes(self):
        self.mode["bad"] = "fail"
        result = await run_models(self.config(("one", "two", "three", "bad")), self.source, self.work)
        self.assertEqual([run["model"] for run in result], ["one", "two", "three", "bad"])
        self.assertEqual([run["status"] for run in result], ["completed"] * 3 + ["failed"])
        self.assertEqual(
            {key: result[0][key] for key in ("provider", "model_name", "agent", "api_format")},
            {"provider": "selected", "model_name": "one", "agent": "fake", "api_format": "openai-chat"},
        )
        self.assertIn("[REDACTED]", result[-1]["error"])
        self.assertNotIn(os.environ["MODEL_KEY"], json.dumps(result))
        active = maximum = 0
        for event in map(json.loads, self.events.read_text().splitlines()):
            if event["model"] == "bad":
                continue
            active += 1 if event["kind"] == "start" else -1
            maximum = max(maximum, active)
        self.assertEqual(maximum, 2)
        self.assertEqual(list(self.work.iterdir()), [])

    async def test_environment_and_code_copies_are_isolated(self):
        self.mode.update({"one": "environment", "two": "environment"})
        result = await run_models(self.config(("one", "two")), self.source, self.work)
        homes = set()
        for run in result:
            self.assertEqual(run["status"], "completed", run)
            info = json.loads(run["findings"][0]["description"])
            self.assertEqual(info["selected"], "[REDACTED]")
            self.assertIsNone(info["other"])
            self.assertIsNone(info["github"])
            self.assertIsNone(info["unrelated"])
            self.assertEqual(info["proxy"], "http://example.test:8080")
            self.assertNotEqual(info["home"], os.environ.get("HOME"))
            self.assertFalse(Path(info["home"]).exists())
            homes.add(info["home"])
        self.assertEqual(len(homes), 2)
        self.assertEqual((self.source / "source.py").read_text(), "query(user_input)\n")

    async def test_guidance_loaded_once_with_shared_prompt_and_terminal_provenance(self):
        events = []
        self.mode["two"] = "fail"
        with patch("autoreviewer.runner.build_audit_prompt", wraps=build_audit_prompt) as load:
            runs = await run_models(self.config(("one", "two")), self.source, self.work,
                                    credentials={"MODEL_KEY": "c1"}, on_event=events.append)
        load.assert_called_once()
        self.assertEqual(len(self.received_prompts), 2)
        self.assertEqual(self.received_prompts[0], self.received_prompts[1])
        prompt_hash = hashlib.sha256(self.received_prompts[0].encode()).hexdigest()
        for run in runs:
            meta = run["audit_guidance"]
            self.assertEqual(meta["prompt_sha256"], prompt_hash)
            self.assertTrue(meta["commit"].startswith("c1"))
            self.assertNotIn("[REDACTED]", json.dumps(meta))
            terminal = next(event for event in events if "run" in event and event["model"] == run["model"])
            self.assertEqual(terminal["run"], run)
            terminal["run"]["audit_guidance"].clear()
            self.assertTrue(run["audit_guidance"])
        self.assertIn("[REDACTED]", runs[1]["error"])

    async def test_invalid_guidance_fails_before_agent_launch(self):
        with patch("autoreviewer.runner.build_audit_prompt", side_effect=GuidanceError("invalid guidance")):
            with self.assertRaisesRegex(GuidanceError, "invalid guidance"):
                await run_models(self.config(), self.source, self.work)
        self.assertFalse(self.events.exists())
        self.assertEqual(self.received_prompts, [])

    async def test_json_escaped_secret_is_redacted(self):
        self.mode["one"] = "environment"
        with patch.dict(os.environ, {"MODEL_KEY": "selected-secret-with-quote\"and-slash\\"}):
            result = await run_models(self.config(), self.source, self.work)
        self.assertEqual(result[0]["status"], "completed", result)
        self.assertNotIn("selected-secret", json.dumps(result))

    async def test_concurrent_calls_keep_explicit_credentials_private_and_separate(self):
        self.mode.update({"one": "environment", "two": "environment"})
        original = os.environ["MODEL_KEY"]
        events = []
        first, second = await asyncio.gather(
            run_models(self.config(("one",)), self.source, self.work / "first",
                       credentials={"MODEL_KEY": "ui-first-session-secret",
                                    "OTHER_MODEL_KEY": "ui-other-session-secret",
                                    "GITHUB_TOKEN": "ui-github-session-secret"},
                       on_event=events.append),
            run_models(self.config(("two",)), self.source, self.work / "second",
                       credentials={"MODEL_KEY": "ui-second-session-secret"},
                       on_event=events.append),
        )
        self.assertEqual(dict(self.received_keys), {"one": "ui-first-session-secret", "two": "ui-second-session-secret"})
        self.assertEqual(os.environ["MODEL_KEY"], original)
        for run in first + second:
            info = json.loads(run["findings"][0]["description"])
            self.assertEqual(info["selected"], "[REDACTED]")
            self.assertIsNone(info["other"])
            self.assertIsNone(info["github"])
        for model in ("one", "two"):
            model_events = [event for event in events if event["model"] == model]
            self.assertEqual([event["status"] for event in model_events], ["queued", "running", "completed"])
            self.assertEqual(model_events[-1]["run"]["model"], model)
            self.assertTrue(all(event["at"].endswith("+00:00") for event in model_events))
        self.assertNotIn("session-secret", json.dumps(events + first + second))

    async def test_event_callbacks_cannot_mutate_or_fail_a_run(self):
        def observer(event):
            if "run" in event:
                event["run"]["status"] = "failed"
                event["run"]["findings"].clear()
                event["run"]["audit_guidance"].clear()
            raise RuntimeError("broken UI observer")

        runs = await run_models(self.config(), self.source, self.work, on_event=observer)
        self.assertEqual(runs[0]["status"], "completed")
        self.assertEqual(len(runs[0]["findings"]), 1)
        self.assertIn("prompt_sha256", runs[0]["audit_guidance"])

    async def test_explicit_failure_secret_is_redacted_from_events(self):
        self.mode["one"] = "fail"
        events = []
        runs = await run_models(self.config(), self.source, self.work,
                                credentials={"MODEL_KEY": "only-in-ui-memory-secret"},
                                on_event=events.append)
        self.assertEqual(events[-1]["status"], "failed")
        self.assertEqual(events[-1]["run"], runs[0])
        self.assertIn("[REDACTED]", events[-1]["run"]["error"])
        self.assertNotIn("only-in-ui-memory-secret", json.dumps(events))

    async def test_explicit_empty_credential_does_not_fall_back_to_environment(self):
        events = []
        runs = await run_models(self.config(), self.source, self.work,
                                credentials={"MODEL_KEY": ""}, on_event=events.append)
        self.assertEqual(runs[0]["status"], "failed")
        self.assertEqual([event["status"] for event in events], ["queued", "failed"])
        self.assertFalse(self.events.exists())

    async def test_malformed_output_is_failure(self):
        self.mode["one"] = "malformed"
        result = await run_models(self.config(), self.source, self.work)
        self.assertEqual(result[0]["status"], "failed")
        self.assertEqual(result[0]["findings"], [])
        self.assertTrue(result[0]["error"])

    async def test_output_limit_is_failure(self):
        self.mode["one"] = "overflow"
        result = await run_models(self.config(limit=1024), self.source, self.work)
        self.assertEqual(result[0]["status"], "failed")
        self.assertIn("exceeded", result[0]["error"])

    async def test_large_combined_output_does_not_deadlock_on_shutdown(self):
        self.mode["one"] = "stress-overflow"
        result = await asyncio.wait_for(
            run_models(self.config(limit=1024), self.source, self.work), timeout=3,
        )
        self.assertEqual(result[0]["status"], "failed")
        self.assertIn("exceeded", result[0]["error"])

    async def test_redacted_title_has_publishable_fingerprint(self):
        from autoreviewer.github import plan_issues
        self.mode["one"] = "secret-title"
        result = await run_models(self.config(), self.source, self.work)
        self.assertEqual(result[0]["status"], "completed", result)
        self.assertIn("[REDACTED]", result[0]["findings"][0]["title"])
        report = {"schema_version": 1, "status": "completed", "target": "local-source",
                  "findings": result[0]["findings"], "runs": result}
        drafts = plan_issues(report)
        self.assertEqual(len(drafts), 1)

    async def test_short_secret_does_not_corrupt_public_enum_metadata(self):
        from autoreviewer.github import plan_issues
        with patch.dict(os.environ, {"MODEL_KEY": "high"}):
            result = await run_models(self.config(), self.source, self.work)
        self.assertEqual(result[0]["status"], "completed", result)
        self.assertEqual(result[0]["findings"][0]["severity"], "high")
        report = {"schema_version": 1, "status": "completed", "target": "local-source",
                  "findings": result[0]["findings"], "runs": result}
        self.assertEqual(len(plan_issues(report)), 1)

    @unittest.skipUnless(os.name == "posix", "POSIX process-group guarantee")
    async def test_timeout_kills_descendants(self):
        self.mode["one"] = "timeout"
        result = await run_models(self.config(timeout=0.2), self.source, self.work)
        self.assertEqual(result[0]["status"], "timeout")
        await asyncio.sleep(0.7)
        self.assertFalse(self.sentinel.exists())

    @unittest.skipUnless(os.name == "posix", "POSIX process-group guarantee")
    async def test_cancellation_kills_descendants(self):
        self.mode["one"] = "timeout"
        task = asyncio.create_task(run_models(self.config(timeout=5), self.source, self.work))
        for _ in range(100):
            if Path(str(self.events) + ".ready").exists():
                break
            await asyncio.sleep(0.01)
        else:
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
            self.fail("Fake agent did not start")
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        await asyncio.sleep(0.7)
        self.assertFalse(self.sentinel.exists())
        self.assertEqual(list(self.work.iterdir()), [])

    async def test_cancellation_reports_running_and_queued_models(self):
        self.mode["one"] = "timeout"
        events = []
        task = asyncio.create_task(run_models(self.config(("one", "two"), concurrency=1, timeout=5),
                                              self.source, self.work, on_event=events.append))
        try:
            for _ in range(100):
                if Path(str(self.events) + ".ready").exists():
                    break
                await asyncio.sleep(0.01)
            else:
                self.fail("Fake agent did not start")
        finally:
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
        for model in ("one", "two"):
            terminal = [event for event in events if event["model"] == model and "run" in event]
            self.assertEqual(len(terminal), 1)
            self.assertEqual(terminal[0]["status"], "cancelled")
            self.assertEqual(terminal[0]["run"]["status"], "cancelled")
        self.assertNotIn("running", [event["status"] for event in events if event["model"] == "two"])
        self.assertEqual(list(self.work.iterdir()), [])

    async def test_unknown_model_selection_fails_before_start(self):
        with self.assertRaisesRegex(ValueError, "Unknown model"):
            await run_models(self.config(), self.source, self.work, ("missing",))
        self.assertFalse(self.events.exists())

    async def test_missing_key_does_not_start_an_agent(self):
        with patch.dict(os.environ, {"MODEL_KEY": ""}):
            result = await run_models(self.config(), self.source, self.work)
        self.assertEqual(result[0]["status"], "failed")
        self.assertIn("MODEL_KEY", result[0]["error"])
        self.assertFalse(self.events.exists())

    async def test_missing_executable_does_not_start_an_agent(self):
        spec = SimpleNamespace(argv=["autoreviewer-nonexistent-test-executable"], env={}, output_path=None)
        with patch("autoreviewer.runner.build_command", return_value=spec):
            result = await run_models(self.config(), self.source, self.work)
        self.assertEqual(result[0]["status"], "failed")
        self.assertIn("not found", result[0]["error"])
        self.assertFalse(self.events.exists())


if __name__ == "__main__":
    unittest.main()
