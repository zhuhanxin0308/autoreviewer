import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from autoreviewer.config import GitHubConfig
from autoreviewer.targets import prepare_target


class TargetTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.work = self.root / "work"

    def test_local_target_is_resolved_without_subprocess(self):
        source = self.root / "source"
        source.mkdir()
        with patch("autoreviewer.targets.subprocess.run") as run:
            self.assertEqual(prepare_target(str(source), self.work), source)
            run.assert_not_called()
        with self.assertRaisesRegex(ValueError, "only supported"):
            prepare_target(str(source), self.work, ref="main")

    def test_invalid_remote_urls_and_refs_are_rejected_before_clone(self):
        for target in ("http://github.com/o/r", "https://evil.test/o/r", "https://token@github.com/o/r",
                       "https://github.com/o/r?token=secret", "https://github.com/o/r#ref",
                       "https://github.com:443/o/r", "https://github.com/o/r/extra"):
            with self.subTest(target=target), patch("autoreviewer.targets.subprocess.run") as run:
                with self.assertRaises(ValueError):
                    prepare_target(target, self.work)
                run.assert_not_called()
        for ref in ("--upload-pack=evil", "a..b", "a//b", "a/", "a.lock", "a.lock/b", "a/.hidden", "a@{b", "a b"):
            with self.subTest(ref=ref), patch("autoreviewer.targets.subprocess.run") as run:
                with self.assertRaises(ValueError):
                    prepare_target("https://github.com/o/r", self.work, ref=ref)
                run.assert_not_called()

    def test_matching_github_token_is_scoped_to_askpass_environment(self):
        secret = "test-token-that-must-never-be-in-argv"
        environment = {"PATH": os.environ.get("PATH", ""), "REVIEW_GH_TOKEN": secret,
                       "OTHER_API_KEY": "another-secret", "GIT_CONFIG_COUNT": "3", "HTTPS_PROXY": "http://proxy:8080"}
        with patch.dict(os.environ, environment, clear=True), patch("autoreviewer.targets.subprocess.run") as run:
            run.return_value = subprocess.CompletedProcess([], 0, b"", b"")
            destination = prepare_target("https://github.com/Owner/Repo.git", self.work,
                                         GitHubConfig("owner/repo", "REVIEW_GH_TOKEN"), ref="release/v1")
        argv = run.call_args.args[0]
        env = run.call_args.kwargs["env"]
        self.assertEqual(destination, self.work / "clone")
        self.assertNotIn(secret, " ".join(argv))
        self.assertIn("http.followRedirects=false", argv)
        self.assertIn("credential.helper=", argv)
        self.assertIn("core.hooksPath=/dev/null", argv)
        self.assertEqual(argv[-2], "https://github.com/Owner/Repo.git")
        self.assertEqual(argv[argv.index("--branch") + 1], "release/v1")
        self.assertEqual(env["AUTOREVIEWER_GIT_TOKEN"], secret)
        self.assertNotIn("REVIEW_GH_TOKEN", env)
        self.assertNotIn("OTHER_API_KEY", env)
        self.assertNotIn("GIT_CONFIG_COUNT", env)
        self.assertEqual(env["HTTPS_PROXY"], "http://proxy:8080")
        askpass = Path(env["GIT_ASKPASS"])
        self.assertNotIn(secret, askpass.read_text())
        self.assertEqual(askpass.stat().st_mode & 0o777, 0o700)
        self.assertEqual(env["GIT_TERMINAL_PROMPT"], "0")

    def test_other_repository_never_receives_token(self):
        with patch.dict(os.environ, {"GITHUB_TOKEN": "sensitive-token", "GIT_ASKPASS": "dangerous-script"}), \
                patch("autoreviewer.targets.subprocess.run") as run:
            run.return_value = subprocess.CompletedProcess([], 0, b"", b"")
            prepare_target("https://github.com/owner/other", self.work, GitHubConfig("owner/repo"))
        env = run.call_args.kwargs["env"]
        self.assertNotIn("GITHUB_TOKEN", env)
        self.assertNotIn("AUTOREVIEWER_GIT_TOKEN", env)
        self.assertNotIn("GIT_ASKPASS", env)

    def test_explicit_clone_credentials_override_without_changing_global_environment(self):
        with patch.dict(os.environ, {"GITHUB_TOKEN": "process-token"}), \
                patch("autoreviewer.targets.subprocess.run") as run:
            run.return_value = subprocess.CompletedProcess([], 0, b"", b"")
            prepare_target("https://github.com/owner/repo", self.work, GitHubConfig("owner/repo"),
                           credentials={"GITHUB_TOKEN": "ui-memory-token", "MODEL_KEY": "private-model-key"})
            self.assertEqual(os.environ["GITHUB_TOKEN"], "process-token")
        env = run.call_args.kwargs["env"]
        self.assertEqual(env["AUTOREVIEWER_GIT_TOKEN"], "ui-memory-token")
        self.assertNotIn("MODEL_KEY", env)
        self.assertNotIn("ui-memory-token", Path(env["GIT_ASKPASS"]).read_text())
        self.assertNotIn("ui-memory-token", str(run.call_args.args))

    def test_clone_failure_does_not_echo_subprocess_credentials(self):
        with patch("autoreviewer.targets.subprocess.run") as run:
            run.return_value = subprocess.CompletedProcess([], 128, b"secret stdout", b"secret stderr")
            with self.assertRaisesRegex(ValueError, "GitHub clone failed") as raised:
                prepare_target("https://github.com/owner/repo", self.work)
        self.assertNotIn("secret", str(raised.exception))

    def test_clone_timeout_becomes_actionable_error(self):
        with patch("autoreviewer.targets.subprocess.run", side_effect=subprocess.TimeoutExpired("git", 180)):
            with self.assertRaisesRegex(ValueError, "timed out"):
                prepare_target("https://github.com/owner/repo", self.work)

    def test_cancelled_preparation_does_not_start_clone(self):
        cancelled = threading.Event()
        cancelled.set()
        with patch("autoreviewer.targets.subprocess.Popen") as popen:
            with self.assertRaisesRegex(ValueError, "cancelled"):
                prepare_target("https://github.com/owner/repo", self.work, cancel_event=cancelled)
        popen.assert_not_called()

    @unittest.skipUnless(os.name == "posix", "POSIX process-group guarantee")
    def test_cancelling_clone_terminates_helpers(self):
        cancelled = threading.Event()
        sentinel = self.root / "helper-survived"
        ready = self.root / "clone-started"
        child = f"import pathlib,time; time.sleep(0.6); pathlib.Path({str(sentinel)!r}).touch()"
        script = (f"import pathlib,subprocess,sys,time; subprocess.Popen([sys.executable, '-c', {child!r}]); "
                  f"pathlib.Path({str(ready)!r}).touch(); time.sleep(10)")
        real_popen = subprocess.Popen

        def fake_clone(argv, **kwargs):
            return real_popen([sys.executable, "-c", script], **kwargs)

        def cancel_after_start():
            for _ in range(100):
                if ready.exists():
                    cancelled.set()
                    return
                time.sleep(0.01)
            cancelled.set()

        cancel_thread = threading.Thread(target=cancel_after_start)
        cancel_thread.start()
        try:
            with patch("autoreviewer.targets.subprocess.Popen", side_effect=fake_clone):
                with self.assertRaisesRegex(ValueError, "GitHub clone cancelled"):
                    prepare_target("https://github.com/owner/repo", self.work, cancel_event=cancelled)
        finally:
            cancel_thread.join(timeout=2)
        self.assertTrue(ready.exists())
        time.sleep(0.7)
        self.assertFalse(sentinel.exists())


if __name__ == "__main__":
    unittest.main()
