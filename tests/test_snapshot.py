import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from autoreviewer.snapshot import snapshot_repository


class SnapshotTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / "source"
        self.source.mkdir()
        self.destination = self.root / "snapshot"

    def write(self, name, contents="reviewable code\n"):
        path = self.source / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents, encoding="utf-8")
        return path

    def test_copies_text_with_private_permissions_and_excludes_sensitive_metadata(self):
        self.write("src/app.py")
        excluded = [".env", ".env.production", "nested/key.pem", "id_rsa", ".aws/config",
                    "nested/AGENTS.md", "CLAUDE.md", "GEMINI.md", "opencode.jsonc",
                    ".codex/config.toml", "autoreviewer.toml", "node_modules/a.js", ".autoreviewer/report.json"]
        for name in excluded:
            self.write(name, "must not be included")
        result = snapshot_repository(self.source, self.destination)
        self.assertEqual(result["files"], 1)
        self.assertEqual((self.destination / "src/app.py").read_text(), "reviewable code\n")
        self.assertEqual((self.destination / "src/app.py").stat().st_mode & 0o777, 0o600)
        for name in excluded:
            self.assertFalse((self.destination / name).exists(), name)

    def test_skips_symlink_files_directories_and_non_utf8_binary(self):
        self.write("app.py")
        (self.root / "outside.txt").write_text("external secret")
        (self.source / "link.txt").symlink_to(self.root / "outside.txt")
        (self.source / "directory-link").symlink_to(self.root, target_is_directory=True)
        (self.source / "binary.bin").write_bytes(b"binary\0data")
        (self.source / "invalid-utf8.bin").write_bytes(b"\xff\xfe")
        result = snapshot_repository(self.source, self.destination)
        self.assertEqual(result["files"], 1)
        self.assertEqual(result["skipped"]["symlink"], 2)
        self.assertEqual(result["skipped"]["binary"], 2)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO support required")
    def test_skips_fifo_without_opening_it(self):
        self.write("app.py")
        os.mkfifo(self.source / "pipe")
        result = snapshot_repository(self.source, self.destination)
        self.assertEqual(result["skipped"]["special"], 1)

    def test_custom_exclusions_and_nested_output_do_not_recurse(self):
        self.write("src/app.py")
        self.write("fixtures/big.txt")
        destination = self.source / "generated" / "review"
        result = snapshot_repository(self.source, destination, ("fixtures/*",))
        self.assertEqual(result["files"], 1)
        self.assertFalse((destination / "generated").exists())
        self.assertFalse((destination / "fixtures").exists())

    @unittest.skipUnless(shutil.which("git"), "Git required")
    def test_gitignore_skips_untracked_files_but_keeps_tracked_ignored_files(self):
        subprocess.run(["git", "init", "-q", str(self.source)], check=True, capture_output=True)
        self.write(".gitignore", "ignored.txt\n*.log\n")
        self.write("app.py")
        self.write("ignored.txt")
        self.write("tracked.log")
        subprocess.run(["git", "-C", str(self.source), "add", "-f", "tracked.log"], check=True, capture_output=True)
        result = snapshot_repository(self.source, self.destination)
        self.assertTrue(result["git_ignore_applied"])
        self.assertTrue((self.destination / "tracked.log").exists())
        self.assertFalse((self.destination / "ignored.txt").exists())
        self.assertFalse((self.destination / ".git").exists())

    def test_snapshot_limits_fail_instead_of_silently_truncating(self):
        self.write("a.py", "abc\n")
        self.write("b.py", "def\n")
        for name, value in (("MAX_FILES", 1), ("MAX_TOTAL_BYTES", 7)):
            with self.subTest(name=name), patch("autoreviewer.snapshot." + name, value):
                with self.assertRaisesRegex(ValueError, "snapshot limits"):
                    snapshot_repository(self.source, self.destination)
                shutil.rmtree(self.destination)

    def test_oversized_files_report_scope_omission(self):
        self.write("small.py", "x\n")
        self.write("large.py", "x" * 20)
        with patch("autoreviewer.snapshot.MAX_FILE_BYTES", 10):
            result = snapshot_repository(self.source, self.destination)
        self.assertEqual(result["files"], 1)
        self.assertEqual(result["skipped"]["oversized"], 1)

    def test_empty_and_unsafe_destinations_fail(self):
        with self.assertRaisesRegex(ValueError, "No reviewable"):
            snapshot_repository(self.source, self.destination)
        self.write("app.py")
        for destination in (self.source, self.root, self.destination):
            with self.subTest(destination=destination), self.assertRaises(ValueError):
                snapshot_repository(self.source, destination)

    def test_git_enumeration_failure_is_visible(self):
        self.write("app.py")
        (self.source / ".git").mkdir()
        with patch("autoreviewer.snapshot.subprocess.run", side_effect=subprocess.CalledProcessError(1, "git")):
            with self.assertRaisesRegex(ValueError, "enumerate"):
                snapshot_repository(self.source, self.destination)


if __name__ == "__main__":
    unittest.main()
