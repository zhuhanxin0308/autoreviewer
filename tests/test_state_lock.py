from pathlib import Path
import os
import subprocess
import sys
import tempfile
import unittest

from autoreviewer.state_lock import DataDirectoryLock


class DataDirectoryLockTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def test_second_writer_is_rejected_and_close_is_idempotent(self):
        first = DataDirectoryLock(self.root)
        self.addCleanup(first.close)
        with self.assertRaisesRegex(ValueError, "already using"):
            DataDirectoryLock(self.root)
        self.assertFalse(os.get_inheritable(first._descriptor))
        first.close()
        first.close()
        with DataDirectoryLock(self.root):
            self.assertTrue((self.root / "ui.lock").is_file())

    def test_distinct_data_directories_are_independent(self):
        with DataDirectoryLock(self.root / "one"), DataDirectoryLock(self.root / "two"):
            pass

    @unittest.skipUnless(os.name == "posix", "POSIX process-death behavior")
    def test_process_exit_releases_lock_without_deleting_file(self):
        script = "from autoreviewer.state_lock import DataDirectoryLock; from pathlib import Path; import sys; lock=DataDirectoryLock(Path(sys.argv[1])); print('ready',flush=True); sys.stdin.read()"
        child = subprocess.Popen([sys.executable, "-c", script, str(self.root)], stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            self.assertEqual(child.stdout.readline().strip(), "ready")
            with self.assertRaises(ValueError):
                DataDirectoryLock(self.root)
            child.kill()
            child.wait(timeout=5)
            with DataDirectoryLock(self.root):
                self.assertEqual((self.root / "ui.lock").stat().st_mode & 0o777, 0o600)
        finally:
            if child.poll() is None:
                child.kill()
            child.communicate(timeout=5)

    @unittest.skipUnless(hasattr(os, "symlink"), "Symlinks unavailable")
    def test_symlink_lock_does_not_touch_target(self):
        target = self.root / "original"
        target.write_text("keep")
        (self.root / "ui.lock").symlink_to(target)
        with self.assertRaises(ValueError):
            DataDirectoryLock(self.root)
        self.assertEqual(target.read_text(), "keep")


if __name__ == "__main__":
    unittest.main()
