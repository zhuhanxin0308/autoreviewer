"""A process-lifetime, non-inherited writer lock for a local UI data directory."""

from __future__ import annotations

import os
from pathlib import Path
import stat


class DataDirectoryLock:
    """Prevent two UI services from recovering or modifying the same history.

    The small lock file is deliberately left in place. OS locks are released on
    process death; deleting the file would allow competing locks on two inodes.
    """

    def __init__(self, directory: Path):
        self._descriptor: int | None = None
        directory = Path(directory)
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        path = directory / "ui.lock"
        if path.is_symlink():
            raise ValueError("The UI data lock must be a regular local file")
        descriptor = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                raise ValueError("The UI data lock must be a regular local file")
            os.set_inheritable(descriptor, False)
            if os.name == "posix":
                import fcntl
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    raise ValueError("Another autoreviewer UI is already using this data directory") from None
                os.fchmod(descriptor, 0o600)
            elif os.name == "nt":
                import msvcrt
                if not os.fstat(descriptor).st_size:
                    os.write(descriptor, b" ")
                os.lseek(descriptor, 0, os.SEEK_SET)
                try:
                    msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
                except OSError:
                    raise ValueError("Another autoreviewer UI is already using this data directory") from None
            else:
                raise ValueError("UI data-directory locking is unsupported on this operating system")
        except BaseException:
            os.close(descriptor)
            raise
        self._descriptor = descriptor

    def close(self) -> None:
        descriptor, self._descriptor = self._descriptor, None
        if descriptor is None:
            return
        try:
            if os.name == "posix":
                import fcntl
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            elif os.name == "nt":
                import msvcrt
                os.lseek(descriptor, 0, os.SEEK_SET)
                msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
        finally:
            os.close(descriptor)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        self.close()
