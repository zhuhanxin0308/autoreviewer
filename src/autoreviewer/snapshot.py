"""Copy reviewable text files without repository metadata or credential files."""

import fnmatch
import os
from pathlib import Path
import stat
import subprocess

DEFAULT_EXCLUDES = (
    ".git", ".hg", ".svn", ".autoreviewer", ".venv", "venv", "node_modules",
    "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", "dist", "build",
    ".env", ".env.*", "*.pem", "*.key", "*.p12", "*.pfx", "id_rsa*", "id_ed25519*",
    ".aws", ".ssh", ".gnupg", ".npmrc", ".netrc", ".pypirc", "credentials.json",
    ".codex", ".claude", ".gemini", ".opencode", "opencode.json", "opencode.jsonc",
    "AGENTS.md", "CLAUDE.md", "GEMINI.md", "autoreviewer.toml",
)
MAX_FILES = 20000
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_TOTAL_BYTES = 100 * 1024 * 1024


def _excluded(relative: Path, patterns: tuple[str, ...]) -> bool:
    parts = relative.parts
    return any(fnmatch.fnmatchcase(relative.as_posix().lower(), pattern.lower())
               or any(fnmatch.fnmatchcase(part.lower(), pattern.lower()) for part in parts)
               for pattern in patterns)


def snapshot_repository(source: Path, destination: Path, excludes: tuple[str, ...] = ()) -> dict:
    source = Path(source).resolve(strict=True)
    destination = Path(destination).resolve()
    if not source.is_dir():
        raise ValueError("Review target must be a directory")
    if destination == source or source.is_relative_to(destination):
        raise ValueError("Snapshot must not contain the source directory")
    if destination.exists():
        raise ValueError("Snapshot destination already exists")
    destination.mkdir(parents=True, mode=0o700)
    patterns = DEFAULT_EXCLUDES + tuple(excludes)
    count = 0
    total = 0
    skipped = {"excluded": 0, "symlink": 0, "binary": 0, "oversized": 0, "unreadable": 0, "special": 0}
    # Honor Git ignore rules for untracked files; tracked files remain reviewable.
    git_files = None
    if (source / ".git").exists():
        try:
            result = subprocess.run(
                ["git", "-c", "core.fsmonitor=false", "-C", str(source), "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
                capture_output=True, timeout=30, check=True,
                env={**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"},
            )
            git_files = {os.fsdecode(p) for p in result.stdout.split(b"\0") if p}
        except (OSError, subprocess.SubprocessError):
            raise ValueError("Cannot enumerate repository files with git") from None
    for current, dirs, files in os.walk(source, followlinks=False):
        current_path = Path(current)
        for name in list(dirs):
            path = current_path / name
            relative = path.relative_to(source)
            if path.is_symlink():
                skipped["symlink"] += 1
                dirs.remove(name)
            elif path == destination or destination.is_relative_to(path) or _excluded(relative, patterns):
                skipped["excluded"] += 1
                dirs.remove(name)
        for name in sorted(files):
            path = current_path / name
            relative = path.relative_to(source)
            if _excluded(relative, patterns) or (git_files is not None and relative.as_posix() not in git_files):
                skipped["excluded"] += 1
                continue
            try:
                if path.is_symlink():
                    skipped["symlink"] += 1
                    continue
                metadata = path.stat(follow_symlinks=False)
                if not stat.S_ISREG(metadata.st_mode):
                    skipped["special"] += 1
                    continue
                if metadata.st_size > MAX_FILE_BYTES:
                    skipped["oversized"] += 1
                    continue
                # O_NOFOLLOW also guards a file changed into a symlink during copying.
                fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
                with os.fdopen(fd, "rb") as stream:
                    if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                        skipped["special"] += 1
                        continue
                    data = stream.read(MAX_FILE_BYTES + 1)
                if len(data) > MAX_FILE_BYTES:
                    skipped["oversized"] += 1
                    continue
                if b"\0" in data:
                    skipped["binary"] += 1
                    continue
                try:
                    data.decode("utf-8")
                except UnicodeDecodeError:
                    skipped["binary"] += 1
                    continue
                if count >= MAX_FILES or total + len(data) > MAX_TOTAL_BYTES:
                    raise ValueError("Repository exceeds snapshot limits (20,000 files / 100 MiB); use scan.excludes")
                target = destination / relative
                target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                target.write_bytes(data)
                target.chmod(0o600)
                total += len(data)
                count += 1
            except OSError:
                skipped["unreadable"] += 1
    if count == 0:
        raise ValueError("No reviewable UTF-8 files remain after filtering")
    return {"files": count, "bytes": total, "skipped": skipped, "git_ignore_applied": git_files is not None}
