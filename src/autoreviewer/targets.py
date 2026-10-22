"""Local targets and narrowly scoped GitHub HTTPS clones."""

import os
from collections.abc import Mapping
from pathlib import Path
import re
import signal
import subprocess
from threading import Event
import time
from urllib.parse import urlsplit

from .config import GitHubConfig


def _clone(argv: list[str], env: dict[str, str], cancel_event: Event | None):
    if cancel_event is None:
        return subprocess.run(argv, env=env, capture_output=True, timeout=180, check=False)
    if cancel_event.is_set():
        raise ValueError("GitHub clone cancelled")
    options = {"start_new_session": True} if os.name == "posix" else {}
    process = subprocess.Popen(argv, env=env, stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, **options)
    deadline = time.monotonic() + 180
    try:
        while True:
            if cancel_event.is_set():
                raise ValueError("GitHub clone cancelled")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired("git", 180)
            try:
                stdout, stderr = process.communicate(timeout=min(0.2, remaining))
                return subprocess.CompletedProcess(argv, process.returncode, stdout, stderr)
            except subprocess.TimeoutExpired:
                continue
    except BaseException:
        # Clone runs in its own process group on POSIX, including Git helpers.
        # Cancelling a UI task must not leave an authenticated helper running.
        if os.name == "posix":
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
        elif process.poll() is None:
            process.terminate()
        try:
            process.communicate(timeout=0.3)
        except subprocess.TimeoutExpired:
            pass
        if os.name == "posix":
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        elif process.poll() is None:
            process.kill()
        process.communicate()
        raise
    finally:
        if process.stdout is not None:
            process.stdout.close()
        if process.stderr is not None:
            process.stderr.close()


def prepare_target(target: str, work_dir: Path, github: GitHubConfig | None = None, ref: str | None = None,
                   *, credentials: Mapping[str, str] | None = None, cancel_event: Event | None = None) -> Path:
    if cancel_event is not None and cancel_event.is_set():
        raise ValueError("Target preparation cancelled")
    if "://" not in target:
        if ref is not None:
            raise ValueError("--ref is only supported for remote GitHub targets")
        path = Path(target).expanduser().resolve(strict=True)
        if not path.is_dir():
            raise ValueError("Target must be a directory")
        return path
    parsed = urlsplit(target)
    if (parsed.scheme != "https" or parsed.netloc != "github.com" or parsed.query or parsed.fragment
            or not re.fullmatch(r"/[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*", parsed.path)):
        raise ValueError("Remote target must be https://github.com/owner/repository without credentials")
    repository = parsed.path[1:].removesuffix(".git")
    if ref is not None and (not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_./-]{0,199}", ref)
                            or ".." in ref or ref.endswith(("/", ".", ".lock")) or "//" in ref
                            or any(part.startswith(".") or part.endswith(".lock") for part in ref.split("/"))):
        raise ValueError("Invalid Git branch or tag for --ref")
    work_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    destination = work_dir / "clone"
    git_home = work_dir / "git-home"
    git_home.mkdir(mode=0o700)
    keep = {"PATH", "SYSTEMROOT", "SystemRoot", "WINDIR", "TMPDIR", "TEMP", "TMP", "LANG", "LC_ALL",
            "HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "NO_PROXY", "https_proxy", "http_proxy", "all_proxy", "no_proxy",
            "SSL_CERT_FILE", "SSL_CERT_DIR", "GIT_SSL_CAINFO", "CURL_CA_BUNDLE"}
    env = {key: value for key, value in os.environ.items() if key in keep}
    env.update({"HOME": str(git_home), "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1", "GIT_TERMINAL_PROMPT": "0", "GIT_LFS_SKIP_SMUDGE": "1"})
    if github and github.repository.lower() == repository.lower():
        token = (credentials or {}).get(github.token_env, os.environ.get(github.token_env))
        if token:
            askpass = work_dir / "git-askpass.sh"
            askpass.write_text('#!/bin/sh\ncase "$1" in\n*Username*) printf "%s\\n" "x-access-token" ;;\n*) printf "%s\\n" "$AUTOREVIEWER_GIT_TOKEN" ;;\nesac\n', encoding="utf-8")
            askpass.chmod(0o700)
            env.update({"GIT_ASKPASS": str(askpass), "AUTOREVIEWER_GIT_TOKEN": token})
    argv = ["git", "-c", "core.hooksPath=/dev/null", "-c", "credential.helper=", "-c", "http.followRedirects=false",
            "clone", "--depth", "1", "--no-recurse-submodules"]
    if ref:
        argv.extend(["--branch", ref])
    argv.extend(["--", f"https://github.com/{repository}.git", str(destination)])
    try:
        result = _clone(argv, env, cancel_event)
    except subprocess.TimeoutExpired as exc:
        raise ValueError("GitHub clone timed out") from exc
    if result.returncode:
        raise ValueError("GitHub clone failed; check repository, ref, network and Contents-read token permission")
    return destination
