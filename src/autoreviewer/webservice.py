"""State and jobs for the local browser interface, independent of HTTP.

Credentials are session-only overlays. Nothing in this module modifies the
process environment, and only non-secret configuration and review reports are
persisted. Each scan uses a stable baseline plus the runner's per-model copies.
"""

from __future__ import annotations

import asyncio
import copy
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timezone
from importlib.resources import files
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import tempfile
import threading
import tomllib
import uuid
from typing import Any
from urllib.parse import urlsplit

from . import __version__
from .config import Config, load_config
from .findings import finding_fingerprint, merge_findings
from .github import plan_issues, publish_issues as publish_to_github
from .reportio import group_findings, validate_report
from .reports import write_reports
from .runner import _redact, _redact_text, run_models
from .snapshot import snapshot_repository
from .state_lock import DataDirectoryLock
from .targets import prepare_target


ACTIVE_STATUSES = frozenset({"queued", "preparing", "running", "cancelling"})
TERMINAL_STATUSES = frozenset({"completed", "partial", "failed", "cancelled", "interrupted"})
MAX_HISTORY = 200
MAX_EVENTS = 256
MAX_REPORT_BYTES = 32 * 1024 * 1024
_JOB_ID = re.compile(r"[a-f0-9]{32}\Z")


class ServiceError(ValueError):
    def __init__(self, message: str, status_code: int = 400):
        super().__init__(message)
        self.status_code = status_code


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _object(value: Any, allowed: set[str], label: str) -> dict:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise ServiceError(f"{label} must be an object")
    if value.keys() - allowed:
        # Do not echo arbitrary keys: a user can accidentally paste a secret.
        raise ServiceError(f"{label} contains an unsupported field")
    return value


def _contains_secret(value: Any, secret_values: tuple[str, ...]) -> bool:
    if isinstance(value, str):
        return any(secret in value for secret in secret_values)
    if isinstance(value, dict):
        return any(_contains_secret(key, secret_values) or _contains_secret(item, secret_values) for key, item in value.items())
    if isinstance(value, list):
        return any(_contains_secret(item, secret_values) for item in value)
    return False


def _redact_import(value: Any, secret_values: tuple[str, ...]) -> Any:
    """Imported JSON keys are untrusted too; never retain credential-bearing keys."""
    if isinstance(value, str):
        return _redact_text(value, secret_values)
    if isinstance(value, list):
        return [_redact_import(item, secret_values) for item in value]
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            safe_key = _redact_text(key, secret_values)
            if safe_key in result:
                raise ServiceError("Credential redaction made report fields ambiguous; remove sensitive data and try again")
            result[safe_key] = _redact_import(item, secret_values)
        return result
    return value


def _redact_runner_run(run: dict, secret_values: tuple[str, ...]) -> dict:
    """Preserve only provenance supplied by the local runner's trusted boundary.

    A credential may coincidentally match a public commit or digest substring.
    Never use this helper for imported reports: their metadata remains untrusted.
    """
    result = _redact(run, secret_values)
    if "audit_guidance" in run:
        result["audit_guidance"] = copy.deepcopy(run["audit_guidance"])
    return result


def _config_shape(raw: Any) -> dict:
    raw = _object(raw, {"version", "providers", "agents", "models", "scan", "github"}, "Configuration")
    for section, allowed in (
        ("providers", {"base_url", "api_key_env", "api_format"}),
        ("agents", {"command", "args"}),
    ):
        values = raw.get(section, {})
        if not isinstance(values, dict) or any(not isinstance(key, str) for key in values):
            raise ServiceError(f"{section} must be an object")
        for value in values.values():
            _object(value, allowed, section)
    models = raw.get("models", [])
    if not isinstance(models, list):
        raise ServiceError("models must be an array")
    for model in models:
        _object(model, {"id", "provider", "model", "agent"}, "Model")
    _object(raw.get("scan", {}), {"concurrency", "timeout_seconds", "max_output_bytes", "excludes"}, "Scan settings")
    if "github" in raw:
        _object(raw["github"], {"repository", "token_env", "labels"}, "GitHub settings")
    return raw


def _toml_value(value: Any) -> str:
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if type(value) is int:
        return str(value)
    if type(value) is bool:
        return "true" if value else "false"
    if isinstance(value, list):
        return "[" + ", ".join(_toml_value(item) for item in value) + "]"
    raise ServiceError("Configuration values must be strings, integers, or arrays")


def _serialize_config(raw: dict) -> str:
    """Quote every table key; validation happens before this text is saved."""
    raw = _config_shape(raw)
    lines = ["version = " + _toml_value(raw.get("version", 1))]
    for section in ("scan", "github"):
        if section in raw:
            lines.extend(["", f"[{section}]"])
            lines.extend(f"{key} = {_toml_value(value)}" for key, value in raw[section].items())
    for section in ("providers", "agents"):
        for name, values in raw.get(section, {}).items():
            lines.extend(["", f"[{section}.{_toml_value(name)}]"])
            lines.extend(f"{key} = {_toml_value(value)}" for key, value in values.items())
    for model in raw.get("models", []):
        lines.extend(["", "[[models]]"])
        lines.extend(f"{key} = {_toml_value(value)}" for key, value in model.items())
    return "\n".join(lines) + "\n"


def _config_dict(config: Config) -> dict:
    providers = {}
    for name, provider in config.providers.items():
        item = {"base_url": provider.base_url, "api_format": provider.api_format}
        if provider.api_key_env:
            item["api_key_env"] = provider.api_key_env
        providers[name] = item
    result = {
        "version": 1,
        "providers": providers,
        "agents": {name: {"command": list(agent.command), "args": list(agent.args)} for name, agent in config.agents.items()},
        "models": [asdict(model) for model in config.models],
        "scan": {**asdict(config.scan), "excludes": list(config.scan.excludes)},
    }
    if config.github:
        result["github"] = {**asdict(config.github), "labels": list(config.github.labels)}
    return result


def _parse_config(raw: dict) -> Config:
    text = _serialize_config(raw)
    if len(text.encode("utf-8")) > 1024 * 1024:
        raise ServiceError("Configuration exceeds 1 MiB")
    with tempfile.TemporaryDirectory(prefix="autoreviewer-config-") as directory:
        path = Path(directory) / "config.toml"
        _atomic_write(path, text)
        try:
            return load_config(path)
        except (ValueError, UnicodeError) as exc:
            raise ServiceError(str(exc)) from None


def _atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor, temporary = tempfile.mkstemp(prefix="." + path.name + ".", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


@dataclass
class _Worker:
    cancel: threading.Event
    thread: threading.Thread | None = None
    loop: asyncio.AbstractEventLoop | None = None
    task: asyncio.Task | None = None


class WebService:
    def __init__(self, config_path: Path, data_dir: Path):
        self.config_path = Path(config_path).expanduser().resolve()
        self.data_dir = Path(data_dir).expanduser().resolve()
        self.data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._lock = threading.RLock()
        self._credentials: dict[str, str] = {}
        self._jobs: dict[str, dict] = {}
        self._workers: dict[str, _Worker] = {}
        self._previews: dict[str, dict] = {}
        self._closed = False
        self._publishing = False
        self._config_revision = 0
        self._data_lock = DataDirectoryLock(self.data_dir)
        try:
            if self.config_path.exists():
                self._config = load_config(self.config_path)
            else:
                raw = tomllib.loads(files("autoreviewer").joinpath("default.toml").read_text(encoding="utf-8"))
                self._config = _parse_config(raw)
            self._load_history()
        except BaseException:
            self._data_lock.close()
            raise

    def _credential_names(self, config: Config | None = None) -> set[str]:
        config = config or self._config
        names = {p.api_key_env for p in config.providers.values() if p.api_key_env}
        if config.github:
            names.add(config.github.token_env)
        return names

    def _credential_snapshot(self, config: Config | None = None) -> dict[str, str]:
        return {name: self._credentials.get(name, os.environ.get(name, "")) for name in self._credential_names(config)}

    def _secret_values(self) -> tuple[str, ...]:
        values = {value for value in self._credential_snapshot().values() if value}
        return tuple(sorted(values, key=len, reverse=True))

    def _credential_status(self) -> list[dict]:
        return [
            {"name": name, "configured": bool(self._credentials.get(name) or os.environ.get(name)),
             "source": "session" if self._credentials.get(name) else "environment" if os.environ.get(name) else "missing"}
            for name in sorted(self._credential_names())
        ]

    def _configuration(self) -> dict:
        return {
            "config": _config_dict(self._config),
            "config_revision": self._config_revision,
            "credentials": self._credential_status(),
            "agents": [{"id": name, "command": list(agent.command), "available": bool(shutil.which(agent.command[0]))}
                       for name, agent in self._config.agents.items()],
        }

    def bootstrap(self) -> dict:
        with self._lock:
            return copy.deepcopy({"version": __version__, **self._configuration(), "jobs": self.list_jobs()})

    def save_config(self, raw: dict, *, expected_revision: int | None = None) -> dict:
        with self._lock:
            self._check_open()
            if expected_revision is not None:
                if type(expected_revision) is not int or expected_revision < 0:
                    raise ServiceError("Configuration revision must be a nonnegative integer")
                if expected_revision != self._config_revision:
                    raise ServiceError("Configuration changed in another session; reload the latest configuration before saving", 409)
            # Detect known secrets before temporary validation files are created.
            if _contains_secret(raw, self._secret_values()):
                raise ServiceError("Keep credential values in the session credential fields, not configuration")
            config = _parse_config(raw)
            _atomic_write(self.config_path, _serialize_config(_config_dict(config)))
            self._config = config
            self._config_revision += 1
            self._previews.clear()
            names = self._credential_names()
            self._credentials = {key: value for key, value in self._credentials.items() if key in names}
            return copy.deepcopy(self._configuration())

    def export_config(self) -> str:
        with self._lock:
            self._check_open()
            return _serialize_config(_config_dict(self._config))

    def set_credential(self, name: str, value: str) -> dict:
        with self._lock:
            self._check_open()
            if not isinstance(name, str) or name not in self._credential_names():
                raise ServiceError("Credential must name a configured provider or GitHub environment variable")
            if not isinstance(value, str) or len(value) > 16384 or any(ord(c) < 33 or 0xD800 <= ord(c) <= 0xDFFF for c in value):
                raise ServiceError("Credential must be a string without whitespace, at most 16384 characters")
            if value:
                self._credentials[name] = value
            else:
                self._credentials.pop(name, None)
            return {"credentials": self._credential_status()}

    def _check_open(self) -> None:
        if self._closed:
            raise ServiceError("The local interface is shutting down", 503)

    def _job(self, job_id: str) -> dict:
        if not isinstance(job_id, str) or not _JOB_ID.fullmatch(job_id) or job_id not in self._jobs:
            raise ServiceError("Review task not found", 404)
        return self._jobs[job_id]

    def _summary(self, job: dict) -> dict:
        result = {key: value for key, value in job.items() if key not in {"report", "events", "runs"}}
        result["runs"] = [{key: value for key, value in run.items() if key != "findings"} |
                          {"finding_count": len(run["findings"]) if "findings" in run else run.get("finding_count", 0)}
                          for run in job.get("runs", [])]
        result["completed_models"] = sum(run.get("status") == "completed" for run in job.get("runs", []))
        result["total_models"] = len(job.get("runs", []))
        result["finding_count"] = len(job["report"].get("findings", [])) if job.get("report") else job.get("finding_count", 0)
        return result

    def list_jobs(self) -> list[dict]:
        with self._lock:
            return copy.deepcopy([self._summary(job) for job in sorted(self._jobs.values(), key=lambda job: job["created_at"], reverse=True)])

    def get_job(self, job_id: str) -> dict:
        with self._lock:
            job = self._job(job_id)
            if job.get("report") is None and job["status"] in TERMINAL_STATUSES:
                self._load_report(job)
            result = {**job, **{key: value for key, value in self._summary(job).items() if key not in {"runs"}}}
            result["finding_groups"] = group_findings(job["report"]["findings"]) if job.get("report") else []
            return copy.deepcopy(result)

    def get_report(self, job_id: str) -> dict:
        with self._lock:
            job = self._job(job_id)
            if job["status"] not in TERMINAL_STATUSES and job.get("report") is None:
                raise ServiceError("The review report is not ready", 409)
            if job.get("report") is None:
                self._load_report(job)
            if job.get("report") is None:
                raise ServiceError("This task has no saved report", 404)
            return copy.deepcopy(job["report"])

    def start_job(self, payload: dict) -> dict:
        return self._start_job(payload)

    def _start_job(self, payload: dict, *, parent_job_id: str | None = None, retry_mode: str | None = None) -> dict:
        payload = _object(payload, {"target", "ref", "models", "concurrency", "timeout_seconds"}, "Review request")
        target = payload.get("target")
        if not isinstance(target, str) or not target.strip() or len(target) > 4096 or any(ord(c) < 32 or 0xD800 <= ord(c) <= 0xDFFF for c in target):
            raise ServiceError("Enter a local directory or a GitHub HTTPS repository")
        ref = payload.get("ref")
        if ref == "":
            ref = None
        if ref is not None and (not isinstance(ref, str) or len(ref) > 200 or any(ord(c) < 32 or 0xD800 <= ord(c) <= 0xDFFF for c in ref)):
            raise ServiceError("Repository ref must be a string of at most 200 characters without control characters")
        if "://" in target:
            try:
                parsed = urlsplit(target.strip())
            except ValueError:
                raise ServiceError("Remote target must be https://github.com/owner/repository without credentials") from None
            if (parsed.scheme != "https" or parsed.netloc != "github.com" or parsed.query or parsed.fragment
                    or not re.fullmatch(r"/[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*", parsed.path)):
                raise ServiceError("Remote target must be https://github.com/owner/repository without credentials")
        elif ref is not None:
            raise ServiceError("Repository ref is only supported for GitHub targets")
        with self._lock:
            self._check_open()
            if _contains_secret([target, ref], self._secret_values()):
                raise ServiceError("Keep credentials out of review targets and repository refs")
            if any(job["status"] in ACTIVE_STATUSES for job in self._jobs.values()):
                raise ServiceError("A review is already running; finish or cancel it before starting another", 409)
            model_ids = payload.get("models", [model.id for model in self._config.models])
            if not isinstance(model_ids, list) or not model_ids or any(not isinstance(item, str) for item in model_ids):
                raise ServiceError("Select at least one configured model")
            selected = set(model_ids)
            if len(selected) != len(model_ids) or selected - {model.id for model in self._config.models}:
                raise ServiceError("Model selection contains duplicate or unknown ids")
            scan = self._config.scan
            changes = {}
            for name, maximum in (("concurrency", 32), ("timeout_seconds", 86400)):
                if name in payload:
                    value = payload[name]
                    if type(value) is not int or not 1 <= value <= maximum:
                        raise ServiceError(f"{name} must be an integer between 1 and {maximum}")
                    changes[name] = value
            config = replace(self._config, models=tuple(model for model in self._config.models if model.id in selected), scan=replace(scan, **changes))
            credentials = self._credential_snapshot(config)
            job_id = uuid.uuid4().hex
            job = {
                "id": job_id, "target": target.strip(), "ref": ref, "status": "queued",
                "created_at": _now(), "started_at": None, "finished_at": None,
                "concurrency": config.scan.concurrency, "timeout_seconds": config.scan.timeout_seconds,
                "runs": [{"model": model.id, "model_name": model.model, "provider": model.provider,
                          "agent": model.agent, "status": "queued", "duration_seconds": 0,
                          "error": None, "findings": []} for model in config.models],
                "events": [], "report": None, "error": None,
                "origin": "scan", "imported": False,
            }
            if parent_job_id:
                job.update({"parent_job_id": parent_job_id, "retry_mode": retry_mode})
            self._jobs[job_id] = job
            self._event(job, "queued", "Review queued")
            try:
                self._persist(job)
                worker = _Worker(threading.Event())
                worker.thread = threading.Thread(target=self._run_job, args=(job_id, config, credentials, worker), name=f"autoreviewer-{job_id[:8]}", daemon=True)
                self._workers[job_id] = worker
                worker.thread.start()
            except Exception:
                self._jobs.pop(job_id, None)
                self._workers.pop(job_id, None)
                shutil.rmtree(self.data_dir / "jobs" / job_id, ignore_errors=True)
                credentials.clear()
                raise ServiceError("Unable to create a review task; check the local data directory and available resources") from None
            self._prune_history()
            return copy.deepcopy(job)

    def retry_job(self, job_id: str, payload: dict) -> dict:
        payload = _object(payload, {"mode"}, "Retry request")
        mode = payload.get("mode", "failed")
        if not isinstance(mode, str) or mode not in {"failed", "all"}:
            raise ServiceError("Retry mode must be failed or all")
        with self._lock:
            self._check_open()
            previous = self._job(job_id)
            if previous.get("imported") or previous.get("origin") == "imported":
                raise ServiceError("Imported reports cannot start scans; create a new scan and choose its target", 409)
            if previous["status"] not in TERMINAL_STATUSES:
                raise ServiceError("Wait for this review to finish before retrying", 409)
            runs = [run for run in previous["runs"] if mode == "all" or run["status"] != "completed"]
            if not runs:
                raise ServiceError("This review has no failed or unfinished models to retry", 409)
            current = {model.id: model for model in self._config.models}
            for run in runs:
                model = current.get(run["model"])
                if model is None or (model.provider, model.model, model.agent) != (run.get("provider"), run.get("model_name"), run.get("agent")):
                    raise ServiceError("A selected model configuration was removed or changed; create a new scan with the desired configuration", 409)
            return self._start_job({"target": previous["target"], "ref": previous.get("ref"),
                                    "models": [run["model"] for run in runs]},
                                   parent_job_id=job_id, retry_mode=mode)

    def import_report(self, payload: dict) -> dict:
        payload = _object(payload, {"report", "name"}, "Report import")
        name = payload.get("name", "report.json")
        if (not isinstance(name, str) or not name.strip() or len(name) > 255
                or any(ord(char) < 32 or 0xD800 <= ord(char) <= 0xDFFF for char in name)
                or "/" in name or "\\" in name):
            raise ServiceError("Use a report filename without a directory path")
        try:
            report = validate_report(payload.get("report"), allow_checkpoint=True)
        except ValueError:
            raise ServiceError("Invalid autoreviewer report; check its schema, findings and model provenance") from None
        with self._lock:
            self._check_open()
            secret_values = self._secret_values()
            report = _redact_import(report, secret_values)
            report.pop("checkpoint", None)
            for run in report["runs"]:
                for finding in run.get("findings", []):
                    finding["fingerprint"] = finding_fingerprint(finding)
            report["findings"] = merge_findings([
                run["findings"] for run in report["runs"] if run["status"] == "completed"
            ])
            try:
                report = validate_report(report)
            except ValueError:
                raise ServiceError("The report cannot be imported after credential redaction; remove sensitive data and try again") from None
            job_id = uuid.uuid4().hex
            job = {"id": job_id, "target": report["target"], "ref": report.get("ref"),
                   "status": report["status"], "created_at": _now(), "started_at": report["started_at"],
                   "finished_at": report["finished_at"], "runs": report["runs"], "report": report,
                   "events": [], "error": None, "origin": "imported", "imported": True,
                   "source_name": _redact_text(name, secret_values)}
            self._event(job, "imported", "Existing report imported; no code or model was executed")
            try:
                write_reports(report, self.data_dir / "jobs" / job_id)
                self._persist(job)
            except OSError:
                shutil.rmtree(self.data_dir / "jobs" / job_id, ignore_errors=True)
                raise ServiceError("Unable to save the imported report; check the local data directory") from None
            self._jobs[job_id] = job
            self._prune_history()
            return self.get_job(job_id)

    def _event(self, job: dict, status: str, message: str, model: str | None = None, at: str | None = None) -> None:
        event = {"at": at or _now(), "status": status, "message": message[:2000]}
        if model is not None:
            event["model"] = model
        job["events"].append(event)
        job["events"] = job["events"][-MAX_EVENTS:]

    def _make_report(self, job: dict, scope: dict | None, *, checkpoint: bool = False) -> dict:
        runs = copy.deepcopy(job["runs"])
        completed = sum(run["status"] == "completed" for run in runs)
        report = {
            "schema_version": 1, "autoreviewer_version": __version__, "target": job["target"], "ref": job["ref"],
            "started_at": job["started_at"], "finished_at": job["finished_at"] or _now(),
            "status": "completed" if completed == len(runs) else "partial" if completed else "failed",
            "scope": copy.deepcopy(scope), "runs": runs,
            "findings": merge_findings([run.get("findings", []) for run in runs if run["status"] == "completed"]),
        }
        if checkpoint:
            report["checkpoint"] = True
        return report

    def _save_progress(self, job: dict, *, checkpoint: bool = False) -> None:
        """Keep observer I/O errors visible without discarding completed results."""
        error = None
        if checkpoint:
            try:
                _atomic_write(self.data_dir / "jobs" / job["id"] / "checkpoint.json",
                              json.dumps(job["report"], ensure_ascii=False, allow_nan=False))
            except OSError:
                error = "Completed results are in memory, but their recovery checkpoint could not be saved"
        if error:
            job["persistence_error"] = error
        elif checkpoint:
            job.pop("persistence_error", None)
        try:
            self._persist(job)
        except OSError:
            job["persistence_error"] = "Task state is available in memory but could not be saved to disk"

    def _run_job(self, job_id: str, config: Config, credentials: dict[str, str], worker: _Worker) -> None:
        secrets_tuple = tuple(sorted({value for value in credentials.values() if value}, key=len, reverse=True))
        scope = None
        runs = None
        loop = None
        try:
            with self._lock:
                job = self._job(job_id)
                job["started_at"] = _now()
                if not worker.cancel.is_set():
                    job["status"] = "preparing"
                self._event(job, job["status"], "Preparing a filtered, stable code snapshot")
                self._save_progress(job)
            with tempfile.TemporaryDirectory(prefix="autoreviewer-ui-") as temporary:
                root = Path(temporary)
                if worker.cancel.is_set():
                    raise asyncio.CancelledError()
                source = prepare_target(job["target"], root / "target", config.github, job["ref"], credentials=credentials, cancel_event=worker.cancel)
                excludes = config.scan.excludes
                if source.is_relative_to(self.data_dir):
                    raise ServiceError("The review target cannot be the interface data directory or its descendants")
                for omitted in (self.data_dir, self.config_path):
                    if omitted.is_relative_to(source):
                        excludes += (omitted.relative_to(source).as_posix(),)
                if worker.cancel.is_set():
                    raise asyncio.CancelledError()
                scope = snapshot_repository(source, root / "baseline", excludes)
                if worker.cancel.is_set():
                    raise asyncio.CancelledError()

                def on_event(event: dict) -> None:
                    safe = _redact(copy.deepcopy(event), secrets_tuple)
                    if isinstance(event.get("run"), dict):
                        safe["run"] = _redact_runner_run(event["run"], secrets_tuple)
                    with self._lock:
                        current = self._job(job_id)
                        model_id = safe.get("model")
                        run = safe.get("run")
                        for index, previous in enumerate(current["runs"]):
                            if previous["model"] == model_id:
                                current["runs"][index] = run if isinstance(run, dict) else {**previous, "status": safe["status"]}
                                break
                        self._event(current, safe["status"], safe.get("message") or f"Model {safe['status']}", model_id, safe.get("at"))
                        checkpoint = safe["status"] in {"completed", "failed", "timeout", "cancelled"}
                        if checkpoint:
                            current["report"] = self._make_report(current, scope, checkpoint=True)
                            current["checkpoint_at"] = current["report"]["finished_at"]
                        self._save_progress(current, checkpoint=checkpoint)

                loop = asyncio.new_event_loop()
                task = loop.create_task(run_models(config, root / "baseline", root / "models", credentials=credentials, on_event=on_event))
                with self._lock:
                    worker.loop, worker.task = loop, task
                    if worker.cancel.is_set():
                        task.cancel()
                    else:
                        job["status"] = "running"
                        self._event(job, "running", "Model reviews started")
                    self._save_progress(job)
                runs = loop.run_until_complete(task)
        except asyncio.CancelledError:
            worker.cancel.set()
        except Exception as exc:
            with self._lock:
                job = self._job(job_id)
                if not worker.cancel.is_set():
                    message = str(exc) if isinstance(exc, ValueError) else "Review failed while preparing or saving the scan"
                    job["error"] = _redact_text(message, secrets_tuple)[:2000]
                    self._event(job, "failed", job["error"])
        finally:
            if loop is not None:
                with self._lock:
                    worker.loop, worker.task = None, None
                loop.close()
            with self._lock:
                job = self._job(job_id)
                if runs is not None:
                    job["runs"] = [_redact_runner_run(run, secrets_tuple) for run in runs]
                for run in job["runs"]:
                    if run["status"] in ACTIVE_STATUSES:
                        run["status"] = "cancelled" if worker.cancel.is_set() else "failed"
                        run["error"] = "Review cancelled" if worker.cancel.is_set() else job.get("error") or "Review did not finish"
                completed = sum(run["status"] == "completed" for run in job["runs"])
                report_status = "completed" if completed == len(job["runs"]) else "partial" if completed else "failed"
                job["status"] = "cancelled" if worker.cancel.is_set() else report_status
                job["finished_at"] = _now()
                report = self._make_report(job, scope)
                if worker.cancel.is_set():
                    report["cancelled"] = True
                job["report"] = _redact(report, secrets_tuple)
                job["report"]["runs"] = [_redact_runner_run(run, secrets_tuple) for run in report["runs"]]
                self._event(job, job["status"], "Review cancelled; completed results were retained" if worker.cancel.is_set() else "Review finished")
                try:
                    write_reports(job["report"], self.data_dir / "jobs" / job_id)
                    job.pop("persistence_error", None)
                    self._persist(job)
                    (self.data_dir / "jobs" / job_id / "checkpoint.json").unlink(missing_ok=True)
                except OSError:
                    job["persistence_error"] = "Results are available in this session but could not be saved to disk"
                self._workers.pop(job_id, None)
                credentials.clear()
                if self._closed and not self._workers and not self._publishing:
                    self._data_lock.close()

    def cancel_job(self, job_id: str) -> dict:
        with self._lock:
            job = self._job(job_id)
            worker = self._workers.get(job_id)
            if job["status"] in ACTIVE_STATUSES and worker and not worker.cancel.is_set():
                worker.cancel.set()
                job["status"] = "cancelling"
                self._event(job, "cancelling", "Stopping model processes and cleaning their workspaces")
                if worker.loop is not None and worker.task is not None:
                    worker.loop.call_soon_threadsafe(worker.task.cancel)
                try:
                    self._persist(job)
                except OSError:
                    job["persistence_error"] = "Cancellation was requested, but its status could not be saved"
            return copy.deepcopy(job)

    def _persist(self, job: dict) -> None:
        metadata = self._summary(job)
        metadata["events"] = job["events"][-MAX_EVENTS:]
        _atomic_write(self.data_dir / "jobs" / job["id"] / "job.json", json.dumps(metadata, ensure_ascii=False, allow_nan=False))

    def _load_history(self) -> None:
        directory = self.data_dir / "jobs"
        if not directory.exists():
            return
        paths = sorted((path for path in directory.iterdir() if _JOB_ID.fullmatch(path.name) and path.is_dir() and not path.is_symlink()), key=lambda path: path.stat().st_mtime, reverse=True)
        for folder in paths[:MAX_HISTORY]:
            path = folder / "job.json"
            try:
                if path.is_symlink() or path.stat().st_size > 2 * 1024 * 1024:
                    continue
                job = json.loads(path.read_text(encoding="utf-8"))
                if (not isinstance(job, dict) or job.get("id") != folder.name or job.get("status") not in ACTIVE_STATUSES | TERMINAL_STATUSES
                        or not isinstance(job.get("created_at"), str) or not isinstance(job.get("runs"), list)
                        or not isinstance(job.get("events"), list)
                        or any(not isinstance(run, dict) or not isinstance(run.get("model"), str)
                               or not isinstance(run.get("status"), str) for run in job["runs"])
                        or any(not isinstance(event, dict) for event in job["events"])):
                    continue
                job["report"] = None
                if job["status"] in ACTIVE_STATUSES:
                    job["status"] = "interrupted"
                    job["finished_at"] = _now()
                    job["error"] = "The application stopped before this review finished"
                    self._load_report(job)
                    for run in job["runs"]:
                        if run.get("status") in ACTIVE_STATUSES:
                            run["status"] = "interrupted"
                            run["error"] = "The application stopped before this model finished"
                    self._event(job, "interrupted", job["error"])
                    if job.get("report") is not None:
                        job["report"].pop("checkpoint", None)
                        job["report"]["interrupted"] = True
                        try:
                            write_reports(job["report"], folder)
                            (folder / "checkpoint.json").unlink(missing_ok=True)
                        except OSError:
                            job["persistence_error"] = "Recovered results are in memory but could not be saved to disk"
                    self._save_progress(job)
                self._jobs[job["id"]] = job
            except (OSError, ValueError, TypeError, KeyError, RecursionError):
                continue

    def _load_report(self, job: dict) -> None:
        path = self.data_dir / "jobs" / job["id"] / "report.json"
        candidates = [(path, False)]
        if job["status"] == "interrupted":
            candidates.append((path.with_name("checkpoint.json"), True))
        invalid_final = False
        for candidate, checkpoint in candidates:
            try:
                if candidate.is_symlink() or candidate.stat().st_size > MAX_REPORT_BYTES:
                    raise ValueError("Saved report is not a bounded regular report")
                report = validate_report(json.loads(candidate.read_text(encoding="utf-8")), allow_checkpoint=checkpoint)
            except FileNotFoundError:
                continue
            except (OSError, ValueError, UnicodeError, TypeError, RecursionError):
                invalid_final = invalid_final or not checkpoint
                continue
            job["report"] = report
            job["runs"] = report["runs"]
            if checkpoint and invalid_final:
                job["persistence_error"] = "The final report was unreadable or invalid; results were recovered from a saved checkpoint"
                # Preserve the rejected file for diagnosis before startup writes
                # the recovered report. Renaming a symlink does not follow it.
                backup = path.with_name(f"report.unreadable-{uuid.uuid4().hex}.json")
                try:
                    path.replace(backup)
                except OSError:
                    # The valid checkpoint stays in place until recovery is saved.
                    pass
            return
        job["persistence_error"] = "No readable saved report or recovery checkpoint is available; saved findings could not be restored"

    def _prune_history(self) -> None:
        if len(self._jobs) <= MAX_HISTORY:
            return
        for job in sorted(self._jobs.values(), key=lambda value: value["created_at"]):
            if len(self._jobs) <= MAX_HISTORY:
                break
            if job["status"] in TERMINAL_STATUSES:
                # Bound session memory; never silently delete saved reports.
                self._jobs.pop(job["id"], None)

    def preview_issues(self, job_id: str, payload: dict) -> dict:
        payload = _object(payload, {"fingerprints", "allow_partial"}, "Issue preview")
        fingerprints = payload.get("fingerprints")
        allow_partial = payload.get("allow_partial", False)
        if not isinstance(fingerprints, list) or not fingerprints:
            raise ServiceError("Select at least one finding for the issue preview")
        if len(fingerprints) > 1000:
            raise ServiceError("Select at most 1000 findings for one issue preview; reduce the selection and try again")
        if any(not isinstance(value, str) for value in fingerprints):
            raise ServiceError("Issue selection must contain finding fingerprints")
        if type(allow_partial) is not bool:
            raise ServiceError("allow_partial must be a boolean")
        with self._lock:
            self._check_open()
            github = self._config.github
            if github is None:
                raise ServiceError("Configure a GitHub repository before preparing issues")
            if self._job(job_id)["status"] in ACTIVE_STATUSES:
                raise ServiceError("Wait for the review to finish before preparing issues", 409)
            report = self.get_report(job_id)
            selected = set(fingerprints)
            findings = [finding for finding in report["findings"] if finding["fingerprint"] in selected]
            if len(selected) != len(fingerprints) or selected != {finding["fingerprint"] for finding in findings}:
                raise ServiceError("Issue selection contains duplicate or unknown fingerprints")
            report["findings"] = findings
            issues = plan_issues(report, allow_partial=allow_partial)
            preview_id = secrets.token_urlsafe(24)
            if len(self._previews) >= 100:
                self._previews.pop(next(iter(self._previews)))
            self._previews[preview_id] = {"job_id": job_id, "report": report, "config": github,
                                          "revision": self._config_revision, "allow_partial": allow_partial, "state": "ready"}
            return copy.deepcopy({"repository": github.repository, "issues": issues, "preview_id": preview_id})

    def publish_issues(self, job_id: str, payload: dict) -> dict:
        payload = _object(payload, {"preview_id", "confirmation"}, "Issue publication")
        preview_id = payload.get("preview_id")
        if not isinstance(preview_id, str):
            raise ServiceError("Preview the selected issues before publishing")
        with self._lock:
            self._check_open()
            self._job(job_id)
            preview = self._previews.get(preview_id)
            if not preview or preview["job_id"] != job_id or preview["revision"] != self._config_revision:
                raise ServiceError("This preview is no longer current; create a new preview", 409)
            if preview["state"] != "ready":
                raise ServiceError("This preview has already been submitted; preview again before retrying", 409)
            if self._publishing:
                raise ServiceError("Another issue publication is running; wait for it to finish", 409)
            github = preview["config"]
            if payload.get("confirmation") != github.repository:
                raise ServiceError("Confirm the exact repository shown in the issue preview")
            token = self._credentials.get(github.token_env, os.environ.get(github.token_env, ""))
            if not token:
                raise ServiceError("Set the configured GitHub token before publishing")
            preview["state"] = "submitted"
            self._publishing = True
            secret_values = self._secret_values()
        try:
            try:
                issues = publish_to_github(preview["report"], github, allow_partial=preview["allow_partial"], token=token,
                                           receipt_path=self.data_dir / "github-publications.json")
            except (ValueError, OSError) as exc:
                raise ServiceError(_redact_text(str(exc), secret_values)[:2000]) from None
            with self._lock:
                job = self._job(job_id)
                self._event(job, "published", f"GitHub returned {len(issues)} issue result(s)")
                self._persist(job)
            return {"repository": github.repository, "issues": issues}
        finally:
            with self._lock:
                self._publishing = False
                if self._closed and not self._workers:
                    self._data_lock.close()

    def close(self) -> None:
        try:
            with self._lock:
                self._closed = True
                workers = list(self._workers.items())
                for job_id, _ in workers:
                    self.cancel_job(job_id)
            for _, worker in workers:
                if worker.thread and worker.thread is not threading.current_thread():
                    worker.thread.join(timeout=10)
        finally:
            with self._lock:
                self._credentials.clear()
                self._previews.clear()
                if not self._workers and not self._publishing:
                    self._data_lock.close()
