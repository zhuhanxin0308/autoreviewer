"""Validate saved reports without trusting their source or execution claims.

Validation checks structure and provenance, not vulnerability correctness. Source
groups only link records at the same file/line/CWE; they do not deduplicate or
verify findings, and the original records remain available for review.
"""

from __future__ import annotations

import copy
from datetime import datetime
import hashlib
import json
import math
import re
from typing import Any

from .findings import CONFIDENCES, MAX_FINDINGS, SEVERITIES, TEXT_LIMITS, merge_findings
from .github import _validate_finding


MAX_REPORT_BYTES = 32 * 1024 * 1024
MAX_REPORT_MODELS = 64
MAX_REPORT_FINDINGS = MAX_REPORT_MODELS * MAX_FINDINGS
_TERMINAL_RUNS = frozenset({"completed", "failed", "timeout", "cancelled", "interrupted"})
_ACTIVE_RUNS = frozenset({"queued", "preparing", "running", "cancelling"})
_REPORT_FIELDS = frozenset({
    "schema_version", "autoreviewer_version", "target", "ref", "started_at", "finished_at",
    "status", "scope", "runs", "findings", "cancelled", "interrupted", "checkpoint",
})
_RUN_FIELDS = frozenset({
    "model", "model_name", "provider", "agent", "api_format", "status", "duration_seconds",
    "error", "scope", "findings", "audit_guidance",
})
_GUIDANCE_FIELDS = frozenset({
    "id", "source", "commit", "mode", "adaptation_version", "guidance_sha256", "prompt_sha256",
})
_FINDING_FIELDS = frozenset({
    "title", "severity", "file", "line", "cwe", "description", "evidence", "recommendation",
    "confidence", "fingerprint", "models", "verification", "observations",
})
_OBSERVATION_FIELDS = frozenset({"models", "severity", "confidence", "description", "evidence", "recommendation"})


def _invalid() -> None:
    # Never include a submitted field name/value, source snippet or credential.
    raise ValueError("Invalid saved report: structure, provenance, or execution status is inconsistent")


def _object(value: Any, allowed: frozenset[str]) -> dict:
    if not isinstance(value, dict) or value.keys() - allowed:
        _invalid()
    return value


def _text(value: Any, limit: int, *, multiline: bool = False, empty: bool = False) -> str:
    if (not isinstance(value, str) or len(value) > limit
            or (not empty and not value.strip())):
        _invalid()
    for character in value:
        code = ord(character)
        if 0xD800 <= code <= 0xDFFF or (code < 32 and not (multiline and character in "\n\r\t")):
            _invalid()
    return value


def _json_tree(value: Any, depth: int = 0, budget: list[int] | None = None) -> None:
    """Reject non-JSON objects and deeply nested/oversized in-memory inputs."""
    if budget is None:
        budget = [2_000_000]
    budget[0] -= 1
    if budget[0] < 0 or depth > 32:
        _invalid()
    if value is None or type(value) in {bool, int}:
        return
    if type(value) is float:
        if not math.isfinite(value):
            _invalid()
        return
    if isinstance(value, str):
        _text(value, MAX_REPORT_BYTES, multiline=True, empty=True)
        return
    if isinstance(value, list):
        for item in value:
            _json_tree(item, depth + 1, budget)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                _invalid()
            _text(key, 500)
            _json_tree(item, depth + 1, budget)
        return
    _invalid()


def _timestamp(value: Any) -> datetime:
    value = _text(value, 100)
    if "T" not in value:
        _invalid()
    try:
        stamp = datetime.fromisoformat(value)
    except ValueError:
        _invalid()
    if stamp.utcoffset() is None:
        _invalid()
    return stamp


def _scope(value: Any) -> None:
    if value is None:
        return
    value = _object(value, frozenset({"files", "bytes", "skipped", "git_ignore_applied"}))
    for name in ("files", "bytes"):
        if name in value and (type(value[name]) is not int or not 0 <= value[name] <= 2**53 - 1):
            _invalid()
    if "git_ignore_applied" in value and type(value["git_ignore_applied"]) is not bool:
        _invalid()
    skipped = value.get("skipped", {})
    if not isinstance(skipped, dict) or len(skipped) > 64:
        _invalid()
    for name, count in skipped.items():
        _text(name, 100)
        if type(count) is not int or not 0 <= count <= 2**53 - 1:
            _invalid()


def _audit_guidance(value: Any) -> None:
    """Validate recorded provenance, without asserting the agent followed it.

    Historical commit and prompt hashes need not match the currently installed
    bundle. Absence of this optional field remains valid for older reports.
    """
    value = _object(value, _GUIDANCE_FIELDS)
    if (value.get("id") != "cloudflare-security-audit"
            or value.get("source") != "https://github.com/cloudflare/security-audit-skill"
            or value.get("mode") != "guidance-readonly"
            or type(value.get("adaptation_version")) is not int
            or not 1 <= value["adaptation_version"] <= 2**53 - 1):
        _invalid()
    for name, length in (("commit", 40), ("guidance_sha256", 64), ("prompt_sha256", 64)):
        candidate = value.get(name)
        if not isinstance(candidate, str) or not re.fullmatch(r"[0-9a-f]{" + str(length) + "}", candidate):
            _invalid()


def _models(value: Any, allowed: set[str]) -> set[str]:
    if not isinstance(value, list) or not 1 <= len(value) <= MAX_REPORT_MODELS:
        _invalid()
    for model in value:
        _text(model, 500)
    selected = set(value)
    if len(selected) != len(value) or not selected <= allowed:
        _invalid()
    return selected


def _finding(value: Any, allowed_models: set[str]) -> dict:
    item = _object(value, _FINDING_FIELDS)
    _text(item.get("file"), 2048)
    for name, limit in TEXT_LIMITS.items():
        _text(item.get(name), limit, multiline=True)
    if type(item.get("line")) is not int or not 1 <= item["line"] <= 2**53 - 1:
        _invalid()
    cwe = item.get("cwe", "")
    if not isinstance(cwe, str) or (cwe and not re.fullmatch(r"CWE-[1-9][0-9]{0,5}", cwe)):
        _invalid()
    if item.get("verification", "unverified") != "unverified":
        _invalid()
    item["verification"] = "unverified"
    selected = _models(item.get("models"), allowed_models)
    try:
        _validate_finding(item)
    except (ValueError, TypeError, KeyError):
        _invalid()
    if "observations" in item:
        observations = item["observations"]
        if not isinstance(observations, list) or not 1 <= len(observations) <= MAX_REPORT_FINDINGS:
            _invalid()
        represented: set[str] = set()
        for observation in observations:
            observation = _object(observation, _OBSERVATION_FIELDS)
            represented |= _models(observation.get("models"), selected)
            if observation.get("severity") not in SEVERITIES or observation.get("confidence") not in CONFIDENCES:
                _invalid()
            for name in ("description", "evidence", "recommendation"):
                _text(observation.get(name), TEXT_LIMITS[name], multiline=True)
        if represented != selected:
            _invalid()
    return item


def validate_report(value: Any, *, allow_checkpoint: bool = False) -> dict:
    """Return a validated independent copy of a current autoreviewer report.

    Only terminal model executions are normally accepted. Explicitly opting into
    a report marked ``checkpoint: true`` turns unfinished runs into interrupted
    runs and recomputes overall execution status. Their findings must be empty;
    no model result or timestamp is invented, and nothing is executed.
    """
    try:
        if type(allow_checkpoint) is not bool:
            _invalid()
        _json_tree(value)
        serialized = json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":"))
        if len(serialized.encode("utf-8")) > MAX_REPORT_BYTES:
            _invalid()
        report = _object(copy.deepcopy(value), _REPORT_FIELDS)
        if type(report.get("schema_version")) is not int or report["schema_version"] != 1:
            _invalid()
        _text(report.get("target"), 4096)
        if "autoreviewer_version" in report:
            _text(report["autoreviewer_version"], 100)
        if report.get("ref") is not None:
            _text(report["ref"], 200)
        started = _timestamp(report.get("started_at"))
        finished = _timestamp(report.get("finished_at"))
        if finished < started:
            _invalid()
        for flag in ("cancelled", "interrupted", "checkpoint"):
            if flag in report and type(report[flag]) is not bool:
                _invalid()
        checkpoint = report.get("checkpoint", False)
        if checkpoint and not allow_checkpoint:
            _invalid()
        if report.get("status") not in {"completed", "partial", "failed"} | ({"running"} if checkpoint else set()):
            _invalid()
        _scope(report.get("scope"))
        runs = report.get("runs")
        if not isinstance(runs, list) or not 1 <= len(runs) <= MAX_REPORT_MODELS:
            _invalid()
        ids: set[str] = set()
        completed: set[str] = set()
        changed = False
        for run in runs:
            run = _object(run, _RUN_FIELDS)
            for field in ("model", "model_name", "provider", "agent"):
                _text(run.get(field), 500)
            if run["model"] in ids:
                _invalid()
            ids.add(run["model"])
            status = run.get("status")
            if checkpoint and status in _ACTIVE_RUNS:
                run["status"] = "interrupted"
                run["error"] = "Review interrupted before this model completed"
                changed = True
            elif status not in _TERMINAL_RUNS:
                _invalid()
            if run["status"] == "completed":
                completed.add(run["model"])
            if "api_format" in run and run["api_format"] not in {"openai-chat", "openai-responses", "anthropic", "gemini"}:
                _invalid()
            duration = run.get("duration_seconds")
            if type(duration) not in {int, float} or not math.isfinite(duration) or not 0 <= duration <= 1e12:
                _invalid()
            if run.get("error") is not None:
                _text(run["error"], 20_000, multiline=True, empty=True)
            _scope(run.get("scope"))
            if "audit_guidance" in run:
                _audit_guidance(run["audit_guidance"])
            if not isinstance(run.get("findings"), list) or len(run["findings"]) > MAX_FINDINGS:
                _invalid()
            if run["status"] != "completed" and run["findings"]:
                _invalid()
        expected_status = "completed" if completed == ids else "partial" if completed else "failed"
        if checkpoint:
            report["status"] = expected_status
            if changed:
                report["interrupted"] = True
        elif report["status"] != expected_status:
            _invalid()
        provenance: dict[str, set[str]] = {}
        for run in runs:
            for item in run["findings"]:
                item = _finding(item, {run["model"]})
                fingerprint = item["fingerprint"]
                # A model can report multiple observations of the same finding.
                # Preserve each raw record; canonical merging below validates
                # that every distinct observation survives in the aggregate.
                provenance.setdefault(fingerprint, set()).add(run["model"])
        findings = report.get("findings")
        if not isinstance(findings, list) or len(findings) > MAX_REPORT_FINDINGS:
            _invalid()
        seen = set()
        for item in findings:
            item = _finding(item, completed)
            fingerprint = item["fingerprint"]
            if fingerprint in seen or provenance.get(fingerprint) != set(item["models"]):
                _invalid()
            seen.add(fingerprint)
        if seen != provenance.keys():
            _invalid()
        canonical = {item["fingerprint"]: item for item in merge_findings(
            [run["findings"] for run in runs if run["status"] == "completed"])}
        for item in findings:
            expected = canonical[item["fingerprint"]]
            # The aggregate must reflect the recorded model observations, not
            # merely reuse their fingerprint while claiming different evidence.
            for field in ("title", "severity", "file", "line", "description", "evidence", "recommendation", "confidence"):
                if item[field] != expected[field]:
                    _invalid()
            if item.get("cwe", "") != expected.get("cwe", ""):
                _invalid()
            if "observations" not in item:
                item["observations"] = copy.deepcopy(expected["observations"])
            def normalized_observations(observations):
                return sorted(json.dumps({**observation, "models": sorted(observation["models"])},
                                         ensure_ascii=False, sort_keys=True, separators=(",", ":"))
                              for observation in observations)
            if normalized_observations(item["observations"]) != normalized_observations(expected["observations"]):
                _invalid()
        return report
    except (ValueError, TypeError, KeyError, OverflowError, RecursionError, UnicodeError):
        _invalid()


def group_findings(findings: list[dict]) -> list[dict]:
    """Link same-location/CWE records, preserving their separate fingerprints.

    Files remain case-sensitive. Missing CWE values are never used as a grouping
    key; each such finding gets its own group. Group IDs and ordering are stable
    across input order, and the input findings are not changed.
    """
    if not isinstance(findings, list) or len(findings) > MAX_REPORT_FINDINGS:
        _invalid()
    groups: dict[str, dict] = {}
    seen: set[str] = set()
    try:
        for original in findings:
            _json_tree(original)
            if not isinstance(original, dict) or not isinstance(original.get("models"), list):
                _invalid()
            allowed = set(_text(model, 500) for model in original["models"])
            item = _finding(copy.deepcopy(original), allowed)
            fingerprint = item["fingerprint"]
            if fingerprint in seen:
                _invalid()
            seen.add(fingerprint)
            cwe = item.get("cwe") or ""
            identity = [item["file"], item["line"], cwe, "" if cwe else fingerprint]
            group_id = hashlib.sha256(json.dumps(identity, ensure_ascii=False, separators=(",", ":")).encode("utf-8")).hexdigest()
            group = groups.setdefault(group_id, {
                "id": group_id, "file": item["file"], "line": item["line"], "cwe": cwe,
                "fingerprints": [], "models": [], "severity": item["severity"], "record_count": 0,
            })
            group["fingerprints"].append(fingerprint)
            group["models"] = sorted(set(group["models"]) | set(item["models"]))
            group["record_count"] += 1
            if SEVERITIES.index(item["severity"]) < SEVERITIES.index(group["severity"]):
                group["severity"] = item["severity"]
        for group in groups.values():
            group["fingerprints"].sort()
        return sorted(groups.values(), key=lambda group: (SEVERITIES.index(group["severity"]), group["file"], group["line"], group["id"]))
    except (ValueError, TypeError, KeyError, OverflowError, RecursionError, UnicodeError):
        _invalid()
