"""Validate untrusted agent output and conservatively combine observations."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
from typing import Any


SEVERITIES = ("critical", "high", "medium", "low", "info")
CONFIDENCES = ("high", "medium", "low")
MAX_OUTPUT_BYTES = 2 * 1024 * 1024
MAX_FINDINGS = 500
MAX_SOURCE_BYTES = 8 * 1024 * 1024
TEXT_LIMITS = {
    "title": 300,
    "description": 16_000,
    "evidence": 16_000,
    "recommendation": 16_000,
}


class FindingValidationError(ValueError):
    """The agent did not return a valid, grounded findings document."""


def _text(item: dict[str, Any], name: str, limit: int) -> str:
    value = item.get(name)
    if not isinstance(value, str) or not value.strip():
        raise FindingValidationError(f"{name} must be a nonempty string")
    value = value.strip()
    if len(value) > limit:
        raise FindingValidationError(f"{name} exceeds {limit} characters")
    if any(ord(char) < 32 and char not in "\n\r\t" for char in value):
        raise FindingValidationError(f"{name} contains control characters")
    if any(0xD800 <= ord(char) <= 0xDFFF for char in value):
        raise FindingValidationError(f"{name} contains invalid Unicode")
    return value


def _source_file(repository: Path, raw: Any) -> tuple[str, Path]:
    if not isinstance(raw, str) or not raw or len(raw) > 2048:
        raise FindingValidationError("file must be a repository-relative path")
    # Keep one portable path convention; drive paths and backslash traversal are
    # rejected even when validation runs on POSIX.
    if "\\" in raw or ":" in raw or any(ord(char) < 32 or 0xD800 <= ord(char) <= 0xDFFF for char in raw):
        raise FindingValidationError("file contains a forbidden path character")
    path = PurePosixPath(raw)
    if path.is_absolute() or any(part in ("", ".", "..") for part in raw.split("/")):
        raise FindingValidationError("file must be a normalized relative path")
    candidate = repository
    for part in path.parts:
        candidate /= part
        if candidate.is_symlink():
            raise FindingValidationError("file must not traverse a symbolic link")
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(repository)
    except (OSError, ValueError, RuntimeError) as exc:
        raise FindingValidationError("file does not exist inside the snapshot") from exc
    if not resolved.is_file():
        raise FindingValidationError("file must identify a regular source file")
    return path.as_posix(), resolved


def finding_fingerprint(item: dict[str, Any]) -> str:
    """Return a deterministic identity for a validated finding's location and kind."""
    identity = [
        item["file"],
        item["line"],
        item.get("cwe", ""),
        " ".join(item["title"].casefold().split()),
    ]
    return hashlib.sha256(
        json.dumps(identity, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise FindingValidationError("JSON contains duplicate object keys")
        result[key] = value
    return result


def parse_findings(text: str, repository: Path, model_id: str) -> list[dict[str, Any]]:
    """Parse a complete JSON response; invalid output never means zero findings.

    A single Markdown JSON fence is accepted. Paths and line numbers are checked
    against the model's snapshot, but the alleged vulnerability remains unverified.
    """
    if not isinstance(text, str):
        raise FindingValidationError("agent output must be text")
    try:
        output_size = len(text.encode("utf-8"))
    except UnicodeEncodeError as exc:
        raise FindingValidationError("agent output contains invalid Unicode") from exc
    if output_size > MAX_OUTPUT_BYTES:
        raise FindingValidationError("agent output exceeds the size limit")
    source = text.strip()
    if source.startswith("```"):
        match = re.fullmatch(r"```(?:json)?[ \t]*\r?\n(.*?)\r?\n```", source, re.DOTALL | re.IGNORECASE)
        if match is None:
            raise FindingValidationError("expected a single complete JSON code fence")
        source = match.group(1)
    try:
        payload = json.loads(source, object_pairs_hook=_unique_object)
    except (json.JSONDecodeError, RecursionError) as exc:
        raise FindingValidationError("agent output is not a complete JSON document") from exc
    if not isinstance(payload, dict) or not isinstance(payload.get("findings"), list):
        raise FindingValidationError("agent output must contain a findings array")
    if len(payload["findings"]) > MAX_FINDINGS:
        raise FindingValidationError(f"agent returned more than {MAX_FINDINGS} findings")
    try:
        root = Path(repository).resolve(strict=True)
    except OSError as exc:
        raise FindingValidationError("repository snapshot does not exist") from exc
    if not root.is_dir():
        raise FindingValidationError("repository snapshot is not a directory")
    if not isinstance(model_id, str) or not model_id.strip():
        raise FindingValidationError("model_id must be a nonempty string")
    line_counts: dict[Path, int] = {}
    results: list[dict[str, Any]] = []
    for index, raw in enumerate(payload["findings"]):
        try:
            if not isinstance(raw, dict):
                raise FindingValidationError("finding must be an object")
            item: dict[str, Any] = {
                name: _text(raw, name, limit) for name, limit in TEXT_LIMITS.items()
            }
            for name, choices in (("severity", SEVERITIES), ("confidence", CONFIDENCES)):
                value = raw.get(name)
                if not isinstance(value, str) or value not in choices:
                    raise FindingValidationError(f"{name} must be one of {', '.join(choices)}")
                item[name] = value
            cwe = raw.get("cwe", "")
            if not isinstance(cwe, str) or (cwe and not re.fullmatch(r"CWE-[1-9][0-9]{0,5}", cwe)):
                raise FindingValidationError("cwe must be empty or a CWE identifier, such as CWE-89")
            item["cwe"] = cwe
            item["file"], source_path = _source_file(root, raw.get("file"))
            line = raw.get("line")
            if type(line) is not int or line < 1:
                raise FindingValidationError("line must be a positive integer")
            if source_path not in line_counts:
                try:
                    if source_path.stat().st_size > MAX_SOURCE_BYTES:
                        raise FindingValidationError("referenced source file exceeds the size limit")
                    with source_path.open("rb") as handle:
                        contents = handle.read(MAX_SOURCE_BYTES + 1)
                    if len(contents) > MAX_SOURCE_BYTES:
                        raise FindingValidationError("referenced source file exceeds the size limit")
                    if b"\x00" in contents:
                        raise FindingValidationError("referenced source file is binary")
                    # Match editor line numbering without treating every Unicode
                    # line separator embedded in a string as a source line.
                    line_counts[source_path] = len(contents.splitlines())
                except OSError as exc:
                    raise FindingValidationError("referenced source file cannot be read") from exc
            if line > line_counts[source_path]:
                raise FindingValidationError("line falls outside the referenced source file")
            item["line"] = line
            item["fingerprint"] = finding_fingerprint(item)
            item["models"] = [model_id]
            item["verification"] = "unverified"
            results.append(item)
        except FindingValidationError as exc:
            raise FindingValidationError(f"finding {index + 1}: {exc}") from exc
    return results


def merge_findings(groups: list[list[dict[str, Any]]]) -> list[dict[str, Any]]:
    """Merge exact location/CWE/title matches and retain every model observation.

    Differently named or differently located findings remain distinct. Agreement
    only records provenance and never changes verification status.
    """
    merged: dict[str, dict[str, Any]] = {}
    for group in groups:
        for original in group:
            fingerprint = finding_fingerprint(original)
            observation = {
                key: copy.deepcopy(original[key])
                for key in ("models", "severity", "confidence", "description", "evidence", "recommendation")
            }
            if fingerprint not in merged:
                item = copy.deepcopy(original)
                item["fingerprint"] = fingerprint
                item["models"] = sorted(set(item["models"]))
                item["verification"] = "unverified"
                item["observations"] = [observation]
                merged[fingerprint] = item
                continue
            item = merged[fingerprint]
            item["models"] = sorted(set(item["models"]) | set(original["models"]))
            if observation not in item["observations"]:
                item["observations"].append(observation)
            if SEVERITIES.index(original["severity"]) < SEVERITIES.index(item["severity"]):
                item["severity"] = original["severity"]
            # Confidence describes the primary observation, not a vote count.
    return sorted(
        merged.values(),
        key=lambda item: (SEVERITIES.index(item["severity"]), item["file"], item["line"], item["fingerprint"]),
    )
