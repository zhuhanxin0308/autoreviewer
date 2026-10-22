"""Prepare reviewable issue drafts and explicitly publish them to GitHub.com."""

from __future__ import annotations

import json
import os
import re
import stat
import tempfile
from http.client import HTTPException
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import HTTPRedirectHandler, Request, build_opener

from .findings import finding_fingerprint
from .reports import render_model_observations

if TYPE_CHECKING:
    from .config import GitHubConfig


API_URL = "https://api.github.com"
MAX_PAGES = 100
MAX_RESPONSE_BYTES = 8 * 1024 * 1024
MAX_ISSUES = 1000
MAX_ISSUE_BODY_CHARS = 65536
MAX_RECEIPT_BYTES = 4 * 1024 * 1024
_FINGERPRINT = re.compile(r"[0-9a-f]{64}\Z")
_MARKER = re.compile(r"(?:^|\n)<!-- autoreviewer:([0-9a-f]{64}) -->\s*\Z")
_REPOSITORY = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9_.-]{1,100}\Z")
_SEVERITIES = {"critical", "high", "medium", "low", "info"}
_CONFIDENCES = {"high", "medium", "low"}


class GitHubError(ValueError):
    """A report or GitHub operation could not be safely completed."""


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise HTTPError(req.full_url, code, "Redirects are disabled", headers, fp)


def _text(value: Any, field: str, *, limit: int = 20000) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise GitHubError(f"Invalid report field: {field}")
    if any(ord(char) < 32 and char not in "\n\r\t" for char in value) or any(
        0xD800 <= ord(char) <= 0xDFFF for char in value
    ):
        raise GitHubError(f"Invalid report field: {field}")
    return value


def _validate_finding(finding: Any) -> dict:
    if not isinstance(finding, dict):
        raise GitHubError("Each finding must be an object")
    for field in ("title", "file", "description", "evidence", "recommendation"):
        _text(finding.get(field), field)
    path = finding["file"]
    if path.startswith(("/", "\\")) or "\\" in path or ":" in path or any(
        part in ("", ".", "..") for part in path.split("/")
    ):
        raise GitHubError("Finding file must be a repository-relative path")
    line = finding.get("line")
    if type(line) is not int or line < 1:
        raise GitHubError("Finding line must be a positive integer")
    if not isinstance(finding.get("severity"), str) or finding["severity"] not in _SEVERITIES:
        raise GitHubError("Invalid finding severity")
    if not isinstance(finding.get("confidence"), str) or finding["confidence"] not in _CONFIDENCES:
        raise GitHubError("Invalid finding confidence")
    cwe = finding.get("cwe")
    if cwe is not None and (not isinstance(cwe, str) or len(cwe) > 100):
        raise GitHubError("Invalid finding CWE")
    models = finding.get("models")
    if not isinstance(models, list) or not models or len(models) > 1000:
        raise GitHubError("Finding model provenance is missing or invalid")
    for model in models:
        _text(model, "models", limit=500)
    fingerprint = finding.get("fingerprint")
    if not isinstance(fingerprint, str) or not _FINGERPRINT.fullmatch(fingerprint):
        raise GitHubError("Invalid finding fingerprint")
    if fingerprint != finding_fingerprint(finding):
        raise GitHubError("Finding fingerprint does not match its content")
    return finding


def _plain(value: str) -> str:
    """Keep report metadata on one line without creating Markdown structure."""
    return " ".join(value.split()).replace("`", "'").replace("<", "&lt;").replace(">", "&gt;")


def _validated_observations(finding: dict) -> list[dict]:
    """Validate newly rendered fields without requiring an entire scan report."""
    if "observations" not in finding:
        return []
    observations = finding["observations"]
    if not isinstance(observations, list) or not 1 <= len(observations) <= 32000:
        raise GitHubError("Finding observations must be a nonempty list of at most 32000 items")
    allowed_models = set(finding["models"])
    for observation in observations:
        if not isinstance(observation, dict):
            raise GitHubError("Each model observation must be an object")
        models = observation.get("models")
        if not isinstance(models, list) or not models or len(models) > len(allowed_models):
            raise GitHubError("Invalid model observation provenance")
        for model in models:
            _text(model, "observation models", limit=500)
        if len(set(models)) != len(models) or not set(models) <= allowed_models:
            raise GitHubError("Invalid model observation provenance")
        for name, choices in (("severity", _SEVERITIES), ("confidence", _CONFIDENCES)):
            if not isinstance(observation.get(name), str) or observation[name] not in choices:
                raise GitHubError(f"Invalid model observation {name}")
        for name in ("description", "evidence", "recommendation"):
            _text(observation.get(name), f"observation {name}")
    return observations


def plan_issues(report: dict, *, allow_partial: bool = False) -> list[dict]:
    """Validate a report and create issue drafts without network access.

    Reports with failed model runs require an explicit ``allow_partial`` choice.
    Findings remain unverified hypotheses even when several models agree.
    """
    if (
        not isinstance(report, dict)
        or type(report.get("schema_version")) is not int
        or report["schema_version"] != 1
    ):
        raise GitHubError("Unsupported report schema; expected schema_version 1")
    status = report.get("status")
    if status != "completed" and not (status == "partial" and allow_partial):
        raise GitHubError("Only completed reports can be published; partial reports require --allow-partial")
    target = _text(report.get("target"), "target", limit=4096)
    findings = report.get("findings")
    if not isinstance(findings, list) or len(findings) > MAX_ISSUES:
        raise GitHubError(f"Report findings must be a list of at most {MAX_ISSUES} items")
    drafts = []
    seen = set()
    for raw_finding in findings:
        finding = _validate_finding(raw_finding)
        observations = _validated_observations(finding)
        multiple = len(observations) > 1
        fingerprint = finding["fingerprint"]
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        title = f"[Security][{finding['severity'].upper()}] {_plain(finding['title'])}"[:256]
        body = "\n".join([
            "> **Unverified AI security finding.** A maintainer must confirm reachability, impact, and reproduction before treating this as a vulnerability. Agreement between models is not verification.",
            "",
            f"- Source: `{_plain(target)}`",
            f"- Location: `{_plain(finding['file'])}:{finding['line']}`",
            f"- Severity: **{finding['severity']}** (model assessment)",
            *([] if multiple else [f"- Confidence: {finding['confidence']} (model assessment)"]),
            f"- CWE: {_plain(finding.get('cwe') or 'Unspecified')}",
            f"- Models: {', '.join('`' + _plain(model) + '`' for model in finding['models'])}",
            "",
            *([render_model_observations(observations, heading_level=2)] if multiple else [
            "## Description",
            "",
            finding["description"],
            "",
            "## Evidence",
            "",
            finding["evidence"],
            "",
            "## Recommended remediation",
            "",
            finding["recommendation"],
            "",
            ]),
            "## Maintainer validation",
            "",
            "- [ ] Confirm the affected code and prerequisites.",
            "- [ ] Reproduce safely and assess impact.",
            "- [ ] Review the proposed remediation.",
            "",
            *(["> This report is partial: one or more model runs did not complete successfully.", ""] if status == "partial" else []),
            f"<!-- autoreviewer:{fingerprint} -->",
        ])
        if len(body) > MAX_ISSUE_BODY_CHARS:
            raise GitHubError("Issue draft exceeds GitHub's 65,536-character body limit. "
                              "Download the complete JSON or Markdown report and prepare a shorter issue manually; "
                              "no evidence was truncated")
        drafts.append({"title": title, "body": body, "fingerprint": fingerprint})
    return drafts


class _Client:
    def __init__(self, token: str):
        self.token = token
        self.opener = build_opener(_NoRedirect())

    def request(self, method: str, path: str, payload: dict | None = None) -> Any:
        if not path.startswith("/repos/") or "\r" in path or "\n" in path:
            raise GitHubError("Invalid GitHub API path")
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {self.token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "autoreviewer/0.1",
        }
        if method == "GET":
            # Publication decisions need the current repository and issue state,
            # including issues just created or closed by an earlier request.
            headers["Cache-Control"] = "no-cache, no-store"
            headers["Pragma"] = "no-cache"
        data = None
        if payload is not None:
            data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = Request(API_URL + path, data=data, headers=headers, method=method)
        try:
            with self.opener.open(request, timeout=30) as response:
                raw = response.read(MAX_RESPONSE_BYTES + 1)
            if len(raw) > MAX_RESPONSE_BYTES:
                raise GitHubError("GitHub response exceeded the size limit")
            return json.loads(raw)
        except HTTPError as exc:
            # Server error bodies and request headers may contain credentials or
            # sensitive content. Return only our own messages and the status code.
            exc.close()
            if 300 <= exc.code < 400:
                message = "GitHub redirected the request; redirects are disabled. Check the repository name"
            elif exc.code == 401:
                message = "GitHub authentication failed; check the configured token"
            elif exc.code == 403:
                message = "GitHub denied the request; check Issues permissions and rate limits"
            elif exc.code == 404:
                message = "GitHub repository is unavailable; check its name and token access"
            elif exc.code == 429:
                message = "GitHub rate limit exceeded; retry publication later"
            elif exc.code == 422:
                message = "GitHub rejected the issue contents or configured labels"
            else:
                message = "GitHub API request failed"
            raise GitHubError(f"{message} (HTTP {exc.code})") from None
        except GitHubError:
            raise
        except (URLError, OSError, HTTPException):
            raise GitHubError("GitHub request failed; check connectivity and retry later") from None
        except (ValueError, UnicodeError, RecursionError):
            raise GitHubError("GitHub returned an invalid JSON response") from None


def _issue_number(issue: dict) -> int:
    number = issue.get("number")
    if type(number) is not int or number < 1:
        raise GitHubError("GitHub returned an invalid issue number")
    return number


def _existing_issues(client: _Client, repository: str) -> dict[str, int]:
    existing = {}
    for page in range(1, MAX_PAGES + 1):
        query = urlencode({"state": "all", "per_page": 100, "page": page, "sort": "created", "direction": "asc"})
        issues = client.request("GET", f"/repos/{repository}/issues?{query}")
        if not isinstance(issues, list) or len(issues) > 100:
            raise GitHubError("GitHub returned an invalid issue list")
        for issue in issues:
            if not isinstance(issue, dict):
                raise GitHubError("GitHub returned an invalid issue")
            if "pull_request" in issue:
                continue
            body = issue.get("body") or ""
            if not isinstance(body, str):
                raise GitHubError("GitHub returned an invalid issue body")
            match = _MARKER.search(body)
            if match:
                existing.setdefault(match.group(1), _issue_number(issue))
        if len(issues) < 100:
            return existing
    raise GitHubError(f"Repository exceeds the {MAX_PAGES * 100}-issue lookup limit; publication stopped before creating issues")


def _load_receipts(path: Path) -> dict:
    def unique_keys(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("Duplicate receipt key")
            value[key] = item
        return value

    try:
        if path.is_symlink():
            raise ValueError("Receipt is a symlink")
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        with os.fdopen(descriptor, "rb") as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise ValueError("Receipt is not a regular file")
            raw = stream.read(MAX_RECEIPT_BYTES + 1)
        if len(raw) > MAX_RECEIPT_BYTES:
            raise ValueError("Receipt exceeds size limit")
        receipts = json.loads(raw, object_pairs_hook=unique_keys)
        if (not isinstance(receipts, dict) or set(receipts) != {"schema_version", "repositories"}
                or type(receipts["schema_version"]) is not int or receipts["schema_version"] != 1
                or not isinstance(receipts["repositories"], dict)):
            raise ValueError("Invalid receipt schema")
        for repository, entries in receipts["repositories"].items():
            if (not _REPOSITORY.fullmatch(repository) or repository != repository.lower()
                    or repository.split("/")[1] in {".", ".."} or not isinstance(entries, dict)):
                raise ValueError("Invalid receipt repository")
            for fingerprint, number in entries.items():
                if not _FINGERPRINT.fullmatch(fingerprint) or type(number) is not int or number < 1:
                    raise ValueError("Invalid receipt entry")
        return receipts
    except FileNotFoundError:
        return {"schema_version": 1, "repositories": {}}
    except (OSError, ValueError, TypeError, RecursionError):
        raise GitHubError("GitHub publication receipts are unreadable or invalid; publication stopped. Restore the receipt file before retrying") from None


def _save_receipts(path: Path, receipts: dict) -> None:
    temporary = None
    try:
        raw = (json.dumps(receipts, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        if len(raw) > MAX_RECEIPT_BYTES or path.is_symlink():
            raise ValueError("Receipt cannot be safely saved")
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        temporary = None
    except (OSError, ValueError, RecursionError):
        raise GitHubError("GitHub publication receipts could not be saved; publication stopped. An issue may already have been created; check GitHub before retrying") from None
    finally:
        if temporary is not None:
            try:
                os.unlink(temporary)
            except OSError:
                pass


def _verify_receipt(client: _Client, repository: str, fingerprint: str, number: int) -> None:
    try:
        issue = client.request("GET", f"/repos/{repository}/issues/{number}")
    except GitHubError as exc:
        raise GitHubError(f"Saved GitHub issue #{number} could not be verified; publication stopped. {exc}") from None
    if isinstance(issue, dict) and "pull_request" not in issue and type(issue.get("number")) is int and issue["number"] == number:
        body = issue.get("body")
        match = _MARKER.search(body) if isinstance(body, str) else None
        if match and match.group(1) == fingerprint:
            return
    raise GitHubError(f"Saved GitHub issue #{number} no longer matches its publication receipt; publication stopped. Check the issue before retrying")


def publish_issues(report: dict, config: GitHubConfig, *, allow_partial: bool = False,
                   token: str | None = None, receipt_path: Path | None = None) -> list[dict]:
    """Publish reviewed drafts, skipping fingerprints in open or closed issues.

    Callers must make publication an explicit action. This function performs no
    automatic retries: after an ambiguous POST failure, rerun to look for its
    fingerprint before creating another issue. Optional local receipts are saved
    after each successful creation and verified by issue number on later calls,
    even when issue listings are stale. Concurrent publishers may still race.
    """
    drafts = plan_issues(report, allow_partial=allow_partial)
    repository = config.repository
    if not isinstance(repository, str) or not _REPOSITORY.fullmatch(repository) or repository.split("/")[1] in {".", ".."}:
        raise GitHubError("GitHub repository must be in owner/repository form")
    labels = config.labels
    if not isinstance(labels, (tuple, list)) or len(labels) > 100 or any(
        not isinstance(label, str) or not label.strip() or len(label) > 50 for label in labels
    ):
        raise GitHubError("Invalid GitHub issue labels")
    if not drafts:
        return []
    if token is None:
        token = os.environ.get(config.token_env, "")
    if not isinstance(token, str) or not token or any(char.isspace() or ord(char) < 32 for char in token):
        raise GitHubError(f"Set a valid GitHub token in {config.token_env}")
    receipts = _load_receipts(receipt_path) if receipt_path is not None else None
    if receipts is not None:
        # Check storage before the first POST, then persist each individual result.
        _save_receipts(receipt_path, receipts)
        saved = receipts["repositories"].setdefault(repository.lower(), {})
    else:
        saved = {}
    client = _Client(token)
    metadata = client.request("GET", f"/repos/{repository}")
    if not isinstance(metadata, dict) or metadata.get("has_issues") is not True:
        raise GitHubError("GitHub Issues are disabled or unavailable for this repository")
    if metadata.get("archived") is True:
        raise GitHubError("Cannot create issues in an archived repository")
    verified = {}
    for draft in drafts:
        fingerprint = draft["fingerprint"]
        if fingerprint in saved:
            number = saved[fingerprint]
            _verify_receipt(client, repository, fingerprint, number)
            verified[fingerprint] = number
    existing = _existing_issues(client, repository) if len(verified) < len(drafts) else {}
    existing.update(verified)
    result = []
    for draft in drafts:
        fingerprint = draft["fingerprint"]
        number = existing.get(fingerprint)
        status = "existing"
        if number is None:
            payload = {"title": draft["title"], "body": draft["body"]}
            if labels:
                payload["labels"] = list(labels)
            created = client.request("POST", f"/repos/{repository}/issues", payload)
            if not isinstance(created, dict):
                raise GitHubError("GitHub returned an invalid issue creation response; check the repository before retrying")
            number = _issue_number(created)
            existing[fingerprint] = number
            status = "created"
        if receipts is not None and saved.get(fingerprint) != number:
            saved[fingerprint] = number
            _save_receipts(receipt_path, receipts)
        result.append({"fingerprint": fingerprint, "status": status, "url": f"https://github.com/{repository}/issues/{number}"})
    return result
