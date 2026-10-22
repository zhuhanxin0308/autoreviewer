"""Human-readable and machine-readable reports from the same scan result."""

from __future__ import annotations

import html
import json
import os
from pathlib import Path
import re
import tempfile
from typing import Any

from .findings import SEVERITIES


def _plain(value: Any) -> str:
    value = html.escape(str(value), quote=False)
    return re.sub(r"([\\`*_{}\[\]()#+\-!|>])", r"\\\1", value)


def _code(value: Any) -> str:
    text = str(value)
    runs = re.findall(r"`+", text)
    fence = "`" * max(3, max((len(run) + 1 for run in runs), default=3))
    return f"{fence}\n{text}\n{fence}"


def render_model_observations(observations: list[dict[str, Any]], *, heading_level: int) -> str:
    """Render each retained assessment without losing its model attribution."""
    heading = "#" * heading_level
    lines = [
        f"{heading} Model observations", "",
        "The severity above is the highest reported severity. Each observation below retains its own "
        "severity, confidence and evidence. All observations remain unverified.", "",
    ]
    for index, observation in enumerate(observations, 1):
        lines.extend([
            f"{heading}# Observation {index}", "",
            f"- Models: {', '.join(_plain(model) for model in observation['models'])}",
            f"- Severity: **{_plain(observation['severity'])}**",
            f"- Model confidence: {_plain(observation['confidence'])}", "",
            "**Description**", "", _plain(observation["description"]), "",
            "**Evidence**", "", _code(observation["evidence"]), "",
            "**Recommendation**", "", _plain(observation["recommendation"]), "",
        ])
    return "\n".join(lines)


def render_markdown(report: dict[str, Any]) -> str:
    findings = report.get("findings", [])
    runs = report.get("runs", [])
    lines = [
        "# autoreviewer security review",
        "",
        "**All findings are unverified hypotheses requiring human review.** "
        "Model agreement does not prove a vulnerability. A clean result does not establish that the code is secure.",
        "",
        f"- Target: {_plain(report.get('target', 'unknown'))}",
        f"- Scan status: {_plain(report.get('status', 'unknown'))}",
        f"- Started: {_plain(report.get('started_at', 'unknown'))}",
        f"- Finished: {_plain(report.get('finished_at', 'unknown'))}",
        f"- Findings: {len(findings)}",
        "",
    ]
    scope = report.get("scope")
    if isinstance(scope, dict):
        lines.extend([
            "## Audit scope",
            "",
            "The snapshot below was supplied to the models. Omitted entries were outside this review.",
            "",
            f"- Snapshot files: {_plain(scope.get('files', 'unknown'))}",
            f"- Snapshot bytes: {_plain(scope.get('bytes', 'unknown'))}",
            f"- Git ignore rules applied: {'yes' if scope.get('git_ignore_applied') else 'no'}",
        ])
        skipped = scope.get("skipped", {})
        if isinstance(skipped, dict) and skipped:
            lines.append("- Omitted entries: " + "; ".join(
                f"{_plain(name)}: {_plain(count)}" for name, count in sorted(skipped.items())
            ))
        lines.append("")
    lines.extend(["## Model runs", ""])
    if not runs:
        lines.append("No model runs were recorded.")
    for run in runs:
        duration = run.get("duration_seconds")
        duration_label = f"; {duration:.2f}s" if isinstance(duration, (int, float)) else ""
        lines.append(f"- **{_plain(run.get('model', 'unknown'))}**: {_plain(run.get('status', 'unknown'))}{duration_label}")
        guidance = run.get("audit_guidance")
        if isinstance(guidance, dict):
            lines.extend([
                "  - Recorded audit guidance: " + _plain(guidance.get("id", "unknown")),
                "  - Guidance source: " + _plain(guidance.get("source", "unknown")),
                "  - Upstream commit: " + _plain(guidance.get("commit", "unknown")),
                "  - Mode: " + _plain(guidance.get("mode", "unknown")) +
                "; adaptation version: " + _plain(guidance.get("adaptation_version", "unknown")),
                "  - Guidance SHA-256: " + _plain(guidance.get("guidance_sha256", "unknown")),
                "  - Prompt SHA-256: " + _plain(guidance.get("prompt_sha256", "unknown")),
            ])
        if run.get("error"):
            lines.extend(["", _code(run["error"]), ""])
    lines.extend(["", "## Findings", ""])
    if not findings:
        if report.get("status") == "completed":
            lines.append("No findings were reported by the completed model runs. This is not a security guarantee.")
        else:
            lines.append("No validated findings were collected. Failed or incomplete model runs are not clean audit results.")
    else:
        counts = {severity: sum(item.get("severity") == severity for item in findings) for severity in SEVERITIES}
        lines.append(" · ".join(f"{severity}: {counts[severity]}" for severity in SEVERITIES))
        lines.append("")
    for index, finding in enumerate(findings, 1):
        observations = finding.get("observations", [])
        multiple = len(observations) > 1
        lines.extend([
            f"### {index}. {_plain(finding['title'])}",
            "",
            f"- Severity: **{_plain(finding['severity'])}**",
            f"- Location: {_plain(finding['file'])}:{finding['line']}",
            f"- CWE: {_plain(finding.get('cwe') or 'unspecified')}",
            *([] if multiple else [f"- Model confidence: {_plain(finding['confidence'])}"]),
            "- Verification: **unverified**",
            f"- Reported by: {', '.join(_plain(model) for model in finding['models'])}",
            f"- Fingerprint: {_plain(finding['fingerprint'])}",
            "",
        ])
        if multiple:
            lines.append(render_model_observations(observations, heading_level=4))
            continue
        lines.extend([
            "**Description**",
            "",
            _plain(finding["description"]),
            "",
            "**Evidence**",
            "",
            _code(finding["evidence"]),
            "",
            "**Recommendation**",
            "",
            _plain(finding["recommendation"]),
            "",
        ])
    return "\n".join(lines).rstrip() + "\n"


def _atomic_write(path: Path, contents: str) -> None:
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(contents)
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def write_reports(report: dict[str, Any], output_dir: Path) -> tuple[Path, Path]:
    """Write report.json and report.md with private permissions and atomic replaces."""
    directory = Path(output_dir)
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    json_path = directory / "report.json"
    markdown_path = directory / "report.md"
    serialized = json.dumps(report, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
    markdown = render_markdown(report)
    _atomic_write(json_path, serialized)
    _atomic_write(markdown_path, markdown)
    return json_path, markdown_path
