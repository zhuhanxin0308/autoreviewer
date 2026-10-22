"""Command line entry point. Scanning and publishing are separate operations."""

import argparse
import asyncio
from dataclasses import replace
from datetime import datetime, timezone
from importlib.resources import files
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import uuid

from . import __version__
from .adapters import build_command
from .config import load_config
from .findings import finding_fingerprint, merge_findings
from .github import plan_issues, publish_issues
from .reportio import validate_report
from .reports import write_reports
from .runner import run_models
from .snapshot import snapshot_repository
from .targets import prepare_target


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _unique_report_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Report contains duplicate JSON object keys")
        result[key] = value
    return result


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="autoreviewer", description="Parallel security reviews using installed coding-agent CLIs.")
    parser.add_argument("--version", action="version", version=f"autoreviewer {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)
    init = commands.add_parser("init", help="Write a starter configuration without overwriting existing files")
    init.add_argument("--output", type=Path, default=Path("autoreviewer.toml"))
    doctor = commands.add_parser("doctor", help="Check configuration, executables and key presence without calling models")
    doctor.add_argument("--config", type=Path, default=Path("autoreviewer.toml"))
    scan = commands.add_parser("scan", help="Review a local directory or GitHub HTTPS repository")
    scan.add_argument("target", help="Local directory or https://github.com/owner/repository")
    scan.add_argument("--config", type=Path, default=Path("autoreviewer.toml"))
    scan.add_argument("--output", type=Path, help="New directory for report.json and report.md")
    scan.add_argument("--model", action="append", dest="models", help="Model configuration id; may be repeated")
    scan.add_argument("--ref", help="Remote GitHub branch or tag (default: default branch)")
    publish = commands.add_parser("publish", help="Preview or explicitly publish issues from an existing JSON report")
    publish.add_argument("report", type=Path)
    publish.add_argument("--config", type=Path, default=Path("autoreviewer.toml"))
    publish.add_argument("--yes", action="store_true", help="Create GitHub issues; without this flag only preview locally")
    publish.add_argument("--allow-partial", action="store_true", help="Allow publishing findings from a partially completed scan")
    ui = commands.add_parser("ui", help="Start the local browser interface on 127.0.0.1")
    ui.add_argument("--config", type=Path, default=Path("autoreviewer.toml"))
    ui.add_argument("--data-dir", type=Path, default=Path(".autoreviewer/ui"), help="Local task history and report directory")
    ui.add_argument("--port", type=int, default=8765)
    ui.add_argument("--open", action="store_true", dest="open_browser", help="Open the local interface in your browser")
    return parser


def _init(args) -> int:
    contents = files("autoreviewer").joinpath("default.toml").read_text(encoding="utf-8")
    # O_EXCL protects user configuration even if two initializers run concurrently.
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(contents)
    print(f"Created {args.output}. Set your model ids, provider URLs and key environment variables.")
    return 0


def _doctor(args) -> int:
    config = load_config(args.config)
    failed = False
    with tempfile.TemporaryDirectory(prefix="autoreviewer-doctor-") as temporary:
        root = Path(temporary)
        for index, model in enumerate(config.models):
            provider = config.providers[model.provider]
            agent = config.agents[model.agent]
            problems = []
            if not shutil.which(agent.command[0]):
                problems.append(f"executable not found: {agent.command[0]}")
            if provider.api_key_env and not os.environ.get(provider.api_key_env):
                problems.append(f"missing environment variable {provider.api_key_env}")
            try:
                build_command(model, provider, agent, root, root / str(index), "Validate configuration only", "doctor-placeholder" if provider.api_key_env else None)
            except ValueError as exc:
                problems.append(str(exc))
            failed |= bool(problems)
            print(f"{model.id} ({model.agent} / {provider.api_format}): " + ("; ".join(problems) if problems else "ready"))
    print("Local checks only; CLI versions, endpoint access, quotas and model capabilities require a real scan.")
    return 2 if failed else 0


def _scan(args) -> int:
    config = load_config(args.config)
    if args.models:
        requested = set(args.models)
        unknown = requested - {model.id for model in config.models}
        if unknown:
            raise ValueError(f"Unknown model ids: {', '.join(sorted(unknown))}")
        config = replace(config, models=tuple(model for model in config.models if model.id in requested))
    output = args.output or Path(".autoreviewer") / "runs" / (datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ-") + uuid.uuid4().hex[:8])
    output = output.expanduser().resolve()
    if output.exists():
        raise ValueError("Output directory already exists; choose a new --output directory")
    started = _now()
    scope = None
    cancelled = False
    observed_runs = {}

    def on_event(event):
        # Terminal events arrive after the runner has validated model output and
        # cleaned up its process. Keep their copies even when asyncio.run raises
        # KeyboardInterrupt after cancelling the remaining models.
        run = event.get("run")
        if isinstance(run, dict):
            for finding in run.get("findings", []):
                finding["fingerprint"] = finding_fingerprint(finding)
            observed_runs[event["model"]] = run

    print(f"Reviewing with {len(config.models)} model(s), concurrency={config.scan.concurrency}.", flush=True)
    # One stable, filtered snapshot gives every model identical input even if the
    # user's working tree changes while review processes start.
    try:
        with tempfile.TemporaryDirectory(prefix="autoreviewer-") as temporary:
            root = Path(temporary)
            source = prepare_target(args.target, root / "target", config.github, args.ref)
            excludes = config.scan.excludes
            if output.is_relative_to(source):
                excludes += (output.relative_to(source).as_posix(),)
            scope = snapshot_repository(source, root / "baseline", excludes)
            runs = asyncio.run(run_models(config, root / "baseline", root / "models", on_event=on_event))
    except KeyboardInterrupt:
        cancelled = True
        runs = [observed_runs.get(model.id, {
            "model": model.id, "model_name": model.model, "provider": model.provider,
            "agent": model.agent, "api_format": config.providers[model.provider].api_format,
            "status": "cancelled", "error": "Audit cancelled before this model completed",
            "duration_seconds": 0.0, "findings": [],
        }) for model in config.models]
    completed = sum(run["status"] == "completed" for run in runs)
    status = "completed" if completed == len(runs) else "partial" if completed else "failed"
    report = {
        "schema_version": 1,
        "autoreviewer_version": __version__,
        "target": args.target,
        "ref": args.ref,
        "started_at": started,
        "finished_at": _now(),
        "status": status,
        "scope": scope,
        "runs": runs,
        "findings": merge_findings([run.get("findings", []) for run in runs if run["status"] == "completed"]),
    }
    if cancelled:
        report["cancelled"] = True
    # Reserve only a new destination, including when another command created it
    # while this scan ran. Never replace that command's report on completion.
    output.mkdir(parents=True, mode=0o700, exist_ok=False)
    json_path, markdown_path = write_reports(report, output)
    for run in runs:
        print(f"{run['model']}: {run['status']}" + (f" ({run['error']})" if run.get("error") else ""))
    print(f"{status}: {len(report['findings'])} unverified finding(s).")
    print(f"JSON: {json_path}\nMarkdown: {markdown_path}")
    if cancelled:
        print("Interrupted; review processes were cancelled and completed results were saved.", file=sys.stderr)
        return 130
    return 0 if status == "completed" else 2


def _publish(args) -> int:
    config = load_config(args.config)
    if config.github is None:
        raise ValueError("Configure [github] before previewing or publishing issues")
    if args.report.stat().st_size > 32 * 1024 * 1024:
        raise ValueError("Report exceeds 32 MiB")
    try:
        report = json.loads(args.report.read_text(encoding="utf-8"), object_pairs_hook=_unique_report_object)
    except (json.JSONDecodeError, UnicodeError, RecursionError) as exc:
        raise ValueError("Invalid UTF-8 JSON report") from exc
    report = validate_report(report)
    if not args.yes:
        drafts = plan_issues(report, allow_partial=args.allow_partial)
        print(json.dumps({"dry_run": True, "repository": config.github.repository, "issues": drafts}, ensure_ascii=False, indent=2))
        return 0
    results = publish_issues(report, config.github, allow_partial=args.allow_partial,
                             receipt_path=args.report.parent / "github-publications.json")
    print(json.dumps({"repository": config.github.repository, "issues": results}, ensure_ascii=False, indent=2))
    return 0


def main(argv=None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "ui":
            from .web import serve
            return serve(args.config, args.data_dir, args.port, args.open_browser)
        return {"init": _init, "doctor": _doctor, "scan": _scan, "publish": _publish}[args.command](args)
    except KeyboardInterrupt:
        print("Interrupted; review processes were cancelled.", file=sys.stderr)
        return 130
    except (ValueError, OSError) as exc:
        print(f"autoreviewer: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
