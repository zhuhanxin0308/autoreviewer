"""CLI-specific launch and output contracts; never invokes a shell.

The caller owns process lifetime, environment allowlisting and temporary directories.
These settings restrict agent tools; they are not a substitute for an OS sandbox.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import stat
from string import Formatter
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .config import AgentConfig, Model, Provider


class AdapterError(ValueError):
    """An incompatible CLI configuration or invalid CLI output."""


@dataclass(frozen=True)
class LaunchSpec:
    argv: list[str]
    env: dict[str, str]
    output_path: Path | None = None
    output_format: str = "text"


SUPPORTED_FORMATS = {
    "opencode": "openai-chat",
    "codex": "openai-responses",
    "claude": "anthropic",
    "gemini": "gemini",
}
DEFAULT_COMMANDS = {name: name for name in SUPPORTED_FORMATS}
MAX_OUTPUT_BYTES = 4 * 1024 * 1024
_SECRET_ENV = "AUTOREVIEWER_API_KEY"


def _write_config(path: Path, content: str) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    # State directories are fresh and owned by the runner. Never replace files.
    with path.open("x", encoding="utf-8") as handle:
        handle.write(content)
    path.chmod(0o600)


def _validate_value(value: str, label: str) -> None:
    if not isinstance(value, str) or not value or value.startswith("-"):
        raise AdapterError(f"{label} must be a nonempty value, not a CLI option")
    if any(ord(char) < 32 for char in value):
        raise AdapterError(f"{label} cannot contain control characters")


def _custom_args(templates: tuple[str, ...], values: dict[str, str]) -> list[str]:
    result = []
    for template in templates:
        try:
            for _, field, format_spec, conversion in Formatter().parse(template):
                if field is not None and (
                    field not in values or format_spec or conversion
                ):
                    raise AdapterError(f"Unsupported CLI template field: {field}")
            result.append(template.format_map(values))
        except (ValueError, KeyError, IndexError) as exc:
            raise AdapterError("Invalid custom CLI argument template") from exc
    return result


def build_command(
    model: Model,
    provider: Provider,
    agent: AgentConfig,
    workspace: Path,
    state_dir: Path,
    prompt: str,
    api_key: str | None,
) -> LaunchSpec:
    """Create per-instance configuration and return argv plus environment overrides.

    Credentials only enter environment values. Built-in adapters do not accept
    extra arguments: use a custom adapter for a deliberately different contract.
    """
    _validate_value(model.model, "model")
    _validate_value(provider.base_url, "base_url")
    adapter = model.agent
    required_format = SUPPORTED_FORMATS.get(adapter)
    if required_format and provider.api_format != required_format:
        raise AdapterError(
            f"{adapter} requires api_format={required_format}; provider uses "
            f"{provider.api_format}. Use a compatible endpoint or opencode for openai-chat."
        )
    if required_format and agent.args:
        raise AdapterError("Extra args are only supported by custom CLI adapters")
    command = list(agent.command or (DEFAULT_COMMANDS.get(adapter, ""),))
    if not command[0]:
        raise AdapterError("Custom CLI adapters require an explicit command")
    if any(not isinstance(arg, str) or "\x00" in arg for arg in command):
        raise AdapterError("CLI command must contain strings without NUL bytes")
    workspace = workspace.resolve()
    state_dir = state_dir.resolve()
    state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    env = {_SECRET_ENV: api_key} if api_key is not None else {}

    if adapter == "opencode":
        permissions = {"*": "deny", "read": "allow", "glob": "allow", "grep": "allow", "list": "allow"}
        config = {
            "$schema": "https://opencode.ai/config.json",
            "autoupdate": False,
            "share": "disabled",
            "enabled_providers": ["autoreviewer"],
            "provider": {
                "autoreviewer": {
                    "npm": "@ai-sdk/openai-compatible",
                    "name": provider.name,
                    "options": {
                        "baseURL": provider.base_url,
                        "apiKey": "{env:AUTOREVIEWER_API_KEY}",
                    },
                    "models": {model.model: {"name": model.model}},
                }
            },
            "permission": permissions,
            "mcp": {},
            "plugin": [],
            "instructions": [],
            "lsp": False,
            "formatter": False,
        }
        # Some OpenAI-compatible clients require a nonempty key for local servers.
        env.setdefault(_SECRET_ENV, "local-no-auth")
        env.update({
            "OPENCODE_CONFIG_CONTENT": json.dumps(config),
            "OPENCODE_PERMISSION": json.dumps(permissions),
            "OPENCODE_CONFIG_DIR": str(state_dir / "opencode"),
            "OPENCODE_DISABLE_PROJECT_CONFIG": "1",
            "OPENCODE_DISABLE_DEFAULT_PLUGINS": "1",
            "OPENCODE_DISABLE_CLAUDE_CODE": "1",
            "OPENCODE_DISABLE_EXTERNAL_SKILLS": "1",
            "OPENCODE_DISABLE_AUTOUPDATE": "1",
            "OPENCODE_DISABLE_LSP_DOWNLOAD": "1",
            "OPENCODE_DISABLE_MODELS_FETCH": "1",
        })
        argv = command + ["run", "--format", "json", "--model", f"autoreviewer/{model.model}", "--", prompt]
        return LaunchSpec(argv, env, output_format="opencode-jsonl")

    if adapter == "codex":
        home = state_dir / "codex"
        config = [
            'model_provider = "autoreviewer"',
            f"model = {json.dumps(model.model)}",
            'approval_policy = "never"',
            'sandbox_mode = "read-only"',
            'web_search = "disabled"',
            'project_doc_max_bytes = 0',
            'allow_login_shell = false',
            '[features]',
            'hooks = false',
            'codex_hooks = false',
            'plugin_hooks = false',
            '[shell_environment_policy]',
            'inherit = "none"',
            'include_only = ["PATH", "HOME", "LANG"]',
            '[model_providers.autoreviewer]',
            'name = "autoreviewer"',
            f"base_url = {json.dumps(provider.base_url)}",
            'wire_api = "responses"',
            'requires_openai_auth = false',
        ]
        if api_key is not None:
            config.append(f'env_key = "{_SECRET_ENV}"')
        _write_config(home / "config.toml", "\n".join(config) + "\n")
        env["CODEX_HOME"] = str(home)
        output = state_dir / "final.json"
        argv = command + [
            "-a", "never", "-s", "read-only", "exec", "--skip-git-repo-check",
            "--ephemeral", "--ignore-rules", "--color", "never", "-C", str(workspace),
            "--model", model.model, "--output-last-message", str(output), "--", prompt,
        ]
        return LaunchSpec(argv, env, output, "file")

    if adapter == "claude":
        env.update({
            "ANTHROPIC_BASE_URL": provider.base_url,
            "CLAUDE_CONFIG_DIR": str(state_dir / "claude"),
            "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
            "DISABLE_AUTOUPDATER": "1",
        })
        if api_key is not None:
            env["ANTHROPIC_API_KEY"] = api_key
        settings = state_dir / "claude-settings.json"
        _write_config(settings, json.dumps({"disableAllHooks": True}))
        argv = command + [
            "--print", "--output-format", "json", "--model", model.model,
            "--restricted", "--safe-mode", "--permission-mode", "plan",
            "--tools", "Read,Glob,Grep", "--allowedTools", "Read,Glob,Grep",
            "--disallowedTools", "mcp__*", "--strict-mcp-config", "--mcp-config", '{"mcpServers":{}}',
            "--setting-sources", "", "--settings", str(settings),
            "--disable-slash-commands", "--no-session-persistence", "--", prompt,
        ]
        return LaunchSpec(argv, env, output_format="claude-json")

    if adapter == "gemini":
        settings = state_dir / "gemini-settings.json"
        _write_config(settings, json.dumps({
            "general": {"defaultApprovalMode": "plan", "enableAutoUpdate": False,
                        "plan": {"enabled": True, "modelRouting": False}},
            "tools": {"core": ["read_file", "read_many_files", "list_directory", "glob", "grep_search"]},
            "security": {"auth": {"selectedType": "gemini-api-key"}},
            "advanced": {"ignoreLocalEnv": True},
            "skills": {"enabled": False},
            "hooksConfig": {"enabled": False},
            "mcpServers": {},
            "admin": {"mcp": {"enabled": False}, "skills": {"enabled": False}},
            "telemetry": {"enabled": False},
        }))
        defaults = state_dir / "gemini-defaults.json"
        _write_config(defaults, "{}")
        env.update({
            "GOOGLE_GEMINI_BASE_URL": provider.base_url,
            "GEMINI_CLI_SYSTEM_SETTINGS_PATH": str(settings),
            "GEMINI_CLI_SYSTEM_DEFAULTS_PATH": str(defaults),
            "GEMINI_TELEMETRY_ENABLED": "false",
        })
        if api_key is not None:
            env["GEMINI_API_KEY"] = api_key
        argv = command + ["--model", model.model, "--approval-mode", "plan", "--output-format", "json", "--prompt", prompt]
        return LaunchSpec(argv, env, output_format="gemini-json")

    output = state_dir / "final.json"
    values = {"model": model.model, "base_url": provider.base_url, "workspace": str(workspace),
              "prompt": prompt, "output_file": str(output)}
    templates = tuple(command) + tuple(agent.args)
    argv = _custom_args(templates, values)
    uses_file = any("{output_file}" in item for item in templates)
    env.update({"AUTOREVIEWER_MODEL": model.model, "AUTOREVIEWER_BASE_URL": provider.base_url,
                "AUTOREVIEWER_AUDIT_PROMPT": prompt,
                "AUTOREVIEWER_WORKSPACE": str(workspace), "AUTOREVIEWER_OUTPUT_FILE": str(output)})
    return LaunchSpec(argv, env, output if uses_file else None, "file" if uses_file else "text")


def _read_output_file(path: Path) -> str:
    # O_NOFOLLOW closes the final-component symlink race on supported systems.
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    if path.is_symlink():
        raise AdapterError("CLI output must be a regular file, not a symlink")
    try:
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode):
                raise AdapterError("CLI output must be a regular file")
            data = handle.read(MAX_OUTPUT_BYTES + 1)
    except OSError as exc:
        raise AdapterError("CLI did not produce a readable result file") from exc
    if len(data) > MAX_OUTPUT_BYTES:
        raise AdapterError("CLI result exceeds the output size limit")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AdapterError("CLI result is not UTF-8") from exc


def _opencode_error_message(event: dict) -> str:
    """Expose HTTP status without forwarding untrusted provider error details."""
    fallback = "OpenCode reported an error"
    error = event.get("error")
    if not isinstance(error, dict) or error.get("name") != "APIError":
        return fallback
    data = error.get("data")
    if not isinstance(data, dict):
        return fallback
    status = data.get("statusCode")
    # bool is an int subclass, but is never a valid HTTP status.
    if type(status) is not int or not 100 <= status <= 599:
        return fallback
    reasons = {
        400: "request rejected",
        401: "authentication failed",
        403: "access denied",
        404: "model or endpoint unavailable",
        429: "rate limit exceeded",
    }
    reason = "service error" if status >= 500 else reasons.get(status, "request failed")
    return f"OpenCode API error (HTTP {status}): {reason}"


def extract_output(spec: LaunchSpec, stdout: str) -> str:
    """Extract only the final model answer; errors never become empty findings."""
    if spec.output_format == "file":
        if spec.output_path is None:
            raise AdapterError("Missing CLI output file path")
        return _read_output_file(spec.output_path)
    if len(stdout.encode("utf-8")) > MAX_OUTPUT_BYTES:
        raise AdapterError("CLI result exceeds the output size limit")
    if spec.output_format == "text":
        return stdout
    if spec.output_format == "opencode-jsonl":
        texts: list[str] = []
        for line in stdout.splitlines():
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError as exc:
                raise AdapterError("Invalid OpenCode JSON event stream") from exc
            if not isinstance(event, dict):
                raise AdapterError("Invalid OpenCode JSON event")
            if event.get("type") == "error":
                raise AdapterError(_opencode_error_message(event))
            if event.get("type") == "text":
                part = event.get("part")
                if not isinstance(part, dict) or not isinstance(part.get("text"), str):
                    raise AdapterError("Invalid OpenCode text event")
                texts.append(part["text"])
        if not texts:
            raise AdapterError("OpenCode returned no answer")
        # The run event stream emits complete text parts, not token deltas. The
        # last text part is the final answer after intermediate narration/tools.
        return texts[-1]
    try:
        envelope = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise AdapterError("CLI returned an invalid JSON envelope") from exc
    if not isinstance(envelope, dict):
        raise AdapterError("CLI returned an invalid JSON envelope")
    if envelope.get("error") or envelope.get("is_error"):
        raise AdapterError("CLI reported an error")
    key = {"claude-json": "result", "gemini-json": "response"}.get(spec.output_format)
    if key is None or not isinstance(envelope.get(key), str):
        raise AdapterError("CLI returned no final answer")
    return envelope[key]
