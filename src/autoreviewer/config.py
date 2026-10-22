"""Validated, non-secret configuration. Credentials are environment references."""

from dataclasses import dataclass, field
from pathlib import Path
import re
import tomllib
from urllib.parse import urlsplit


class ConfigError(ValueError):
    pass


@dataclass(frozen=True)
class Provider:
    name: str
    base_url: str
    api_key_env: str | None = None
    api_format: str = "openai-chat"


@dataclass(frozen=True)
class Model:
    id: str
    provider: str
    model: str
    agent: str = "opencode"


@dataclass(frozen=True)
class AgentConfig:
    command: tuple[str, ...] = ()
    args: tuple[str, ...] = ()


@dataclass(frozen=True)
class ScanConfig:
    concurrency: int = 3
    timeout_seconds: int = 600
    max_output_bytes: int = 4 * 1024 * 1024
    excludes: tuple[str, ...] = ()


@dataclass(frozen=True)
class GitHubConfig:
    repository: str
    token_env: str = "GITHUB_TOKEN"
    labels: tuple[str, ...] = ()


@dataclass(frozen=True)
class Config:
    providers: dict[str, Provider]
    models: tuple[Model, ...]
    agents: dict[str, AgentConfig] = field(default_factory=dict)
    scan: ScanConfig = field(default_factory=ScanConfig)
    github: GitHubConfig | None = None


DEFAULT_COMMANDS = {"opencode": "opencode", "codex": "codex", "claude": "claude", "gemini": "gemini"}
API_FORMATS = {"openai-chat", "openai-responses", "anthropic", "gemini"}
_RUNTIME_VARIABLES = {
    "PATH", "HOME", "USERPROFILE", "PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP",
    "LD_PRELOAD", "LD_LIBRARY_PATH", "DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH",
    "NODE_OPTIONS", "SHELL", "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT",
    "BASH_ENV", "ENV", "TMP", "TEMP", "TMPDIR", "LANG", "LANGUAGE", "LC_ALL",
    "LC_CTYPE", "TZ", "TERM", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
    "SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE",
    "NODE_EXTRA_CA_CERTS", "GRPC_DEFAULT_SSL_ROOTS_FILE_PATH", "CODEX_HOME",
    "OPENCODE_CONFIG_CONTENT", "OPENCODE_CONFIG_DIR", "OPENCODE_PERMISSION",
    "CLAUDE_CONFIG_DIR", "ANTHROPIC_BASE_URL", "GOOGLE_GEMINI_BASE_URL",
    "GEMINI_CLI_SYSTEM_SETTINGS_PATH", "GEMINI_CLI_SYSTEM_DEFAULTS_PATH",
    "AUTOREVIEWER_AUDIT_PROMPT",
}


def _table(value, name):
    if not isinstance(value, dict):
        raise ConfigError(f"{name} must be a TOML table")
    return value


def _keys(data, allowed, name):
    unknown = data.keys() - set(allowed)
    if unknown:
        raise ConfigError(f"Unknown option in {name}: {', '.join(sorted(unknown))}")


def _str(value, name):
    if not isinstance(value, str) or not value.strip() or any(ord(c) < 32 or 0xD800 <= ord(c) <= 0xDFFF for c in value):
        raise ConfigError(f"{name} must be a nonempty string without control characters")
    return value


def _identifier(value, name):
    value = _str(value, name)
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}", value):
        raise ConfigError(f"{name} must use letters, numbers, dots, underscores or hyphens")
    return value


def _env(value, name):
    value = _str(value, name)
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", value):
        raise ConfigError(f"{name} must name an environment variable")
    # Never let a model key overwrite runtime or executable-search settings.
    if value.upper() in _RUNTIME_VARIABLES or value.upper().startswith(("XDG_", "GIT_")):
        raise ConfigError(f"{name} cannot use a runtime environment variable")
    return value


def _strings(value, name):
    if not isinstance(value, list):
        raise ConfigError(f"{name} must be an array of strings")
    return tuple(_str(item, name) for item in value)


def _integer(value, name, low, high):
    if type(value) is not int or not low <= value <= high:
        raise ConfigError(f"{name} must be an integer between {low} and {high}")
    return value


def load_config(path: Path) -> Config:
    path = Path(path)
    if path.stat().st_size > 1024 * 1024:
        raise ConfigError("Configuration exceeds 1 MiB")
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (tomllib.TOMLDecodeError, UnicodeError) as exc:
        raise ConfigError("Invalid UTF-8 TOML configuration") from exc
    _keys(data, {"version", "providers", "models", "agents", "scan", "github"}, "configuration")
    if type(data.get("version")) is not int or data["version"] != 1:
        raise ConfigError("Configuration version must be 1")
    providers = {}
    for name, item in _table(data.get("providers", {}), "providers").items():
        _identifier(name, "provider name")
        item = _table(item, f"providers.{name}")
        _keys(item, {"base_url", "api_key_env", "api_format"}, f"providers.{name}")
        base_url = _str(item.get("base_url"), "base_url").rstrip("/")
        try:
            url = urlsplit(base_url)
            valid_port = url.port
        except ValueError as exc:
            raise ConfigError("Invalid base_url") from exc
        if (not url.hostname or url.username is not None or url.password is not None
                or url.query or url.fragment or url.scheme not in {"https", "http"}
                or (url.scheme == "http" and url.hostname not in {"localhost", "127.0.0.1", "::1"})):
            raise ConfigError("base_url requires HTTPS (or HTTP on loopback), without credentials, query or fragment")
        fmt = item.get("api_format", "openai-chat")
        if not isinstance(fmt, str) or fmt not in API_FORMATS:
            raise ConfigError(f"api_format must be one of {', '.join(sorted(API_FORMATS))}")
        key = _env(item["api_key_env"], "api_key_env") if "api_key_env" in item else None
        providers[name] = Provider(name, base_url, key, fmt)
    agents = {name: AgentConfig((cmd,)) for name, cmd in DEFAULT_COMMANDS.items()}
    for name, item in _table(data.get("agents", {}), "agents").items():
        _identifier(name, "agent name")
        item = _table(item, f"agents.{name}")
        _keys(item, {"command", "args"}, f"agents.{name}")
        command = _strings(item.get("command", [DEFAULT_COMMANDS[name]] if name in DEFAULT_COMMANDS else []), "command")
        if not command:
            raise ConfigError(f"agents.{name}.command cannot be empty")
        agents[name] = AgentConfig(command, _strings(item.get("args", []), "args"))
    models = []
    raw_models = data.get("models", [])
    if not isinstance(raw_models, list) or not 1 <= len(raw_models) <= 64:
        raise ConfigError("Configure between 1 and 64 [[models]] entries")
    seen = set()
    for item in raw_models:
        item = _table(item, "models")
        _keys(item, {"id", "provider", "model", "agent"}, "models")
        name = _identifier(item.get("id"), "model id")
        provider = _str(item.get("provider"), "provider")
        model = _str(item.get("model"), "model")
        agent = _str(item.get("agent", "opencode"), "agent")
        if name in seen:
            raise ConfigError(f"Duplicate model id: {name}")
        if provider not in providers:
            raise ConfigError(f"Unknown provider for model {name}")
        if agent not in agents:
            raise ConfigError(f"Unknown agent for model {name}; configure [agents.{agent}]")
        if model.startswith("-"):
            raise ConfigError("model cannot start with '-'")
        seen.add(name)
        models.append(Model(name, provider, model, agent))
    scan = _table(data.get("scan", {}), "scan")
    _keys(scan, {"concurrency", "timeout_seconds", "max_output_bytes", "excludes"}, "scan")
    scan_config = ScanConfig(
        _integer(scan.get("concurrency", 3), "concurrency", 1, 32),
        _integer(scan.get("timeout_seconds", 600), "timeout_seconds", 1, 86400),
        _integer(scan.get("max_output_bytes", 4194304), "max_output_bytes", 1024, 67108864),
        _strings(scan.get("excludes", []), "excludes"),
    )
    github = None
    if "github" in data:
        item = _table(data["github"], "github")
        _keys(item, {"repository", "token_env", "labels"}, "github")
        repository = _str(item.get("repository"), "github.repository")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*", repository):
            raise ConfigError("github.repository must be owner/repository")
        github = GitHubConfig(repository, _env(item.get("token_env", "GITHUB_TOKEN"), "token_env"), _strings(item.get("labels", []), "labels"))
    github_token_variables = {"GITHUB_TOKEN", "GH_TOKEN"}
    if github is not None:
        github_token_variables.add(github.token_env.upper())
    for provider in providers.values():
        if provider.api_key_env and provider.api_key_env.upper() in github_token_variables:
            raise ConfigError("Model API keys and GitHub tokens must use different environment variables")
    return Config(providers, tuple(models), agents, scan_config, github)
