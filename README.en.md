# autoreviewer

Review code in parallel with multiple models through local code agent CLIs, collect security hypotheses, and publish GitHub issues after human review.

**Alpha / MVP.** Includes a local Web UI and a command line interface. Live model testing currently focuses on OpenCode + NVIDIA; findings are unverified, not confirmed vulnerabilities.

[中文](README.md) · [Web UI guide](docs/web-ui.md) · [CLI adapters](docs/cli-adapters.md) · [Audit guidance](docs/audit-guidance.md) · [Architecture](docs/architecture.md) · [Security](SECURITY.md)

## Quick start: local Web UI

You need **Python 3.11+, Git**, and at least one separately installed [agent CLI](#models-and-clis). Linux/macOS are the primary platforms. Make the CLI available on `PATH` or configure its executable path. autoreviewer orchestrates existing CLIs; your configured providers supply the models.

```bash
git clone https://github.com/zhuhanxin0308/autoreviewer.git
cd autoreviewer
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
autoreviewer ui --open
```

Open `http://127.0.0.1:8765`:

1. Configure each provider's `base_url`, protocol, API key, and available model IDs; select a CLI for each model.
2. Start a scan of a local directory or GitHub HTTPS repository, selecting models and concurrency.
3. Follow model status, activity, and partial results; filter findings and download JSON/Markdown reports. Preview selected GitHub issues before explicitly confirming publication.

Each model gets its own process, source copy, configuration, and HOME, with bounded concurrency and timeouts. The UI supports cancellation, recovery of saved results, retries as new tasks, report imports, and side-by-side review of related findings. Original records and failures remain visible. The UI runs one scan at a time, with multiple models running concurrently within that scan.

Non-secret configuration defaults to `autoreviewer.toml`; task history goes to `.autoreviewer/ui/jobs/`. Credentials can come from environment variables. Credentials entered in the UI remain in server memory and must be entered again after restart. The server binds only to `127.0.0.1` for one local user; source paths refer to the machine running it. See the [Web UI guide](docs/web-ui.md).

## Models and CLIs

Configure multiple providers and multiple models per provider. Each `[[models]]` entry creates one review instance. Model IDs, free tiers, pricing, and availability depend on each provider's current offerings.

| CLI / `agent` | `api_format` | Current adapter and validation limits |
| --- | --- | --- |
| [OpenCode](https://opencode.ai/docs/) / `opencode` | `openai-chat` | OpenAI Chat Completions-compatible API; live NVIDIA model tests used **1.2.27** |
| [Codex CLI](https://developers.openai.com/codex/cli/) / `codex` | `openai-responses` | Requires Responses; local configuration parsing checked with **0.163.0**, no live model audit validation yet |
| [Claude Code](https://code.claude.com/docs/en/cli-reference) / `claude` | `anthropic` | Requires Anthropic Messages and **2.1.248+** with `--restricted` and `--safe-mode`; no live model audit validation yet |
| [Gemini CLI](https://geminicli.com/docs/) / `gemini` | `gemini` | Requires Gemini API; adapted from upstream documentation/source with plan mode and a read-tool allowlist, no live model audit validation yet |
| Custom wrapper / `custom` | Handled by the wrapper | Connect other CLIs; the trusted wrapper owns permissions, protocol handling, and prompt delivery |

**Changing `base_url` does not convert protocols.** Use OpenCode for Chat Completions providers; Claude/Gemini require an external protocol bridge to use those providers. Services must also support the CLI's tool calls and streaming behavior. CLI upgrades may change compatibility; see [adapter details](docs/cli-adapters.md).

## Scan from the command line

After installation, create a configuration. If you already saved one through the UI, edit that file instead:

```bash
autoreviewer init --output autoreviewer.toml
```

This example runs two models. Replace both `model` placeholders with IDs available from your provider, and set `OPENROUTER_API_KEY` through your shell or secret manager. The configuration contains only the credential's **environment variable name**.

```toml
version = 1

[scan]
concurrency = 2
timeout_seconds = 600

[providers.router]
base_url = "https://openrouter.ai/api/v1"
api_key_env = "OPENROUTER_API_KEY"
api_format = "openai-chat"

[[models]]
id = "reviewer-a"
provider = "router"
model = "replace-with-available-model-id"
agent = "opencode"

[[models]]
id = "reviewer-b"
provider = "router"
model = "replace-with-another-model-id"
agent = "opencode"
```

Add `[providers.NAME]` blocks for other platforms and reference each name in a model's `provider` field. Model configuration `id` values must be unique. See the [full example](examples/autoreviewer.toml), or use the [NVIDIA example](examples/nvidia.toml) with `NVIDIA_API_KEY`.

```bash
autoreviewer doctor --config autoreviewer.toml

# Review a local directory
autoreviewer scan ./your-project --config autoreviewer.toml --output ./audit-local

# Review a GitHub branch
autoreviewer scan https://github.com/OWNER/REPO.git --ref main \
  --config autoreviewer.toml --output ./audit-remote
```

Add `--model reviewer-a` to select one configuration; the option can be repeated. `doctor` checks configuration, executables, and credential presence. It does not verify CLI versions, provider connectivity, or permissions.

Outputs are `report.json` and `report.md`. The `--output` directory must not exist; omitting it creates a unique directory under `.autoreviewer/runs/`. Exit code `0` means all models completed, regardless of findings; `2` means invalid configuration or partial/total failure. Ctrl+C saves completed results, cancels unfinished instances, and returns `130`, provided the output location is writable.

## Offline demo

Run from the repository root without an agent CLI or model API key:

```bash
autoreviewer scan examples/demo-repository \
  --config examples/demo.toml --output ./demo-result
```

Two local Python fixture processes return a fixed `DEMO ONLY` finding to demonstrate orchestration, deduplication, and reporting. They do not analyze code or call models. Use a new output directory for each run.

## GitHub issues: preview, then publish

Configure a repository you are authorized to use, and provide its token through `GITHUB_TOKEN`:

```toml
[github]
repository = "OWNER/REPO"
token_env = "GITHUB_TOKEN"
labels = []
```

Use a fine-grained token scoped to that repository: **Contents: Read** for private source access, **Issues: Read and write** for publication, and repository metadata access. Issues must be enabled. Public repository scans usually need no token. Labels must already exist, or leave the list empty.

```bash
# Local preview only; no GitHub request
autoreviewer publish ./audit-local/report.json --config autoreviewer.toml

# Publish after reviewing the result
autoreviewer publish ./audit-local/report.json --config autoreviewer.toml --yes
```

Scanning never publishes automatically. Partial reports require explicit `--allow-partial`; entirely failed reports cannot be published. Publication checks existing finding fingerprints and saves a `github-publications.json` receipt. Keep it for later deduplication; closed issues are not reopened. Independent clients can still race. Public issues disclose the report details; use the repository's private reporting channel for sensitive vulnerabilities. See [publication behavior](docs/architecture.md#发布边界) and the [live GitHub test](docs/live-tests/github-2026-10-23.md).

## Cloudflare audit guidance

Scans include a read-only adaptation of [Cloudflare security-audit-skill](https://github.com/cloudflare/security-audit-skill), pinned to commit `c1c8a8c1471069fb0e188eeaff69b8e8db6564a8`. It asks models to trace trust boundaries and complete entrypoint-to-sink paths, challenge candidates against existing defenses, and provide source evidence and minimal fixes.

The guidance is bundled; no extra skill installation or runtime download is needed. All four built-in CLIs receive the shared prompt. Custom wrappers must forward `{prompt}` or `AUTOREVIEWER_AUDIT_PROMPT`. Each model run records the source, commit, adaptation version, and guidance/prompt hashes; old reports are not backfilled with the current version. These records do not prove model compliance.

The `guidance-readonly` mode does not run target code, tests, or PoCs, modify target files, or implement the upstream full audit and independent verification workflow. Findings remain `unverified`, and severity is a provisional impact estimate. See the [integration and upgrade guide](docs/audit-guidance.md).

## Validation so far

**248 Python automated tests** and Chromium browser workflow checks pass, covering orchestration, parsing, reports, recovery, retries, guidance provenance, the UI, and publication flows. Automation uses fixture CLIs and mocked GitHub APIs; it does not validate every real CLI/model combination.

| Live test | Results and scope |
| --- | --- |
| [Three-model review with guidance](docs/live-tests/cloudflare-guidance-three-2026-10-22.md) | OpenCode + NVIDIA on a fixed `clipboard.js` commit. **1/3** models produced valid reports initially; **2/3** did after unchanged retries, across 3 models and 5 process attempts. Muse's one candidate needs host validation: **0** new accepted vulnerabilities and **0** new issues. Overall completion remains partial; no manual answer repair |
| [Earlier five/eight-model concurrency](docs/live-tests/nvidia-parallel-2026-10-22.md) | A 41-line seeded fixture: 2 models completed in the five-model batch; 5 completed, 2 failed, and 1 timed out in the eight-model batch. Both reports preserve partial failures; [reproduction configuration](examples/nvidia-parallel.toml) |
| [GitHub integration](docs/live-tests/github-2026-10-23.md) | Real repository retrieval, test issue creation, repeat-publication deduplication, and deduplication after restart with closed issues |

These are limited integration tests, not accuracy or stability benchmarks. Targets and prompt scope differ between rounds, so finding counts cannot measure the guidance's effect. Improved detection accuracy has not been established.

## Results and security boundaries

Findings are **unverified security hypotheses**. Model agreement does not confirm a vulnerability, and an empty report does not prove safety. Errors, timeouts, and invalid outputs remain failures, rather than clean results.

Snapshots filter common secret files, Git metadata, symlinks, and agent project configuration; filtering also limits review scope. Separate copies and CLI read-only policies are not an OS sandbox, and custom CLIs are trusted programs. Code is sent to your selected model services, so use only code you are authorized to review and transmit. See [SECURITY.md](SECURITY.md).

## Documentation, contributions, and license

[Web UI](docs/web-ui.md) · [Example configuration](examples/autoreviewer.toml) · [CLI adapters](docs/cli-adapters.md) · [Audit guidance](docs/audit-guidance.md) · [Architecture and data format](docs/architecture.md) · [Contributing](CONTRIBUTING.md)

```bash
python -m unittest discover -s tests -v
```

See [CONTRIBUTING.md](CONTRIBUTING.md) to install and run browser tests. Contributions to adapters, live compatibility checks, reporting, and the review experience are welcome. Include versions and sanitized error details in bug reports.

Licensed under [Apache License 2.0](LICENSE). Bundled Cloudflare material and adapted guidance retain the MIT license; see [third-party notices](THIRD_PARTY_NOTICES.md).
