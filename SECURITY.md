# Security policy and boundaries

autoreviewer sends selected source code to model services configured by the user and runs locally installed agent CLIs. Only audit code you are authorized to review and choose services permitted to process that code.

## Credentials

Configuration stores environment variable names, not keys or tokens. Model subprocesses receive the selected model credential and a restricted runtime environment. GitHub publication uses its token separately. Do not place credentials in CLI arguments, model IDs, URLs, repository files, or committed configuration.

The runner redacts known credential values from recorded outputs, but redaction cannot guarantee removal of every encoding, partial disclosure, or unknown secret. Review reports before publishing them.

Use fine-grained GitHub tokens limited to the intended repository. Reading private source needs Contents read; creating issues needs Issues read/write, with metadata access. Use an environment or secret manager. Revoke and rotate exposed credentials.

The local Web UI can also accept session-only credentials. These values stay in the server process memory; configuration files, browser local storage, and API responses do not retain or return them. They are lost when the server stops. This is not an encrypted credential vault, and other processes with sufficient access to the same user or machine may inspect process memory.

## Local browser UI

The UI server binds only to `127.0.0.1` and is intended for a single local user. It is not a public, authenticated multi-user service. Do not expose it through a public reverse proxy or port forwarding. A scan path refers to the server machine's filesystem, and configured CLI executables run with that server process's permissions.

Configuration changes persist to the selected TOML file, with credentials represented only by environment variable names. Task metadata and reports persist under the chosen data directory and may include source excerpts. Review access to that directory and remove reports when they are no longer needed. Stopping the UI clears session-entered credentials but does not remove saved reports.

The UI offers issue previews and requires an explicit publication action. Previewing and scanning do not create GitHub issues. A partially completed report requires a separate opt-in before publication; selecting findings or several models agreeing on them does not verify those findings.

## Execution and source isolation

Each model receives a separate source copy and HOME. Common secret files, symlinks, Git metadata, and agent project configuration are excluded. Additional exclusions can be configured. Filtering cannot identify every secret embedded in ordinary source files.

Copies and CLI read-only settings are **not an operating-system sandbox**. A CLI runs with the user's process permissions and has network access to its model service. Custom commands are trusted programs. Repository content is untrusted model input; prompts alone cannot reliably prevent prompt injection. For stronger isolation, run autoreviewer and its CLIs in a dedicated restricted environment with only the necessary credentials and source.

Process-group cleanup is designed for POSIX systems. Windows support requires further integration testing; do not assume identical descendant-process termination behavior there.

## Reports and publication

Findings are unverified hypotheses requiring human review. Multiple model votes do not verify exploitability, and no findings does not prove security. Partial or failed audits are visible in the report.

Scanning does not publish. The separate `publish` command previews locally by default and requires `--yes` for GitHub writes. Review the repository, source excerpts, and vulnerability details before publishing. Public issues may disclose information attackers can use; use the target project's private reporting channel when appropriate.

## Reporting an autoreviewer vulnerability

Do not post credentials or exploitable private details in a public issue. If GitHub private vulnerability reporting is enabled, use **Security → Report a vulnerability**. Otherwise, contact a maintainer through an available private channel to agree on a secure reporting route before sending details. This project does not yet publish a dedicated security contact address or response-time guarantee.
