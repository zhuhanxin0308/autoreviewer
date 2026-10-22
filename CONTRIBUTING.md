# Contributing

Thanks for helping improve autoreviewer. Small, focused changes are easiest to review.

## Local development

Use Python 3.11 or newer. Runtime dependencies are limited to the standard library.

```bash
python -m pip install -e .
python -m unittest discover -s tests -v
```

For adapter changes, add meaningful tests for command construction, credential handling, output parsing, and failure behavior. For subprocess changes, exercise timeouts and cleanup with a fake local CLI. Mock HTTP in GitHub tests; tests must never create live issues.

For task-history changes, test checkpoint recovery, malformed or incomplete saved data, write failures, and competing writers. A recovered finding must originate from a completed model run; unfinished runs must remain interrupted rather than becoming clean results. Retry tests should preserve the original report and reject changed model bindings. Report imports must not access a supplied target path, run a CLI, or publish an issue.

The optional browser test exercises the real local server and fixture CLI processes. It covers configuration forms and export, session credentials, parallel scans, report imports, retries, checkpoints, candidate groups, filtering, downloads, cancellation, history recovery, mobile layouts, and escaped report content. GitHub publication is mocked; it never calls a model or creates a real issue.

```bash
python -m pip install -e '.[browser-tests]'
python -m playwright install chromium
python tests/browser_smoke.py
python tests/browser_regressions.py
```

Use `--browser-binary /path/to/chromium` to reuse an installed Chromium browser, and `--artifacts ./work/ui-check` to save screenshots. HTTP and threaded asyncio tests need permission to use local loopback sockets. The UI runtime itself requires neither Playwright nor Node.js.

The browser regression suite exercises conflicting edits across tabs, keyboard focus and skip navigation, pending responses after navigation, live scan availability, per-model evidence, and the issue selection limit. Keep unsaved inputs intact when refreshing status or handling a rejected configuration revision. CLI cancellation tests send a real SIGINT to a fixture scan and verify that completed findings survive and child processes stop.

## Pull requests

Describe the problem, resulting behavior, and validation performed. Explain protocol or CLI version assumptions. Keep examples runnable without real credentials and do not add secrets, private source code, or raw model transcripts to fixtures.

Document whether compatibility was checked using fixtures or a real CLI/provider. Claims of live compatibility need tested versions and relevant limitations. Avoid pinning a model as permanently free: availability and pricing change independently of this project.

Preserve the distinction between an unverified model finding, a confirmed vulnerability, and a failed audit. Do not silently convert errors into empty results or publish issues during a scan.

By contributing, you agree that your contribution is licensed under the repository's Apache License 2.0. For sensitive security reports, see [SECURITY.md](SECURITY.md).
