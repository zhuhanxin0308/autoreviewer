"""Optional browser integration test; uses real local fixture CLIs, no model API.

Install Playwright and Chromium, then run:
    python tests/browser_smoke.py --browser-binary /usr/bin/chromium
GitHub publication is mocked; no external issue or network request is made.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import shutil
import sys
import tempfile
import threading
from unittest.mock import patch

from playwright.sync_api import expect, sync_playwright

from autoreviewer.web import LocalWebServer
from autoreviewer.webservice import WebService


FIXTURE = r'''
import json, sys, time
model = sys.argv[1]
if model == "flaky":
    from pathlib import Path
    counter = Path(sys.argv[2])
    if not counter.exists():
        counter.write_text("attempted")
        sys.stderr.write("Offline fixture failed on its first attempt")
        sys.exit(2)
time.sleep(60 if model == "slow" else 4 if model == "b" else 0.2)
title = 'UI fixture A <img src=x onerror="window.fixtureXss=1">' if model == "a" else "UI fixture B"
print(json.dumps({"findings": [{"title": title, "severity": "high" if model == "a" else "low",
    "file": "app.py", "line": 1, "cwe": "CWE-89", "description": "Offline browser test data, not a model audit.",
    "evidence": "query(user_input)", "recommendation": "Use parameters.", "confidence": "low"}]}))
'''


def exercise(browser, base_url, service, root, artifacts, publication):
    page = browser.new_page(viewport={"width": 1440, "height": 1000})
    errors = []
    page.on("pageerror", lambda error: errors.append(str(error)))
    page.goto(base_url, wait_until="networkidle")
    expect(page.get_by_role("heading", name="安全审阅工作台")).to_be_visible()

    def navigate(route):
        page.locator(f'[data-nav="{route}"]').click()
        expect(page.locator(f'[data-nav="{route}"]')).to_have_attribute("aria-current", "page")

    def submit(form):
        page.locator(f"#{form} button[type=submit]").click()

    def saved_dialog():
        expect(page.locator("#modal")).not_to_be_visible()

    navigate("models")
    page.locator('[data-action="add-provider"]').click()
    page.locator("#provider-id").fill("secondary")
    page.locator("#provider-url").fill("https://example.invalid/v1")
    submit("provider-form")
    saved_dialog()
    assert "secondary" in service.bootstrap()["config"]["providers"]
    page.locator('[data-action="credential"][data-name="BROWSER_MODEL_KEY"]').click()
    page.locator("#credential-value").fill("browser-fixture-model-key")
    submit("credential-form")
    saved_dialog()
    assert "browser-fixture-model-key" not in json.dumps(service.bootstrap())
    assert "browser-fixture-model-key" not in service.config_path.read_text()
    with page.expect_download() as config_download:
        page.locator('[data-action="export-config"]').click()
    exported = root / "exported.toml"
    config_download.value.save_as(exported)
    assert "BROWSER_MODEL_KEY" in exported.read_text()
    assert "browser-fixture-model-key" not in exported.read_text()

    page.locator('[data-action="add-model"]').click()
    page.locator("#model-id").fill("slow-run")
    page.locator("#model-name").fill("slow")
    page.locator("#model-provider").select_option("fixture")
    page.locator("#model-agent").select_option("fixture")
    submit("model-form")
    saved_dialog()
    assert len(service.bootstrap()["config"]["models"]) == 4

    navigate("agents")
    page.locator('[data-action="edit-agent"][data-id="fixture"]').click()
    original_command = page.locator("#agent-command").input_value()
    page.locator("#agent-command").fill("invalid JSON")
    submit("agent-form")
    expect(page.locator("#modal-error")).to_be_visible()
    page.locator("#agent-command").fill(original_command)
    submit("agent-form")
    saved_dialog()

    navigate("github")
    page.locator("#github-repository").fill("fixture/repo")
    page.locator("#github-token-env").fill("BROWSER_GITHUB_TOKEN")
    submit("github-form")
    page.locator('[data-action="credential"][data-name="BROWSER_GITHUB_TOKEN"]').click()
    page.locator("#credential-value").fill("browser-fixture-github-token")
    submit("credential-form")
    saved_dialog()

    navigate("scan")
    page.locator("#scan-target").fill(str(root / "repo"))
    page.locator('input[name="models"][value="slow-run"]').uncheck()
    page.locator('input[name="models"][value="reviewer-flaky"]').uncheck()
    page.locator("#scan-concurrency").fill("2")
    submit("scan-form")
    page.wait_for_url("**/#job/*")
    expect(page.locator("#job-runs .run-card")).to_have_count(2)
    expect(page.locator("#findings-count")).to_have_text("1", timeout=10000)
    expect(page.locator(".checkpoint-notice")).to_be_visible()
    expect(page.locator('[data-action="preview-issues"]')).to_be_disabled()
    with page.expect_download() as checkpoint_download:
        page.locator('[data-action="download-json"]').click()
    checkpoint_file = root / "checkpoint-download.json"
    checkpoint_download.value.save_as(checkpoint_file)
    checkpoint = json.loads(checkpoint_file.read_text())
    assert checkpoint["checkpoint"] is True and checkpoint["status"] == "partial"
    expect(page.locator("#findings-count")).to_have_text("2", timeout=15000)
    completed_id = page.url.rsplit("/", 1)[1]
    job = service.get_job(completed_id)
    assert job["status"] == "completed" and len(job["report"]["findings"]) == 2
    expect(page.locator("#job-runs .audit-guidance")).to_have_count(2)
    for index, run in enumerate(job["runs"]):
        guidance_link = page.locator("#job-runs .audit-guidance a").nth(index)
        expect(guidance_link).to_have_attribute("href", "https://github.com/cloudflare/security-audit-skill/commit/" + run["audit_guidance"]["commit"])
        expect(guidance_link).to_contain_text("Cloudflare Security Audit · 只读指导")
    assert len(job["finding_groups"]) == 1 and job["finding_groups"][0]["record_count"] == 2
    expect(page.locator(".finding-group")).to_have_count(1)
    page.locator("#group-related").uncheck()
    expect(page.locator(".finding-group")).to_have_count(0)
    page.locator("#group-related").check()
    assert page.evaluate("() => window.fixtureXss || null") is None
    expect(page.locator("#findings-list img")).to_have_count(0)

    page.locator("#finding-severity").select_option("high")
    expect(page.locator("#findings-list")).not_to_contain_text("UI fixture B")
    page.locator("#finding-severity").select_option("")
    page.locator("#finding-text").fill("no-matching-file")
    expect(page.locator("#findings-list")).not_to_contain_text("UI fixture B")
    page.locator("#finding-text").fill("")
    page.locator("#finding-model").select_option("reviewer-b")
    expect(page.locator("#findings-list")).not_to_contain_text("UI fixture A")
    page.locator("#finding-model").select_option("")

    for kind, suffix in (("json", "json"), ("markdown", "md")):
        with page.expect_download() as download:
            page.locator(f'[data-action="download-{kind}"]').click()
        destination = root / f"download.{suffix}"
        download.value.save_as(destination)
        assert "Offline browser test data" in destination.read_text()

    page.locator("#select-visible").check()
    page.locator('[data-action="preview-issues"]').click()
    expect(page.locator("#publish-form")).to_be_visible()
    assert not publication.called
    page.locator("#publish-confirmation").fill("wrong/repo")
    submit("publish-form")
    expect(page.locator("#modal-error")).to_be_visible()
    assert not publication.called
    page.locator("#publish-confirmation").fill("fixture/repo")
    submit("publish-form")
    expect(page.get_by_role("heading", name="GitHub 提交结果")).to_be_visible()
    publication.assert_called_once()
    assert len(publication.call_args.args[0]["findings"]) == 2
    page.locator('[data-action="close-modal"]').last.click()

    page.reload(wait_until="networkidle")
    expect(page.locator("#findings-count")).to_have_text("2")
    if artifacts:
        page.screenshot(path=str(artifacts / "report-desktop.png"), full_page=True)

    navigate("overview")
    page.locator("#import-report-file").set_input_files(root / "download.json")
    page.wait_for_url("**/#job/*")
    expect(page.locator(".imported-tag")).to_be_visible()
    expect(page.locator("#findings-count")).to_have_text("2")
    imported = service.get_job(page.url.rsplit("/", 1)[1])
    assert imported["origin"] == "imported"
    assert imported["report"]["findings"] == job["report"]["findings"]
    expect(page.locator("#job-runs .audit-guidance")).to_have_count(2)
    expect(page.locator('[data-action="retry-failed"], [data-action="retry-all"]')).to_have_count(0)
    publication.assert_called_once()

    navigate("scan")
    page.locator("#scan-target").fill(str(root / "repo"))
    for model_id in ("reviewer-a", "reviewer-b", "slow-run"):
        page.locator(f'input[name="models"][value="{model_id}"]').uncheck()
    submit("scan-form")
    page.wait_for_url("**/#job/*")
    expect(page.locator("#job-heading")).to_contain_text("失败", timeout=10000)
    failed_id = page.url.rsplit("/", 1)[1]
    page.locator('[data-action="retry-failed"]').click()
    page.wait_for_url(lambda url: "/#job/" in url and url.rsplit("/", 1)[1] != failed_id)
    expect(page.locator("#findings-count")).to_have_text("1", timeout=10000)
    retried = service.get_job(page.url.rsplit("/", 1)[1])
    assert retried["parent_job_id"] == failed_id and retried["retry_mode"] == "failed"
    assert retried["status"] == "completed"
    assert service.get_job(failed_id)["status"] == "failed"

    page.set_viewport_size({"width": 390, "height": 844})
    for route in ("overview", "models", "agents", "github", "scan"):
        navigate(route)
        expect(page.locator("#view h1")).to_be_visible()
        size = page.evaluate("() => [innerWidth, document.documentElement.scrollWidth]")
        if size[1] > size[0] and artifacts:
            page.screenshot(path=str(artifacts / f"overflow-{route}.png"), full_page=True)
        assert size[1] <= size[0], (route, size)
    if artifacts:
        page.screenshot(path=str(artifacts / "scan-mobile.png"), full_page=True)

    page.set_viewport_size({"width": 1440, "height": 1000})
    navigate("scan")
    page.locator("#scan-target").fill(str(root / "repo"))
    page.locator('input[name="models"][value="reviewer-a"]').uncheck()
    page.locator('input[name="models"][value="reviewer-b"]').uncheck()
    page.locator('input[name="models"][value="reviewer-flaky"]').uncheck()
    submit("scan-form")
    page.wait_for_url("**/#job/*")
    expect(page.locator("#job-runs")).to_contain_text("运行中", timeout=10000)
    page.locator('[data-action="cancel-job"]').click()
    expect(page.locator("#job-heading")).to_contain_text("已取消", timeout=10000)
    assert service.get_job(page.url.rsplit("/", 1)[1])["status"] == "cancelled"
    assert not errors, errors
    assert page.evaluate("() => localStorage.length") == 0
    page.close()
    return completed_id


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--browser-binary", default=shutil.which("chromium"))
    parser.add_argument("--artifacts", type=Path)
    args = parser.parse_args()
    if args.artifacts:
        args.artifacts.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="autoreviewer-browser-") as temporary:
        root = Path(temporary)
        (root / "repo").mkdir()
        (root / "repo" / "app.py").write_text("query(user_input)\n")
        script = root / "fixture.py"
        script.write_text(FIXTURE)
        service = WebService(root / "config.toml", root / "history")
        service.save_config({"version": 1,
            "providers": {"fixture": {"base_url": "https://example.invalid/v1", "api_key_env": "BROWSER_MODEL_KEY"}},
            "agents": {"fixture": {"command": [sys.executable, str(script), "{model}", str(root / "attempt-counter")]}},
            "models": [{"id": "reviewer-" + model, "model": model, "provider": "fixture", "agent": "fixture"} for model in ("a", "b", "flaky")],
            "scan": {"concurrency": 2, "timeout_seconds": 120}})
        server = LocalWebServer(("127.0.0.1", 0), service)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with patch("autoreviewer.webservice.publish_to_github", return_value=[{"status": "created", "url": "https://github.com/fixture/repo/issues/1"}]) as publication:
                with sync_playwright() as p:
                    browser = p.chromium.launch(executable_path=args.browser_binary, headless=True)
                    try:
                        completed_id = exercise(browser, f"http://127.0.0.1:{server.server_port}", service, root, args.artifacts, publication)
                    finally:
                        browser.close()
            service.close()
            reloaded = WebService(root / "config.toml", root / "history")
            try:
                assert len(reloaded.list_jobs()) == 5
                assert all(not item["configured"] for item in reloaded.bootstrap()["credentials"])
                assert len(reloaded.get_report(next(job["id"] for job in reloaded.list_jobs() if job["id"] == completed_id))["findings"]) == 2
            finally:
                reloaded.close()
        finally:
            server.shutdown()
            server.server_close()
            thread.join()
            service.close()
    print("Browser checks passed: configuration export, credentials, live checkpoints, finding groups, filters, downloads, report import, isolated retries, explicit mocked publication, cancellation, restart, XSS escaping and mobile layouts.")


if __name__ == "__main__":
    main()
