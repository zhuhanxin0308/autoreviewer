"""Optional browser regressions from independent user-experience reviews.

Uses the real loopback server and offline fixture CLI processes. No model API,
GitHub publication, or user credentials are used. Run after installing the
browser-tests extra and Chromium, for example:
    python tests/browser_regressions.py --browser-binary /usr/bin/chromium
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

from autoreviewer.findings import finding_fingerprint, merge_findings
from autoreviewer.web import LocalWebServer
from autoreviewer.webservice import WebService


FIXTURE = r'''
import json, sys, time
from pathlib import Path
model = sys.argv[1]
if model == "slow":
    release = Path(sys.argv[2])
    deadline = time.monotonic() + 25
    while not release.exists() and time.monotonic() < deadline:
        time.sleep(0.02)
print(json.dumps({"findings": [{"title": "Fixture finding", "severity": "high",
    "file": "app.py", "line": 1, "cwe": "CWE-89", "description": "Offline fixture only.",
    "evidence": "Fixture evidence from " + model, "recommendation": "Use parameters.",
    "confidence": "low"}]}))
'''


def finding(model: str, *, index: int = 0) -> dict:
    item = {
        "title": f"Fixture finding {index}", "severity": "high" if model == "alpha" else "medium",
        "file": "app.py", "line": index + 1, "cwe": "CWE-89",
        "description": f"Description supplied by {model}.",
        "evidence": f"Distinct evidence supplied by {model}.",
        "recommendation": f"Recommendation supplied by {model}.",
        "confidence": "medium", "models": [model], "verification": "unverified",
    }
    item["fingerprint"] = finding_fingerprint(item)
    return item


def saved_report(*, large: bool = False) -> dict:
    groups = {
        model: [finding(model, index=index) for index in range(offset, offset + 334)]
        for model, offset in (("alpha", 0), ("beta", 334), ("gamma", 668))
    } if large else {model: [finding(model)] for model in ("alpha", "beta")}
    return {
        "schema_version": 1, "autoreviewer_version": "0.1.0", "target": "/offline/imported-fixture",
        "ref": None, "started_at": "2026-10-22T09:00:00+00:00",
        "finished_at": "2026-10-22T09:00:05+00:00", "status": "completed", "scope": None,
        "runs": [{"model": model, "model_name": model, "provider": "fixture", "agent": "fixture",
                  "status": "completed", "duration_seconds": 1, "error": None, "findings": items}
                 for model, items in groups.items()],
        "findings": merge_findings(list(groups.values())),
    }


def navigate(page, route: str) -> None:
    page.locator(f'[data-nav="{route}"]').click()
    expect(page.locator(f'[data-nav="{route}"]')).to_have_attribute("aria-current", "page")


def assert_helper_contrast(page, selector: str) -> None:
    ratios = page.locator(selector).evaluate_all(r"""elements => {
      const channels = value => (value.match(/[\d.]+/g) || []).map(Number);
      const luminance = rgb => rgb.slice(0, 3).map(value => {
        value /= 255; return value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4;
      }).reduce((sum, value, index) => sum + value * [0.2126, 0.7152, 0.0722][index], 0);
      return elements.filter(element => element.getClientRects().length).map(element => {
        const foreground = channels(getComputedStyle(element).color);
        const layers = [];
        for (let current = element; current; current = current.parentElement) {
          layers.push(channels(getComputedStyle(current).backgroundColor));
        }
        let background = [255, 255, 255];
        for (const layer of layers.reverse()) {
          const alpha = layer.length > 3 ? layer[3] : 1;
          background = background.map((value, index) => layer[index] * alpha + value * (1 - alpha));
        }
        const a = luminance(foreground), b = luminance(background);
        return {text: element.textContent.trim().slice(0, 80), ratio: (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05)};
      });
    }""")
    assert ratios, f"No visible helper text matched {selector}"
    assert all(item["ratio"] >= 4.5 for item in ratios), ratios


def exercise(browser, base_url: str, service: WebService, root: Path, artifacts: Path | None) -> None:
    page = browser.new_page(viewport={"width": 1440, "height": 1000})
    other = browser.new_page(viewport={"width": 1440, "height": 1000})
    errors = []
    for current in (page, other):
        current.on("pageerror", lambda error: errors.append(str(error)))
        current.goto(base_url, wait_until="networkidle")
        navigate(current, "models")

    # Two tabs edit the same revision: a stale save must never overwrite the first.
    opener = '[data-action="edit-provider"][data-id="fixture"]'
    for current, suffix in ((page, "first"), (other, "second")):
        current.locator(opener).click()
        current.locator("#provider-url").fill(f"https://example.invalid/{suffix}/v1")
        expect(current.locator("#provider-url")).to_have_value(f"https://example.invalid/{suffix}/v1")
    expect(page.locator("#provider-url")).to_have_value("https://example.invalid/first/v1")
    page.locator("#provider-form button[type=submit]").click()
    expect(page.locator("#modal")).not_to_be_visible()
    expect(page.locator(opener)).to_be_focused()
    with other.expect_response(lambda response: response.url.endswith("/api/config") and response.request.method == "PUT") as conflict:
        other.locator("#provider-form button[type=submit]").click()
    assert conflict.value.status == 409
    expect(other.locator("#modal-error")).to_be_visible()
    expect(other.locator("#provider-url")).to_have_value("https://example.invalid/second/v1")
    stored_url = service.bootstrap()["config"]["providers"]["fixture"]["base_url"]
    assert stored_url == "https://example.invalid/first/v1", stored_url
    if artifacts:
        other.screenshot(path=str(artifacts / "configuration-conflict.png"), full_page=True)
    other.close()

    # Saving an inline form must not close a different dialog opened while it waited.
    navigate(page, "github")
    page.locator("#github-labels").fill("security")
    save_entered, save_release = threading.Event(), threading.Event()
    original_save = service.save_config
    def delayed_save(*args, **kwargs):
        save_entered.set()
        if not save_release.wait(timeout=5):
            raise AssertionError("The browser did not release the pending configuration save")
        return original_save(*args, **kwargs)
    try:
        with patch.object(service, "save_config", side_effect=delayed_save):
            with page.expect_response(lambda response: response.url.endswith("/api/config") and response.request.method == "PUT") as saved:
                page.locator("#github-form button[type=submit]").click()
                assert save_entered.wait(timeout=3)
                page.locator('[data-action="credential"][data-name="REGRESSION_GITHUB_TOKEN"]').click()
                page.locator("#credential-value").fill("offline-unsaved-token-draft")
                save_release.set()
            assert saved.value.status == 200
            expect(page.locator("#github-form button[type=submit]")).to_be_enabled()
            expect(page.locator("#credential-form")).to_be_visible()
            expect(page.locator("#credential-value")).to_have_value("offline-unsaved-token-draft")
    finally:
        save_release.set()
    page.locator('[data-action="close-modal"]').first.click()

    # Keyboard skip navigation retains the draft and focuses the actual main region.
    navigate(page, "scan")
    draft_target = str(root / "draft-target")
    page.locator("#scan-target").fill(draft_target)
    page.locator("#scan-concurrency").fill("7")
    page.locator('input[name="models"][value="beta"]').uncheck()
    page.locator(".skip-link").focus()
    page.locator(".skip-link").press("Enter")
    expect(page).to_have_url(base_url + "/#scan")
    expect(page.locator("#main-content")).to_be_focused()
    expect(page.locator("#scan-target")).to_have_value(draft_target)
    expect(page.locator("#scan-concurrency")).to_have_value("7")
    expect(page.locator('input[name="models"][value="beta"]')).not_to_be_checked()
    assert_helper_contrast(page, ".field-help")

    # A real CLI waits on a local file, so the scan remains active until released.
    page.locator("#scan-target").fill(str(root / "repo"))
    for model in ("alpha", "beta"):
        page.locator(f'input[name="models"][value="{model}"]').uncheck()
    page.locator("#scan-form button[type=submit]").click()
    page.wait_for_url("**/#job/*")
    active_id = page.url.rsplit("/", 1)[1]
    expect(page.locator("#job-runs")).to_contain_text("运行中", timeout=10000)
    navigate(page, "scan")
    expect(page.locator("#scan-form button[type=submit]")).to_be_disabled()
    page.locator("#scan-target").fill(draft_target)
    page.locator("#scan-concurrency").fill("7")
    page.locator('input[name="models"][value="beta"]').uncheck()
    (root / "release-model").write_text("finish")
    expect(page.locator("#scan-form button[type=submit]")).to_be_enabled(timeout=12000)
    expect(page.get_by_role("heading", name="已有扫描正在运行")).to_have_count(0)
    expect(page.locator("#scan-target")).to_have_value(draft_target)
    expect(page.locator("#scan-concurrency")).to_have_value("7")
    expect(page.locator('input[name="models"][value="beta"]')).not_to_be_checked()
    assert service.get_job(active_id)["status"] == "completed"

    # A pending create response must not undo a newer navigation choice.
    page.locator('#notifications button[aria-label="关闭通知"]').evaluate_all("buttons => buttons.forEach(button => button.click())")
    page.locator("#scan-target").fill(str(root / "repo"))
    page.locator('input[name="models"][value="slow"]').uncheck()
    entered, release = threading.Event(), threading.Event()
    original_start = service.start_job
    def delayed_start(payload):
        entered.set()
        if not release.wait(timeout=5):
            raise AssertionError("The browser did not release the pending create request")
        return original_start(payload)
    try:
        with patch.object(service, "start_job", side_effect=delayed_start):
            with page.expect_response(lambda response: response.url.endswith("/api/jobs") and response.request.method == "POST") as created:
                page.locator("#scan-form button[type=submit]").click()
                assert entered.wait(timeout=3)
                navigate(page, "models")
                release.set()
            assert created.value.status == 202
            expect(page.locator("#notifications .toast")).to_have_count(1)
            expect(page).to_have_url(base_url + "/#models")
            expect(page.locator("#view h1")).to_have_text("模型与平台")
    finally:
        release.set()

    # An exact-match aggregate must expose both model observations, then filter accurately.
    report_path = root / "observations.json"
    report_path.write_text(json.dumps(saved_report()))
    navigate(page, "overview")
    page.locator("#import-report-file").set_input_files(report_path)
    page.wait_for_url("**/#job/*")
    expect(page.locator("#findings-count")).to_have_text("1")
    page.locator(".finding-details summary").click()
    expect(page.locator(".model-observation")).to_have_count(2)
    expect(page.locator("#findings-list")).to_contain_text("Distinct evidence supplied by alpha.")
    expect(page.locator("#findings-list")).to_contain_text("Distinct evidence supplied by beta.")
    page.locator("#finding-model").select_option("beta")
    expect(page.locator(".model-observation")).to_have_count(1)
    expect(page.locator("#findings-list")).to_contain_text("Distinct evidence supplied by beta.")
    expect(page.locator("#findings-list")).not_to_contain_text("Distinct evidence supplied by alpha.")
    assert_helper_contrast(page, ".finding-meta")
    if artifacts:
        page.screenshot(path=str(artifacts / "filtered-observation.png"), full_page=True)

    # Large valid reports can be reviewed, but issue preview explains its batch limit.
    large_path = root / "large-report.json"
    large_path.write_text(json.dumps(saved_report(large=True)))
    navigate(page, "overview")
    page.locator("#import-report-file").set_input_files(large_path)
    page.wait_for_url("**/#job/*")
    expect(page.locator("#findings-count")).to_have_text("1002", timeout=15000)
    page.locator("#select-visible").check()
    expect(page.locator('[data-action="preview-issues"]')).to_be_disabled()
    expect(page.locator("#findings-controls")).to_contain_text("1000")
    page.locator("#finding-model").select_option("alpha")
    page.locator("#select-visible").uncheck()
    expect(page.locator('[data-action="preview-issues"]')).to_be_enabled()
    assert not errors, errors
    page.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--browser-binary", default=shutil.which("chromium"))
    parser.add_argument("--artifacts", type=Path)
    args = parser.parse_args()
    if args.artifacts:
        args.artifacts.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="autoreviewer-browser-regressions-") as temporary:
        root = Path(temporary)
        (root / "repo").mkdir()
        (root / "repo" / "app.py").write_text("query(user_input)\n")
        (root / "fixture.py").write_text(FIXTURE)
        service = WebService(root / "config.toml", root / "history")
        service.save_config({"version": 1,
            "providers": {"fixture": {"base_url": "https://example.invalid/v1"}},
            "agents": {"fixture": {"command": [sys.executable, str(root / "fixture.py"), "{model}", str(root / "release-model")]}},
            "models": [{"id": model, "model": model, "provider": "fixture", "agent": "fixture"} for model in ("alpha", "beta", "slow")],
            "scan": {"concurrency": 2, "timeout_seconds": 30},
            "github": {"repository": "fixture/repo", "token_env": "REGRESSION_GITHUB_TOKEN"}})
        server = LocalWebServer(("127.0.0.1", 0), service)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(executable_path=args.browser_binary, headless=True)
                try:
                    exercise(browser, f"http://127.0.0.1:{server.server_port}", service, root, args.artifacts)
                finally:
                    browser.close()
        finally:
            server.shutdown()
            server.server_close()
            thread.join()
            service.close()
    print("Experience regressions passed: conflicting tabs, pending saves, keyboard skip/focus, contrast, live scan availability, navigation races, model observations and issue batch limits.")


if __name__ == "__main__":
    main()
