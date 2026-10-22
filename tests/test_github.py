from __future__ import annotations

import copy
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch
from urllib.error import HTTPError, URLError
from urllib.request import Request

from autoreviewer.findings import finding_fingerprint, merge_findings
from autoreviewer.github import MAX_ISSUE_BODY_CHARS, GitHubError, _Client, _NoRedirect, plan_issues, publish_issues


def report():
    finding = {
        "title": "Untrusted query reaches SQL execution",
        "severity": "high",
        "file": "app/service.py",
        "line": 14,
        "cwe": "CWE-89",
        "description": "A request parameter is concatenated into a SQL statement.",
        "evidence": "The query includes request.args['name'] without parameter binding.",
        "recommendation": "Use parameterized queries.",
        "confidence": "medium",
        "models": ["provider/model-a", "other/model-b"],
        "verification": "unverified",
    }
    finding["fingerprint"] = finding_fingerprint(finding)
    return {"schema_version": 1, "target": "/tmp/example", "status": "completed", "runs": [], "findings": [finding]}


def config(**kwargs):
    return SimpleNamespace(repository=kwargs.get("repository", "owner/example"), token_env="AR_TEST_GITHUB_TOKEN", labels=kwargs.get("labels", ()))


class PlanningTests(unittest.TestCase):
    @staticmethod
    def multi_observation_report():
        data = report()
        first = {**data["findings"][0], "models": ["provider/model-a"], "severity": "low", "confidence": "low",
                 "description": "First description", "evidence": "First evidence", "recommendation": "First remedy"}
        second = {**first, "models": ["other/model-b"], "severity": "critical", "confidence": "high",
                  "description": "Second description", "evidence": "Second evidence", "recommendation": "Second remedy"}
        data["findings"] = merge_findings([[first], [second]])
        return data

    def test_planning_requires_no_token_or_network(self):
        with patch.dict(os.environ, {}, clear=True), patch("autoreviewer.github.build_opener") as opener:
            draft = plan_issues(report())[0]
        opener.assert_not_called()
        self.assertIn("Unverified AI security finding", draft["body"])
        self.assertIn("provider/model-a", draft["body"])
        self.assertIn("app/service.py:14", draft["body"])
        self.assertTrue(draft["body"].endswith(f"<!-- autoreviewer:{draft['fingerprint']} -->"))

    def test_partial_reports_need_explicit_opt_in(self):
        data = report()
        data["status"] = "partial"
        with self.assertRaisesRegex(GitHubError, "allow-partial"):
            plan_issues(data)
        self.assertIn("report is partial", plan_issues(data, allow_partial=True)[0]["body"])
        data["status"] = "failed"
        with self.assertRaises(GitHubError):
            plan_issues(data, allow_partial=True)

    def test_corrupted_or_unsafe_report_is_rejected(self):
        for key, value in (("file", "../private.key"), ("file", "C:/private.key"), ("line", True), ("line", 0), ("severity", "urgent"), ("severity", []), ("confidence", "verified"), ("confidence", {}), ("models", []), ("fingerprint", "a" * 64)):
            with self.subTest(key=key, value=value):
                data = report()
                data["findings"][0][key] = value
                with self.assertRaises(GitHubError):
                    plan_issues(data)

    def test_duplicate_fingerprints_only_make_one_draft(self):
        data = report()
        data["findings"].append(copy.deepcopy(data["findings"][0]))
        self.assertEqual(len(plan_issues(data)), 1)

    def test_title_is_single_line_and_bounded(self):
        data = report()
        item = data["findings"][0]
        item["title"] = "A\n" + "x" * 400
        item["fingerprint"] = finding_fingerprint(item)
        title = plan_issues(data)[0]["title"]
        self.assertNotIn("\n", title)
        self.assertLessEqual(len(title), 256)

    def test_each_model_observation_is_included_in_issue_preview(self):
        data = self.multi_observation_report()
        original = copy.deepcopy(data)
        with patch("autoreviewer.github.build_opener") as opener:
            draft = plan_issues(data)[0]
        opener.assert_not_called()
        for model in ("First", "Second"):
            for field in ("description", "evidence", "remedy"):
                self.assertEqual(draft["body"].count(f"{model} {field}"), 1)
        self.assertIn("- Models: provider/model\\-a", draft["body"])
        self.assertIn("- Models: other/model\\-b", draft["body"])
        self.assertIn("- Severity: **low**", draft["body"])
        self.assertIn("- Severity: **critical**", draft["body"])
        self.assertIn("- Model confidence: low", draft["body"])
        self.assertIn("- Model confidence: high", draft["body"])
        self.assertIn("highest reported severity", draft["body"])
        self.assertIn("All observations remain unverified", draft["body"])
        self.assertTrue(draft["body"].endswith(f"<!-- autoreviewer:{draft['fingerprint']} -->"))
        self.assertEqual(data, original)

    def test_malformed_model_observations_fail_before_network(self):
        cases = [None, {}, [], [None]]
        valid = self.multi_observation_report()["findings"][0]["observations"]
        for field, value in (("models", ["unrelated-model"]), ("models", [{}]),
                             ("severity", []), ("confidence", "verified"), ("evidence", None)):
            altered = copy.deepcopy(valid)
            altered[1][field] = value
            cases.append(altered)
        for observations in cases:
            with self.subTest(observations=observations), patch("autoreviewer.github.build_opener") as opener:
                data = self.multi_observation_report()
                data["findings"][0]["observations"] = observations
                with self.assertRaises(GitHubError):
                    plan_issues(data)
                opener.assert_not_called()

    def test_issue_body_limit_counts_characters_without_silently_dropping_observations(self):
        data = self.multi_observation_report()
        observations = data["findings"][0]["observations"]
        for observation in observations:
            for field in ("description", "evidence", "recommendation"):
                observation[field] = "文" * 10000
        body = plan_issues(data)[0]["body"]
        self.assertGreater(len(body.encode("utf-8")), MAX_ISSUE_BODY_CHARS)
        remaining = MAX_ISSUE_BODY_CHARS - len(body)
        self.assertGreater(remaining, 0)
        observations[1]["evidence"] += "文" * remaining
        self.assertEqual(len(plan_issues(data)[0]["body"]), MAX_ISSUE_BODY_CHARS)
        observations[1]["evidence"] += "文"
        with patch("autoreviewer.github.build_opener") as opener:
            with self.assertRaisesRegex(GitHubError, "65,536-character.*Download.*no evidence was truncated"):
                plan_issues(data)
        opener.assert_not_called()

    def test_selected_finding_subset_does_not_require_whole_report_validation(self):
        # The UI previews an explicitly selected subset; its runs may still
        # contain findings that are absent from this preview's aggregate list.
        data = self.multi_observation_report()
        data["runs"] = [{"findings": [{"title": "An unselected record"}]}]
        self.assertEqual(len(plan_issues(data)), 1)


class PublishingTests(unittest.TestCase):
    def setUp(self):
        self.env_patch = patch.dict(os.environ, {"AR_TEST_GITHUB_TOKEN": "github-test-token"})
        self.env_patch.start()
        self.addCleanup(self.env_patch.stop)

    @patch("autoreviewer.github._Client.request")
    def test_publish_has_metadata_preflight_and_labels(self, request):
        request.side_effect = [{"has_issues": True, "archived": False}, [], {"number": 25}]
        result = publish_issues(report(), config(labels=("security",)))
        self.assertEqual(result[0]["status"], "created")
        self.assertEqual(result[0]["url"], "https://github.com/owner/example/issues/25")
        self.assertEqual(request.call_args_list[0].args, ("GET", "/repos/owner/example"))
        self.assertEqual(request.call_args_list[-1].args[0], "POST")
        self.assertEqual(request.call_args_list[-1].args[2]["labels"], ["security"])

    @patch("autoreviewer.github._Client")
    def test_explicit_token_is_local_to_publication(self, client):
        client.return_value.request.side_effect = [{"has_issues": True}, [], {"number": 26}]
        result = publish_issues(report(), config(), token="ui-memory-github-token")
        client.assert_called_once_with("ui-memory-github-token")
        self.assertEqual(os.environ["AR_TEST_GITHUB_TOKEN"], "github-test-token")
        self.assertEqual(result[0]["status"], "created")

    @patch("autoreviewer.github._Client")
    def test_explicit_empty_token_does_not_use_environment(self, client):
        with self.assertRaisesRegex(GitHubError, "valid GitHub token"):
            publish_issues(report(), config(), token="")
        client.assert_not_called()

    @patch("autoreviewer.github._Client.request")
    def test_existing_closed_issue_is_not_reopened_or_duplicated(self, request):
        data = report()
        marker = f"<!-- autoreviewer:{data['findings'][0]['fingerprint']} -->"
        request.side_effect = [{"has_issues": True}, [{"number": 7, "state": "closed", "body": marker}]]
        result = publish_issues(data, config())
        self.assertEqual(result[0]["status"], "existing")
        self.assertEqual(result[0]["url"], "https://github.com/owner/example/issues/7")
        self.assertTrue(all(call.args[0] == "GET" for call in request.call_args_list))
        self.assertIn("state=all", request.call_args_list[1].args[1])

    def test_sequential_publications_revalidate_cached_issue_lists(self):
        class CachingGitHub:
            def __init__(self):
                self.issues = []
                self.cached_lists = {}
                self.returned_states = []
                self.posts = []

            def open(self, request, timeout):
                method = request.get_method()
                url = request.full_url
                if method == "GET" and url.endswith("/repos/owner/example"):
                    payload = {"has_issues": True, "archived": False}
                elif method == "GET" and "/repos/owner/example/issues?" in url:
                    revalidate = "no-cache" in request.get_header("Cache-control", "")
                    if revalidate or url not in self.cached_lists:
                        self.cached_lists[url] = copy.deepcopy(self.issues)
                    payload = copy.deepcopy(self.cached_lists[url])
                    self.returned_states.append([issue["state"] for issue in payload])
                elif method == "POST" and url.endswith("/repos/owner/example/issues"):
                    self.posts.append(request)
                    payload = {**json.loads(request.data), "number": len(self.issues) + 1, "state": "open"}
                    self.issues.append(copy.deepcopy(payload))
                else:
                    raise AssertionError(f"Unexpected request: {method} {url}")
                return io.BytesIO(json.dumps(payload).encode("utf-8"))

        remote = CachingGitHub()
        with patch("autoreviewer.github.build_opener", return_value=remote):
            first = publish_issues(report(), config())
            second = publish_issues(report(), config())
            remote.issues[0]["state"] = "closed"
            after_close = publish_issues(report(), config())

        self.assertEqual(first[0]["status"], "created")
        self.assertEqual(second[0]["status"], "existing")
        self.assertEqual(after_close[0]["status"], "existing")
        self.assertEqual(first[0]["url"], second[0]["url"])
        self.assertEqual(first[0]["url"], after_close[0]["url"])
        self.assertEqual(remote.returned_states, [[], ["open"], ["closed"]])
        self.assertEqual(len(remote.posts), 1)
        self.assertEqual(remote.issues[0]["state"], "closed")
        self.assertIsNone(remote.posts[0].get_header("Cache-control"))
        self.assertIsNone(remote.posts[0].get_header("Pragma"))

    def test_receipts_survive_stale_lists_and_reloaded_closed_issue(self):
        class StaleListingGitHub:
            def __init__(self):
                self.issue = None
                self.posts = 0
                self.list_calls = 0
                self.verified_states = []

            def open(self, request, timeout):
                method, url = request.get_method(), request.full_url
                if method == "GET" and url.endswith("/repos/owner/example"):
                    payload = {"has_issues": True, "archived": False}
                elif method == "GET" and "/repos/owner/example/issues?" in url:
                    self.list_calls += 1
                    payload = []  # Deliberately stale, even with no-cache headers.
                elif method == "GET" and url.endswith("/repos/owner/example/issues/1"):
                    payload = copy.deepcopy(self.issue)
                    self.verified_states.append(payload["state"])
                elif method == "POST" and url.endswith("/repos/owner/example/issues"):
                    self.posts += 1
                    self.issue = {**json.loads(request.data), "number": self.posts, "state": "open"}
                    payload = self.issue
                else:
                    raise AssertionError(f"Unexpected request: {method} {url}")
                return io.BytesIO(json.dumps(payload).encode("utf-8"))

        remote = StaleListingGitHub()
        with tempfile.TemporaryDirectory() as folder, patch("autoreviewer.github.build_opener", return_value=remote):
            path = Path(folder) / "receipts.json"
            first = publish_issues(report(), config(), receipt_path=path)
            receipts = json.loads(path.read_text())
            self.assertEqual(receipts, {"schema_version": 1, "repositories": {
                "owner/example": {report()["findings"][0]["fingerprint"]: 1}}})
            if os.name != "nt":
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            second = publish_issues(report(), config(), receipt_path=Path(str(path)))
            remote.issue["state"] = "closed"
            after_close = publish_issues(report(), config(), receipt_path=Path(str(path)))
        self.assertEqual([first[0]["status"], second[0]["status"], after_close[0]["status"]],
                         ["created", "existing", "existing"])
        self.assertEqual(first[0]["url"], second[0]["url"])
        self.assertEqual(first[0]["url"], after_close[0]["url"])
        self.assertEqual(remote.posts, 1)
        self.assertEqual(remote.list_calls, 1)
        self.assertEqual(remote.verified_states, ["open", "closed"])
        self.assertEqual(remote.issue["state"], "closed")

    @patch("autoreviewer.github._Client.request")
    def test_invalid_receipts_stop_before_network(self, request):
        fingerprint = report()["findings"][0]["fingerprint"]
        invalid = ["{", '{"schema_version":1,"schema_version":1,"repositories":{}}',
                   json.dumps({"schema_version": True, "repositories": {}}),
                   json.dumps({"schema_version": 1, "repositories": {"owner/..": {fingerprint: 1}}}),
                   json.dumps({"schema_version": 1, "repositories": {"owner/example": {fingerprint: True}}}),
                   json.dumps({"schema_version": 1, "repositories": {"owner/example": {"invalid": 1}}})]
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "receipts.json"
            for raw in invalid:
                with self.subTest(raw=raw):
                    path.write_text(raw)
                    with self.assertRaisesRegex(GitHubError, "receipts are unreadable or invalid"):
                        publish_issues(report(), config(), receipt_path=path)
            path.write_text(" " * 101)
            with patch("autoreviewer.github.MAX_RECEIPT_BYTES", 100):
                with self.assertRaisesRegex(GitHubError, "receipts are unreadable or invalid"):
                    publish_issues(report(), config(), receipt_path=path)
            if hasattr(os, "symlink"):
                link = Path(folder) / "link.json"
                link.symlink_to(path)
                with self.assertRaisesRegex(GitHubError, "receipts are unreadable or invalid"):
                    publish_issues(report(), config(), receipt_path=link)
        request.assert_not_called()

    @patch("autoreviewer.github._Client.request")
    def test_receipt_mismatch_or_missing_issue_never_posts(self, request):
        fingerprint = report()["findings"][0]["fingerprint"]
        marker = f"<!-- autoreviewer:{fingerprint} -->"
        cases = [{"number": 7, "body": "changed"}, {"number": 8, "body": marker},
                 {"number": 7, "body": marker, "pull_request": {}},
                 GitHubError("GitHub repository is unavailable (HTTP 404)")]
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "receipts.json"
            path.write_text(json.dumps({"schema_version": 1, "repositories": {"owner/example": {fingerprint: 7}}}))
            for response in cases:
                with self.subTest(response=response):
                    request.reset_mock()
                    request.side_effect = [{"has_issues": True}, response]
                    with self.assertRaisesRegex(GitHubError, "Saved GitHub issue #7"):
                        publish_issues(report(), config(repository="Owner/Example"), receipt_path=path)
                    self.assertTrue(all(call.args[0] == "GET" for call in request.call_args_list))
                    self.assertEqual(request.call_args_list[-1].args[1], "/repos/Owner/Example/issues/7")

    @patch("autoreviewer.github._Client.request")
    def test_existing_listing_is_saved_for_later_direct_verification(self, request):
        fingerprint = report()["findings"][0]["fingerprint"]
        issue = {"number": 7, "body": f"<!-- autoreviewer:{fingerprint} -->", "state": "closed"}
        request.side_effect = [{"has_issues": True}, [issue], {"has_issues": True}, issue]
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "receipts.json"
            for _ in range(2):
                result = publish_issues(report(), config(), receipt_path=path)
                self.assertEqual(result[0]["status"], "existing")
            self.assertEqual(json.loads(path.read_text())["repositories"]["owner/example"][fingerprint], 7)
        self.assertTrue(all(call.args[0] == "GET" for call in request.call_args_list))
        self.assertEqual(request.call_args_list[-1].args[1], "/repos/owner/example/issues/7")

    @patch("autoreviewer.github._Client.request")
    def test_receipt_storage_failure_stops_before_post(self, request):
        with tempfile.TemporaryDirectory() as folder, patch("autoreviewer.github.os.replace", side_effect=OSError("cannot replace")):
            with self.assertRaisesRegex(GitHubError, "receipts could not be saved"):
                publish_issues(report(), config(), receipt_path=Path(folder) / "receipts.json")
        request.assert_not_called()

    @patch("autoreviewer.github._Client.request")
    def test_each_success_is_saved_before_a_later_post_fails(self, request):
        data = report()
        second = {**data["findings"][0], "file": "app/other.py"}
        second["fingerprint"] = finding_fingerprint(second)
        data["findings"].append(second)
        request.side_effect = [{"has_issues": True}, [], {"number": 7}, GitHubError("Request failed (HTTP 503)")]
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "receipts.json"
            with self.assertRaisesRegex(GitHubError, "HTTP 503"):
                publish_issues(data, config(), receipt_path=path)
            saved = json.loads(path.read_text())["repositories"]["owner/example"]
            self.assertEqual(saved, {data["findings"][0]["fingerprint"]: 7})
        self.assertEqual([call.args[0] for call in request.call_args_list], ["GET", "GET", "POST", "POST"])

    @patch("autoreviewer.github._Client.request")
    def test_save_failure_after_creation_stops_further_posts(self, request):
        data = report()
        second = {**data["findings"][0], "file": "app/other.py"}
        second["fingerprint"] = finding_fingerprint(second)
        data["findings"].append(second)
        request.side_effect = [{"has_issues": True}, [], {"number": 7}]
        replace = os.replace
        saves = 0

        def fail_after_preflight(source, destination):
            nonlocal saves
            saves += 1
            if saves > 1:
                raise OSError("Cannot save after first creation")
            return replace(source, destination)

        with tempfile.TemporaryDirectory() as folder, patch("autoreviewer.github.os.replace", side_effect=fail_after_preflight):
            path = Path(folder) / "receipts.json"
            with self.assertRaisesRegex(GitHubError, "An issue may already have been created"):
                publish_issues(data, config(), receipt_path=path)
            self.assertEqual(json.loads(path.read_text()), {"schema_version": 1, "repositories": {}})
            self.assertEqual(list(Path(folder).iterdir()), [path])
        self.assertEqual([call.args[0] for call in request.call_args_list], ["GET", "GET", "POST"])

    @patch("autoreviewer.github._Client.request")
    def test_all_pages_are_searched_and_pull_requests_ignored(self, request):
        data = report()
        marker = f"<!-- autoreviewer:{data['findings'][0]['fingerprint']} -->"
        first_page = [{"number": 1, "body": marker, "pull_request": {}}] + [{"number": n, "body": None} for n in range(2, 101)]
        request.side_effect = [{"has_issues": True}, first_page, [{"number": 101, "body": marker}]]
        result = publish_issues(data, config())
        self.assertTrue(result[0]["url"].endswith("/101"))
        self.assertIn("page=2", request.call_args_list[2].args[1])
        self.assertEqual(request.call_count, 3)

    @patch("autoreviewer.github.MAX_PAGES", 1)
    @patch("autoreviewer.github._Client.request")
    def test_pagination_limit_fails_before_posting(self, request):
        request.side_effect = [{"has_issues": True}, [{"number": n, "body": None} for n in range(1, 101)]]
        with self.assertRaisesRegex(GitHubError, "lookup limit"):
            publish_issues(report(), config())
        self.assertTrue(all(call.args[0] == "GET" for call in request.call_args_list))

    @patch("autoreviewer.github._Client.request")
    def test_issues_disabled_or_archived_fails_before_post(self, request):
        for metadata in ({"has_issues": False}, {"has_issues": True, "archived": True}):
            with self.subTest(metadata=metadata):
                request.return_value = metadata
                with self.assertRaises(GitHubError):
                    publish_issues(report(), config())
                self.assertTrue(all(call.args[0] == "GET" for call in request.call_args_list))

    @patch("autoreviewer.github._Client.request")
    def test_missing_token_invalid_repository_and_empty_report(self, request):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(GitHubError, "AR_TEST_GITHUB_TOKEN"):
                publish_issues(report(), config())
            empty = report()
            empty["findings"] = []
            self.assertEqual(publish_issues(empty, config()), [])
        for repository in ("owner/repo/../../secrets", "https://github.com/owner/repo", "owner/repo?token=x", "owner/.."):
            with self.subTest(repository=repository):
                with self.assertRaises(GitHubError):
                    publish_issues(report(), config(repository=repository))
        request.assert_not_called()


class TransportTests(unittest.TestCase):
    def test_request_keeps_token_out_of_url_and_sets_timeout(self):
        with patch("autoreviewer.github.build_opener") as factory:
            response = factory.return_value.open.return_value.__enter__.return_value
            response.read.return_value = b'{"number": 3}'
            self.assertEqual(_Client("secret-token").request("GET", "/repos/owner/repo"), {"number": 3})
            request = factory.return_value.open.call_args.args[0]
            self.assertEqual(request.full_url, "https://api.github.com/repos/owner/repo")
            self.assertEqual(request.get_header("Authorization"), "Bearer secret-token")
            self.assertEqual(request.get_header("Cache-control"), "no-cache, no-store")
            self.assertEqual(request.get_header("Pragma"), "no-cache")
            self.assertEqual(factory.return_value.open.call_args.kwargs["timeout"], 30)

    def test_http_errors_do_not_expose_server_body_or_token(self):
        for status in (301, 401, 403, 404, 429, 500):
            with self.subTest(status=status), patch("autoreviewer.github.build_opener") as factory:
                factory.return_value.open.side_effect = HTTPError("https://api.github.com/repos/owner/repo", status, "secret-token", {}, io.BytesIO(b"secret-token"))
                with self.assertRaises(GitHubError) as caught:
                    _Client("secret-token").request("POST", "/repos/owner/repo/issues", {"body": "sensitive code"})
                self.assertIn(str(status), str(caught.exception))
                self.assertNotIn("secret-token", str(caught.exception))
                self.assertEqual(factory.return_value.open.call_count, 1)

    def test_redirect_handler_does_not_forward_authorization(self):
        request = Request("https://api.github.com/repos/owner/repo", headers={"Authorization": "Bearer token"})
        with self.assertRaises(HTTPError):
            _NoRedirect().redirect_request(request, None, 302, "Found", {}, "https://attacker.example/")

    def test_network_errors_are_sanitized(self):
        with patch("autoreviewer.github.build_opener") as factory:
            factory.return_value.open.side_effect = URLError("secret-token")
            with self.assertRaises(GitHubError) as caught:
                _Client("secret-token").request("GET", "/repos/owner/repo")
            self.assertNotIn("secret-token", str(caught.exception))

    def test_invalid_json_and_large_response_are_rejected(self):
        for body, limit in ((b"not JSON", 100), (b"0123456789", 5)):
            with self.subTest(body=body), patch("autoreviewer.github.build_opener") as factory, patch("autoreviewer.github.MAX_RESPONSE_BYTES", limit):
                factory.return_value.open.return_value.__enter__.return_value.read.return_value = body
                with self.assertRaises(GitHubError):
                    _Client("secret-token").request("GET", "/repos/owner/repo")


if __name__ == "__main__":
    unittest.main()
