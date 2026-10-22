import copy
import json
from pathlib import Path
import tempfile
import unittest

from autoreviewer.findings import FindingValidationError, merge_findings, parse_findings
from autoreviewer.reports import render_markdown, write_reports


class FindingTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / "app.py").write_text("def fetch(query):\n    return db.execute(query)\n", encoding="utf-8")
        self.finding = {
            "title": "Untrusted query reaches SQL execution",
            "severity": "high",
            "file": "app.py",
            "line": 2,
            "cwe": "CWE-89",
            "description": "The query appears to flow from user input to the database.",
            "evidence": "return db.execute(query)",
            "recommendation": "Bind parameters and validate the calling path.",
            "confidence": "medium",
        }

    def parse(self, finding=None, model="one/model"):
        return parse_findings(json.dumps({"findings": [finding or self.finding]}), self.root, model)

    def test_plain_and_fenced_json_preserve_provenance(self):
        plain = self.parse()
        fenced = parse_findings("```json\n" + json.dumps({"findings": [self.finding]}) + "\n```", self.root, "one/model")
        self.assertEqual(plain, fenced)
        self.assertEqual(plain[0]["models"], ["one/model"])
        self.assertEqual(plain[0]["verification"], "unverified")
        self.assertEqual(len(plain[0]["fingerprint"]), 64)

    def test_only_valid_empty_results_count_as_empty(self):
        self.assertEqual(parse_findings('{"findings": []}', self.root, "one/model"), [])
        for output in ("", "No vulnerabilities found", "[]", "{}", '{"findings": null}',
                       '{"findings": [], "findings": []}', 'prefix {"findings": []}',
                       '```json\n{"findings": []}\n```\nExtra text'):
            with self.subTest(output=output), self.assertRaises(FindingValidationError):
                parse_findings(output, self.root, "one/model")

    def test_rejects_invalid_fields_and_locations(self):
        for field, values in {
            "file": ["../app.py", "/app.py", "C:\\app.py", "nested/../app.py", "./app.py", "missing.py", "a//app.py"],
            "line": [0, -1, 3, True, "2", 2.0],
            "severity": ["urgent", [], None],
            "confidence": ["certain", {}],
            "title": ["", "x" * 301, "bad\x00title", "bad\ud800title"],
            "evidence": [None, ""],
            "cwe": ["89", "CWE-0", "CWE-89extra", None],
        }.items():
            for value in values:
                with self.subTest(field=field, value=value), self.assertRaises(FindingValidationError):
                    candidate = dict(self.finding, **{field: value})
                    self.parse(candidate)

    def test_rejects_symlinks_even_inside_repository(self):
        (self.root / "link.py").symlink_to(self.root / "app.py")
        with self.assertRaises(FindingValidationError):
            self.parse(dict(self.finding, file="link.py"))
        (self.root / "directory-link").symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(FindingValidationError):
            self.parse(dict(self.finding, file="directory-link/app.py"))

    def test_one_invalid_finding_rejects_entire_document(self):
        payload = {"findings": [self.finding, dict(self.finding, line=99)]}
        with self.assertRaisesRegex(FindingValidationError, "finding 2"):
            parse_findings(json.dumps(payload), self.root, "one/model")

    def test_missing_cwe_allowed(self):
        candidate = dict(self.finding)
        del candidate["cwe"]
        self.assertEqual(self.parse(candidate)[0]["cwe"], "")

    def test_invalid_unicode_output_is_validation_error(self):
        with self.assertRaises(FindingValidationError):
            parse_findings("\ud800", self.root, "one/model")

    def test_merge_preserves_observations_without_claiming_verification(self):
        first = self.parse()
        second = self.parse(dict(self.finding, title=self.finding["title"].upper(), severity="critical", confidence="high", evidence="A second observation"), model="two/model")
        before = copy.deepcopy(first)
        merged = merge_findings([first, second, second])
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0]["models"], ["one/model", "two/model"])
        self.assertEqual(merged[0]["severity"], "critical")
        self.assertEqual(merged[0]["confidence"], "medium")
        self.assertEqual(merged[0]["verification"], "unverified")
        self.assertEqual(len(merged[0]["observations"]), 2)
        self.assertEqual(first, before)

    def test_different_locations_cwes_and_titles_do_not_merge(self):
        groups = [self.parse(), self.parse(dict(self.finding, line=1)),
                  self.parse(dict(self.finding, cwe="CWE-20")),
                  self.parse(dict(self.finding, title="Other vulnerability"))]
        self.assertEqual(len(merge_findings(groups)), 4)

    def test_report_records_failure_and_safe_evidence_fence(self):
        finding = self.parse(dict(self.finding, title="<script>alert(1)</script>", evidence="```\n# injected heading"))[0]
        report = {"schema_version": 1, "target": "local", "status": "partial",
                  "runs": [{"model": "one/model", "status": "failed", "error": "invalid JSON", "duration_seconds": 1.1}],
                  "findings": merge_findings([[finding]])}
        text = render_markdown(report)
        self.assertIn("unverified hypotheses", text)
        self.assertIn("partial", text)
        self.assertIn("invalid JSON", text)
        self.assertIn("````\n```\n# injected heading\n````", text)
        self.assertNotIn("<script>", text)
        paths = write_reports(report, self.root / "out")
        self.assertEqual(json.loads(paths[0].read_text()), report)
        self.assertEqual(paths[1].read_text(), text)
        self.assertEqual(paths[0].stat().st_mode & 0o777, 0o600)

    def test_empty_failed_report_is_not_clean_result(self):
        text = render_markdown({"status": "failed", "findings": [], "runs": []})
        self.assertIn("not clean audit results", text)

    def test_markdown_exposes_snapshot_scope_and_omissions(self):
        report = {"status": "completed", "findings": [], "runs": [],
                  "scope": {"files": 12, "bytes": 456, "git_ignore_applied": True,
                            "skipped": {"excluded": 3, "binary": 2, "oversized": 1}}}
        text = render_markdown(report)
        self.assertIn("Snapshot files: 12", text)
        self.assertIn("Snapshot bytes: 456", text)
        self.assertIn("Git ignore rules applied: yes", text)
        self.assertIn("binary: 2; excluded: 3; oversized: 1", text)
        self.assertIn("outside this review", text)


if __name__ == "__main__":
    unittest.main()
