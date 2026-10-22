from __future__ import annotations

import copy
import json
from pathlib import Path
import tempfile
import unittest

from autoreviewer.findings import finding_fingerprint, merge_findings
from autoreviewer.reports import render_markdown, write_reports


def observation_report():
    first = {
        "title": "Shared SQL issue", "severity": "low", "file": "app.py", "line": 6,
        "cwe": "CWE-89", "confidence": "low", "models": ["first"], "verification": "unverified",
        "description": "First model description", "evidence": "First model evidence",
        "recommendation": "First model recommendation",
    }
    first["fingerprint"] = finding_fingerprint(first)
    second = {**first, "models": ["second"], "severity": "critical", "confidence": "high",
              "description": "Second model description", "evidence": "Second model evidence",
              "recommendation": "Second model recommendation"}
    return {"schema_version": 1, "target": "/fixture/project", "status": "completed", "runs": [],
            "findings": merge_findings([[first], [second]])}


class ReportObservationTests(unittest.TestCase):
    def test_recorded_guidance_is_preserved_in_markdown_and_json(self):
        report = observation_report()
        guidance = {
            "id": "cloudflare-security-audit",
            "source": "https://github.com/cloudflare/security-audit-skill",
            "commit": "a" * 40, "mode": "guidance-readonly", "adaptation_version": 1,
            "guidance_sha256": "b" * 64, "prompt_sha256": "c" * 64,
        }
        report["runs"] = [{"model": "first", "status": "completed", "audit_guidance": guidance},
                          {"model": "second", "status": "completed"}]
        original = copy.deepcopy(report)
        with tempfile.TemporaryDirectory() as temporary:
            json_path, markdown_path = write_reports(report, Path(temporary))
            text = markdown_path.read_text()
            self.assertEqual(json.loads(json_path.read_text()), original)
        self.assertEqual(text.count("Recorded audit guidance:"), 1)
        self.assertIn(r"cloudflare\-security\-audit", text)
        self.assertIn(r"https://github.com/cloudflare/security\-audit\-skill", text)
        self.assertIn("Upstream commit: " + "a" * 40, text)
        self.assertIn(r"Mode: guidance\-readonly; adaptation version: 1", text)
        self.assertIn("Guidance SHA-256: " + "b" * 64, text)
        self.assertIn("Prompt SHA-256: " + "c" * 64, text)
        self.assertEqual(report, original)

    def test_guidance_rendering_escapes_unvalidated_input_and_does_not_label_old_reports(self):
        report = observation_report()
        self.assertNotIn("Recorded audit guidance:", render_markdown(report))
        report["runs"] = [{"model": "untrusted", "status": "completed", "audit_guidance": {
            "id": "<script>unsafe()</script>",
            "source": "[click](javascript:alert(1))",
            "commit": "# forged heading", "mode": "<img src=x onerror=alert(1)>",
        }}]
        text = render_markdown(report)
        self.assertNotIn("<script>", text)
        self.assertNotIn("<img", text)
        self.assertNotIn("[click](javascript:", text)
        self.assertIn("&lt;script&gt;", text)
        self.assertIn("\\# forged heading", text)

    def test_markdown_contains_each_model_assessment_without_repeating_primary_text(self):
        report = observation_report()
        original = copy.deepcopy(report)
        text = render_markdown(report)
        for model in ("First", "Second"):
            for field in ("description", "evidence", "recommendation"):
                self.assertEqual(text.count(f"{model} model {field}"), 1)
        self.assertIn("- Models: first", text)
        self.assertIn("- Models: second", text)
        self.assertIn("- Severity: **low**", text)
        self.assertIn("- Severity: **critical**", text)
        self.assertIn("- Model confidence: low", text)
        self.assertIn("- Model confidence: high", text)
        self.assertIn("highest reported severity", text)
        self.assertIn("All observations remain unverified", text)
        self.assertEqual(report, original)

    def test_single_observation_keeps_existing_report_sections(self):
        report = observation_report()
        finding = report["findings"][0]
        finding["observations"] = finding["observations"][:1]
        text = render_markdown(report)
        self.assertNotIn("#### Model observations", text)
        self.assertIn("**Description**\n\nFirst model description", text)
        self.assertEqual(text.count("First model evidence"), 1)

    def test_observation_prose_is_escaped_and_code_fences_preserve_full_evidence(self):
        report = observation_report()
        second = report["findings"][0]["observations"][1]
        second["description"] = '<script>unsafe()</script>\n# forged heading'
        second["evidence"] = '```\n# literal code, not a heading\n```'
        text = render_markdown(report)
        self.assertNotIn('<script>', text)
        self.assertIn('&lt;script&gt;unsafe', text)
        self.assertIn('\\# forged heading', text)
        self.assertIn('````\n' + second["evidence"] + '\n````', text)

    def test_saved_markdown_and_json_both_retain_secondary_model_evidence(self):
        report = observation_report()
        with tempfile.TemporaryDirectory() as temporary:
            json_path, markdown_path = write_reports(report, Path(temporary))
            self.assertEqual(json.loads(json_path.read_text()), report)
            self.assertIn('Second model evidence', markdown_path.read_text())


if __name__ == "__main__":
    unittest.main()
