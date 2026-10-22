from __future__ import annotations

import copy
import json
import unittest
from unittest.mock import patch

from autoreviewer.findings import MAX_FINDINGS, TEXT_LIMITS, finding_fingerprint, merge_findings
from autoreviewer.reportio import group_findings, validate_report


def finding(model="first", *, title="Input reaches SQL", file="app.py", line=6, cwe="CWE-89", severity="high"):
    item = {
        "title": title, "severity": severity, "file": file, "line": line, "cwe": cwe,
        "description": "Request input enters a query without parameter binding.",
        "evidence": "query(user_input)", "recommendation": "Use bound query parameters.",
        "confidence": "medium", "models": [model], "verification": "unverified",
    }
    item["fingerprint"] = finding_fingerprint(item)
    return item


def report():
    first = finding()
    second = finding("second", severity="medium")
    return {
        "schema_version": 1, "autoreviewer_version": "0.1.0", "target": "/fixture/project",
        "ref": None, "started_at": "2026-10-22T09:00:00+00:00", "finished_at": "2026-10-22T09:00:05+00:00",
        "status": "completed", "scope": {"files": 1, "bytes": 41, "skipped": {"excluded": 1}, "git_ignore_applied": False},
        "runs": [
            {"model": "first", "model_name": "fixture/first", "provider": "fixture", "agent": "opencode",
             "api_format": "openai-chat", "status": "completed", "duration_seconds": 1.25, "error": None,
             "findings": [first]},
            {"model": "second", "model_name": "fixture/second", "provider": "fixture", "agent": "opencode",
             "api_format": "openai-chat", "status": "completed", "duration_seconds": 2.5, "error": None,
             "findings": [second]},
        ],
        "findings": merge_findings([[first], [second]]),
    }


def partial_report():
    value = report()
    value["runs"][1].update(status="timeout", error="Model exceeded its timeout", findings=[])
    value["findings"] = merge_findings([value["runs"][0]["findings"]])
    value["status"] = "partial"
    return value


def audit_guidance():
    return {
        "id": "cloudflare-security-audit",
        "source": "https://github.com/cloudflare/security-audit-skill",
        "commit": "a" * 40, "mode": "guidance-readonly", "adaptation_version": 1,
        "guidance_sha256": "b" * 64, "prompt_sha256": "c" * 64,
    }


class ReportValidationTests(unittest.TestCase):
    def test_current_report_round_trips_without_mutating_original(self):
        original = report()
        validated = validate_report(original)
        self.assertEqual(validated, original)
        validated["findings"][0]["observations"][0]["evidence"] = "changed"
        validated["runs"][0]["findings"][0]["title"] = "changed"
        self.assertNotEqual(validated, original)
        self.assertEqual(original["findings"][0]["observations"][0]["evidence"], "query(user_input)")

    def test_recorded_guidance_round_trips_without_relabeling_older_runs(self):
        value = report()
        value["runs"][0]["audit_guidance"] = audit_guidance()
        validated = validate_report(value)
        self.assertEqual(validated, value)
        self.assertNotIn("audit_guidance", validated["runs"][1])
        # Historical hashes are retained, not replaced by this installation's
        # current bundle metadata or treated as proof of model compliance.
        validated["runs"][0]["audit_guidance"]["commit"] = "d" * 40
        self.assertEqual(value["runs"][0]["audit_guidance"]["commit"], "a" * 40)

    def test_guidance_provenance_rejects_missing_extra_and_untrusted_fields(self):
        malformed = [None, [], {}, {**audit_guidance(), "extra": "not-allowed"}]
        for field in audit_guidance():
            missing = audit_guidance()
            del missing[field]
            malformed.append(missing)
        for field, bad in (
            ("id", "other-skill"), ("mode", "full-audit"),
            ("source", "http://github.com/cloudflare/security-audit-skill"),
            ("source", "https://github.com/attacker/security-audit-skill"),
            ("source", "https://github.com/cloudflare/security-audit-skill?secret=credential"),
            ("adaptation_version", True), ("adaptation_version", 0),
            ("adaptation_version", -1), ("adaptation_version", 1.5),
            ("adaptation_version", "1"), ("adaptation_version", 2**53),
            ("commit", "a" * 39), ("commit", "z" * 40),
            ("guidance_sha256", "b" * 63), ("prompt_sha256", None),
        ):
            malformed.append({**audit_guidance(), field: bad})
        for metadata in malformed:
            value = report()
            value["runs"][0]["audit_guidance"] = metadata
            with self.subTest(metadata=metadata), self.assertRaises(ValueError) as failure:
                validate_report(value)
            self.assertNotIn("credential", str(failure.exception))

    def test_guidance_adaptation_versions_do_not_require_a_new_report_schema(self):
        for version in (1, 2, 2**53 - 1):
            value = report()
            value["runs"][0]["audit_guidance"] = {**audit_guidance(), "adaptation_version": version}
            with self.subTest(version=version):
                self.assertEqual(validate_report(value), value)

    def test_checkpoint_recovery_preserves_guidance_for_interrupted_runs(self):
        value = partial_report()
        value.update(checkpoint=True, status="running")
        value["runs"][1].update(status="running", error=None, audit_guidance=audit_guidance())
        validated = validate_report(value, allow_checkpoint=True)
        self.assertEqual(validated["runs"][1]["status"], "interrupted")
        self.assertEqual(validated["runs"][1]["audit_guidance"], audit_guidance())
        self.assertEqual(value["runs"][1]["status"], "running")

    def test_partial_and_failed_audits_preserve_execution_failures(self):
        value = partial_report()
        self.assertEqual(validate_report(value)["runs"][1]["status"], "timeout")
        value["runs"][0].update(status="failed", error="No result", findings=[])
        value["findings"] = []
        value["status"] = "failed"
        self.assertEqual(validate_report(value)["status"], "failed")

    def test_status_cannot_claim_completion_for_missing_runs(self):
        for fake_status in ("completed", "failed"):
            with self.subTest(fake_status=fake_status):
                value = partial_report()
                value["status"] = fake_status
                with self.assertRaises(ValueError):
                    validate_report(value)

    def test_invalid_structure_and_injected_errors_never_echo_input(self):
        secret = "credential-that-must-not-appear-in-errors"
        cases = [None, [], {"schema_version": secret}, {secret: report()}]
        value = report()
        value["runs"][0]["status"] = secret
        cases.append(value)
        value = report()
        value["findings"][0]["cwe"] = secret
        cases.append(value)
        for value in cases:
            with self.subTest(value_type=type(value).__name__):
                with self.assertRaises(ValueError) as failure:
                    validate_report(value)
                self.assertNotIn(secret, str(failure.exception))
                self.assertIn("Invalid saved report", str(failure.exception))

    def test_boolean_schema_and_line_are_not_integers(self):
        for field in ("schema_version", "line"):
            value = report()
            if field == "schema_version":
                value[field] = True
            else:
                value["findings"][0][field] = True
            with self.subTest(field=field), self.assertRaises(ValueError):
                validate_report(value)

    def test_duplicate_models_and_aggregate_fingerprints_are_rejected(self):
        value = report()
        value["runs"][1]["model"] = "first"
        with self.assertRaises(ValueError):
            validate_report(value)
        value = report()
        value["findings"].append(copy.deepcopy(value["findings"][0]))
        with self.assertRaises(ValueError):
            validate_report(value)

    def test_repeated_identical_per_run_records_remain_importable(self):
        value = report()
        value["runs"][0]["findings"].append(copy.deepcopy(value["runs"][0]["findings"][0]))
        validated = validate_report(value)
        self.assertEqual(len(validated["runs"][0]["findings"]), 2)
        self.assertEqual(len(validated["findings"][0]["observations"]), 2)

    def test_repeated_per_run_fingerprints_preserve_every_distinct_observation(self):
        value = report()
        value["runs"][0]["findings"] = []
        for index in range(MAX_FINDINGS):
            item = finding(severity="critical" if index == MAX_FINDINGS - 1 else "high")
            item["evidence"] = f"Distinct recorded observation {index}"
            value["runs"][0]["findings"].append(item)
        value["findings"] = merge_findings([run["findings"] for run in value["runs"]])
        validated = validate_report(value)
        self.assertEqual(len(validated["runs"][0]["findings"]), MAX_FINDINGS)
        self.assertEqual(len(validated["findings"]), 1)
        self.assertEqual(validated["findings"][0]["severity"], "critical")
        self.assertEqual(validated["findings"][0]["models"], ["first", "second"])
        self.assertEqual(len(validated["findings"][0]["observations"]), MAX_FINDINGS + 1)
        self.assertEqual(validated["findings"][0]["observations"], value["findings"][0]["observations"])
        self.assertEqual(group_findings(validated["findings"])[0]["record_count"], 1)
        value["findings"][0]["observations"].pop()
        with self.assertRaises(ValueError):
            validate_report(value)

    def test_findings_cannot_reference_failed_or_unknown_models(self):
        for name in ("second", "missing"):
            value = partial_report()
            value["findings"][0]["models"] = [name]
            value["findings"][0].pop("observations")
            with self.subTest(name=name), self.assertRaises(ValueError):
                validate_report(value)

    def test_aggregate_provenance_must_match_completed_run_findings(self):
        value = report()
        value["findings"][0]["models"] = ["first"]
        value["findings"][0].pop("observations")
        with self.assertRaises(ValueError):
            validate_report(value)

    def test_aggregate_text_and_severity_cannot_diverge_from_run_observations(self):
        for field, replacement in (("severity", "critical"), ("confidence", "high"),
                                   ("description", "Unrecorded model claim"), ("evidence", "Unrecorded evidence"),
                                   ("recommendation", "Unrecorded advice")):
            value = report()
            value["findings"][0][field] = replacement
            with self.subTest(field=field), self.assertRaises(ValueError):
                validate_report(value)
        value = report()
        value["findings"][0]["observations"][0]["evidence"] = "Invented observation"
        with self.assertRaises(ValueError):
            validate_report(value)

    def test_aggregate_order_is_irrelevant_and_missing_observations_are_reconstructed(self):
        value = report()
        value["findings"][0]["models"].reverse()
        value["findings"][0]["observations"].reverse()
        self.assertEqual(validate_report(value)["status"], "completed")
        value["findings"][0].pop("observations")
        self.assertEqual(validate_report(value)["findings"][0]["observations"], report()["findings"][0]["observations"])
        value = report()
        value["findings"] = []
        with self.assertRaises(ValueError):
            validate_report(value)
        value = report()
        extra = finding(title="Invented aggregate-only record")
        value["findings"].append(extra)
        with self.assertRaises(ValueError):
            validate_report(value)

    def test_failed_runs_cannot_carry_findings(self):
        value = report()
        value["status"] = "partial"
        value["runs"][1]["status"] = "failed"
        with self.assertRaises(ValueError):
            validate_report(value)

    def test_observations_retain_all_provenance_and_reject_unknown_models(self):
        value = report()
        self.assertEqual(len(validate_report(value)["findings"][0]["observations"]), 2)
        for changed in ([], [{"models": ["missing"]}], [{"models": ["first"], "severity": "high"}]):
            value = report()
            value["findings"][0]["observations"] = changed
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                validate_report(value)

    def test_verified_claims_and_unknown_metadata_are_rejected(self):
        value = report()
        value["findings"][0]["verification"] = "confirmed"
        with self.assertRaises(ValueError):
            validate_report(value)
        for location in ("report", "run", "finding", "observation"):
            value = report()
            target = {"report": value, "run": value["runs"][0], "finding": value["findings"][0],
                      "observation": value["findings"][0]["observations"][0]}[location]
            target["credential"] = "must-not-be-retained"
            with self.subTest(location=location), self.assertRaises(ValueError):
                validate_report(value)

    def test_unsafe_paths_and_noncanonical_cwe_are_rejected(self):
        for path in ("../secret", "/secret", "a//b", "a/./b", "C:\\secret", "app.py\n"):
            value = report()
            value["findings"][0]["file"] = path
            value["findings"][0]["fingerprint"] = finding_fingerprint(value["findings"][0])
            with self.subTest(path=path), self.assertRaises(ValueError):
                validate_report(value)
        for cwe in (None, "CWE-0", "cwe-89", "CWE-89\n", "private-key"):
            value = report()
            value["findings"][0]["cwe"] = cwe
            value["findings"][0]["fingerprint"] = finding_fingerprint(value["findings"][0])
            with self.subTest(cwe=cwe), self.assertRaises(ValueError):
                validate_report(value)

    def test_nonfinite_unicode_control_and_non_json_values_are_rejected(self):
        for invalid in (float("nan"), float("inf"), -1, True, {}, []):
            value = report()
            value["runs"][0]["duration_seconds"] = invalid
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                validate_report(value)
        for invalid in ("target\ud800", "target\x00", "target\n"):
            value = report()
            value["target"] = invalid
            with self.subTest(invalid=repr(invalid)), self.assertRaises(ValueError):
                validate_report(value)
        value = report()
        value["scope"] = {"files": {1, 2}}
        with self.assertRaises(ValueError):
            validate_report(value)

    def test_timestamps_require_offset_and_chronological_order(self):
        for timestamp in ("2026-10-22", "2026-10-22T09:00:05", "2026-99-99T09:00:05Z", "2026-10-22T08:00:00Z"):
            value = report()
            value["finished_at"] = timestamp
            with self.subTest(timestamp=timestamp), self.assertRaises(ValueError):
                validate_report(value)
        value = report()
        value["finished_at"] = "2026-10-22T11:00:05+02:00"
        self.assertEqual(validate_report(value)["finished_at"], value["finished_at"])

    def test_report_size_and_depth_are_bounded(self):
        with patch("autoreviewer.reportio.MAX_REPORT_BYTES", 1000), self.assertRaises(ValueError):
            validate_report(report())
        value = report()
        value["scope"] = value
        with self.assertRaises(ValueError):
            validate_report(value)

    def test_reports_above_a_thousand_findings_remain_importable_and_groupable(self):
        value = report()
        template = value["runs"][0]
        value["runs"] = []
        for index in range(3):
            model = f"model-{index}"
            run = {**template, "model": model, "model_name": f"fixture/{model}", "findings": [
                finding(model, line=index * 334 + number + 1) for number in range(334)
            ]}
            value["runs"].append(run)
        value["findings"] = merge_findings([run["findings"] for run in value["runs"]])
        validated = validate_report(value)
        self.assertEqual(len(validated["findings"]), 1002)
        self.assertEqual(len(group_findings(validated["findings"])), 1002)

    def test_each_run_obeys_the_producer_finding_limit(self):
        value = report()
        value["runs"][0]["findings"] = [finding(line=index + 1) for index in range(MAX_FINDINGS)]
        value["findings"] = merge_findings([run["findings"] for run in value["runs"]])
        self.assertEqual(len(validate_report(value)["runs"][0]["findings"]), MAX_FINDINGS)
        value["runs"][0]["findings"].append(finding(line=MAX_FINDINGS + 1))
        value["findings"] = merge_findings([run["findings"] for run in value["runs"]])
        with self.assertRaises(ValueError):
            validate_report(value)

    def test_text_limits_and_allowed_characters_match_the_finding_producer(self):
        for field, limit in TEXT_LIMITS.items():
            with self.subTest(field=field):
                value = report()
                for run in value["runs"]:
                    item = run["findings"][0]
                    item[field] = "x" * limit
                    item["fingerprint"] = finding_fingerprint(item)
                value["findings"] = merge_findings([run["findings"] for run in value["runs"]])
                self.assertEqual(len(validate_report(value)["findings"][0][field]), limit)
                for run in value["runs"]:
                    item = run["findings"][0]
                    item[field] += "x"
                    item["fingerprint"] = finding_fingerprint(item)
                value["findings"] = merge_findings([run["findings"] for run in value["runs"]])
                with self.assertRaises(ValueError):
                    validate_report(value)
        value = report()
        text = "Text with\r\nline breaks\ttabs and DEL\x7f"
        for run in value["runs"]:
            item = run["findings"][0]
            for field in TEXT_LIMITS:
                item[field] = text
            item["fingerprint"] = finding_fingerprint(item)
        value["findings"] = merge_findings([run["findings"] for run in value["runs"]])
        validated = validate_report(value)
        self.assertEqual(validated, value)
        self.assertEqual(len(group_findings(validated["findings"])), 1)

    def test_html_evidence_is_preserved_as_unverified_text(self):
        value = report()
        text = '<img src=x onerror="alert(1)"> & <script>not executable report data</script>'
        for run in value["runs"]:
            run["findings"][0]["evidence"] = text
        value["findings"] = merge_findings([run["findings"] for run in value["runs"]])
        validated = validate_report(value)
        self.assertEqual(validated["findings"][0]["evidence"], text)
        self.assertEqual(validated["findings"][0]["verification"], "unverified")

    def test_checkpoint_requires_opt_in_and_keeps_completed_results(self):
        value = partial_report()
        value["checkpoint"] = True
        value["status"] = "running"
        value["runs"][1].update(status="running", error=None)
        original = copy.deepcopy(value)
        with self.assertRaises(ValueError):
            validate_report(value)
        recovered = validate_report(value, allow_checkpoint=True)
        self.assertEqual(value, original)
        self.assertEqual(recovered["status"], "partial")
        self.assertEqual(recovered["runs"][0]["status"], "completed")
        self.assertEqual(recovered["runs"][1]["status"], "interrupted")
        self.assertTrue(recovered["checkpoint"])
        self.assertTrue(recovered["interrupted"])
        self.assertEqual(recovered["finished_at"], original["finished_at"])
        self.assertEqual(recovered["findings"], original["findings"])

    def test_checkpoint_cannot_supply_unfinished_findings_or_unmarked_active_runs(self):
        value = report()
        value["checkpoint"] = True
        value["runs"][1]["status"] = "running"
        with self.assertRaises(ValueError):
            validate_report(value, allow_checkpoint=True)
        value = partial_report()
        value["runs"][1]["status"] = "running"
        with self.assertRaises(ValueError):
            validate_report(value, allow_checkpoint=True)


class SourceGroupingTests(unittest.TestCase):
    def test_links_title_variants_without_merging_original_records(self):
        items = [finding(title="First phrasing"), finding("second", title="Different phrasing", severity="critical")]
        original = copy.deepcopy(items)
        groups = group_findings(items)
        self.assertEqual(items, original)
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0]["record_count"], 2)
        self.assertEqual(groups[0]["models"], ["first", "second"])
        self.assertEqual(groups[0]["severity"], "critical")
        self.assertCountEqual(groups[0]["fingerprints"], [item["fingerprint"] for item in items])

    def test_group_ids_and_order_are_stable_across_input_order(self):
        items = [finding(), finding("second", title="Different wording"), finding(file="b.py", cwe="CWE-22")]
        self.assertEqual(group_findings(items), group_findings(list(reversed(items))))
        changed_title = finding(title="A third wording", severity="critical")
        self.assertEqual(group_findings([items[0]])[0]["id"], group_findings([changed_title])[0]["id"])

    def test_missing_cwe_different_line_and_case_sensitive_files_stay_separate(self):
        missing_cwe = finding(title="Unknown B", cwe="")
        del missing_cwe["cwe"]
        items = [finding(title="Unknown A", cwe=""), missing_cwe,
                 finding(), finding(file="App.py"), finding(line=7), finding(cwe="CWE-22")]
        groups = group_findings(items)
        self.assertEqual(len(groups), len(items))
        self.assertTrue(all(group["record_count"] == 1 for group in groups))

    def test_duplicate_and_malformed_findings_do_not_inflate_group_counts(self):
        item = finding()
        for values in ([item, item], [None], [{"file": "app.py"}], [dict(item, models=["first", "first"])]):
            with self.subTest(values_type=type(values[0]).__name__), self.assertRaises(ValueError):
                group_findings(values)
        self.assertEqual(group_findings([]), [])


if __name__ == "__main__":
    unittest.main()
