import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from azure_guardrail.scanner import assess

ROOT = Path(__file__).resolve().parents[1]


def fixture(name="safe"):
    return json.loads((ROOT / "examples" / f"{name}-plan.json").read_text())


class ScannerTests(unittest.TestCase):
    def test_safe_plan(self):
        report = assess(fixture())
        self.assertEqual(report["findings"], [])
        self.assertEqual(report["summary"]["assessed_resources"], 1)

    def test_risky_plan_explains_each_rule(self):
        findings = assess(fixture("risky"))["findings"]
        self.assertEqual([f["id"] for f in findings], ["AZG001", "AZG002", "AZG003", "AZG004"])
        for finding in findings:
            self.assertEqual(finding["status"], "risk")
            self.assertTrue(finding["why"])
            self.assertTrue(finding["suggestion"])

    def test_missing_null_and_wrong_types_need_review(self):
        for value in (None, 0, 1, "true", [], {}):
            with self.subTest(value=value):
                plan = fixture()
                plan["resource_changes"][0]["change"]["after"]["https_traffic_only_enabled"] = value
                self.assertEqual(assess(plan)["findings"][0]["status"], "review")
        plan = fixture()
        plan["resource_changes"][0]["change"]["after"] = {}
        self.assertEqual(assess(plan)["summary"]["review_findings"], 4)

    def test_unknown_overrides_apparently_safe_value(self):
        for unknown, count in ((True, 4), ({"min_tls_version": True}, 1)):
            plan = fixture()
            plan["resource_changes"][0]["change"]["after_unknown"] = unknown
            self.assertEqual(assess(plan)["summary"]["review_findings"], count)

    def test_unknown_tls_version_needs_review(self):
        plan = fixture()
        plan["resource_changes"][0]["change"]["after"]["min_tls_version"] = "future-version"
        self.assertEqual(assess(plan)["findings"][0]["status"], "review")

    def test_skip_deleted_data_unsupported_and_other_provider(self):
        for modification in ({"mode": "data"}, {"type": "azurerm_key_vault"},
                             {"provider_name": "example/other"},
                             {"change": {"actions": ["delete"], "after": None}}):
            plan = fixture("risky")
            plan["resource_changes"][0].update(modification)
            report = assess(plan)
            self.assertEqual(report["findings"], [])
            self.assertEqual(report["summary"]["skipped_resources"], 1)

    def test_replacement_update_and_unchanged_use_future_values(self):
        for actions in (["delete", "create"], ["create", "delete"], ["update"], ["no-op"]):
            plan = fixture("risky")
            resource = plan["resource_changes"][0]
            resource["address"] = 'module.app.azurerm_storage_account.example["primary"]'
            resource["change"]["actions"] = actions
            resource["change"]["before"] = fixture()["resource_changes"][0]["change"]["after"]
            findings = assess(plan)["findings"]
            self.assertEqual(len(findings), 4)
            self.assertEqual(findings[0]["resource"], resource["address"])

    def test_empty_plan_reports_zero_coverage(self):
        report = assess({"format_version": "1.2", "planned_values": {}})
        self.assertEqual(report["summary"]["assessed_resources"], 0)

    def test_invalid_plans_are_rejected(self):
        for plan in (None, [], {}, {"format_version": "2.0", "planned_values": {}},
                     dict(fixture(), resource_changes=None), dict(fixture(), errored=True),
                     dict(fixture(), complete=False), dict(fixture(), resource_changes=[None])):
            with self.subTest(plan=plan), self.assertRaises(ValueError):
                assess(plan)

    def test_bad_resource_changes_are_rejected(self):
        for change in ({"actions": [["create"]]}, {"actions": []},
                       {"actions": ["create"], "after": None},
                       {"actions": ["create"], "after": {}, "after_unknown": []}):
            plan = fixture()
            plan["resource_changes"][0]["change"] = change
            with self.assertRaises(ValueError):
                assess(plan)

    def test_plan_not_mutated_and_secrets_not_reported(self):
        plan = fixture("risky")
        plan["resource_changes"][0]["change"]["after"]["access_key"] = "SECRET_SENTINEL"
        original = copy.deepcopy(plan)
        self.assertNotIn("SECRET_SENTINEL", json.dumps(assess(plan)))
        self.assertEqual(plan, original)


class CliTests(unittest.TestCase):
    def run_cli(self, *args):
        return subprocess.run([sys.executable, "-m", "azure_guardrail", *map(str, args)],
                              cwd=ROOT, text=True, capture_output=True)

    def test_examples_and_json(self):
        for name, code in (("safe", 0), ("risky", 1)):
            result = self.run_cli(ROOT / "examples" / f"{name}-plan.json", "--json")
            self.assertEqual(result.returncode, code, result.stderr)
            self.assertEqual(json.loads(result.stdout)["summary"]["assessed_resources"], 1)

    def test_text_report(self):
        result = self.run_cli(ROOT / "examples" / "risky-plan.json")
        self.assertEqual(result.returncode, 1)
        self.assertIn("Why:", result.stdout)
        self.assertIn("Suggestion:", result.stdout)

    def test_usage_and_missing_file(self):
        self.assertEqual(self.run_cli().returncode, 2)
        self.assertEqual(self.run_cli("does-not-exist.json").returncode, 2)
        self.assertEqual(self.run_cli("--help").returncode, 0)

    def test_malformed_json_does_not_leak_content(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "plan.json"
            path.write_text('{"SECRET_SENTINEL": invalid}', encoding="utf-8")
            result = self.run_cli(path)
            self.assertEqual(result.returncode, 2)
            self.assertNotIn("SECRET_SENTINEL", result.stdout + result.stderr)

    def test_utf8_bom_and_review_exit_code(self):
        plan = fixture()
        plan["resource_changes"][0]["change"]["after_unknown"] = True
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "plan.json"
            path.write_text(json.dumps(plan), encoding="utf-8-sig")
            result = self.run_cli(path, "--json")
            self.assertEqual(result.returncode, 1)
            self.assertEqual(json.loads(result.stdout)["summary"]["review_findings"], 4)


if __name__ == "__main__":
    unittest.main()
