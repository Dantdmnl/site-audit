from __future__ import annotations

import copy
import io
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from site_audit import reporting
from site_audit import cli as audit
from site_audit.report_validation import load_report, validate_report


def report():
    return {"schema_version": "1.1", "target": "https://example.com/", "mode": "audit", "settings": {}, "findings": [{"severity": "LOW", "category": "header", "title": "Example", "detail": "Observed", "url": "https://example.com/"}], "scan": {"status": "complete", "reasons": []}}


class ReportValidationTests(unittest.TestCase):
    def test_current_and_legacy_reports_validate(self):
        for version in ("1.0", "1.1"):
            value = report()
            value["schema_version"] = version
            self.assertEqual(validate_report(value), value)

    def test_invalid_report_fields_are_rejected(self):
        for key, value in (("schema_version", "2.0"), ("target", "javascript:alert(1)"), ("findings", "invalid"), ("settings", []), ("duration_seconds", float("nan")), ("scan", {"status": "unknown"}), ("ports", {"70000": True})):
            value_report = report()
            value_report[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                validate_report(value_report)

    def test_invalid_finding_fields_are_rejected(self):
        for key, value in (("severity", "UNKNOWN"), ("confidence", "maybe"), ("url", "javascript:alert(1)"), ("references", ["file:///private"]), ("status_code", 900), ("extra", {"body_issues": [42]})):
            value_report = report()
            value_report["findings"][0][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                validate_report(value_report)

    def test_bounded_report_loader(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "large.json"
            path.write_bytes(b" " * 2048)
            with patch("site_audit.report_validation.MAX_REPORT_BYTES", 1024), self.assertRaisesRegex(ValueError, "exceeds"):
                load_report(str(path))

    def test_corrupt_last_report_returns_error_without_falling_back(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "last.json"
            path.write_text('{"target":42}')
            with patch.object(audit, "_last_project_path", return_value=str(path)), redirect_stdout(io.StringIO()):
                code = audit.export_last_report(str(Path(tmp) / "out.html"), "html", "project", report_title="Test", report_brand="Test", report_logo=None)
            self.assertEqual(code, 1)

    def test_iso_z_timestamp_exports_in_python_310_compatible_form(self):
        value = report()
        value["started_at"] = "2026-10-10T00:00:00Z"
        value["finished_at"] = "2026-10-10T00:00:01Z"
        with tempfile.TemporaryDirectory() as tmp, redirect_stdout(io.StringIO()):
            path = Path(tmp) / "report.html"
            self.assertEqual(reporting.write_report(value, str(path), "html", report_title="Test", report_brand="Test", report_logo=None), 0)
            self.assertIn("2026-10-10T00:00:00Z", path.read_text())

    def test_all_export_formats_accept_one_validated_contract(self):
        value = report()
        original = copy.deepcopy(value)
        with tempfile.TemporaryDirectory() as tmp, redirect_stdout(io.StringIO()):
            for format_name in ("json", "html", "csv", "xml"):
                path = Path(tmp) / ("report." + format_name)
                self.assertEqual(reporting.write_report(value, str(path), format_name, report_title="Test", report_brand="Test", report_logo=None), 0)
                self.assertGreater(path.stat().st_size, 0)
        self.assertEqual(value, original)

    def test_discovery_contract_requires_http_urls(self):
        value = report()
        value.update(mode="discover", result={"discovered": ["https://example.com/article.html?x=1"]})
        self.assertEqual(validate_report(value), value)
        value["result"]["discovered"] = ["javascript:alert(1)"]
        with self.assertRaises(ValueError):
            validate_report(value)
