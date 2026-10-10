from __future__ import annotations

import csv
import json
import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import site_audit


class FakeResponse:
    def __init__(self, text: str, content_type: str = "text/html", ok: bool = True):
        self.text = text
        self.ok = ok
        self.headers = {"Content-Type": content_type}


class ValidationTests(unittest.TestCase):
    def test_parse_custom_headers_accepts_repeatable_headers(self) -> None:
        headers = site_audit.parse_custom_headers([
            "X-Custom: value",
            "Authorization: Bearer token",
        ])

        self.assertEqual(headers["X-Custom"], "value")
        self.assertEqual(headers["Authorization"], "Bearer token")

    def test_parse_custom_headers_rejects_malformed_headers(self) -> None:
        with self.assertRaisesRegex(ValueError, "expected KEY:VALUE"):
            site_audit.parse_custom_headers(["X-Custom"])

        with self.assertRaisesRegex(ValueError, "Invalid header name"):
            site_audit.parse_custom_headers(["Bad Header: value"])

        with self.assertRaisesRegex(ValueError, "Invalid header value"):
            site_audit.parse_custom_headers(["X-Custom: good\r\nInjected: bad"])

    def test_validate_proxy_url(self) -> None:
        self.assertEqual(
            site_audit.validate_proxy_url("http://proxy.example:8080"),
            "http://proxy.example:8080",
        )

        with self.assertRaisesRegex(ValueError, "proxy must use"):
            site_audit.validate_proxy_url("ftp://proxy.example")

        with self.assertRaisesRegex(ValueError, "hostname"):
            site_audit.validate_proxy_url("http:///missing-host")

    def test_get_ports_for_url_validates_custom_ports(self) -> None:
        self.assertEqual(
            site_audit.get_ports_for_url("https://example.com", "443,8443,443"),
            [443, 8443],
        )

        with self.assertRaisesRegex(ValueError, "out of range"):
            site_audit.get_ports_for_url("https://example.com", "0")

        with self.assertRaisesRegex(ValueError, "empty port"):
            site_audit.get_ports_for_url("https://example.com", "80,")

        with self.assertRaisesRegex(ValueError, "ports must be"):
            site_audit.get_ports_for_url("https://example.com", "wide")

    def test_normalize_base_url(self) -> None:
        self.assertEqual(
            site_audit.normalize_base_url("example.com/app"),
            "https://example.com/app",
        )

        with self.assertRaisesRegex(ValueError, "Only http and https"):
            site_audit.normalize_base_url("ftp://example.com")


class OutputWriterTests(unittest.TestCase):
    def test_report_writers_create_expected_files(self) -> None:
        finding = site_audit.Finding(
            severity="HIGH",
            category="endpoint",
            title="Exposed admin",
            detail="HTTP 200",
            url="https://example.com/admin/",
            status_code=200,
        )

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            json_path = tmp_path / "report.json"
            csv_path = tmp_path / "report.csv"
            xml_path = tmp_path / "report.xml"
            html_path = tmp_path / "report.html"

            site_audit.write_json_atomic(str(json_path), {"tool": {"version": site_audit.__version__}})
            site_audit.write_csv(str(csv_path), [finding])
            site_audit.write_xml(str(xml_path), [finding], "https://example.com/")
            site_audit.write_html_report(
                str(html_path),
                mode="audit",
                target="https://example.com/",
                platforms=[],
                settings={},
                findings=[finding],
            )

            self.assertEqual(json.loads(json_path.read_text(encoding="utf-8"))["tool"]["version"], site_audit.__version__)

            with csv_path.open(newline="", encoding="utf-8") as fh:
                rows = list(csv.DictReader(fh))
            self.assertEqual(rows[0]["title"], "Exposed admin")

            root = ET.fromstring(xml_path.read_text(encoding="utf-8"))
            self.assertEqual(root.get("target"), "https://example.com/")
            self.assertEqual(root.findtext("./finding/severity"), "HIGH")

            html = html_path.read_text(encoding="utf-8")
            self.assertIn(f"site-audit v{site_audit.__version__}", html)


class RuntimeBehaviorTests(unittest.TestCase):
    def test_print_summary_handles_empty_findings(self) -> None:
        out = StringIO()
        with redirect_stdout(out):
            site_audit.print_summary([])

        self.assertIn("Summary", out.getvalue())
        self.assertIn("no findings", out.getvalue())

    def test_soft_404_matches_dynamic_html_with_same_visible_text(self) -> None:
        profile_response = FakeResponse("""
            <html><head><title>One moment</title><script>token = 'abc123'</script></head>
            <body><main>Please wait while your request is being verified...</main></body></html>
        """)
        candidate_response = FakeResponse("""
            <html><head><title>One moment</title><script>token = 'different456'</script></head>
            <body><main>Please wait while your request is being verified...</main></body></html>
        """)

        profile = site_audit.body_fingerprint(profile_response)

        self.assertIsNotNone(profile)
        self.assertTrue(site_audit.is_soft_404(candidate_response, [profile]))

    def test_endpoint_audit_reports_already_exhausted_budget(self) -> None:
        class ExhaustedBudget:
            def exhausted(self) -> bool:
                return True

        class FakeSessionPool:
            def get(self):
                raise AssertionError("No request should be scheduled")

        with patch.object(site_audit, "COMMON_PATHS", [("/admin/", "HIGH", "admin")]):
            findings = site_audit.run_endpoint_audit(
                FakeSessionPool(),
                "https://example.com/",
                [],
                workers=4,
                config=site_audit.ScanConfig(),
                profile="standard",
                soft_404_profiles=[],
                time_budget=ExhaustedBudget(),
            )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].title, "Time budget reached during endpoint probing")

    def test_cli_version(self) -> None:
        result = subprocess.run(
            [sys.executable, str(ROOT / "site_audit.py"), "--version"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )

        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.strip(), f"site-audit {site_audit.__version__}")

    def test_cli_dry_run_report_contains_version_and_makes_no_requests(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report_path = Path(tmp) / "report.json"
            result = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "site_audit.py"),
                    "https://example.com",
                    "--dry-run",
                    "--ports",
                    "80,443",
                    "--output",
                    str(report_path),
                    "--no-save-prefs",
                    "--no-save-last",
                    "--no-load-prefs",
                ],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn(f"site-audit v{site_audit.__version__}", result.stdout)
            self.assertIn("[DRY-RUN] Skipping endpoint audits", result.stdout)
            self.assertNotIn("Scanning 2 ports", result.stdout)

            payload = json.loads(report_path.read_text(encoding="utf-8"))
            self.assertEqual(payload["tool"], {"name": "site-audit", "version": site_audit.__version__})
            self.assertEqual(payload["schema_version"], site_audit.REPORT_SCHEMA_VERSION)
            self.assertEqual(payload["scan"]["status"], "dry_run")

    def test_cli_invalid_header_fails_before_scan(self) -> None:
        result = subprocess.run(
            [
                sys.executable,
                str(ROOT / "site_audit.py"),
                "https://example.com",
                "--dry-run",
                "--header",
                "BadHeader",
                "--no-save-prefs",
                "--no-save-last",
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )

        self.assertEqual(result.returncode, 1)
        self.assertIn("Invalid header", result.stdout)
        self.assertNotIn("[DRY-RUN MODE", result.stdout)


if __name__ == "__main__":
    unittest.main()
