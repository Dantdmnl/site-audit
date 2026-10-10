from __future__ import annotations

import copy
import io
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

import site_audit as audit
from audit_reports import load_report, validate_report


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
            with patch("audit_reports.MAX_REPORT_BYTES", 1024), self.assertRaisesRegex(ValueError, "exceeds"):
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
            self.assertEqual(audit.write_report(value, str(path), "html", report_title="Test", report_brand="Test", report_logo=None), 0)
            self.assertIn("2026-10-10T00:00:00Z", path.read_text())

    def test_all_export_formats_accept_one_validated_contract(self):
        value = report()
        original = copy.deepcopy(value)
        with tempfile.TemporaryDirectory() as tmp, redirect_stdout(io.StringIO()):
            for format_name in ("json", "html", "csv", "xml"):
                path = Path(tmp) / ("report." + format_name)
                self.assertEqual(audit.write_report(value, str(path), format_name, report_title="Test", report_brand="Test", report_logo=None), 0)
                self.assertGreater(path.stat().st_size, 0)
        self.assertEqual(value, original)

    def test_discovery_contract_requires_http_urls(self):
        value = report()
        value.update(mode="discover", result={"discovered": ["https://example.com/article.html?x=1"]})
        self.assertEqual(validate_report(value), value)
        value["result"]["discovered"] = ["javascript:alert(1)"]
        with self.assertRaises(ValueError):
            validate_report(value)


class DiscoveryParsingTests(unittest.TestCase):
    def test_sitemap_index_can_point_to_extensionless_urls(self):
        data = '<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><sitemap><loc>https://example.com/maps?id=1</loc></sitemap></sitemapindex>'
        nested, pages = audit.extract_sitemap_entries(data)
        self.assertEqual(nested, ["https://example.com/maps?id=1"])
        self.assertEqual(pages, [])

    def test_xml_document_url_is_not_recursed_as_a_sitemap(self):
        data = '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>https://example.com/document.xml</loc></url></urlset>'
        self.assertEqual(audit.extract_sitemap_entries(data), ([], ["https://example.com/document.xml"]))

    def test_xml_entities_are_rejected(self):
        value = '<!DOCTYPE urlset [<!ENTITY x "private">]><urlset><url><loc>&x;</loc></url></urlset>'
        self.assertEqual(audit.extract_sitemap_entries(value), ([], []))

    def test_atom_href_and_rss_document_links_are_retained(self):
        xml = '<feed xmlns="http://www.w3.org/2005/Atom"><entry><link rel="alternate" href="https://example.com/article.html?q=1"/><link rel="self" href="https://example.com/feed-item"/></entry></feed>'
        with patch.object(audit, "fetch_text", return_value=xml):
            result = audit.crawl_feeds(object(), "https://example.com/", "", audit.ScanConfig())
        self.assertEqual(result, {"https://example.com/article.html?q=1"})

    def test_document_urls_are_content_but_static_assets_are_not(self):
        for url in ("/article.html", "/document.pdf", "/page.php?id=1"):
            self.assertTrue(audit.is_content_url(url, "https://example.com/"))
        for url in ("/image.png", "/assets/site.js", "https://foreign.example/article.html"):
            self.assertFalse(audit.is_content_url(url, "https://example.com/"))
