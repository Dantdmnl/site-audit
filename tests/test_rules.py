from __future__ import annotations

import unittest
from unittest.mock import patch

import requests

from site_audit import discovery
from site_audit import cli as audit
from site_audit.core import ScanRuntime, ScanScope, TimeBudget
from site_audit.rules import header_checks, sensitive_match


def response(body: str, content_type: str = "text/plain", url: str = "https://example.com/", status: int = 200):
    result = requests.Response()
    result.status_code = status
    result.url = url
    result._content = body.encode()
    result.headers["Content-Type"] = content_type
    return result


class DetectionTests(unittest.TestCase):
    def probe(self, body, path="/.env", content_type="text/plain", status=200):
        resp = response(body, content_type, status=status)
        pool = type("Pool", (), {"get": lambda self: object()})()
        with patch.object(audit, "fetch_response", return_value=(resp, None)):
            return audit.probe_path(pool, "https://example.com/", path, "CRITICAL", "sensitive file", audit.ScanConfig(), [])

    def test_generic_html_is_not_critical(self):
        result = self.probe("<html>Sign in</html>", content_type="text/html")
        self.assertEqual(result.severity, "INFO")
        self.assertEqual(result.confidence, "tentative")

    def test_env_exposure_requires_assignment_and_redacts_secret(self):
        result = self.probe("DB_PASSWORD=super-secret-value\nAPP_ENV=production")
        self.assertEqual(result.severity, "CRITICAL")
        self.assertEqual(result.rule_id, "exposure.env")
        self.assertNotIn("super-secret-value", str(result))

    def test_html_containing_env_examples_is_not_confirmed(self):
        self.assertIsNone(sensitive_match("/.env", "<html>\nDB_PASSWORD=example\n</html>", "text/html"))

    def test_git_config_positive_and_negative(self):
        self.assertIsNotNone(sensitive_match("/.git/config", "[core]\nrepositoryformatversion = 0", "text/plain"))
        self.assertIsNone(sensitive_match("/.git/config", "[core]\nrandom = 1", "text/plain"))

    def test_sql_dump_positive_and_negative(self):
        self.assertIsNotNone(sensitive_match("/backup.sql", "CREATE TABLE accounts (id integer);", "text/plain"))
        self.assertIsNone(sensitive_match("/backup.sql", "This is an error page", "text/plain"))

    def test_secret_json_positive_and_negative(self):
        self.assertIsNotNone(sensitive_match("/secrets.json", '{"api_key":"secret"}', "application/json"))
        self.assertIsNone(sensitive_match("/secrets.json", '{"error":"not found"}', "application/json"))

    def test_supported_config_formats_have_positive_and_negative_fixtures(self):
        fixtures = [
            ("/.git/HEAD", "ref: refs/heads/main\n", "Not found"),
            ("/config.yaml", "password: private\n", "title: public\n"),
            ("/web.config", "<configuration><connectionStrings /></configuration>", "<configuration />"),
            ("/.htaccess", "RewriteEngine On\n", "Not found"),
            ("/.svn/entries", "<wc-entries></wc-entries>", "Not found"),
        ]
        for path, positive, negative in fixtures:
            with self.subTest(path=path):
                self.assertIsNotNone(sensitive_match(path, positive, "text/plain"))
                self.assertIsNone(sensitive_match(path, negative, "text/plain"))

    def test_denied_response_does_not_claim_existence(self):
        result = self.probe("Forbidden", status=403)
        self.assertEqual(result.severity, "INFO")
        self.assertIn("existence is not confirmed", result.detail)

    def test_waf_challenge_marks_partial_and_has_no_exposure(self):
        cfg = audit.ScanConfig(runtime=ScanRuntime(TimeBudget(None)))
        pool = type("Pool", (), {"get": lambda self: object()})()
        with patch.object(audit, "fetch_response", return_value=(response("Your request is being verified", "text/html"), None)):
            result = audit.probe_path(pool, "https://example.com/", "/.env", "CRITICAL", "env", cfg, [])
        self.assertIsNone(result)
        self.assertEqual(cfg.runtime.snapshot()["status"], "partial")

    def test_stable_id_does_not_depend_on_severity(self):
        a = audit.Finding("HIGH", "endpoint", "a", "", url="https://example.com/", rule_id="test.rule")
        b = audit.Finding("LOW", "endpoint", "b", "", url="https://example.com/", rule_id="test.rule")
        self.assertEqual(a.id, b.id)


class HeaderTests(unittest.TestCase):
    def test_json_does_not_need_csp_or_framing(self):
        rules = {item["rule_id"] for item in header_checks(response("{}", "application/json"))}
        self.assertNotIn("header.csp.missing", rules)
        self.assertNotIn("header.framing", rules)

    def test_http_does_not_need_hsts(self):
        rules = {item["rule_id"] for item in header_checks(response("", url="http://example.com/"))}
        self.assertNotIn("header.hsts.missing", rules)

    def test_frame_ancestors_replaces_xfo(self):
        resp = response("<html></html>", "text/html")
        resp.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'"
        self.assertNotIn("header.framing", {item["rule_id"] for item in header_checks(resp)})

    def test_report_only_policy_does_not_count_as_enforcement(self):
        resp = response("<html></html>", "text/html")
        resp.headers["Content-Security-Policy-Report-Only"] = "default-src 'none'"
        self.assertIn("header.csp.missing", {item["rule_id"] for item in header_checks(resp)})

    def test_disabled_hsts_and_invalid_nosniff(self):
        resp = response("")
        resp.headers.update({"Strict-Transport-Security": "max-age=0", "X-Content-Type-Options": "yes"})
        rules = {item["rule_id"] for item in header_checks(resp)}
        self.assertIn("header.hsts.disabled", rules)
        self.assertIn("header.nosniff", rules)

    def test_nonce_csp_ignores_unsafe_inline_fallback(self):
        resp = response("", "text/html")
        resp.headers["Content-Security-Policy"] = "script-src 'nonce-abc123' 'unsafe-inline'; frame-ancestors 'self'"
        self.assertNotIn("header.csp.permissive-script", {item["rule_id"] for item in header_checks(resp)})

    def test_cookie_value_does_not_spoof_flags(self):
        resp = response("")
        resp.headers["Set-Cookie"] = "session=secure-httponly-samesite; Path=/"
        titles = [item.title for item in audit.audit_cookies(resp)]
        self.assertEqual(len(titles), 3)

    def test_real_cookie_flags_are_respected(self):
        resp = response("")
        resp.headers["Set-Cookie"] = "session=abc; Secure; HttpOnly; SameSite=Lax"
        self.assertEqual(audit.audit_cookies(resp), [])

    def test_wildcard_public_cors_is_not_a_vulnerability(self):
        resp = response("{}", "application/json")
        resp.headers["Access-Control-Allow-Origin"] = "*"
        with patch.object(audit, "fetch_response", return_value=(resp, None)):
            self.assertEqual(audit.audit_cors(resp.url, audit.ScanConfig()), [])


class ConfigurationTests(unittest.TestCase):
    def test_explicit_default_value_beats_preferences_and_profile(self):
        args = audit.parse_args(["https://example.com", "--workers", "20", "--profile", "quick"])
        audit.apply_preferences_to_args(args, {"defaults": {"workers": 99}})
        self.assertEqual(args.workers, 20)
        self.assertIn("workers", args._configured)

    def test_invalid_preference_types_and_choices_are_ignored(self):
        args = audit.parse_args(["https://example.com"])
        audit.apply_preferences_to_args(args, {"defaults": {"workers": "many", "mode": "invalid", "timeout": -1, "ports": 42}})
        self.assertEqual((args.workers, args.mode, args.timeout), (20, "audit", 10))
        self.assertIsNone(args.ports)

    def test_invalid_url_forms(self):
        for value in ("https://example.com:abc", "https://user:pass@example.com", "https://example.com\nInjected", "https://example.com:99999"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                audit.normalize_base_url(value)

    def test_url_identity_preserves_query_path_and_strips_fragment(self):
        self.assertEqual(discovery.normalize_url("/post?id=7#section", "https://example.com/"), "https://example.com/post?id=7")
        self.assertFalse(discovery.is_internal("http://example.com/", "https://example.com/"))

    def test_public_and_private_suffixes(self):
        self.assertEqual(discovery._base_domain("shop.example.co.uk"), "example.co.uk")
        self.assertEqual(discovery._base_domain("tenant.github.io"), "tenant.github.io")

    def test_scalar_and_malformed_data_json_are_ignored(self):
        for body in ("42", "null", '"string"', '{"data":42}'):
            with self.subTest(body=body), patch.object(discovery, "fetch_response", return_value=(response(body), None)):
                self.assertEqual(discovery.fetch_api_urls(object(), "https://example.com/", audit.ScanConfig()), set())

    def test_foreign_sitemap_is_never_fetched(self):
        called = []
        def fetch(session, url, config):
            called.append(url)
            return "Sitemap: https://foreign.invalid/map.xml" if url.endswith("robots.txt") else "<sitemapindex><sitemap><loc>https://foreign.invalid/nested.xml</loc></sitemap></sitemapindex>"
        with patch.object(discovery, "fetch_text", side_effect=fetch):
            discovery.crawl_sitemaps(object(), "https://example.com/", audit.ScanConfig())
        self.assertTrue(all(ScanScope("https://example.com/").allows(url) for url in called))
