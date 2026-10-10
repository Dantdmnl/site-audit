from __future__ import annotations

import io
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import requests
from urllib3.exceptions import HTTPError
from urllib3.response import HTTPResponse

from site_audit import reporting
from site_audit import cli as audit
from site_audit.core import ScanExecutor, ScanRuntime, ScanScope, TimeBudget, canonical_url, redacted_url, retry_delay


class ScopeTests(unittest.TestCase):
    def test_canonical_default_ports_ipv6_and_idna(self):
        self.assertEqual(canonical_url("https://EXAMPLE.com:443/a?q=1#x"), "https://example.com/a?q=1")
        self.assertEqual(canonical_url("http://[::1]:80/a"), "http://[::1]/a")
        self.assertEqual(canonical_url("https://b\u00fccher.example/"), "https://xn--bcher-kva.example/")

    def test_malformed_hosts_and_ports(self):
        for url in ("https://bad_host/", "https://-bad.example/", "http://example.com:0/", "ftp://example.com/", "http://example.com/a\x01"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                canonical_url(url)

    def test_scope_uses_effective_port_and_rejects_credentials(self):
        scope = ScanScope("https://example.com/")
        self.assertTrue(scope.allows("https://example.com:443/path"))
        self.assertFalse(scope.allows("https://example.com:8443/"))
        self.assertFalse(scope.allows("https://other.example.com/"))
        self.assertFalse(scope.allows("https://user@example.com/"))

    def test_initial_upgrade_is_narrow(self):
        scope = ScanScope("http://example.com/")
        self.assertTrue(scope.allows_upgrade("http://example.com/a", "https://example.com/a"))
        self.assertFalse(scope.allows_upgrade("http://example.com/a", "https://www.example.com/a"))
        self.assertFalse(scope.allows_upgrade("http://example.com/a", "https://example.com:8443/a"))
        self.assertFalse(ScanScope("https://example.com/").allows_upgrade("https://example.com/a", "http://example.com/a"))

    def test_proxy_redaction_removes_credentials_and_query(self):
        self.assertEqual(redacted_url("http://user:secret@proxy.example:8080/?token=private"), "http://proxy.example:8080/")

    def test_canonical_alias_scope_is_narrow(self):
        scope = ScanScope("https://example.co.uk/")
        self.assertTrue(scope.allows_canonical_alias(scope.target, "https://www.example.co.uk/"))
        for target in ("https://other.example.co.uk/", "https://www.example.co.uk:8443/", "http://www.example.co.uk/", "https://www.other.co.uk/"):
            with self.subTest(target=target):
                self.assertFalse(scope.allows_canonical_alias(scope.target, target))
        self.assertFalse(ScanScope("https://tenant.github.io/").allows_canonical_alias("https://tenant.github.io/", "https://other.github.io/"))
        self.assertFalse(ScanScope("https://shop.example.com/").allows_canonical_alias("https://shop.example.com/", "https://www.shop.example.com/"))


class CanonicalStartupTests(unittest.TestCase):
    def config(self, target="https://example.com/", **kwargs):
        return audit.ScanConfig(scope=ScanScope(target), runtime=ScanRuntime(TimeBudget(None), rate_limit=10000), retries=0, allow_initial_upgrade=True, allow_initial_canonical_redirect=True, **kwargs)

    def fetch_chain(self, config, redirects, *, set_cookie=False):
        records = []
        session = audit.build_session(config)

        def request(method, url, **kwargs):
            prepared = session.prepare_request(requests.Request(method, url))
            records.append((url, dict(prepared.headers)))
            result = requests.Response()
            result.request = prepared
            result.url = url
            result.status_code = 301 if url in redirects else 200
            if url in redirects:
                result.headers["Location"] = redirects[url]
            if set_cookie and len(records) == 1:
                session.cookies.set("origin-session", "do-not-forward", domain=".example.com", path="/")
            result.raw = HTTPResponse(body=io.BytesIO(b"home"), preload_content=False)
            return result

        with session, patch.object(session, "request", side_effect=request):
            response, error = audit.fetch_response(session, config.scope.target, config=config)
        return response, error, records

    def test_apex_www_resolves_and_locks_scope(self):
        config = self.config()
        response, error, records = self.fetch_chain(config, {"https://example.com/": "https://www.example.com/"})
        self.assertIsNone(error)
        self.assertEqual(response.url, "https://www.example.com/")
        self.assertEqual(len(records), 2)
        self.assertTrue(config.scope.allows(response.url))
        self.assertFalse(config.scope.allows("https://example.com/"))
        self.assertFalse(config.allow_initial_canonical_redirect)
        self.assertEqual(config.runtime.snapshot()["status"], "complete")

    def test_www_apex_resolves(self):
        config = self.config("https://www.example.com/")
        response, error, _ = self.fetch_chain(config, {"https://www.example.com/": "https://example.com/"})
        self.assertIsNone(error)
        self.assertEqual(response.url, "https://example.com/")

    def test_upgrade_then_www_resolves(self):
        config = self.config("http://example.com/")
        response, error, records = self.fetch_chain(config, {"http://example.com/": "https://example.com/", "https://example.com/": "https://www.example.com/"})
        self.assertIsNone(error)
        self.assertEqual(response.url, "https://www.example.com/")
        self.assertEqual(len(records), 3)

    def test_supplied_auth_or_headers_are_not_forwarded(self):
        jar = requests.cookies.RequestsCookieJar()
        jar.set("session", "secret")
        for kwargs in ({"auth": ("user", "secret")}, {"bearer_token": "secret"}, {"cookies": jar}, {"custom_headers": {"X-Api-Key": "secret"}}):
            with self.subTest(kwargs=list(kwargs)):
                config = self.config(**kwargs)
                response, error, records = self.fetch_chain(config, {"https://example.com/": "https://www.example.com/"})
                self.assertIsNone(response)
                self.assertEqual(len(records), 1)
                self.assertIn("use https://www.example.com/ as the target", error)
                self.assertEqual(config.runtime.blocked_requests, 1)

    def test_cookies_received_from_source_are_cleared(self):
        config = self.config()
        response, error, records = self.fetch_chain(config, {"https://example.com/": "https://www.example.com/"}, set_cookie=True)
        self.assertIsNone(error)
        self.assertIsNotNone(response)
        self.assertNotIn("Cookie", records[1][1])

    def test_alias_permission_is_consumed_by_startup(self):
        config = self.config()
        _, error, _ = self.fetch_chain(config, {})
        self.assertIsNone(error)
        response, error, records = self.fetch_chain(config, {"https://example.com/": "https://www.example.com/"})
        self.assertIsNone(response)
        self.assertIn("Out-of-scope", error)
        self.assertEqual(len(records), 1)

    def test_canonical_startup_does_not_allow_unrelated_hosts_or_downgrades(self):
        for destination in ("https://other.example.com/", "https://evil.invalid/", "https://www.example.com:8443/", "http://www.example.com/"):
            with self.subTest(destination=destination):
                config = self.config()
                response, error, records = self.fetch_chain(config, {"https://example.com/": destination})
                self.assertIsNone(error)
                self.assertEqual(response.status_code, 301)
                self.assertEqual(response._audit_blocked_redirect, destination)
                self.assertEqual(config.scope.target, "https://example.com/")
                self.assertEqual(config.runtime.snapshot()["status"], "partial")
                self.assertEqual(len(records), 1)

    def test_external_consent_redirect_preserves_in_scope_response(self):
        config = self.config()
        response, error, records = self.fetch_chain(config, {"https://example.com/": "https://www.example.com/", "https://www.example.com/": "https://consent.invalid/?token=private"})
        self.assertIsNone(error)
        self.assertEqual(response.url, "https://www.example.com/")
        self.assertEqual(response._audit_blocked_redirect, "https://consent.invalid/")
        self.assertEqual(len(records), 2)
        self.assertTrue(config.scope.allows(response.url))
        self.assertEqual(response.content, b"")


class TransportFailureTests(unittest.TestCase):
    def config(self, **kwargs):
        return audit.ScanConfig(scope=ScanScope("https://example.com/"), runtime=ScanRuntime(TimeBudget(None), rate_limit=10000), retries=0, **kwargs)

    def test_out_of_scope_url_is_rejected_before_request(self):
        session = Mock()
        cfg = self.config()
        response, error = audit.fetch_response(session, "https://other.example.com/", config=cfg)
        session.request.assert_not_called()
        self.assertIsNone(response)
        self.assertIn("scope", error)
        self.assertEqual(cfg.runtime.snapshot()["status"], "partial")

    def test_tls_errors_do_not_retry(self):
        session = Mock()
        session.request.side_effect = requests.exceptions.SSLError("certificate failed")
        cfg = self.config()
        cfg.retries = 3
        response, error = audit.fetch_response(session, cfg.scope.target, config=cfg)
        self.assertIsNone(response)
        self.assertIn("SSLError", error)
        self.assertEqual(session.request.call_count, 1)
        self.assertEqual(cfg.runtime.network_errors, 1)

    def test_read_error_closes_response_and_counts_failure(self):
        result = Mock(status_code=200, headers={})
        result.raw.read1.side_effect = HTTPError("broken stream")
        session = Mock()
        session.request.return_value = result
        cfg = self.config()
        self.assertIsNone(audit.fetch_response(session, cfg.scope.target, config=cfg)[0])
        result.close.assert_called_once()
        self.assertEqual(cfg.runtime.network_errors, 1)

    def test_head_response_does_not_read_body(self):
        result = Mock(status_code=200, headers={})
        session = Mock()
        session.request.return_value = result
        cfg = self.config()
        response, error = audit.fetch_response(session, cfg.scope.target, method="HEAD", config=cfg)
        self.assertIsNone(error)
        result.raw.read1.assert_not_called()
        self.assertEqual(response._content, b"")

    def test_cancelled_runtime_sends_nothing(self):
        cfg = self.config()
        cfg.runtime.stop.set()
        session = Mock()
        self.assertIsNone(audit.fetch_response(session, cfg.scope.target, config=cfg)[0])
        session.request.assert_not_called()

    def test_retry_after_is_capped_and_accepts_http_date(self):
        self.assertEqual(retry_delay("9000", 0), 5.0)
        self.assertEqual(retry_delay("Wed, 01 Jan 2020 00:00:00 GMT", 0), 0)
        self.assertEqual(retry_delay("not-a-date", 0), 0.4)

    def test_executor_signals_cancellation_on_exception(self):
        runtime = ScanRuntime(TimeBudget(None))
        with self.assertRaises(RuntimeError), ScanExecutor(1, runtime) as executor:
            executor.submit(lambda: 1).result()
            raise RuntimeError("abort")
        self.assertTrue(runtime.stop.is_set())

    def test_request_cap_is_shared_across_threads(self):
        runtime = ScanRuntime(TimeBudget(None), rate_limit=10000, max_requests=5)
        accepted = []
        threads = [threading.Thread(target=lambda: accepted.append(runtime.acquire())) for _ in range(20)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=1)
        self.assertEqual(sum(accepted), 5)
        self.assertEqual(runtime.requests_sent, 5)


class ExportTests(unittest.TestCase):
    def test_csv_formula_protection(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "report.csv"
            reporting.write_csv(str(path), [audit.Finding("INFO", "tech", "=HYPERLINK('evil')", "@formula")])
            value = path.read_text()
        self.assertIn("'=HYPERLINK", value)
        self.assertIn("'@formula", value)

    def test_html_escapes_evidence_and_records_partial_coverage(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "report.html"
            reporting.write_html_report(str(path), mode="audit", target="https://example.com/", platforms=[], settings={}, findings=[audit.Finding("INFO", "body", "example", "<script>bad()</script>", evidence="<img onerror=bad()>")], scan={"status": "partial", "reasons": ["body_limit"]})
            value = path.read_text()
        self.assertNotIn("<script>bad()", value)
        self.assertIn("&lt;img", value)
        self.assertIn("Status: partial", value)
        self.assertNotIn("fonts.googleapis", value)

    def test_atomic_failure_preserves_original_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "report.json"
            reporting.write_json_atomic(str(path), {"original": True})
            with patch.object(reporting._os, "replace", side_effect=OSError("denied")), self.assertRaises(OSError):
                reporting.write_json_atomic(str(path), {"original": False})
            self.assertIn('"original": true', path.read_text())
            self.assertEqual(list(Path(tmp).glob("*.tmp")), [])

    def test_env_secrets_are_not_persisted_or_printed(self):
        args = audit.parse_args(["https://example.com", "--dry-run", "--bearer-token-env", "SITE_AUDIT_TEST_SECRET", "--no-save-last", "--no-save-prefs"])
        out = io.StringIO()
        with patch.dict(audit._os.environ, {"SITE_AUDIT_TEST_SECRET": "private-env-token"}), patch.object(audit, "build_session", wraps=audit.build_session) as build, patch("sys.stdout", out):
            self.assertEqual(audit.run_scan(args), 0)
            self.assertEqual(build.call_args.args[0].bearer_token, "private-env-token")
        self.assertNotIn("private-env-token", out.getvalue())
        self.assertNotIn("bearer_token_env", audit.update_preferences_from_args({}, args)["defaults"])

    def test_missing_env_secret_is_configuration_error(self):
        args = audit.parse_args(["https://example.com", "--dry-run", "--bearer-token-env", "ABSENT_SITE_AUDIT_TEST_ENV"])
        with patch.dict(audit._os.environ, {}, clear=True), patch("sys.stdout", io.StringIO()):
            self.assertEqual(audit.run_scan(args), 1)
