from __future__ import annotations

import gzip
import json
import tempfile
import threading
import time
import unittest
from contextlib import redirect_stdout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from site_audit import network
from site_audit import cli as audit
from site_audit.core import ScanRuntime, ScanScope, TimeBudget


class Handler(BaseHTTPRequestHandler):
    records: list = []
    attempts = 0
    foreign = ""

    def log_message(self, *args):
        pass

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Allow", "GET, HEAD, OPTIONS, PUT")
        self.end_headers()

    def do_GET(self):
        type(self).records.append((self.path, dict(self.headers)))
        status, headers, body = 200, {}, b"<html><body>Home</body></html>"
        if self.path == "/redirect":
            status, headers = 302, {"Location": "/final?x=1"}
        elif self.path == "/foreign":
            status, headers = 302, {"Location": type(self).foreign + "/stolen"}
        elif self.path == "/loop":
            status, headers = 302, {"Location": "/loop"}
        elif self.path == "/invalid-redirect":
            status, headers = 302, {"Location": "file:///etc/passwd"}
        elif self.path == "/limited":
            status = 429
        elif self.path == "/retry":
            type(self).attempts += 1
            status = 503 if type(self).attempts == 1 else 200
            headers = {"Retry-After": "0"}
        elif self.path == "/large":
            body = b"a" * 10000
        elif self.path == "/compressed":
            body, headers = gzip.compress(b"a" * 10000), {"Content-Encoding": "gzip"}
        elif self.path == "/slow":
            time.sleep(0.35)
        elif self.path == "/.env":
            body, headers = b"DB_PASSWORD=fixture-private-value\nAPP_ENV=production", {"Content-Type": "text/plain"}
        elif self.path == "/secrets.json":
            body = b"<html><body>Sign in to continue</body></html>"
        elif self.path.startswith("/api/") or self.path.startswith("/wp-json/"):
            body, headers = b"42", {"Content-Type": "application/json"}
        elif self.path in ("/robots.txt", "/sitemap.xml", "/sitemap_index.xml"):
            body, headers = b"", {"Content-Type": "text/plain"}
        elif self.path not in ("/", "/final?x=1"):
            status, body = 404, b"Not found"
        self.send_response(status)
        self.send_header("Content-Type", headers.pop("Content-Type", "text/html"))
        for key, value in headers.items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            pass


class LocalHTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.foreign_server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.base = f"http://127.0.0.1:{cls.server.server_port}/"
        Handler.foreign = f"http://127.0.0.1:{cls.foreign_server.server_port}"
        cls.threads = []
        for server in (cls.server, cls.foreign_server):
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            cls.threads.append(thread)

    @classmethod
    def tearDownClass(cls):
        for server in (cls.server, cls.foreign_server):
            server.shutdown()
            server.server_close()
        for thread in cls.threads:
            thread.join(timeout=2)

    def setUp(self):
        Handler.records.clear()
        Handler.attempts = 0

    def config(self, **kwargs):
        return audit.ScanConfig(scope=ScanScope(self.base), runtime=ScanRuntime(TimeBudget(None), rate_limit=1000), retries=0, **kwargs)

    def fetch(self, path, config=None):
        cfg = config or self.config()
        with audit.build_session(cfg) as session:
            result = audit.fetch_response(session, self.base + path, config=cfg)
        return result

    def test_same_origin_redirect_keeps_query(self):
        response, error = self.fetch("redirect")
        self.assertIsNone(error)
        self.assertTrue(response.url.endswith("/final?x=1"))
        self.assertEqual(len(response.history), 1)

    def test_foreign_redirect_never_sends_credentials(self):
        cfg = self.config(custom_headers={"X-Secret": "private"}, bearer_token="token")
        response, error = self.fetch("foreign", cfg)
        self.assertIsNone(response)
        self.assertIn("scope", error)
        self.assertEqual([entry[0] for entry in Handler.records], ["/foreign"])
        self.assertEqual(cfg.runtime.blocked_requests, 1)

    def test_redirect_loop_is_bounded(self):
        cfg = self.config(max_redirects=2)
        response, error = self.fetch("loop", cfg)
        self.assertIsNone(response)
        self.assertEqual(cfg.runtime.requests_sent, 3)
        self.assertIn("redirect", error.lower())

    def test_invalid_redirect_is_a_partial_scan(self):
        cfg = self.config()
        self.assertIsNone(self.fetch("invalid-redirect", cfg)[0])
        self.assertEqual(cfg.runtime.requests_sent, 1)
        self.assertIn("invalid_redirect", cfg.runtime.snapshot()["reasons"])

    def test_429_is_reported_as_incomplete(self):
        cfg = self.config()
        response, error = self.fetch("limited", cfg)
        self.assertIsNone(error)
        self.assertEqual(response.status_code, 429)
        self.assertIn("rate_limited", cfg.runtime.snapshot()["reasons"])

    def test_decoded_body_limits_cover_plain_and_compressed(self):
        for path in ("large", "compressed"):
            with self.subTest(path=path):
                cfg = self.config(max_body_bytes=1024)
                response, error = self.fetch(path, cfg)
                self.assertIsNone(response)
                self.assertIn("max-body", error)
                self.assertIn("body_limit", cfg.runtime.snapshot()["reasons"])

    def test_retry_counts_every_attempt(self):
        cfg = self.config()
        cfg.retries = 1
        response, error = self.fetch("retry", cfg)
        self.assertIsNone(error)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(cfg.runtime.requests_sent, 2)

    def test_request_limit_prevents_retry(self):
        cfg = self.config()
        cfg.retries = 1
        cfg.runtime.max_requests = 1
        response, error = self.fetch("retry", cfg)
        self.assertIsNone(response)
        self.assertEqual(Handler.attempts, 1)
        self.assertIn("request_limit", cfg.runtime.snapshot()["reasons"])

    def test_deadline_caps_request_timeout(self):
        cfg = self.config()
        cfg.runtime.budget = TimeBudget(0.1)
        started = time.monotonic()
        response, error = self.fetch("slow", cfg)
        self.assertIsNone(response)
        self.assertIsNotNone(error)
        self.assertLess(time.monotonic() - started, 0.3)

    def test_global_rate_limit(self):
        cfg = self.config()
        cfg.runtime.rate_limit = 10
        started = time.monotonic()
        with audit.build_session(cfg) as session:
            for _ in range(3):
                audit.fetch_response(session, self.base, config=cfg)
        self.assertGreaterEqual(time.monotonic() - started, 0.18)

    def test_exhausted_budget_sends_nothing(self):
        cfg = self.config()
        cfg.runtime.budget = TimeBudget(0)
        self.assertIsNone(self.fetch("", cfg)[0])
        self.assertEqual(Handler.records, [])

    def test_report_preserves_findings_and_ports_and_threshold(self):
        with tempfile.TemporaryDirectory() as temp:
            destination = Path(temp) / "report.json"
            args = audit.parse_args([self.base, "--output", str(destination), "--ports", str(self.server.server_port), "--min-severity", "CRITICAL", "--fail-on", "CRITICAL", "--rate-limit", "1000", "--retries", "0", "--no-save-last", "--no-save-prefs", "--no-load-prefs"])
            with redirect_stdout(StringIO()):
                code = audit.run_scan(args)
            report = json.loads(destination.read_text())
        self.assertEqual(code, 2)
        self.assertEqual(report["scan"]["status"], "complete")
        self.assertEqual(report["ports"][str(self.server.server_port)], True)
        self.assertTrue(any(f["severity"] == "INFO" for f in report["findings"]))
        self.assertEqual(len([f for f in report["findings"] if f["severity"] == "CRITICAL"]), 1)
        self.assertNotIn("fixture-private-value", json.dumps(report))

    def test_strict_partial_scan_has_distinct_exit(self):
        args = audit.parse_args([self.base, "--strict", "--max-requests", "2", "--rate-limit", "1000", "--no-save-last", "--no-save-prefs", "--no-load-prefs"])
        with redirect_stdout(StringIO()):
            self.assertEqual(audit.run_scan(args), 3)

    def test_dry_run_does_not_discover_pac_or_request(self):
        args = audit.parse_args([self.base, "--dry-run", "--system-proxy", "--no-save-last", "--no-save-prefs", "--no-load-prefs"])
        with patch.object(network.pypac, "get_pac", side_effect=AssertionError("PAC should not run")), redirect_stdout(StringIO()):
            self.assertEqual(audit.run_scan(args), 0)
        self.assertEqual(Handler.records, [])

    def test_discovery_report_ignores_scalar_json_and_dry_run_keeps_mode(self):
        for dry in (False, True):
            with tempfile.TemporaryDirectory() as tmp:
                destination = Path(tmp) / "inventory.json"
                tokens = [self.base, "--mode", "discover", "--output", str(destination), "--rate-limit", "1000", "--retries", "0", "--no-save-last", "--no-save-prefs", "--no-load-prefs"]
                if dry:
                    tokens.append("--dry-run")
                with redirect_stdout(StringIO()):
                    self.assertEqual(audit.run_scan(audit.parse_args(tokens)), 0)
                report = json.loads(destination.read_text())
                self.assertEqual(report["mode"], "discover")
                self.assertEqual(report["scan"]["status"], "dry_run" if dry else "complete")
                self.assertIn("discovered", report["result"])

    def test_initial_failure_writes_partial_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            destination = Path(tmp) / "failure.json"
            args = audit.parse_args([self.base, "--output", str(destination), "--no-save-last", "--no-save-prefs"])
            with patch.object(audit, "fetch_response", return_value=(None, "ConnectionError")), redirect_stdout(StringIO()):
                self.assertEqual(audit.run_scan(args), 1)
            report = json.loads(destination.read_text())
            self.assertEqual(report["scan"]["status"], "partial")
            self.assertIn("initial_connection_failed", report["scan"]["reasons"])

    def test_external_startup_redirect_runs_in_scope_and_skips_document_headers(self):
        with tempfile.TemporaryDirectory() as tmp:
            destination = Path(tmp) / "redirect.json"
            args = audit.parse_args([self.base + "foreign", "--output", str(destination), "--strict", "--max-requests", "10", "--rate-limit", "1000", "--retries", "0", "--no-save-last", "--no-save-prefs", "--no-load-prefs"])
            with redirect_stdout(StringIO()):
                self.assertEqual(audit.run_scan(args), 3)
            report = json.loads(destination.read_text())
        self.assertEqual(report["scan"]["status"], "partial")
        self.assertIn("scope_blocked", report["scan"]["reasons"])
        self.assertTrue(any(f["rule_id"] == "scope.startup-redirect" for f in report["findings"]))
        self.assertFalse(any(f["category"] == "header" for f in report["findings"]))
        self.assertFalse(any(path == "/stolen" for path, _ in Handler.records))
