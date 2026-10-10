from __future__ import annotations

import io
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

import site_audit as audit


def state():
    return {**audit.PREF_DEFAULTS, "_provided": set()}


class InteractiveSettingsTests(unittest.TestCase):
    def test_request_controls_round_trip_into_parser(self):
        settings = state()
        for key, value in (("rate-limit", "2.5"), ("max-requests", "75"), ("max-body-bytes", "2048"), ("ports", "80,443"), ("strict", "true"), ("system-proxy", "true")):
            audit.update_interactive_setting(settings, key, value)
        args = audit.parse_args(audit.build_interactive_tokens("https://example.com/", settings, []))
        self.assertEqual((args.rate_limit, args.max_requests, args.max_body_bytes, args.ports), (2.5, 75, 2048, "80,443"))
        self.assertTrue(args.strict)
        self.assertTrue(args.system_proxy)

    def test_explicit_default_survives_profile_and_preferences(self):
        settings = state()
        audit.update_interactive_setting(settings, "profile", "quick")
        audit.update_interactive_setting(settings, "workers", "20")
        prefs = audit.update_preferences_from_state({}, settings)
        self.assertEqual(prefs["defaults"]["workers"], 20)
        args = audit.parse_args(audit.build_interactive_tokens("https://example.com/", settings, []))
        self.assertIn("workers", args._provided)

    def test_negative_flags_override_saved_boolean_values(self):
        args = audit.parse_args(["https://example.com/", "--no-insecure", "--no-strict", "--no-system-proxy", "--no-verbose", "--no-discover-subdomains"])
        audit.apply_preferences_to_args(args, {"defaults": {"insecure": True, "strict": True, "system_proxy": True, "verbose": True, "discover_subdomains": True}})
        self.assertFalse(args.insecure or args.strict or args.system_proxy or args.verbose or args.discover_subdomains)

    def test_unset_restores_default_and_removes_explicit_marker(self):
        settings = state()
        audit.update_interactive_setting(settings, "max-requests", "25")
        audit.unset_interactive_setting(settings, "max-requests")
        self.assertEqual(settings["max_requests"], 1000)
        self.assertNotIn("max_requests", settings["_provided"])

    def test_invalid_numeric_settings_do_not_mutate_state(self):
        for key, value in (("workers", "201"), ("timeout", "0"), ("retries", "11"), ("time-budget", "-1"), ("rate-limit", "nan"), ("max-requests", "0"), ("max-body-bytes", "10")):
            settings = state()
            with self.subTest(key=key), self.assertRaises(ValueError):
                audit.update_interactive_setting(settings, key, value)
            self.assertEqual(settings, state())

    def test_windows_paths_preserve_backslashes_and_spaces(self):
        tokens = audit.split_interactive_line('example.com --output "C:\\Audit Reports\\report.json"', windows=True)
        self.assertEqual(tokens[-1], "C:\\Audit Reports\\report.json")
        self.assertEqual(audit.split_interactive_line("example.com --output C:\\reports\\a.json", windows=True)[-1], "C:\\reports\\a.json")

    def test_history_redacts_secrets_in_separate_and_equals_forms(self):
        line = 'scan example.com --basic-user admin --basic-pass password123 --bearer-token=token123 --cookie "session=cookie123" --header "X-Key:header123" --proxy http://user:proxy123@proxy.example'
        redacted = audit.redact_history_line(line)
        for value in ("admin", "password123", "token123", "cookie123", "header123", "proxy123"):
            self.assertNotIn(value, redacted)
        self.assertIn("example.com", redacted)
        self.assertIn("redacted", redacted)

    def test_malformed_history_command_does_not_store_original(self):
        self.assertEqual(audit.redact_history_line('scan example.com --bearer-token "private'), "<unparsed command omitted>")

    @unittest.skipUnless(audit.HAS_PROMPT_TOOLKIT, "prompt_toolkit unavailable")
    def test_prompt_toolkit_persists_only_redacted_commands(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "history"
            history = audit.RedactedFileHistory(str(path))
            history.append_string("scan example.com --bearer-token private-token")
            self.assertNotIn("private-token", path.read_text())
            self.assertNotIn("private-token", str(history.get_strings()))


class InteractiveSessionTests(unittest.TestCase):
    def session(self, commands, initial=None, **patches):
        args = initial or audit.parse_args(["--no-load-prefs", "--no-save-prefs", "--no-save-last"])
        output = io.StringIO()
        with patch.object(audit, "HAS_PROMPT_TOOLKIT", False), patch("builtins.input", side_effect=commands), patch.object(audit, "run_scan", return_value=0) as scan, patch.object(audit, "save_preferences") as save, patch.object(audit, "load_preferences", return_value={}) as load, redirect_stdout(output):
            audit.interactive_mode(args.workers, initial_args=args)
        return output.getvalue(), scan, save, load

    def test_initial_limits_and_privacy_flags_reach_scans(self):
        args = audit.parse_args(["--rate-limit", "3", "--max-requests", "9", "--no-load-prefs", "--no-save-prefs", "--no-save-last", "--last-scope", "project"])
        _, scan, save, load = self.session(["set workers 4", "example.com", "exit"], args)
        load.assert_not_called()
        save.assert_not_called()
        scan_args = scan.call_args.args[0]
        self.assertEqual((scan_args.workers, scan_args.rate_limit, scan_args.max_requests), (4, 3, 9))
        self.assertTrue(scan_args.no_save_last)
        self.assertEqual(scan_args.last_scope, "project")

    def test_invalid_command_is_recoverable(self):
        output, scan, _, _ = self.session(["unknown", "set rate-limit 0", "example.com", "exit"])
        self.assertIn("Unknown command", output)
        self.assertIn("Set error", output)
        scan.assert_called_once()

    def test_export_os_error_does_not_end_session(self):
        with patch.object(audit, "export_last_report", side_effect=OSError("denied")):
            output, scan, _, _ = self.session(["export report.html", "example.com", "exit"])
        self.assertIn("Export failed", output)
        scan.assert_called_once()

    def test_version_command_stays_in_session(self):
        output, scan, _, _ = self.session(["version", "exit"])
        self.assertIn(audit.__version__, output)
        scan.assert_not_called()
