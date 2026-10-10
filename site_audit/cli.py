"""Command-line parsing, interactive sessions, and scan orchestration."""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os as _os
import re
import shlex
import sys
import time
import uuid
from concurrent.futures import FIRST_COMPLETED, wait
from dataclasses import asdict
from datetime import datetime, timezone
from http.cookies import SimpleCookie
from typing import TypedDict
from urllib.parse import urljoin, urlparse

from .core import ScanExecutor, ScanRuntime, ScanScope, TimeBudget, canonical_url, redacted_url
from .rules import HEADER_REFERENCE, challenge_page, header_checks, sensitive_match
from .report_validation import load_report

from .catalog import COMMON_PATHS, PLATFORM_PATHS, TECH_HEADERS, WAPPALYZER_RULES, BODY_PATTERNS_COMPILED
from .defaults import (
    TIMEOUT, MAX_WORKERS, RETRIES, PREFS_VERSION, USER_PREFS_FILENAME,
    PROJECT_PREFS_FILENAME, USER_LAST_FILENAME, PROJECT_LAST_FILENAME, PROFILE_DEFAULTS,
    PROFILE_ALLOWED_SEVERITIES, IMPORTANT_PATHS, PREF_KEYS, PREF_DEFAULTS, TEXTUAL_CONTENT_TYPES,
    COLOURS, DISCOVER_SUBDOMAIN_PREFIXES, HEADER_NAME_RE, SEVERITY_ORDER,
)
from .models import Finding, ScanConfig, BodyFingerprint, severity_index, has_findings_at_or_above
from .network import build_session, ThreadLocalSessionPool, scan_ports, get_ports_for_url, fetch_response
from .discovery import discover_mode
from .reporting import write_json_atomic, write_report
from .version import APP_NAME, SCHEMA_VERSION as REPORT_SCHEMA_VERSION, VERSION as __version__

import requests
import urllib3
from bs4 import BeautifulSoup
from requests.cookies import RequestsCookieJar
from urllib3.exceptions import InsecureRequestWarning

try:
    from prompt_toolkit import PromptSession as PT_PromptSession
    from prompt_toolkit.completion import Completer as PT_Completer, Completion as PT_Completion
    from prompt_toolkit.document import Document as PT_Document
    from prompt_toolkit.history import FileHistory as PT_FileHistory, DummyHistory as PT_DummyHistory
    HAS_PROMPT_TOOLKIT = True
except ImportError:
    HAS_PROMPT_TOOLKIT = False


LOGGER = logging.getLogger("site-audit")


INTERACTIVE_COMMANDS = [
    "scan",
    "audit",
    "discover",
    "export",
    "set",
    "unset",
    "show",
    "history",
    "clear",
    "help",
    "version",
    "exit",
    "quit",
]

INTERACTIVE_SET_KEYS = [
    "mode",
    "profile",
    "format",
    "min-severity",
    "workers",
    "timeout",
    "time-budget",
    "retries",
    "insecure",
    "fail-on",
    "verbose",
    "log-file",
    "output",
    "report-title",
    "report-brand",
    "report-logo",
    "rate-limit", "max-requests", "max-body-bytes", "ports", "proxy", "system-proxy", "strict", "discover-subdomains",
]

INTERACTIVE_UNSET_KEYS = list(INTERACTIVE_SET_KEYS)

INTERACTIVE_FLAGS = [
    "--mode",
    "--profile",
    "--format",
    "--output",
    "--min-severity",
    "--workers",
    "--timeout",
    "--time-budget",
    "--retries",
    "--insecure",
    "--fail-on",
    "--verbose",
    "--log-file",
    "--report-title",
    "--report-brand",
    "--report-logo",
    "--export-scope",
    "--no-load-prefs",
    "--no-save-prefs",
    "--prefs-scope",
    "--no-save-last",
    "--last-scope",
    "--basic-user",
    "--basic-pass",
    "--bearer-token",
    "--cookie",
    "--discover-subdomains",
    "--rate-limit", "--max-requests", "--max-body-bytes", "--ports", "--proxy", "--header", "--system-proxy", "--strict",
    "--no-insecure", "--no-verbose", "--no-system-proxy", "--no-strict", "--no-discover-subdomains", "--bearer-token-env", "--basic-pass-env", "--dry-run",
]


def c(colour: str, text: str) -> str:
    if not sys.stdout.isatty():
        return text
    return f"{COLOURS.get(colour, '')}{text}{COLOURS['RESET']}"


def setup_logging(verbose: bool, log_file: str | None) -> None:
    level = logging.DEBUG if verbose else logging.WARNING
    handlers: list[logging.Handler] = [logging.StreamHandler()]
    if log_file:
        log_dir = _os.path.dirname(_os.path.abspath(log_file))
        if log_dir:
            _os.makedirs(log_dir, exist_ok=True)
        handlers.append(logging.FileHandler(log_file, encoding="utf-8"))

    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        handlers=handlers,
        force=True,
    )

    # Suppress noisy urllib3 connection pool retry warnings (they clutter output)
    # but keep ERROR level for real issues
    logging.getLogger("urllib3.connectionpool").setLevel(logging.ERROR)
    logging.getLogger("urllib3.util.retry").setLevel(logging.ERROR)


def should_inspect_body(resp: requests.Response) -> bool:
    if not resp.ok:
        return False
    content_type = (resp.headers.get("Content-Type", "").split(";", 1)[0].strip().lower())
    if content_type and not any(content_type.startswith(prefix) for prefix in TEXTUAL_CONTENT_TYPES):
        return False
    return len(resp.text) <= 500_000


def clean_snippet(text: str) -> str:
    sanitized = re.sub(r"[\r\n\t]+", " ", text)
    sanitized = re.sub(r"\s{2,}", " ", sanitized).strip()
    return sanitized[:220]


def normalize_body_text(text: str) -> str:
    # Strip dynamic tokens to improve soft-404 matching.
    cleaned = re.sub(r"\b[0-9a-f]{8,}\b", " ", text, flags=re.I)
    cleaned = re.sub(r"\b\d+\b", " ", cleaned)
    cleaned = re.sub(r"\s+", " ", cleaned).strip().lower()
    return cleaned[:200_000]


def normalize_visible_text(html_text: str) -> str:
    soup = BeautifulSoup(html_text, "html.parser")
    for tag in soup(("script", "style", "noscript", "template")):
        tag.decompose()
    cleaned = re.sub(r"\s+", " ", soup.get_text(" ", strip=True)).strip().lower()
    return cleaned[:50_000]


def body_fingerprint(resp: requests.Response) -> BodyFingerprint | None:
    if not should_inspect_body(resp):
        return None
    content_type = resp.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
    normalized = normalize_body_text(resp.text)
    if not normalized:
        return None
    digest = hashlib.sha256(normalized.encode("utf-8", errors="ignore")).hexdigest()
    visible = normalize_visible_text(resp.text) if "html" in content_type else ""
    visible_digest = hashlib.sha256(visible.encode("utf-8", errors="ignore")).hexdigest() if visible else ""
    return BodyFingerprint(
        content_type=content_type,
        hash=digest,
        length=len(normalized),
        visible_hash=visible_digest,
        visible_length=len(visible),
    )


def is_soft_404(resp: requests.Response, profiles: list[BodyFingerprint]) -> bool:
    fingerprint = body_fingerprint(resp)
    if not fingerprint:
        return False
    for profile in profiles:
        if fingerprint.content_type == profile.content_type and fingerprint.hash == profile.hash:
            return True
        if (
            fingerprint.content_type == profile.content_type
            and fingerprint.visible_hash
            and fingerprint.visible_hash == profile.visible_hash
            and abs(fingerprint.visible_length - profile.visible_length) <= 200
        ):
            return True
    return False


def build_soft_404_profiles(
    session: requests.Session,
    base_url: str,
    homepage: requests.Response | None,
    config: ScanConfig,
    time_budget: TimeBudget | None = None,
) -> list[BodyFingerprint]:
    profiles: list[BodyFingerprint] = []
    if time_budget:
        remaining = time_budget.remaining()
        if remaining is not None and remaining < 3:
            return profiles

    random_path = f"__site_audit_{uuid.uuid4().hex}.html"
    resp, _ = fetch_response(
        session,
        urljoin(base_url, random_path),
        allow_redirects=True,
        config=config,
    )
    if resp is not None and resp.ok:
        fp = body_fingerprint(resp)
        if fp:
            profiles.append(fp)
    return profiles


def deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple] = set()
    unique: list[Finding] = []
    for finding in findings:
        key = (
            finding.severity,
            finding.category,
            finding.title,
            finding.detail,
            finding.url,
            finding.status_code,
            json.dumps(finding.extra, sort_keys=True, default=str),
        )
        if key not in seen:
            seen.add(key)
            unique.append(finding)
    return unique


def filter_paths_for_profile(
    paths: list[tuple[str, str, str]],
    profile: str,
) -> list[tuple[str, str, str]]:
    allowed = PROFILE_ALLOWED_SEVERITIES.get(profile)
    if not allowed:
        return paths
    return [
        (path, sev, desc)
        for path, sev, desc in paths
        if sev in allowed or path in IMPORTANT_PATHS
    ]


def parse_cookie_values(values: list[str]) -> RequestsCookieJar:
    jar = RequestsCookieJar()
    for raw in values:
        for part in raw.split(";"):
            if "=" not in part:
                continue
            name, value = part.split("=", 1)
            name = name.strip()
            if not name:
                continue
            jar.set(name, value.strip())
    return jar


def audit_header_versions(response: requests.Response) -> list[Finding]:
    findings: list[Finding] = []
    for header in TECH_HEADERS:
        val = response.headers.get(header)
        if not val:
            continue
        if re.search(r"\d+\.\d+(?:\.\d+)?", val):
            findings.append(Finding(
                severity="LOW", category="tech",
                title=f"Version disclosed via {header}",
                detail=f"{header}: {val}",
                url=str(response.url),
            ))
    return findings


def audit_cache_headers(response: requests.Response) -> list[Finding]:
    if not response.ok:
        return []
    if "Set-Cookie" not in response.headers:
        return []
    cache_control = response.headers.get("Cache-Control", "").lower()
    pragma = response.headers.get("Pragma", "").lower()
    if ("no-store" not in cache_control and "no-cache" not in cache_control and "no-cache" not in pragma):
        return [Finding(
            severity="LOW", category="header",
            title="Cache headers missing on response with cookies",
            detail="Set-Cookie without Cache-Control no-store/no-cache",
            url=str(response.url),
        )]
    return []


def parse_custom_headers(header_values: list[str]) -> dict[str, str]:
    headers: dict[str, str] = {}
    for header_str in header_values:
        if ":" not in header_str:
            raise ValueError(f"Invalid header {header_str!r}; expected KEY:VALUE")
        key, val = header_str.split(":", 1)
        key = key.strip()
        if not key or not HEADER_NAME_RE.fullmatch(key):
            raise ValueError(f"Invalid header name {key!r}")
        if "\r" in val or "\n" in val:
            raise ValueError(f"Invalid header value for {key!r}")
        headers[key] = val.strip()
    return headers


def validate_proxy_url(proxy: str | None) -> str | None:
    if not proxy:
        return None
    parsed = urlparse(proxy)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("proxy must use http or https")
    if not parsed.hostname:
        raise ValueError("proxy URL must include a hostname")
    if parsed.port == 0:
        raise ValueError("proxy port must be 1..65535")
    if any(ord(ch) < 32 for ch in proxy):
        raise ValueError("proxy URL contains control characters")
    return proxy


def normalize_output_target(output_path: str | None, output_format: str) -> tuple[str | None, str]:
    if not output_path:
        return output_path, output_format
    base = _os.path.basename(output_path)
    name, ext = _os.path.splitext(base)
    if not ext:
        if base in ("json", "csv", "xml", "html"):
            return f"report.{base}", base
        return f"{output_path}.{output_format}", output_format
    return output_path, output_format


def _prefs_user_path() -> str:
    return _os.path.join(_os.path.expanduser("~"), USER_PREFS_FILENAME)


def _prefs_project_path() -> str:
    return _os.path.join(_os.getcwd(), PROJECT_PREFS_FILENAME)


def _last_user_path() -> str:
    return _os.path.join(_os.path.expanduser("~"), USER_LAST_FILENAME)


def _last_project_path() -> str:
    return _os.path.join(_os.getcwd(), PROJECT_LAST_FILENAME)


def _load_prefs_file(path: str) -> dict:
    if not _os.path.isfile(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8-sig") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError, ValueError):
        return {}
    if not isinstance(data, dict):
        return {}
    return data


def _merge_prefs(base: dict, override: dict) -> dict:
    merged = dict(base)
    defaults = dict(base.get("defaults", {}))
    incoming = override.get("defaults", {})
    if isinstance(incoming, dict):
        defaults.update(incoming)
    merged["defaults"] = defaults
    if "version" in override:
        merged["version"] = override["version"]
    return merged


def load_preferences() -> dict:
    prefs: dict = {"version": PREFS_VERSION, "defaults": {}}
    prefs = _merge_prefs(prefs, _load_prefs_file(_prefs_user_path()))
    prefs = _merge_prefs(prefs, _load_prefs_file(_prefs_project_path()))
    return prefs


def _normalize_pref_defaults(values: dict, provided: set[str] | None = None) -> dict:
    normalized: dict = {}
    for key in PREF_KEYS:
        if key not in values or key == "proxy":
            continue
        value = values[key]
        if value == PREF_DEFAULTS.get(key) and key not in (provided or set()):
            continue
        normalized[key] = value
    return normalized


def apply_preferences_to_args(args: argparse.Namespace, prefs: dict) -> None:
    configured = set(getattr(args, "_provided", set()))
    args._configured = configured
    defaults = prefs.get("defaults", {}) or {}
    if not isinstance(defaults, dict):
        return
    for key in PREF_KEYS:
        if key not in defaults:
            continue
        if not hasattr(args, key):
            continue
        if key not in configured:
            value = defaults[key]
            expected = PREF_DEFAULTS.get(key)
            if expected is not None and type(value) is not type(expected):
                continue
            if key in {"output", "log_file", "report_logo", "ports", "proxy"} and value is not None and not isinstance(value, str):
                continue
            if key in {"workers", "timeout", "retries", "time_budget", "max_requests", "max_body_bytes"} and value is not None and (type(value) is not int or value < (0 if key == "retries" else 1)):
                continue
            if key in {"mode", "profile", "format", "min_severity", "fail_on"} and value is not None:
                choices = {"mode": ("audit", "discover"), "profile": PROFILE_DEFAULTS, "format": ("json", "csv", "xml", "html"), "min_severity": SEVERITY_ORDER, "fail_on": SEVERITY_ORDER}
                if value not in choices[key]:
                    continue
            setattr(args, key, value)
            configured.add(key)
    args._configured = configured


def apply_preferences_to_state(state: InteractiveState, prefs: dict) -> None:
    args = argparse.Namespace(**state)
    apply_preferences_to_args(args, prefs)
    for key in state:
        state[key] = getattr(args, key)
    state["_provided"] = args._configured


def update_preferences_from_state(prefs: dict, state: InteractiveState) -> dict:
    defaults = {key: state.get(key) for key in PREF_KEYS if key in state}
    prefs["defaults"] = _normalize_pref_defaults(defaults, state.get("_provided", set()))
    prefs["version"] = PREFS_VERSION
    return prefs


def update_preferences_from_args(prefs: dict, args: argparse.Namespace) -> dict:
    defaults = {}
    for key in PREF_KEYS:
        if key != "proxy" and hasattr(args, key):
            defaults[key] = getattr(args, key)
    prefs["defaults"] = _normalize_pref_defaults(defaults, getattr(args, "_configured", getattr(args, "_provided", set())))
    prefs["version"] = PREFS_VERSION
    return prefs


def save_preferences(prefs: dict, scope: str) -> None:
    payload = {
        "version": PREFS_VERSION,
        "defaults": prefs.get("defaults", {}) or {},
    }
    if scope in ("user", "both"):
        write_json_atomic(_prefs_user_path(), payload)
    if scope in ("project", "both"):
        write_json_atomic(_prefs_project_path(), payload)


def _load_last_report(scope: str) -> dict | None:
    candidates: list[str] = []
    if scope == "user":
        candidates = [_last_user_path()]
    elif scope == "project":
        candidates = [_last_project_path()]
    else:
        candidates = [_last_project_path(), _last_user_path()]

    for path in candidates:
        if _os.path.isfile(path):
            return load_report(path)
    return None


def save_last_report(report: dict, scope: str) -> None:
    if scope in ("user", "both"):
        write_json_atomic(_last_user_path(), report)
    if scope in ("project", "both"):
        write_json_atomic(_last_project_path(), report)


def export_last_report(
    output_path: str,
    output_format: str,
    scope: str,
    *,
    report_title: str,
    report_brand: str,
    report_logo: str | None,
) -> int:
    try:
        report = _load_last_report(scope)
    except (OSError, ValueError, TypeError, UnicodeError):
        print("[ERROR] Stored report is invalid or unreadable; run a new scan to replace it")
        return 1
    if not report:
        print("[ERROR] No previous report found to export")
        return 1
    return write_report(report, output_path, output_format, report_title=report_title, report_brand=report_brand, report_logo=report_logo)


class InteractiveState(TypedDict):
    mode: str
    profile: str
    format: str
    output: str | None
    min_severity: str
    workers: int
    timeout: int
    time_budget: int | None
    retries: int
    insecure: bool
    fail_on: str | None
    verbose: bool
    log_file: str | None
    report_title: str
    report_brand: str
    report_logo: str | None
    rate_limit: float
    max_requests: int
    max_body_bytes: int
    ports: str | None
    proxy: str | None
    system_proxy: bool
    discover_subdomains: bool
    strict: bool
    _provided: set[str]


if HAS_PROMPT_TOOLKIT:
    class RedactedFileHistory(PT_FileHistory):
        def load_history_strings(self):
            for string in super().load_history_strings():
                yield redact_history_line(string)

        def append_string(self, string: str) -> None:
            super().append_string(redact_history_line(string))

    class SiteAuditCompleter(PT_Completer):
        def get_completions(self, document: PT_Document, complete_event):
            text = document.text_before_cursor
            current = document.get_word_before_cursor(WORD=True)
            current_lower = current.lower()

            try:
                tokens = split_interactive_line(text)
            except ValueError:
                tokens = text.strip().split()

            at_new_token = text.endswith(" ")
            if at_new_token:
                tokens.append("")

            if not tokens or tokens == [""]:
                for cmd in INTERACTIVE_COMMANDS:
                    yield PT_Completion(cmd, start_position=-len(current))
                return

            first = (tokens[0] or "").lower()

            if len(tokens) == 1 and not at_new_token:
                for cmd in INTERACTIVE_COMMANDS:
                    if cmd.startswith(current_lower):
                        yield PT_Completion(cmd, start_position=-len(current))
                return

            if first == "set":
                if len(tokens) <= 2:
                    # Complete set <key>
                    for key in INTERACTIVE_SET_KEYS:
                        if key.startswith(current_lower):
                            yield PT_Completion(key, start_position=-len(current))
                elif len(tokens) == 3:
                    # Complete set <key> <value>
                    key = tokens[1].lower()
                    if key == "mode":
                        for val in ("audit", "discover"):
                            if val.startswith(current_lower):
                                yield PT_Completion(val, start_position=-len(current))
                    elif key == "profile":
                        for val in ("quick", "standard", "deep"):
                            if val.startswith(current_lower):
                                yield PT_Completion(val, start_position=-len(current))
                    elif key == "format":
                        for val in ("json", "csv", "xml", "html"):
                            if val.startswith(current_lower):
                                yield PT_Completion(val, start_position=-len(current))
                    elif key in ("min-severity", "fail-on"):
                        for sev in SEVERITY_ORDER:
                            if sev.lower().startswith(current_lower):
                                yield PT_Completion(sev, start_position=-len(current))
                    elif key in ("insecure", "verbose", "strict", "system-proxy", "discover-subdomains"):
                        for val in ("true", "false"):
                            if val.startswith(current_lower):
                                yield PT_Completion(val, start_position=-len(current))
                return

            if first == "unset":
                if len(tokens) <= 2:
                    for key in INTERACTIVE_UNSET_KEYS:
                        if key.startswith(current_lower):
                            yield PT_Completion(key, start_position=-len(current))
                return

            if first == "show":
                if len(tokens) <= 2 and "config".startswith(current_lower):
                    yield PT_Completion("config", start_position=-len(current))
                return

            if first in ("scan", "audit", "discover") or (first not in INTERACTIVE_COMMANDS and text.strip()):
                # Complete flags for scan/audit/discover commands
                if current.startswith("-") or (len(tokens) >= 2 and tokens[-1].startswith("-")):
                    for flag in INTERACTIVE_FLAGS:
                        if flag.startswith(current):
                            yield PT_Completion(flag, start_position=-len(current))
                return


# ---------------------------------------------------------------------------
# Wappalyzer-style fingerprinting
# ---------------------------------------------------------------------------
def fingerprint(
    response: requests.Response, session: requests.Session
) -> tuple[list[str], list[Finding]]:
    html_lower = response.text.lower()
    headers_str = " ".join(
        f"{k.lower()}:{v.lower()}" for k, v in response.headers.items()
    )
    cookies_str = " ".join(session.cookies.keys()).lower()

    sources = {
        "html":    html_lower,
        "headers": headers_str,
        "cookies": cookies_str,
    }

    detected: list[str] = []
    for platform, rules in WAPPALYZER_RULES.items():
        for pattern, source in rules:
            if re.search(pattern, sources.get(source, ""), re.I):
                if platform not in detected:
                    detected.append(platform)
                break

    findings: list[Finding] = []

    for header in TECH_HEADERS:
        val = response.headers.get(header)
        if val:
            findings.append(Finding(
                severity="LOW", category="tech",
                title=f"Technology disclosed via {header}",
                detail=f"{header}: {val}",
                url=str(response.url),
            ))

    soup = BeautifulSoup(response.text, "html.parser")
    gen = soup.find("meta", attrs={"name": re.compile("generator", re.I)})
    if gen and gen.get("content"):
        findings.append(Finding(
            severity="LOW", category="tech",
            title="Generator meta tag",
            detail=str(gen["content"]),
            url=str(response.url),
        ))

    return detected, findings


# ---------------------------------------------------------------------------
# Security header audit
# ---------------------------------------------------------------------------
def audit_security_headers(response: requests.Response) -> list[Finding]:
    return [Finding(
        category="header", url=str(response.url), status_code=response.status_code,
        confidence="certain", detail=item["evidence"], references=[HEADER_REFERENCE],
        **item,
    ) for item in header_checks(response)]


# ---------------------------------------------------------------------------
# Cookie security flags
# ---------------------------------------------------------------------------
def audit_cookies(response: requests.Response) -> list[Finding]:
    findings: list[Finding] = []
    raw_cookie_headers: list[str] = []
    if response.raw is not None and hasattr(response.raw, "headers"):
        raw_headers = response.raw.headers
        if hasattr(raw_headers, "getlist"):
            raw_cookie_headers = raw_headers.getlist("Set-Cookie")

    if not raw_cookie_headers:
        raw = response.headers.get("Set-Cookie", "")
        if raw:
            raw_cookie_headers = [raw]

    if not raw_cookie_headers:
        return findings

    for raw in raw_cookie_headers:
        name_match = re.match(r"\s*([^=;]+)=", raw)
        name = name_match.group(1).strip() if name_match else "unknown"
        cookie = SimpleCookie()
        try:
            cookie.load(raw)
        except Exception:
            continue
        morsel = cookie.get(name)
        if morsel is None:
            continue

        if not morsel["secure"]:
            findings.append(Finding(
                severity="MEDIUM", category="cookie",
                title=f"Cookie '{name}' missing Secure flag",
                detail="Cookie can be sent over HTTP",
                url=str(response.url),
            ))
        if not morsel["httponly"]:
            findings.append(Finding(
                severity="MEDIUM", category="cookie",
                title=f"Cookie '{name}' missing HttpOnly flag",
                detail="Cookie accessible via JavaScript",
                url=str(response.url),
            ))
        if morsel["samesite"].lower() not in ("lax", "strict", "none"):
            findings.append(Finding(
                severity="LOW", category="cookie",
                title=f"Cookie '{name}' missing SameSite attribute",
                detail="CSRF protection not enforced by cookie",
                url=str(response.url),
            ))

    return findings


# ---------------------------------------------------------------------------
# CORS misconfiguration
# ---------------------------------------------------------------------------
def audit_cors(base_url: str, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    with build_session(config) as test_session:
        test_session.headers.update({"Origin": "https://evil.example.com"})
        resp, _ = fetch_response(test_session, base_url, config=config)
    if resp is None:
        return findings

    acao = resp.headers.get("Access-Control-Allow-Origin", "")
    acac = resp.headers.get("Access-Control-Allow-Credentials", "")

    if acao == "https://evil.example.com":
        with build_session(config) as confirmation_session:
            confirmation_session.headers["Origin"] = "https://another-origin.invalid"
            confirm, _ = fetch_response(confirmation_session, base_url, config=config)
        if confirm is None or confirm.headers.get("Access-Control-Allow-Origin") != "https://another-origin.invalid":
            return findings
        severity = "MEDIUM" if acac.lower() == "true" else "INFO"
        findings.append(Finding(
            severity=severity, category="cors",
            title="CORS: arbitrary origin reflected"
                  + (" with credentials" if acac.lower() == "true" else ""),
            detail=f"ACAO: {acao}  ACAC: {acac or 'not set'}",
            url=base_url,
            rule_id="cors.origin-reflection", confidence="firm",
            evidence="Two distinct untrusted origins reflected; sensitive authenticated content was not verified",
            remediation="Use an explicit trusted-origin allowlist when returning private data; review credential requirements.",
        ))

    return findings


# ---------------------------------------------------------------------------
# HTTP methods check
# ---------------------------------------------------------------------------
def audit_methods(session: requests.Session, base_url: str, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    resp, _ = fetch_response(session, base_url, method="OPTIONS", config=config)
    if resp is None:
        return findings

    allow = resp.headers.get("Allow", "")
    methods = {part.strip().upper() for part in allow.split(",")}
    dangerous = [m for m in ("PUT", "DELETE", "TRACE", "CONNECT") if m in methods]
    if dangerous:
        findings.append(Finding(
            severity="INFO", category="method",
            title=f"HTTP methods advertised: {', '.join(dangerous)}",
            detail=f"Allow: {allow}",
            url=base_url,
        ))
    return findings


# ---------------------------------------------------------------------------
# Response body content analysis
# ---------------------------------------------------------------------------
def check_response_body(resp: requests.Response) -> list[Finding]:
    if not should_inspect_body(resp):
        return []
    findings: list[Finding] = []
    for pattern, severity, title in BODY_PATTERNS_COMPILED:
        m = pattern.search(resp.text)
        if m:
            findings.append(Finding(
                severity="MEDIUM" if severity == "CRITICAL" else severity, category="body",
                title=title,
                detail="Response matched a diagnostic/sensitive-content pattern; matched values withheld",
                url=str(resp.url),
                status_code=resp.status_code,
                confidence="tentative", evidence="Pattern match requires manual verification",
                remediation="Review the response and remove unintended diagnostic or sensitive content.",
            ))
    return findings


# ---------------------------------------------------------------------------
# Concurrent endpoint probing
# ---------------------------------------------------------------------------
def probe_path(
    session_pool: ThreadLocalSessionPool,
    base_url: str,
    path: str,
    severity: str,
    description: str,
    config: ScanConfig,
    soft_404_profiles: list[BodyFingerprint],
) -> Finding | None:
    session = session_pool.get()
    url = urljoin(base_url, path)
    resp, err = fetch_response(session, url, allow_redirects=False, config=config)
    if resp is None:
        if severity in ("CRITICAL", "HIGH"):
            return Finding(
                severity="INFO", category="endpoint",
                title=f"UNREACHABLE: {description}",
                detail=err or "Request failed",
                url=url,
            )
        return None

    sc = resp.status_code

    if sc == 404:
        return None

    if 200 <= sc < 300:
        if challenge_page(resp.text):
            if config.runtime:
                config.runtime.mark_partial("challenge_page")
            return None
        if is_soft_404(resp, soft_404_profiles):
            return None
        body_issues = [f.title for f in check_response_body(resp)]
        match = sensitive_match(path, resp.text, resp.headers.get("Content-Type", ""))
        if severity in ("CRITICAL", "HIGH") and not match:
            return Finding(
                severity="INFO", category="endpoint", title=f"REACHABLE: {description} (unverified)",
                detail=f"HTTP {sc}; expected sensitive content was not confirmed", url=url,
                status_code=sc, rule_id="endpoint.reachable." + re.sub(r"[^a-z0-9]+", "-", path.lower()).strip("-"),
                confidence="tentative", evidence="Successful response alone does not demonstrate exposure",
                remediation="Review the endpoint and its intended access controls.",
            )
        return Finding(
            severity=severity if match else "INFO", category="endpoint",
            title=f"{'EXPOSED' if match else 'PUBLIC'}: {description}",
            detail=f"HTTP {sc} ({resp.headers.get('Content-Type', '').split(';')[0].strip()})",
            url=url, status_code=sc,
            extra={"body_issues": body_issues} if body_issues else {},
            rule_id=match[0] if match else "endpoint.public." + re.sub(r"[^a-z0-9]+", "-", path.lower()).strip("-"),
            confidence="certain" if match else "tentative",
            evidence=match[1] if match else "HTTP success; public endpoint observation",
            remediation="Remove sensitive files from the web root and rotate affected secrets." if match else "Review whether this resource is intended to be public.",
        )

    if 300 <= sc < 400:
        return Finding(
            severity="INFO", category="endpoint",
            title=f"REDIRECT: {description}",
            detail=f"{sc} → {resp.headers.get('Location', '')}",
            url=url, status_code=sc,
        )

    if sc in (401, 403) and severity in ("CRITICAL", "HIGH"):
        return Finding(
            severity="INFO", category="endpoint",
            title=f"PROTECTED: {description}",
            detail=f"HTTP {sc}; access denied (resource existence is not confirmed)",
            url=url, status_code=sc,
        )

    if 500 <= sc <= 599:
        return Finding(
            severity="INFO", category="endpoint",
            title=f"SERVER ERROR: {description}",
            detail=f"HTTP {sc} at endpoint",
            url=url, status_code=sc,
        )

    return None


def run_endpoint_audit(
    session_pool: ThreadLocalSessionPool,
    base_url: str,
    platforms: list[str],
    workers: int,
    config: ScanConfig,
    profile: str,
    soft_404_profiles: list[BodyFingerprint],
    time_budget: TimeBudget | None = None,
    max_paths: int | None = None,
) -> list[Finding]:
    seen: set[str] = set()
    tasks: list[tuple[str, str, str]] = []
    common_paths = filter_paths_for_profile(COMMON_PATHS, profile)
    for path, sev, desc in common_paths:
        if path not in seen:
            seen.add(path)
            tasks.append((path, sev, desc))
    for platform in platforms:
        platform_paths = filter_paths_for_profile(PLATFORM_PATHS.get(platform, []), profile)
        for path, sev, desc in platform_paths:
            if path not in seen:
                seen.add(path)
                tasks.append((path, sev, desc))

    if max_paths is not None:
        tasks = tasks[:max_paths]
    if config.runtime:
        config.runtime.endpoints_planned = len(tasks)

    findings: list[Finding] = []
    errors = 0
    truncated = False
    with ScanExecutor(workers, config.runtime) as pool:
        futures: dict = {}
        task_iter = iter(tasks)

        def submit_next() -> bool:
            nonlocal truncated
            if time_budget and time_budget.exhausted():
                truncated = True
                return False
            try:
                path, sev, desc = next(task_iter)
            except StopIteration:
                return False
            future = pool.submit(
                probe_path,
                session_pool,
                base_url,
                path,
                sev,
                desc,
                config,
                soft_404_profiles,
            )
            futures[future] = path
            return True

        for _ in range(workers):
            if not submit_next():
                break

        while futures:
            if time_budget and time_budget.exhausted():
                truncated = True
                for future in futures:
                    future.cancel()
                break

            done, _ = wait(futures, timeout=0.25, return_when=FIRST_COMPLETED)
            if not done:
                continue

            for future in done:
                path = futures.pop(future)
                if config.runtime:
                    config.runtime.endpoint_done()
                if future.cancelled():
                    continue
                try:
                    result = future.result()
                except Exception as exc:
                    errors += 1
                    result = Finding(
                        severity="INFO", category="endpoint",
                        title="Probe task failed",
                        detail=str(exc),
                        url=urljoin(base_url, path),
                    )
                if result is not None:
                    findings.append(result)

                if not submit_next() and futures:
                    if time_budget and time_budget.exhausted():
                        truncated = True
                        for pending in futures:
                            pending.cancel()
                        break
            if truncated:
                break

        # Preserve results of in-flight probes that completed during shutdown.
        for future in futures:
            if future.cancelled():
                continue
            try:
                result = future.result()
                if result is not None:
                    findings.append(result)
            except Exception:
                errors += 1
            if config.runtime:
                config.runtime.endpoint_done()

    if errors:
        if config.runtime:
            config.runtime.mark_partial("worker_errors")
        findings.append(Finding(
            severity="INFO", category="endpoint",
            title="Some endpoint probes failed",
            detail=f"{errors} worker task(s) raised an exception",
            url=base_url,
        ))

    if truncated:
        if config.runtime:
            config.runtime.mark_partial("time_budget")
        findings.append(Finding(
            severity="INFO", category="endpoint",
            title="Time budget reached during endpoint probing",
            detail="Scan stopped early to respect the time budget",
            url=base_url,
        ))

    return sorted(
        findings,
        key=lambda f: (
            ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "OK"].index(f.severity),
            f.url,
        ),
    )


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------


def normalize_base_url(raw_url: str) -> str:
    url = raw_url.strip()
    if not url:
        raise ValueError("URL is empty")
    if "://" not in url:
        url = "https://" + url

    return canonical_url(url)


def print_findings(findings: list[Finding]) -> None:
    for sev in SEVERITY_ORDER:
        group = [f for f in findings if f.severity == sev]
        if not group:
            continue
        for f in group:
            label = c(sev, f"[{sev:<8}]")
            sc_str = f" HTTP {f.status_code}" if f.status_code else ""
            print(f"{label} {f.title}{sc_str}")
            if f.detail:
                print(f"           {f.detail}")
            if f.url:
                print(f"           {f.url}")
            for issue in f.extra.get("body_issues", []):
                print(f"           ⚠ body: {issue}")


def print_summary(findings: list[Finding]) -> None:
    counts = {sev: sum(1 for f in findings if f.severity == sev) for sev in SEVERITY_ORDER}
    parts = [f"{c(sev, sev)}: {counts[sev]}" for sev in SEVERITY_ORDER if counts[sev]]
    if parts:
        print(f"\nSummary: {' | '.join(parts)}")
    else:
        print("\nSummary: no findings")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def add_request_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--rate-limit", type=float, default=10.0, help="Maximum HTTP requests per second across all workers (default: 10)")
    parser.add_argument("--max-requests", type=int, default=1000, help="Total HTTP request cap including redirects/retries (default: 1000)")
    parser.add_argument("--max-body-bytes", type=int, default=1_048_576, help="Maximum decoded response bytes (default: 1048576)")
    parser.add_argument("--system-proxy", action=argparse.BooleanOptionalAction, default=False, help="Opt into environment/system/PAC proxy settings")
    parser.add_argument("--strict", action=argparse.BooleanOptionalAction, default=False, help="Exit 3 when a scan is partial and no fail-on threshold is hit")


def record_provided_options(args: argparse.Namespace, parser: argparse.ArgumentParser, tokens: list[str]) -> None:
    options = {token.split("=", 1)[0] for token in tokens if token.startswith("--")}
    args._provided = {action.dest for action in parser._actions if options.intersection(action.option_strings)}


def build_parser(*, exit_on_error: bool = True) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=APP_NAME,
        exit_on_error=exit_on_error,
        allow_abbrev=False,
        description=(
            "Authorized web site exposure auditor.\n"
            "Inspired by nuclei, gobuster, wappalyzer, and nikto.\n\n"
            "Only use against targets you own or have explicit permission to test."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"{APP_NAME} {__version__}",
    )
    parser.add_argument("url", nargs="?", default=None, help="Base URL to inspect (e.g. https://example.com) — omit to enter interactive mode")
    parser.add_argument(
        "--mode", choices=["audit", "discover"], default="audit",
        help="audit: headers/cookies/CORS/endpoints  discover: unlinked URL inventory",
    )
    parser.add_argument(
        "--profile", choices=["quick", "standard", "deep"], default="standard",
        help="Scan profile presets (quick/standard/deep)",
    )
    parser.add_argument(
        "--output", metavar="FILE",
        help="Write full JSON report to FILE",
    )
    parser.add_argument(
        "--min-severity", choices=SEVERITY_ORDER, default="INFO",
        help="Only show findings at or above this severity (default: INFO)",
    )
    parser.add_argument(
        "--workers", type=int, default=MAX_WORKERS,
        help=f"Concurrent workers for endpoint probing (default: {MAX_WORKERS})",
    )
    parser.add_argument(
        "--timeout", type=int, default=TIMEOUT,
        help=f"HTTP timeout in seconds (default: {TIMEOUT})",
    )
    parser.add_argument(
        "--time-budget", type=int, default=None,
        help="Max runtime budget in seconds (best effort)",
    )
    parser.add_argument(
        "--retries", type=int, default=RETRIES,
        help=f"Retries on transient HTTP errors (default: {RETRIES})",
    )
    parser.add_argument(
        "--insecure", action=argparse.BooleanOptionalAction, default=False,
        help="Disable SSL certificate verification",
    )
    parser.add_argument(
        "--fail-on", choices=SEVERITY_ORDER, default=None,
        help="Exit with code 2 if findings at/above this severity exist (for CI)",
    )
    parser.add_argument(
        "--verbose", action=argparse.BooleanOptionalAction, default=False,
        help="Enable verbose logging",
    )
    parser.add_argument(
        "--log-file", metavar="FILE", default=None,
        help="Write operational logs to FILE",
    )
    parser.add_argument(
        "--history", action="store_true",
        help="Enable command history in interactive mode",
    )
    parser.add_argument(
        "--no-load-prefs", action="store_true",
        help="Ignore saved preferences",
    )
    parser.add_argument(
        "--no-save-prefs", action="store_true",
        help="Do not persist CLI options to preference files",
    )
    parser.add_argument(
        "--prefs-scope", choices=["user", "project", "both"], default="both",
        help="Where to save preferences (default: both)",
    )
    parser.add_argument(
        "--ports", metavar="TYPE|PORTS", default=None,
        help="Scan ports: 'http', 'https', 'services', or comma-separated list (e.g. 80,443,8080)",
    )
    parser.add_argument(
        "--proxy", metavar="URL", default=None,
        help="HTTP proxy URL (e.g. http://proxy.corp:8080)",
    )
    parser.add_argument(
        "--header", metavar="KEY:VALUE", action="append", dest="headers", default=[],
        help="Add custom header (repeatable, e.g. --header 'X-Custom:value')",
    )
    parser.add_argument(
        "--basic-user", metavar="USER", default=None,
        help="Username for basic auth",
    )
    parser.add_argument(
        "--basic-pass", metavar="PASS", default=None,
        help="Password for basic auth",
    )
    parser.add_argument(
        "--bearer-token", metavar="TOKEN", default=None,
        help="Bearer token for Authorization header",
    )
    parser.add_argument("--bearer-token-env", metavar="NAME", help="Read bearer token from environment variable NAME")
    parser.add_argument("--basic-pass-env", metavar="NAME", help="Read basic-auth password from environment variable NAME")
    parser.add_argument(
        "--cookie", metavar="COOKIE", action="append", default=[],
        help="Cookie header value (repeatable, e.g. 'session=abc; theme=dark')",
    )
    parser.add_argument(
        "--format", choices=["json", "csv", "xml", "html"], default="json",
        help="Output format for --output file (default: json)",
    )
    parser.add_argument(
        "--export-last", action="store_true",
        help="Export the last saved report without running a scan",
    )
    parser.add_argument(
        "--export-scope", choices=["user", "project", "both"], default="both",
        help="Where to load the last report from (default: both)",
    )
    parser.add_argument(
        "--report-title", metavar="TEXT", default="Security Exposure Report",
        help="Custom title for HTML report",
    )
    parser.add_argument(
        "--report-brand", metavar="TEXT", default="site-audit",
        help="Brand label for HTML report",
    )
    parser.add_argument(
        "--report-logo", metavar="URL", default=None,
        help="Logo URL for HTML report header",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Simulate scan without making requests (useful for configuration testing)",
    )
    parser.add_argument(
        "--discover-subdomains", action=argparse.BooleanOptionalAction, default=False,
        help="Discover common subdomains (discover mode only)",
    )
    parser.add_argument(
        "--no-save-last", action="store_true",
        help="Do not persist the last report for export",
    )
    parser.add_argument(
        "--last-scope", choices=["user", "project", "both"], default="both",
        help="Where to save the last report (default: both)",
    )
    add_request_options(parser)
    return parser


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = build_parser()
    tokens = sys.argv[1:] if argv is None else argv
    args = parser.parse_args(tokens)
    record_provided_options(args, parser, tokens)
    return args


def run_scan(args: argparse.Namespace) -> int:
    """Execute a single scan given a populated Namespace. Called from both CLI and interactive mode."""
    try:
        base_url = normalize_base_url(args.url)
    except ValueError as exc:
        print(c("CRITICAL", f"[ERROR] Invalid URL: {exc}"))
        return 1

    setup_logging(args.verbose, args.log_file)
    start_time = datetime.now(timezone.utc)
    start_monotonic = time.monotonic()

    profile = getattr(args, "profile", "standard")
    profile_defaults = PROFILE_DEFAULTS.get(profile, PROFILE_DEFAULTS["standard"])

    configured = getattr(args, "_configured", getattr(args, "_provided", set()))
    workers = args.workers if "workers" in configured else profile_defaults["workers"]
    timeout = args.timeout if "timeout" in configured else profile_defaults["timeout"]
    retries = args.retries if "retries" in configured else profile_defaults["retries"]
    if not 1 <= workers <= 200 or timeout <= 0 or not 0 <= retries <= 10:
        print("[ERROR] workers must be 1..200, timeout positive, and retries 0..10")
        return 1
    min_idx = SEVERITY_ORDER.index(args.min_severity)

    time_budget_seconds = args.time_budget if args.time_budget is not None else profile_defaults["time_budget"]
    if time_budget_seconds is not None and time_budget_seconds <= 0:
        print(c("CRITICAL", "[ERROR] time-budget must be greater than 0 seconds"))
        return 1
    time_budget = TimeBudget(time_budget_seconds)
    rate_limit = getattr(args, "rate_limit", 10.0)
    max_requests = getattr(args, "max_requests", 1000)
    max_body_bytes = getattr(args, "max_body_bytes", 1_048_576)
    if not 0 < rate_limit <= 10000 or not 1 <= max_requests <= 1_000_000 or not 1024 <= max_body_bytes <= 100_000_000:
        print("[ERROR] rate-limit must be 0..10000 (exclusive of 0), max-requests 1..1000000, max-body-bytes 1024..100000000")
        return 1
    runtime = ScanRuntime(time_budget, rate_limit=rate_limit, max_requests=max_requests)
    max_paths = profile_defaults.get("max_paths")

    try:
        custom_headers = parse_custom_headers(getattr(args, "headers", []) or [])
        proxy = validate_proxy_url(getattr(args, "proxy", None))
    except ValueError as exc:
        print(c("CRITICAL", f"[ERROR] {exc}"))
        return 1

    port_list: list[int] | None = None
    if getattr(args, "ports", None):
        try:
            port_list = get_ports_for_url(base_url, args.ports)
        except ValueError as exc:
            print(c("CRITICAL", f"[ERROR] Invalid --ports value: {exc}"))
            return 1

    basic_user = getattr(args, "basic_user", None)
    basic_pass = getattr(args, "basic_pass", None)
    bearer_token = getattr(args, "bearer_token", None)
    for direct, env_name, label in ((basic_pass, getattr(args, "basic_pass_env", None), "basic-pass"), (bearer_token, getattr(args, "bearer_token_env", None), "bearer-token")):
        if env_name and (direct is not None or not _os.environ.get(env_name)):
            print(f"[ERROR] {label}: use either a direct value or a populated environment variable")
            return 1
    if getattr(args, "basic_pass_env", None):
        basic_pass = _os.environ[args.basic_pass_env]
    if getattr(args, "bearer_token_env", None):
        bearer_token = _os.environ[args.bearer_token_env]
    if (basic_user and not basic_pass) or (basic_pass and not basic_user):
        print(c("CRITICAL", "[ERROR] Both --basic-user and --basic-pass are required"))
        return 1
    auth = (basic_user, basic_pass) if basic_user and basic_pass else None
    if auth and bearer_token:
        print("[ERROR] Choose basic authentication or bearer authentication")
        return 1
    cookie_values = getattr(args, "cookie", []) or []
    cookie_jar = parse_cookie_values(cookie_values) if cookie_values else None

    config = ScanConfig(
        timeout=timeout,
        retries=retries,
        verify_ssl=not args.insecure,
        proxy=proxy,
        custom_headers=custom_headers,
        auth=auth,
        bearer_token=bearer_token,
        cookies=cookie_jar,
        scope=ScanScope(base_url), runtime=runtime, max_body_bytes=max_body_bytes,
        system_proxy=getattr(args, "system_proxy", False) and not getattr(args, "dry_run", False),
        allow_initial_upgrade=True,
        allow_initial_canonical_redirect=True,
    )
    fail_on = args.fail_on
    output_format = getattr(args, 'format', 'json')
    dry_run = getattr(args, 'dry_run', False)
    report_title = getattr(args, "report_title", "Security Exposure Report")
    report_brand = getattr(args, "report_brand", "site-audit")
    report_logo = getattr(args, "report_logo", None)
    output_path, output_format = normalize_output_target(args.output, output_format)
    if args.mode == "discover" and output_format not in ("json", "html"):
        print("[ERROR] Discover mode supports json or html output")
        return 1

    # Suppress urllib3 warnings globally (connection pool, retries, etc)
    # They are logged but not useful to end users
    if args.insecure:
        urllib3.disable_warnings(InsecureRequestWarning)
        LOGGER.warning("TLS certificate verification disabled")

    if dry_run:
        print(c("INFO", "[DRY-RUN MODE - No requests will be made]"))
        LOGGER.info("Dry-run mode enabled")

    LOGGER.info("Starting %s scan for %s", args.mode, base_url)
    startup_findings: list[Finding] = []

    with build_session(config) as session:
        if dry_run:
            homepage = None
            fetch_err = None
        else:
            homepage, fetch_err = fetch_response(session, base_url, config=config)

        if not dry_run:
            if homepage is None:
                runtime.mark_partial("initial_connection_failed")
                finished_time = datetime.now(timezone.utc)
                failed_report = {
                    "schema_version": REPORT_SCHEMA_VERSION,
                    "tool": {"name": APP_NAME, "version": __version__},
                    "target": base_url, "mode": args.mode, "settings": {}, "findings": [], "ports": {},
                    "started_at": start_time.isoformat(), "finished_at": finished_time.isoformat(),
                    "timestamp": finished_time.isoformat(), "duration_seconds": time.monotonic() - start_monotonic,
                    "scan": runtime.snapshot(),
                }
                if args.mode == "discover":
                    failed_report["result"] = {"homepage_internal_links": [], "discovered": [], "subdomains": [], "hidden": []}
                if output_path:
                    write_report(failed_report, output_path, output_format, report_title=report_title, report_brand=report_brand, report_logo=report_logo)
                print(c("CRITICAL", f"[ERROR] Could not open target {base_url}"))
                # Simplify error message - show just the core issue, not full stack
                if fetch_err:
                    print(f"       {fetch_err}")
                    if "timeout" in fetch_err.lower():
                        print(f"       Tip: Try --timeout {max(int(args.timeout) + 5, 15)} for slow networks")
                if args.insecure:
                    print("       SSL verification is disabled (--insecure).")
                return 1
            if not homepage.ok:
                runtime.mark_partial("homepage_http_error")
                print(c("HIGH", f"[WARN] Homepage returned HTTP {homepage.status_code} for {base_url}"))
                print("       The tool will continue, but results may be incomplete.")
                LOGGER.warning("Homepage returned HTTP %s", homepage.status_code)
            blocked_redirect = getattr(homepage, "_audit_blocked_redirect", None)
            if blocked_redirect:
                print(c("INFO", f"[WARN] Homepage redirects outside scope to {blocked_redirect}"))
                print("       Continuing on the original site; homepage coverage is incomplete.")
                startup_findings.append(Finding(
                    severity="INFO", category="scope", title="Homepage redirect outside scan scope",
                    detail="External consent/login or other redirect was not followed; homepage checks are incomplete",
                    url=homepage.url, status_code=homepage.status_code,
                    rule_id="scope.startup-redirect", confidence="certain",
                    evidence=f"Redirect destination: {blocked_redirect}",
                    remediation="Review the redirect and provide an in-scope starting URL or authenticated session if needed.",
                ))
            if challenge_page(homepage.text):
                runtime.mark_partial("challenge_page")
            # Canonicalization is limited to startup; subsequent probes use one exact origin.
            if canonical_url(homepage.url) != base_url:
                print(c("INFO", f"[INFO] Canonical target: {redacted_url(homepage.url)}"))
            base_url = canonical_url(homepage.url)
            config.scope = ScanScope(base_url)
            config.allow_initial_upgrade = False
            config.allow_initial_canonical_redirect = False

            if args.mode == "discover":
                print(f"Mode: public URL discovery\nTarget: {base_url}\n")
                result = discover_mode(
                    session,
                    base_url,
                    homepage.text,
                    config,
                    time_budget=time_budget,
                    discover_subdomains_flag=getattr(args, "discover_subdomains", False),
                    subdomain_prefixes=DISCOVER_SUBDOMAIN_PREFIXES,
                )
                finished_time = datetime.now(timezone.utc)
                duration_seconds = time.monotonic() - start_monotonic
                settings_payload = {
                    "profile": profile,
                    "workers": workers,
                    "timeout": timeout,
                    "retries": retries,
                    "verify_ssl": config.verify_ssl,
                    "min_severity": args.min_severity,
                    "fail_on": fail_on,
                    "time_budget": time_budget_seconds,
                    "proxy": redacted_url(config.proxy) if config.proxy else None,
                    "custom_headers": len(config.custom_headers),
                    "rate_limit": rate_limit, "max_requests": max_requests, "max_body_bytes": max_body_bytes,
                }
                report_payload = {
                    "schema_version": REPORT_SCHEMA_VERSION,
                    "tool": {"name": APP_NAME, "version": __version__},
                    "target": base_url,
                    "timestamp": finished_time.isoformat(),
                    "mode": "discover",
                    "settings": settings_payload,
                    "result": result,
                    "started_at": start_time.isoformat(),
                    "finished_at": finished_time.isoformat(),
                    "duration_seconds": duration_seconds,
                    "scan": runtime.snapshot(),
                    "findings": [asdict(f) for f in startup_findings],
                }
                if output_path:
                    write_report(report_payload, output_path, output_format, report_title=report_title, report_brand=report_brand, report_logo=report_logo)
                if not getattr(args, "no_save_last", False):
                    try:
                        save_last_report(report_payload, getattr(args, "last_scope", "both"))
                    except OSError:
                        print("[WARN] Failed to save last report")
                LOGGER.info("Discover mode finished")
                return 3 if getattr(args, "strict", False) and report_payload["scan"]["status"] == "partial" else 0

        platforms, tech_findings = fingerprint(homepage, session) if (not dry_run and homepage is not None and 200 <= homepage.status_code < 300 and not challenge_page(homepage.text)) else ([], [])
        soft_404_profiles: list[BodyFingerprint] = []
        if not dry_run:
            soft_404_profiles = build_soft_404_profiles(
                session,
                base_url,
                homepage,
                config,
                time_budget=time_budget,
            )

        print(c("INFO", "=" * 64))
        print(c("INFO", f"  {APP_NAME} v{__version__}"))
        print(c("INFO", f"  Target   : {base_url}"))
        print(c("INFO", f"  Platform : {', '.join(platforms) or 'unknown'}"))
        print(c("INFO", f"  Time     : {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}"))
        print(c("INFO", f"  Profile  : {profile}"))
        print(c("INFO", f"  Workers  : {workers}"))
        print(c("INFO", f"  Timeout  : {timeout}s"))
        print(c("INFO", f"  Retries  : {retries}"))
        if time_budget_seconds is not None:
            print(c("INFO", f"  Budget   : {time_budget_seconds}s"))
        print(c("INFO", f"  Verify   : {'on' if config.verify_ssl else 'off'}"))
        if config.proxy:
            print(c("INFO", f"  Proxy    : {redacted_url(config.proxy)}"))
        print(c("INFO", "=" * 64))
        print()

        all_findings: list[Finding] = []
        all_findings += startup_findings
        port_results: dict[int, bool | None] = {}

        # Port scanning
        if port_list and not dry_run and not time_budget.exhausted():
            try:
                parsed_url = urlparse(base_url)
                host = parsed_url.hostname or ""
                print(f"Scanning {len(port_list)} ports on {host}...")
                port_results = scan_ports(host, port_list, timeout=2.0, runtime=runtime)
                open_ports = [p for p, is_open in port_results.items() if is_open is True]
                if open_ports:
                    print(f"Open ports: {', '.join(map(str, sorted(open_ports)))}")
            except Exception as e:
                runtime.mark_partial("port_errors")
                LOGGER.error(f"Port scanning failed: {e}")

        if dry_run:
            print("[DRY-RUN] Skipping endpoint audits")
        else:
            all_findings += tech_findings
            if homepage is not None and 200 <= homepage.status_code < 300 and not challenge_page(homepage.text):
                all_findings += audit_security_headers(homepage)
                all_findings += audit_cookies(homepage)
                all_findings += audit_cache_headers(homepage)
                all_findings += audit_header_versions(homepage)
            all_findings += audit_cors(base_url, config)
            all_findings += audit_methods(session, base_url, config)

            common_count = len(filter_paths_for_profile(COMMON_PATHS, profile))
            platform_count = sum(
                len(filter_paths_for_profile(PLATFORM_PATHS.get(p, []), profile))
                for p in platforms
            )
            total_count = common_count + platform_count
            if max_paths is not None:
                total_count = min(total_count, max_paths)
            print(f"Probing {total_count} common + platform-specific paths "
                  f"({workers} workers)...")
            session_pool = ThreadLocalSessionPool(config=config, seed_cookies=session.cookies)
            try:
                all_findings += run_endpoint_audit(
                    session_pool,
                    base_url,
                    platforms,
                    workers,
                    config,
                    profile,
                    soft_404_profiles,
                    time_budget=time_budget,
                    max_paths=max_paths,
                )
            finally:
                session_pool.close()

        all_findings = deduplicate_findings(all_findings)

        filtered = [f for f in all_findings if severity_index(f.severity) <= min_idx]

        print()
        print_findings(filtered)
        print_summary(filtered)

        finished_time = datetime.now(timezone.utc)
        duration_seconds = time.monotonic() - start_monotonic
        settings_payload = {
            "profile": profile,
            "workers": workers,
            "timeout": timeout,
            "retries": retries,
            "verify_ssl": config.verify_ssl,
            "min_severity": args.min_severity,
            "fail_on": fail_on,
            "time_budget": time_budget_seconds,
            "proxy": redacted_url(config.proxy) if config.proxy else None,
            "custom_headers": len(config.custom_headers),
            "rate_limit": rate_limit, "max_requests": max_requests, "max_body_bytes": max_body_bytes,
        }
        report_payload = {
            "schema_version": REPORT_SCHEMA_VERSION,
            "tool": {"name": APP_NAME, "version": __version__},
            "target": base_url,
            "timestamp": finished_time.isoformat(),
            "mode": args.mode,
            "platforms": platforms,
            "settings": settings_payload,
            "findings": [asdict(f) for f in all_findings],
            "started_at": start_time.isoformat(),
            "finished_at": finished_time.isoformat(),
            "duration_seconds": duration_seconds,
            "scan": runtime.snapshot(dry_run),
            "ports": {str(port): state for port, state in port_results.items()},
        }
        if dry_run and args.mode == "discover":
            report_payload["result"] = {"homepage_internal_links": [], "discovered": [], "subdomains": [], "hidden": []}
        print(f"Scan status: {report_payload['scan']['status']} ({runtime.requests_sent} HTTP requests)")
        if report_payload["scan"]["reasons"]:
            print("Incomplete checks: " + ", ".join(report_payload["scan"]["reasons"]))

        if output_path:
            write_report(report_payload, output_path, output_format, report_title=report_title, report_brand=report_brand, report_logo=report_logo)

        if not getattr(args, "no_save_last", False):
            try:
                save_last_report(report_payload, getattr(args, "last_scope", "both"))
            except OSError:
                print("[WARN] Failed to save last report")

        if fail_on and has_findings_at_or_above(all_findings, fail_on):
            LOGGER.warning("Fail-on threshold hit: %s", fail_on)
            return 2
        if getattr(args, "strict", False) and report_payload["scan"]["status"] == "partial":
            return 3

        LOGGER.info("Audit finished successfully")
        return 0


INTERACTIVE_HELP = """
Commands:
  scan <url> [options]       run with session defaults and optional overrides
  audit <url> [options]      force audit mode
  discover <url> [options]   force public URL discovery
  export <file> [options]    export the last stored report
  set <key> <value>          change a default; save unless --no-save-prefs
  unset <key>               restore a built-in default
  show config               print current interactive defaults
  history                   show current session command history
  history clear             clear current and configured persistent history
  clear                     clear screen
  help                      show this message
  version                   show the version without leaving the session
  exit / quit / EOF         leave; Ctrl-C cancels the current prompt/scan

Settings:
  mode, profile, format, min-severity, fail-on, workers, timeout, retries,
  rate-limit, max-requests, max-body-bytes, time-budget, ports, strict,
  insecure, proxy, system-proxy, discover-subdomains, verbose, log-file,
  output, report-title, report-brand, report-logo

Boolean values: true/false. Use --no-strict, --no-insecure, etc. to override
a true default for one command. Proxy credentials are never saved as defaults.
CLI authentication and privacy flags carry into this session's scans.
Preferences: ~/.site_audit_config.json and ./.site_audit.json, controlled by
--no-load-prefs, --no-save-prefs, and --prefs-scope.

Examples:
  set profile quick
  set rate-limit 2
  set strict true
  show config
  scan https://example.com
  discover https://example.com --output discover.json
  export report.html --format html --export-scope project
  audit https://example.com --fail-on HIGH

Exits: 1 operational/configuration error, 2 finding threshold, 3 strict partial
scan, 130 interruption. Reports retain all findings; min-severity filters display.
""".strip()


def parse_bool(value: str) -> bool:
    normalized = value.strip().lower()
    if normalized in ("1", "true", "yes", "y", "on"):
        return True
    if normalized in ("0", "false", "no", "n", "off"):
        return False
    raise ValueError("expected boolean value: true/false")


def split_interactive_line(line: str, *, windows: bool | None = None) -> list[str]:
    lexer = shlex.shlex(line, posix=True)
    lexer.whitespace_split = True
    lexer.commenters = ""
    is_windows = windows if windows is not None else _os.name == "nt"
    if is_windows:
        lexer.escape = ""
    return list(lexer)


def redact_history_line(line: str) -> str:
    try:
        tokens = split_interactive_line(line)
    except ValueError:
        return "<unparsed command omitted>"
    secret_flags = {"--basic-user", "--basic-pass", "--bearer-token", "--cookie", "--header", "--proxy"}
    result = []
    skip = False
    for token in tokens:
        if skip:
            skip = False
            continue
        flag, separator, _value = token.partition("=")
        if flag in secret_flags:
            result.extend([flag, "<redacted>"])
            skip = not separator
        else:
            try:
                parsed = urlparse(token)
                if parsed.username is not None or parsed.password is not None:
                    token = redacted_url(token)
            except ValueError:
                token = "<invalid URL omitted>"
            result.append(token)
    return shlex.join(result)


def build_interactive_tokens(url: str, state: InteractiveState, extra_tokens: list[str]) -> list[str]:
    tokens = [url]
    explicit = state.get("_provided", set())
    for key in PREF_KEYS:
        value = state.get(key, PREF_DEFAULTS[key])
        if value is None or (key not in explicit and value == PREF_DEFAULTS[key]):
            continue
        flag = "--" + key.replace("_", "-")
        if isinstance(value, bool):
            tokens.append(flag if value else "--no-" + key.replace("_", "-"))
        else:
            tokens += [flag, str(value)]
    tokens.extend(extra_tokens)
    return tokens


def update_interactive_setting(state: InteractiveState, key: str, value: str) -> str:
    normalized = _update_interactive_setting(state, key, value)
    state.setdefault("_provided", set()).add(normalized.replace("-", "_"))
    return normalized


def _update_interactive_setting(state: InteractiveState, key: str, value: str) -> str:
    k = key.strip().lower().replace("_", "-")
    if k in ("rate-limit", "max-requests", "max-body-bytes"):
        numeric = float(value) if k == "rate-limit" else int(value)
        limits = {"rate-limit": (0, 10000), "max-requests": (0, 1_000_000), "max-body-bytes": (1023, 100_000_000)}
        low, high = limits[k]
        if not low < numeric <= high:
            raise ValueError(f"{k} must be greater than {low} and at most {high}")
        state[k.replace("-", "_")] = numeric
        return k
    if k in ("strict", "system-proxy", "discover-subdomains"):
        state[k.replace("-", "_")] = parse_bool(value)
        return k
    if k == "ports":
        get_ports_for_url("https://example.com/", value)
        state["ports"] = value
        return k
    if k == "proxy":
        state["proxy"] = validate_proxy_url(value)
        return k
    if k == "mode":
        if value not in ("audit", "discover"):
            raise ValueError("mode must be audit or discover")
        state["mode"] = value
        return "mode"
    if k == "profile":
        if value not in PROFILE_DEFAULTS:
            raise ValueError("profile must be quick, standard, or deep")
        state["profile"] = value
        return "profile"
    if k == "format":
        if value not in ("json", "csv", "xml", "html"):
            raise ValueError("format must be json, csv, xml, or html")
        state["format"] = value
        return "format"
    if k in ("min-severity", "minseverity"):
        if value not in SEVERITY_ORDER:
            raise ValueError(f"min-severity must be one of: {', '.join(SEVERITY_ORDER)}")
        state["min_severity"] = value
        return "min-severity"
    if k == "workers":
        if not 1 <= int(value) <= 200:
            raise ValueError("workers must be 1..200")
        state["workers"] = int(value)
        return "workers"
    if k == "timeout":
        if int(value) <= 0:
            raise ValueError("timeout must be positive")
        state["timeout"] = int(value)
        return "timeout"
    if k in ("time-budget", "timebudget"):
        if int(value) <= 0:
            raise ValueError("time-budget must be positive")
        state["time_budget"] = int(value)
        return "time-budget"
    if k == "retries":
        if not 0 <= int(value) <= 10:
            raise ValueError("retries must be 0..10")
        state["retries"] = int(value)
        return "retries"
    if k == "insecure":
        state["insecure"] = parse_bool(value)
        return "insecure"
    if k in ("fail-on", "failon"):
        if value not in SEVERITY_ORDER:
            raise ValueError(f"fail-on must be one of: {', '.join(SEVERITY_ORDER)}")
        state["fail_on"] = value
        return "fail-on"
    if k == "verbose":
        state["verbose"] = parse_bool(value)
        return "verbose"
    if k in ("log-file", "logfile"):
        state["log_file"] = value
        return "log-file"
    if k == "output":
        state["output"] = value
        return "output"
    if k in ("report-title", "reporttitle"):
        state["report_title"] = value
        return "report-title"
    if k in ("report-brand", "reportbrand"):
        state["report_brand"] = value
        return "report-brand"
    if k in ("report-logo", "reportlogo"):
        state["report_logo"] = value
        return "report-logo"
    raise ValueError(f"Unknown setting: {key}")


def unset_interactive_setting(state: InteractiveState, key: str) -> str:
    k = key.strip().lower().replace("_", "-")
    k = {"failon": "fail-on", "logfile": "log-file", "reporttitle": "report-title", "reportbrand": "report-brand", "reportlogo": "report-logo"}.get(k, k)
    pref_key = k.replace("-", "_")
    if pref_key not in PREF_DEFAULTS:
        raise ValueError("Unknown setting")
    state[pref_key] = PREF_DEFAULTS[pref_key]
    state.setdefault("_provided", set()).discard(pref_key)
    return k


def print_interactive_config(state: InteractiveState) -> None:
    print("Current defaults:")
    print(f"  mode         : {state['mode']}")
    print(f"  profile      : {state['profile']}")
    print(f"  format       : {state['format']}")
    print(f"  min-severity : {state['min_severity']}")
    print(f"  workers      : {state['workers']}")
    print(f"  timeout      : {state['timeout']}")
    print(f"  time-budget  : {state['time_budget'] or '-'}")
    print(f"  retries      : {state['retries']}")
    print(f"  insecure     : {state['insecure']}")
    print(f"  fail-on      : {state['fail_on'] or '-'}")
    print(f"  verbose      : {state['verbose']}")
    print(f"  log-file     : {state['log_file'] or '-'}")
    print(f"  output       : {state['output'] or '-'}")
    print(f"  report-title : {state['report_title']}")
    print(f"  report-brand : {state['report_brand']}")
    print(f"  report-logo  : {state['report_logo'] or '-'}")
    for key in ("rate_limit", "max_requests", "max_body_bytes", "ports", "system_proxy", "strict", "discover_subdomains"):
        print(f"  {key.replace('_', '-'):<13}: {state.get(key, PREF_DEFAULTS[key])}")
    print(f"  proxy        : {redacted_url(state['proxy']) if state.get('proxy') else '-'}")


def create_prompt_session(history_enabled: bool, history_path: str):
    if not HAS_PROMPT_TOOLKIT:
        return None
    pt_history = RedactedFileHistory(history_path) if history_enabled else PT_DummyHistory()
    return PT_PromptSession(
        completer=SiteAuditCompleter(),
        history=pt_history,
        reserve_space_for_menu=3,
        complete_while_typing=True,
        complete_in_thread=False,
        enable_history_search=True,
        search_ignore_case=True
    )

def interactive_mode(default_workers: int, history_enabled: bool = False, initial_args: argparse.Namespace | None = None) -> None:
    print(c("INFO", "=" * 64))
    print(c("INFO", f"  {APP_NAME} v{__version__} - interactive mode"))
    print(c("INFO", "  type a URL to scan, 'help' for options, 'exit' to quit"))
    print(c("INFO", "=" * 64))

    parser = build_parser(exit_on_error=False)
    parser.set_defaults(workers=default_workers)

    export_parser = argparse.ArgumentParser(exit_on_error=False, add_help=False)
    export_parser.add_argument("output")
    export_parser.add_argument("--format", choices=["json", "csv", "xml", "html"], default="html")
    export_parser.add_argument("--export-scope", choices=["user", "project", "both"], default="both")
    export_parser.add_argument("--report-title", metavar="TEXT", default="Security Exposure Report")
    export_parser.add_argument("--report-brand", metavar="TEXT", default="site-audit")
    export_parser.add_argument("--report-logo", metavar="URL", default=None)

    initial_args = initial_args or parse_args([])
    prefs = {} if initial_args.no_load_prefs else load_preferences()
    prefs_scope = initial_args.prefs_scope
    state: InteractiveState = {key: getattr(initial_args, key, PREF_DEFAULTS[key]) for key in PREF_KEYS}
    state["workers"] = default_workers
    state["_provided"] = set(getattr(initial_args, "_provided", set()))
    apply_preferences_to_state(state, prefs)
    history: list[str] = []
    history_path = _os.path.join(_os.path.expanduser("~"), ".site_audit_history")
    session = None

    if HAS_PROMPT_TOOLKIT:
        session = create_prompt_session(history_enabled, history_path)
    else:
        LOGGER.info("prompt_toolkit not installed; tab completion unavailable")

    if not HAS_PROMPT_TOOLKIT and history_enabled and _os.path.isfile(history_path):
        try:
            with open(history_path, "r", encoding="utf-8") as fh:
                history = [line.rstrip("\n") for line in fh if line.strip()]
        except OSError:
            history = []

    while True:
        try:
            if session is not None:
                line = session.prompt("\nsite-audit> ").strip()
            else:
                line = input("\nsite-audit> ").strip()
        except KeyboardInterrupt:
            # Graceful line cancel (don't exit on Ctrl+C at the prompt)
            print()
            continue
        except EOFError:
            print("\nBye.")
            break

        if not line:
            continue
        if line.lower() in ("exit", "quit", "q"):
            print("Bye.")
            break
        if line.lower() in ("help", "?", "h"):
            print(INTERACTIVE_HELP)
            continue
        if line.lower() in ("version", "--version"):
            print(f"{APP_NAME} {__version__}")
            continue

        if history_enabled:
            # Keep runtime history array updated for the 'history' command to read
            history.append(redact_history_line(line))

            # Only write to file manually if we aren't using prompt_toolkit's FileHistory
            if not HAS_PROMPT_TOOLKIT:
                try:
                    with open(history_path, "a", encoding="utf-8") as fh:
                        fh.write(redact_history_line(line) + "\n")
                except OSError:
                    pass

        if line.lower() == "show config" or line.lower() == "show":
            print_interactive_config(state)
            continue

        if line.lower() == "clear":
            _os.system("cls" if _os.name == "nt" else "clear")
            continue

        try:
            tokens = split_interactive_line(line)
        except ValueError as exc:
            print(f"Parse error: {exc}")
            continue

        if not tokens:
            continue

        command = tokens[0].lower()

        if command == "history":
            if len(tokens) == 2 and tokens[1].lower() == "clear":
                if session is not None and hasattr(session, "history"):
                    if hasattr(session.history, "_loaded_strings"):
                        session.history._loaded_strings.clear()

                if _os.path.isfile(history_path):
                    try:
                        _os.remove(history_path)
                    except OSError:
                        pass
                if session is not None and HAS_PROMPT_TOOLKIT:
                    session = create_prompt_session(history_enabled, history_path)

                history.clear()
                print("History cleared.")
                continue
            elif len(tokens) == 2 and tokens[1].lower() == "off":
                history_enabled = False
                if session is not None and HAS_PROMPT_TOOLKIT:
                    session = create_prompt_session(False, history_path)
                history.clear()
                print("History disabled and cleared for this session.")
                continue
            elif len(tokens) == 2 and tokens[1].lower() == "on":
                history_enabled = True
                if session is not None and HAS_PROMPT_TOOLKIT:
                    session = create_prompt_session(True, history_path)
                print("History enabled and bound to .site_audit_history.")
                continue
            elif len(tokens) > 1:
                print("Usage: history [clear|on|off]")
                continue

            if session is not None:
                history_list = list(session.history.get_strings())
            else:
                history_list = history

            if not history_list:
                print("No history yet.")
            else:
                for idx, entry in enumerate(history_list[-50:], start=max(1, len(history_list) - 49)):
                    print(f"{idx:>4}: {redact_history_line(entry)}")
            continue

        if command == "export":
            if len(tokens) < 2:
                print("Usage: export <file> [--format html|json|csv|xml]")
                continue
            export_parser.set_defaults(
                format=state["format"],
                report_title=state["report_title"],
                report_brand=state["report_brand"],
                report_logo=state["report_logo"],
            )
            try:
                export_args = export_parser.parse_args(tokens[1:])
            except (argparse.ArgumentError, SystemExit) as exc:
                print(f"Parse error: {exc}")
                continue
            output_path, output_format = normalize_output_target(export_args.output, export_args.format)
            if not output_path:
                print("[ERROR] Export requires an output path")
                continue
            try:
                exit_code = export_last_report(
                    output_path, output_format, export_args.export_scope,
                    report_title=export_args.report_title, report_brand=export_args.report_brand,
                    report_logo=export_args.report_logo,
                )
            except (OSError, ValueError, TypeError):
                print("[ERROR] Export failed; check report data and file permissions")
                exit_code = 1
            print(f"Export exit code: {exit_code}")
            continue

        if command == "set":
            if len(tokens) < 3:
                print("Usage: set <key> <value>")
                continue
            key = tokens[1]
            value = " ".join(tokens[2:])
            try:
                normalized = update_interactive_setting(state, key, value)
            except (ValueError, TypeError) as exc:
                print(f"Set error: {exc}")
                continue
            display = redacted_url(value) if normalized == "proxy" else value
            print(f"Set {normalized} = {display}")
            try:
                prefs = update_preferences_from_state(prefs, state)
                if not initial_args.no_save_prefs:
                    save_preferences(prefs, prefs_scope)
            except OSError:
                print("[WARN] Failed to save preferences")
            continue

        if command == "unset":
            if len(tokens) != 2:
                print("Usage: unset <key>")
                continue
            try:
                normalized = unset_interactive_setting(state, tokens[1])
            except ValueError as exc:
                print(f"Unset error: {exc}")
                continue
            print(f"Unset {normalized}")
            try:
                prefs = update_preferences_from_state(prefs, state)
                if not initial_args.no_save_prefs:
                    save_preferences(prefs, prefs_scope)
            except OSError:
                print("[WARN] Failed to save preferences")
            continue

        if command in ("scan", "audit", "discover"):
            if len(tokens) < 2:
                print(f"Usage: {command} <url> [options]")
                continue
            scan_url = tokens[1]
            extra_tokens = tokens[2:]
            if command == "audit":
                extra_tokens = ["--mode", "audit"] + extra_tokens
            elif command == "discover":
                extra_tokens = ["--mode", "discover"] + extra_tokens
        else:
            looks_like_url = (
                "://" in command
                or ("." in command and not command.startswith("-"))
                or command == "localhost"
            )
            if not looks_like_url:
                print(f"Unknown command or invalid target: '{command}'. Type 'help' to see commands.")
                continue

            scan_url = tokens[0]
            extra_tokens = tokens[1:]

        if "://" not in scan_url and not scan_url.startswith("-"):
            scan_url = "https://" + scan_url
            print(c("INFO", "  (assumed https:// - use full URL to override)"))

        tokens = build_interactive_tokens(scan_url, state, extra_tokens)

        try:
            args = parser.parse_args(tokens)
            record_provided_options(args, parser, tokens)
            args.no_save_prefs = args.no_save_prefs or initial_args.no_save_prefs
            args.no_save_last = args.no_save_last or initial_args.no_save_last
            for key in ("basic_user", "basic_pass", "basic_pass_env", "bearer_token", "bearer_token_env", "cookie", "headers", "dry_run", "last_scope", "prefs_scope"):
                if key not in args._provided:
                    setattr(args, key, getattr(initial_args, key))
        except (argparse.ArgumentError, SystemExit) as exc:
            print(f"Parse error: {exc} - type 'help' for usage")
            continue

        try:
            exit_code = run_scan(args)
            print(f"Exit code: {exit_code}")
        except KeyboardInterrupt:
            print("\n[INFO] Scan interrupted; enter another target or 'exit'.")
        except Exception as exc:
            print(f"\n[!] Unexpected scan error: {exc}")


def main() -> None:
    args = parse_args()
    prefs = {} if args.no_load_prefs else load_preferences()

    if getattr(args, "export_last", False):
        if not args.output:
            print("[ERROR] --output is required when using --export-last")
            raise SystemExit(1)
        output_path, output_format = normalize_output_target(args.output, args.format)
        if not output_path:
            print("[ERROR] --output is required when using --export-last")
            raise SystemExit(1)
        try:
            code = export_last_report(
                output_path,
                output_format,
                getattr(args, "export_scope", "both"),
                report_title=args.report_title,
                report_brand=args.report_brand,
                report_logo=args.report_logo,
            )
        except (OSError, ValueError, TypeError, KeyError):
            print("[ERROR] Could not export report; check report contents and file permissions", file=sys.stderr)
            code = 1
        raise SystemExit(code)

    if args.url is None:
        interactive_mode(default_workers=args.workers, history_enabled=args.history, initial_args=args)
        return

    if not getattr(args, "no_load_prefs", False):
        apply_preferences_to_args(args, prefs)

    try:
        code = run_scan(args)
    except KeyboardInterrupt:
        print("\nInterrupted.")
        code = 130
    except (OSError, ValueError, TypeError) as exc:
        print(f"[ERROR] {type(exc).__name__}: operation failed; check configuration and file permissions", file=sys.stderr)
        LOGGER.debug("Scan failed", exc_info=True)
        code = 1
    if not getattr(args, "no_save_prefs", False) and code in (0, 2):
        prefs = update_preferences_from_args(prefs, args)
        try:
            save_preferences(prefs, getattr(args, "prefs_scope", "both"))
        except OSError:
            print("[WARN] Failed to save preferences")
    raise SystemExit(code)


if __name__ == "__main__":
    main()
