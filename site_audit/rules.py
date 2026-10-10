"""Conservative exposure matchers. Never store credential values as evidence."""
from __future__ import annotations

import json
import re
from urllib.parse import urlsplit

HEADER_REFERENCE = "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html"


def sensitive_match(path: str, text: str, content_type: str) -> tuple[str, str] | None:
    """Return rule ID and non-secret evidence only for recognizable file content."""
    name = urlsplit(path).path.lower()
    html = "html" in content_type or re.search(r"<!doctype\s+html|<html\b|<form\b", text, re.I)
    if html:
        return None
    if "/.env" in name:
        keys = re.findall(r"^\s*(?:export\s+)?([A-Z_][A-Z0-9_]*)\s*=", text, re.M)
        relevant = [key for key in keys if re.search(r"SECRET|TOKEN|PASSWORD|DB_|DATABASE|APP_KEY|API_KEY|AWS_", key)]
        if relevant:
            return "exposure.env", f"Environment assignments include keys: {', '.join(sorted(set(relevant))[:8])} (values withheld)"
    if name.endswith("/.git/config") and re.search(r"^\s*\[core\]\s*$", text, re.M) and re.search(r"^\s*(repositoryformatversion|bare)\s*=", text, re.M):
        return "exposure.git-config", "Git [core] section and repository configuration present"
    if name.endswith("/.git/head") and re.fullmatch(r"\s*(?:ref: refs/[^\s]+|[a-f0-9]{40}|[a-f0-9]{64})\s*", text, re.I):
        return "exposure.git-head", "Git HEAD reference or object ID present"
    if name.endswith(".sql") and re.search(r"(?:CREATE TABLE\s|INSERT INTO\s|-- (?:MySQL|PostgreSQL) database dump)", text, re.I):
        return "exposure.sql-dump", "SQL table/dump statements present"
    if name.endswith(".json"):
        try:
            data = json.loads(text)
        except ValueError:
            return None
        if isinstance(data, dict) and any(re.search(r"secret|password|private_key|api_key|access_token", str(key), re.I) for key in data):
            return "exposure.secret-json", "JSON object contains sensitive configuration keys (values withheld)"
    if name.endswith((".yml", ".yaml")) and re.search(r"^\s*(?:password|secret|api_key|database|private_key)\s*:", text, re.I | re.M):
        return "exposure.config-yaml", "YAML-like configuration contains sensitive keys (values withheld)"
    if name.endswith("/web.config") and "<configuration" in text.lower() and "<connectionstrings" in text.lower():
        return "exposure.web-config", "ASP.NET configuration includes connectionStrings (values withheld)"
    if name.endswith("/.htaccess") and re.search(r"^\s*(?:RewriteEngine|RewriteRule|AuthType|Require)\s", text, re.M | re.I):
        return "exposure.htaccess", "Apache per-directory configuration directives present"
    if name.endswith("/.svn/entries") and ("<wc-entries" in text or re.match(r"^\d+\n", text)):
        return "exposure.svn-entries", "Subversion working-copy metadata present"
    return None


def challenge_page(text: str) -> bool:
    return bool(re.search(r"cf-chl-|checking your browser|verify you are human|request is being verified|just a moment.*cloudflare", text, re.I | re.S))


def header_checks(response) -> list[dict]:
    """Observe actual policy values without claiming an exploitable XSS flaw."""
    result = []
    headers = response.headers
    is_html = "html" in headers.get("Content-Type", "").lower()

    def add(rule, severity, title, evidence, remediation):
        result.append(dict(rule_id=rule, severity=severity, title=title, evidence=evidence, remediation=remediation))

    if urlsplit(response.url).scheme == "https":
        hsts = headers.get("Strict-Transport-Security", "")
        age = re.search(r"(?:^|;)\s*max-age\s*=\s*(\d+)\s*(?:;|$)", hsts, re.I)
        if not hsts:
            add("header.hsts.missing", "MEDIUM", "Missing Strict-Transport-Security", "HSTS absent on HTTPS response", "Deploy HSTS after validating HTTPS on the intended host; choose max-age deliberately.")
        elif not age or int(age[1]) == 0:
            add("header.hsts.disabled", "MEDIUM", "HSTS policy is disabled or invalid", "No positive max-age directive", "Set a valid positive max-age; assess subdomain coverage before includeSubDomains.")
    if headers.get("X-Content-Type-Options", "").lower().strip() != "nosniff":
        add("header.nosniff", "LOW", "MIME sniffing protection missing or invalid", "X-Content-Type-Options is not nosniff", "Send X-Content-Type-Options: nosniff with accurate Content-Type values.")
    if is_html:
        csp = headers.get("Content-Security-Policy", "")
        directives = {}
        for item in csp.split(";"):
            parts = item.strip().split()
            if parts and parts[0].lower() not in directives:
                directives[parts[0].lower()] = parts[1:]
        if not csp:
            add("header.csp.missing", "LOW", "Missing enforcing Content-Security-Policy", "Enforcing CSP absent on HTML response", "Develop an application-specific CSP, test in report-only mode, then enforce it.")
        elif "default-src" not in directives and "script-src" not in directives:
            add("header.csp.script-unrestricted", "LOW", "CSP does not restrict script sources", "Neither default-src nor script-src is present", "Define script-src or default-src appropriate to the application.")
        sources = directives.get("script-src", directives.get("default-src", []))
        nonce_or_hash = any(value.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) for value in sources)
        if "*" in sources or ("'unsafe-inline'" in sources and not nonce_or_hash):
            add("header.csp.permissive-script", "LOW", "CSP permits broad script execution", "Wildcard or unrestricted unsafe-inline script source", "Restrict script sources and use nonces or hashes for necessary inline scripts.")
        frame_sources = directives.get("frame-ancestors")
        frame_restricted = frame_sources is not None and bool(frame_sources) and not {"*", "http:", "https:"}.intersection(frame_sources)
        xfo = headers.get("X-Frame-Options", "").strip().lower()
        if not frame_restricted and xfo not in ("deny", "sameorigin"):
            add("header.framing", "LOW", "Framing protection missing or unrestricted", "No restrictive frame-ancestors or valid X-Frame-Options", "Use CSP frame-ancestors 'none' or an explicit trusted origin list.")
        if not headers.get("Referrer-Policy"):
            add("header.referrer", "INFO", "Referrer-Policy not explicit", "No Referrer-Policy header; browser defaults apply", "Choose an explicit policy such as strict-origin-when-cross-origin based on application needs.")
    return result
