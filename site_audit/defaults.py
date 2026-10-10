"""Built-in scan, preference, and display defaults."""
from __future__ import annotations

import re

from .version import VERSION

TIMEOUT = 10


MAX_WORKERS = 20


RETRIES = 2


VERIFY_SSL = True


PREFS_VERSION = 1


USER_PREFS_FILENAME = ".site_audit_config.json"


PROJECT_PREFS_FILENAME = ".site_audit.json"


USER_LAST_FILENAME = ".site_audit_last.json"


PROJECT_LAST_FILENAME = ".site_audit_last.json"


PROFILE_DEFAULTS = {
    "quick": {
        "workers": 16,
        "timeout": 8,
        "retries": 1,
        "time_budget": 45,
        "max_paths": 120,
    },
    "standard": {
        "workers": MAX_WORKERS,
        "timeout": TIMEOUT,
        "retries": RETRIES,
        "time_budget": None,
        "max_paths": None,
    },
    "deep": {
        "workers": min(MAX_WORKERS * 2, 50),
        "timeout": max(TIMEOUT, 12),
        "retries": max(RETRIES, 2),
        "time_budget": 120,
        "max_paths": None,
    },
}


PROFILE_ALLOWED_SEVERITIES = {
    "quick": {"CRITICAL", "HIGH", "MEDIUM"},
}


IMPORTANT_PATHS = {
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/security.txt",
    "/security.txt",
}


PREF_KEYS = [
    "mode",
    "profile",
    "format",
    "output",
    "min_severity",
    "workers",
    "timeout",
    "time_budget",
    "retries",
    "insecure",
    "fail_on",
    "verbose",
    "log_file",
    "report_title",
    "report_brand",
    "report_logo",
    "ports",
    "proxy",
    "discover_subdomains",
    "rate_limit", "max_requests", "max_body_bytes", "system_proxy",
    "strict",
]


PREF_DEFAULTS = {
    "mode": "audit",
    "profile": "standard",
    "format": "json",
    "output": None,
    "min_severity": "INFO",
    "workers": MAX_WORKERS,
    "timeout": TIMEOUT,
    "time_budget": None,
    "retries": RETRIES,
    "insecure": False,
    "fail_on": None,
    "verbose": False,
    "log_file": None,
    "report_title": "Security Exposure Report",
    "report_brand": "site-audit",
    "report_logo": None,
    "ports": None,
    "proxy": None,
    "discover_subdomains": False,
    "rate_limit": 10.0,
    "max_requests": 1000,
    "max_body_bytes": 1_048_576,
    "system_proxy": False,
    "strict": False,
}


TEXTUAL_CONTENT_TYPES = (
    "text/",
    "application/json",
    "application/javascript",
    "application/xml",
    "application/xhtml+xml",
)


HEADERS = {
    "User-Agent": (
        f"site-audit/{VERSION}"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}


COLOURS = {
    "CRITICAL": "\033[91m",
    "HIGH":     "\033[31m",
    "MEDIUM":   "\033[33m",
    "LOW":      "\033[36m",
    "INFO":     "\033[37m",
    "OK":       "\033[32m",
    "RESET":    "\033[0m",
}


COMMON_PORTS = {
    "http": [80, 8080, 8000, 3000, 5000],
    "https": [443, 8443, 8453],
    "services": [22, 21, 25, 53, 110, 143, 389, 445, 3306, 5432, 6379, 9200, 27017],
}


DISCOVER_SUBDOMAIN_PREFIXES = [
    "www", "api", "admin", "app", "dev", "staging", "test", "beta",
    "status", "static", "cdn", "assets", "portal",
]


HEADER_NAME_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")


MAX_PORT_COUNT = 256


SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "OK"]
