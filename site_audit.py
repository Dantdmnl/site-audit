"""
site-audit — inspired by nuclei (severity templates), gobuster/ffuf (concurrency),
wappalyzer (regex fingerprinting), and nikto (comprehensive path lists).
"""
# ---------------------------------------------------------------------------
# Venv bootstrap — re-exec under .venv if we're not already inside it
# ---------------------------------------------------------------------------
import os as _os
import sys as _sys

_here = _os.path.dirname(_os.path.abspath(__file__))
_venv_python = _os.path.join(_here, ".venv", "Scripts", "python.exe")
if _os.path.isfile(_venv_python) and _os.path.abspath(_sys.executable) != _os.path.abspath(_venv_python):
    _os.execv(_venv_python, [_venv_python] + _sys.argv)
# ---------------------------------------------------------------------------

import argparse
import csv
import io
import json
import logging
import re
import shlex
import socket
import sys
import tempfile
import threading
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import TypedDict
from urllib.parse import urljoin, urlparse

import requests
import pypac
import urllib3
from bs4 import BeautifulSoup
from requests.adapters import HTTPAdapter
from requests.cookies import RequestsCookieJar
from urllib3.exceptions import InsecureRequestWarning
from urllib3.util.retry import Retry

try:
    from prompt_toolkit import PromptSession as PT_PromptSession
    from prompt_toolkit.completion import Completer as PT_Completer, Completion as PT_Completion
    from prompt_toolkit.document import Document as PT_Document
    from prompt_toolkit.history import FileHistory as PT_FileHistory, InMemoryHistory as PT_InMemoryHistory, DummyHistory as PT_DummyHistory
    HAS_PROMPT_TOOLKIT = True
except ImportError:
    HAS_PROMPT_TOOLKIT = False

TIMEOUT = 10
MAX_WORKERS = 20
RETRIES = 2
VERIFY_SSL = True
REPORT_SCHEMA_VERSION = "1.0"
TEXTUAL_CONTENT_TYPES = (
    "text/",
    "application/json",
    "application/javascript",
    "application/xml",
    "application/xhtml+xml",
)
HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/134.0.0.0 Safari/537.36"
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

LOGGER = logging.getLogger("site-audit")

INTERACTIVE_COMMANDS = [
    "scan",
    "audit",
    "discover",
    "set",
    "unset",
    "show",
    "history",
    "clear",
    "help",
    "exit",
    "quit",
]

INTERACTIVE_SET_KEYS = [
    "mode",
    "min-severity",
    "workers",
    "timeout",
    "retries",
    "insecure",
    "fail-on",
    "verbose",
    "log-file",
    "output",
]

INTERACTIVE_UNSET_KEYS = ["output", "fail-on", "log-file"]

INTERACTIVE_FLAGS = [
    "--mode",
    "--output",
    "--min-severity",
    "--workers",
    "--timeout",
    "--retries",
    "--insecure",
    "--fail-on",
    "--verbose",
    "--log-file",
]


def c(colour: str, text: str) -> str:
    if not sys.stdout.isatty():
        return text
    return f"{COLOURS.get(colour, '')}{text}{COLOURS['RESET']}"


# ---------------------------------------------------------------------------
# Nuclei-style path templates: (path, severity, description)
# ---------------------------------------------------------------------------
COMMON_PATHS: list[tuple[str, str, str]] = [
    # Info / recon
    ("/robots.txt",               "INFO",     "robots.txt"),
    ("/sitemap.xml",              "INFO",     "sitemap"),
    ("/.well-known/security.txt", "INFO",     "security.txt"),
    ("/security.txt",             "INFO",     "security.txt (root)"),
    ("/crossdomain.xml",          "MEDIUM",   "Flash crossdomain policy"),
    ("/clientaccesspolicy.xml",   "MEDIUM",   "Silverlight access policy"),
    # Admin surfaces
    ("/admin/",                   "HIGH",     "admin panel"),
    ("/administrator/",           "HIGH",     "admin panel"),
    ("/login/",                   "MEDIUM",   "login page"),
    ("/dashboard/",               "MEDIUM",   "dashboard"),
    ("/register/",                "LOW",      "registration page"),
    ("/user/login",               "MEDIUM",   "user login"),
    # APIs & schemas
    ("/api/",                     "LOW",      "API root"),
    ("/api/v1/",                  "LOW",      "API v1"),
    ("/api/v2/",                  "LOW",      "API v2"),
    ("/api/v3/",                  "LOW",      "API v3"),
    ("/graphql",                  "MEDIUM",   "GraphQL endpoint"),
    ("/graphiql",                 "HIGH",     "GraphiQL IDE (interactive)"),
    ("/swagger.json",             "MEDIUM",   "Swagger/OpenAPI spec"),
    ("/swagger-ui.html",          "MEDIUM",   "Swagger UI"),
    ("/openapi.json",             "MEDIUM",   "OpenAPI spec"),
    ("/api-docs",                 "MEDIUM",   "API docs"),
    # Health / monitoring
    ("/health",                   "LOW",      "health endpoint"),
    ("/healthz",                  "LOW",      "health endpoint"),
    ("/ping",                     "LOW",      "ping endpoint"),
    ("/status",                   "LOW",      "status endpoint"),
    ("/metrics",                  "MEDIUM",   "Prometheus metrics"),
    ("/ready",                    "LOW",      "readiness probe"),
    # Sensitive files — CRITICAL if reachable
    ("/.env",                     "CRITICAL", ".env file (credentials)"),
    ("/.env.production",          "CRITICAL", ".env.production"),
    ("/.env.local",               "CRITICAL", ".env.local"),
    ("/.git/config",              "CRITICAL", "git config (repo leak)"),
    ("/.git/HEAD",                "CRITICAL", "git HEAD"),
    ("/.svn/entries",             "CRITICAL", "SVN entries"),
    ("/.htaccess",                "HIGH",     ".htaccess rules"),
    ("/web.config",               "HIGH",     "web.config"),
    ("/config.json",              "HIGH",     "config.json"),
    ("/config.yaml",              "HIGH",     "config.yaml"),
    ("/config.yml",               "HIGH",     "config.yml"),
    ("/database.yml",             "HIGH",     "database config"),
    ("/secrets.json",             "CRITICAL", "secrets file"),
    ("/credentials.json",         "CRITICAL", "credentials file"),
    ("/backup.sql",               "CRITICAL", "SQL backup"),
    ("/dump.sql",                 "CRITICAL", "SQL dump"),
    # Debug / dev leftovers
    ("/debug/",                   "HIGH",     "debug panel"),
    ("/debug",                    "HIGH",     "debug endpoint"),
    ("/trace",                    "MEDIUM",   "trace endpoint"),
    ("/phpinfo.php",              "HIGH",     "phpinfo()"),
    ("/info.php",                 "HIGH",     "phpinfo()"),
    ("/test.php",                 "MEDIUM",   "test PHP file"),
    ("/backup/",                  "HIGH",     "backup directory"),
    ("/old/",                     "MEDIUM",   "old/ directory"),
    ("/dev/",                     "HIGH",     "dev/ directory"),
    ("/staging/",                 "HIGH",     "staging directory"),
    ("/temp/",                    "MEDIUM",   "temp directory"),
    ("/tmp/",                     "MEDIUM",   "tmp directory"),
]

PLATFORM_PATHS: dict[str, list[tuple[str, str, str]]] = {
    "wordpress": [
        ("/wp-admin/",                  "HIGH",     "WP admin panel"),
        ("/wp-login.php",               "HIGH",     "WP login"),
        ("/xmlrpc.php",                 "HIGH",     "XML-RPC (brute/SSRF vector)"),
        ("/wp-json/",                   "LOW",      "WP REST API root"),
        ("/wp-json/wp/v2/users",        "HIGH",     "WP user enumeration endpoint"),
        ("/wp-content/debug.log",       "CRITICAL", "WP debug log"),
        ("/wp-config.php",              "CRITICAL", "WP config (credentials)"),
        ("/wp-config.php.bak",          "CRITICAL", "WP config backup"),
        ("/wp-config-sample.php",       "LOW",      "WP sample config"),
        ("/readme.html",                "LOW",      "WP version disclosure"),
        ("/license.txt",                "INFO",     "WP license"),
        ("/wp-sitemap.xml",             "INFO",     "WP sitemap"),
    ],
    "drupal": [
        ("/user/login",                 "MEDIUM",   "Drupal login"),
        ("/user/register",              "MEDIUM",   "Drupal registration"),
        ("/admin/config",               "HIGH",     "Drupal config"),
        ("/update.php",                 "CRITICAL", "Drupal update script"),
        ("/install.php",                "CRITICAL", "Drupal install script"),
        ("/CHANGELOG.txt",              "MEDIUM",   "Drupal version disclosure"),
        ("/core/CHANGELOG.txt",         "MEDIUM",   "Drupal core version"),
        ("/sites/default/settings.php", "CRITICAL", "Drupal settings (credentials)"),
        ("/sites/default/files/",       "MEDIUM",   "Drupal public files"),
    ],
    "joomla": [
        ("/administrator/",             "HIGH",     "Joomla admin"),
        ("/administrator/index.php",    "HIGH",     "Joomla admin login"),
        ("/README.txt",                 "LOW",      "Joomla version disclosure"),
        ("/htaccess.txt",               "LOW",      "Joomla .htaccess sample"),
        ("/web.config.txt",             "LOW",      "Joomla web.config sample"),
        ("/cache/",                     "MEDIUM",   "Joomla cache directory"),
        ("/components/",               "LOW",      "Joomla components"),
    ],
    "laravel": [
        ("/storage/logs/laravel.log",   "CRITICAL", "Laravel log file"),
        ("/telescope",                  "HIGH",     "Laravel Telescope"),
        ("/horizon",                    "HIGH",     "Laravel Horizon"),
        ("/api/user",                   "MEDIUM",   "Laravel API user endpoint"),
        ("/_ignition/health-check",     "LOW",      "Ignition health"),
        ("/_ignition/execute-solution", "CRITICAL", "Ignition RCE endpoint"),
    ],
    "django": [
        ("/admin/",                     "HIGH",     "Django admin"),
        ("/api/schema/",                "MEDIUM",   "Django schema"),
        ("/api/docs/",                  "MEDIUM",   "Django API docs"),
        ("/__debug__/",                 "HIGH",     "Django Debug Toolbar"),
    ],
    "aspnet": [
        ("/elmah.axd",                  "HIGH",     "ELMAH error log"),
        ("/trace.axd",                  "HIGH",     "ASP.NET trace"),
        ("/ScriptResource.axd",         "LOW",      "ASP.NET resources"),
    ],
    "symfony": [
        ("/app_dev.php",                "HIGH",     "Symfony dev frontend"),
        ("/app_dev.php/_profiler/",     "HIGH",     "Symfony profiler"),
        ("/_profiler/",                 "HIGH",     "Symfony profiler"),
        ("/_wdt/",                      "MEDIUM",   "Symfony web debug toolbar"),
    ],
    "rails": [
        ("/rails/info/properties",      "HIGH",     "Rails info (env disclosure)"),
        ("/rails/info/routes",          "MEDIUM",   "Rails route list"),
        ("/sidekiq",                    "HIGH",     "Sidekiq web UI"),
        ("/letter_opener",              "MEDIUM",   "Letter Opener (email preview)"),
    ],
    "spring": [
        ("/actuator",                   "HIGH",     "Spring Actuator root"),
        ("/actuator/env",               "CRITICAL", "Spring env (credentials leak)"),
        ("/actuator/mappings",          "MEDIUM",   "Spring route mappings"),
        ("/actuator/beans",             "MEDIUM",   "Spring beans"),
        ("/actuator/health",            "LOW",      "Spring health"),
        ("/h2-console",                 "CRITICAL", "H2 database console"),
    ],
    "nextjs": [
        ("/_next/static/",              "INFO",     "Next.js static assets"),
    ],
}

# (header-name, severity-if-missing, description)
SECURITY_HEADERS: list[tuple[str, str, str]] = [
    ("Strict-Transport-Security", "HIGH",   "HSTS not set — HTTPS not enforced"),
    ("Content-Security-Policy",   "HIGH",   "CSP not set — XSS/injection exposure"),
    ("X-Content-Type-Options",    "MEDIUM", "MIME sniffing not disabled"),
    ("X-Frame-Options",           "MEDIUM", "Clickjacking protection missing"),
    ("Referrer-Policy",           "LOW",    "Referrer-Policy not set"),
    ("Permissions-Policy",        "LOW",    "Permissions-Policy not set"),
    ("Cross-Origin-Opener-Policy","LOW",    "COOP not set"),
]

TECH_HEADERS = [
    "Server", "X-Powered-By", "X-Generator", "Via",
    "X-AspNet-Version", "X-AspNetMvc-Version",
    "X-Drupal-Cache", "X-WordPress-Cache",
]

# Wappalyzer-style rules: (platform, [(regex_pattern, source), ...])
# source: "html" | "headers" | "cookies"
WAPPALYZER_RULES: dict[str, list[tuple[str, str]]] = {
    "wordpress":  [(r"wp-content|wp-includes|wp-json", "html"),
                   (r"x-pingback", "headers"),
                   (r"wordpress", "cookies")],
    "drupal":     [(r"drupal|sites/default", "html"),
                   (r"x-generator.*drupal", "headers"),
                   (r"drupal", "cookies")],
    "joomla":     [(r"/media/system/js/|joomla", "html"),
                   (r"x-generator.*joomla", "headers")],
    "laravel":    [(r'name="csrf-token"|laravel', "html"),
                   (r"laravel_session|xsrf-token", "cookies")],
    "django":     [(r"csrfmiddlewaretoken|__admin_media", "html"),
                   (r"csrftoken", "cookies")],
    "aspnet":     [(r"__viewstate|webresource\.axd", "html"),
                   (r"x-aspnet-version|x-aspnetmvc-version", "headers"),
                   (r"asp\.net_sessionid", "cookies")],
    "symfony":    [(r"symfony", "html"), (r"sf_", "cookies")],
    "rails":      [(r"rails|data-turbo", "html"), (r"_rails|_session_id", "cookies")],
    "nextjs":     [(r"__next_data__|/_next/", "html")],
    "nuxtjs":     [(r"__nuxt__|/_nuxt/", "html")],
    "spring":     [(r"x-application-context", "headers"), (r"jsessionid", "cookies")],
    "express":    [(r"x-powered-by.*express", "headers")],
    "nginx":      [(r"nginx", "headers")],
    "apache":     [(r"apache", "headers")],
    "iis":        [(r"microsoft-iis", "headers")],
    "cloudflare": [(r"cf-ray|cloudflare", "headers"),
                   (r"__cfduid|cf_clearance", "cookies")],
    "varnish":    [(r"x-varnish|varnish", "headers")],
    "jquery":     [(r"jquery[.\-/][\d.]+", "html")],
    "react":      [(r"__reactfiber|data-reactroot|react(?:dom)?[.\-/][\d.]+", "html")],
    "vue":        [(r"vue[.\-/][\d.]+|data-v-", "html")],
    "bootstrap":  [(r"bootstrap[.\-/][\d.]+", "html")],
}

# Patterns that indicate sensitive/debug content in a 200 response body
BODY_PATTERNS: list[tuple[str, str, str]] = [
    (r"stack trace|traceback \(most recent call\)|exception in thread",
     "HIGH",     "Stack trace / exception in response body"),
    (r"sql syntax|mysql_fetch|pg_query|sqlite3\.operationalerror|ora-\d{5}",
     "CRITICAL", "SQL error in response body (possible SQLi surface)"),
    (r'password\s*=\s*[\'"]?\w+|db_password|api_key\s*=\s*[\'"]?\w+',
     "CRITICAL", "Credential-like string in response body"),
    (r"PHP (Warning|Parse error|Fatal error|Notice)",
     "MEDIUM",   "PHP error visible in response body"),
    (r"<b>Warning</b>|<b>Notice</b>|<b>Fatal error</b>",
     "MEDIUM",   "PHP error (HTML formatted) in response body"),
    (r"Directory listing for|Index of /",
     "HIGH",     "Directory listing enabled"),
    (r'"access_token":|"secret":|"private_key":',
     "CRITICAL", "Sensitive key in response body"),
]

BODY_PATTERNS_COMPILED: list[tuple[re.Pattern[str], str, str]] = [
    (re.compile(pattern, re.I), severity, title)
    for pattern, severity, title in BODY_PATTERNS
]


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------
@dataclass
class Finding:
    severity: str
    category: str   # endpoint | header | cookie | cors | method | body | tech
    title: str
    detail: str
    url: str = ""
    status_code: int | None = None
    extra: dict = field(default_factory=dict)


@dataclass
class ScanConfig:
    timeout: int = TIMEOUT
    retries: int = RETRIES
    verify_ssl: bool = VERIFY_SSL
    proxy: str | None = None
    custom_headers: dict[str, str] = field(default_factory=dict)


def setup_logging(verbose: bool, log_file: str | None) -> None:
    level = logging.DEBUG if verbose else logging.WARNING
    handlers: list[logging.Handler] = [logging.StreamHandler()]
    if log_file:
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


def build_session(config: ScanConfig) -> requests.Session:
    if config.proxy:
        # Explicit proxy overrides Windows/PAC settings
        session = requests.Session()
        session.proxies = {
            "http": config.proxy,
            "https": config.proxy,
        }
    else:
        # Use Windows PAC file if available, otherwise fallback to standard session
        try:
            pac = pypac.get_pac()
            if pac:
                session = pypac.PACSession(pac)
            else:
                session = requests.Session()
        except Exception:
            session = requests.Session()
    
    session.headers.update(HEADERS)
    session.headers.update(config.custom_headers)

    retry = Retry(
        total=max(0, config.retries),
        connect=max(0, config.retries),
        read=max(0, config.retries),
        backoff_factor=0.4,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset({"GET", "HEAD", "OPTIONS"}),
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry, pool_connections=50, pool_maxsize=50)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.verify = config.verify_ssl
    return session


class ThreadLocalSessionPool:
    """Thread-safe session pool with one requests.Session per worker thread."""

    def __init__(self, config: ScanConfig, seed_cookies: RequestsCookieJar | None = None):
        self.config = config
        self.seed_cookies = seed_cookies
        self.local = threading.local()
        self._sessions: list[requests.Session] = []
        self._lock = threading.Lock()

    def get(self) -> requests.Session:
        session = getattr(self.local, "session", None)
        if session is None:
            session = build_session(self.config)
            if self.seed_cookies is not None:
                session.cookies.update(self.seed_cookies)
            self.local.session = session
            with self._lock:
                self._sessions.append(session)
        return session

    def close(self) -> None:
        with self._lock:
            for session in self._sessions:
                try:
                    session.close()
                except Exception:
                    pass
            self._sessions.clear()


# ---------------------------------------------------------------------------
# Port scanning
# ---------------------------------------------------------------------------
def scan_ports(host: str, ports: list[int], timeout: float = 2.0) -> dict[int, bool]:
    """
    Scan a list of ports on a host.
    Returns dict mapping port -> is_open (True/False).
    """
    results = {}
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            results[port] = (result == 0)
        except (socket.timeout, socket.error):
            results[port] = False
    return results


def get_ports_for_url(base_url: str, scan_type: str = "http") -> list[int]:
    """
    Get ports to scan based on URL scheme and scan_type.
    scan_type: 'http' (80,8080,etc), 'https' (443,8443,etc), 'services' (all common), or comma-separated ports.
    """
    try:
        parsed = urlparse(base_url)
        scheme = parsed.scheme.lower()
    except:
        scheme = "https"
    
    if scan_type == "http":
        return COMMON_PORTS["http"]
    elif scan_type == "https":
        return COMMON_PORTS["https"]
    elif scan_type == "services":
        return COMMON_PORTS["services"]
    elif "," in scan_type:
        try:
            return [int(p.strip()) for p in scan_type.split(",")]
        except ValueError:
            return COMMON_PORTS["http"] if scheme == "http" else COMMON_PORTS["https"]
    else:
        return COMMON_PORTS["http"] if scheme == "http" else COMMON_PORTS["https"]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def fetch_response(
    session: requests.Session,
    url: str,
    *,
    method: str = "GET",
    allow_redirects: bool = True,
    config: ScanConfig | None = None,
) -> tuple[requests.Response | None, str | None]:
    """Return (response, error_message). On success error_message is None."""
    cfg = config or ScanConfig()
    try:
        response = session.request(
            method=method,
            url=url,
            timeout=cfg.timeout,
            allow_redirects=allow_redirects,
        )
        return response, None
    except requests.exceptions.SSLError as exc:
        return None, f"SSL error: {exc}"
    except requests.exceptions.ConnectionError as exc:
        return None, f"Connection error: {exc}"
    except requests.exceptions.Timeout:
        return None, f"Timed out after {cfg.timeout}s"
    except requests.RequestException as exc:
        return None, str(exc)


def fetch_text(session: requests.Session, url: str, config: ScanConfig) -> str | None:
    resp, _ = fetch_response(session, url, config=config)
    return resp.text if resp is not None and resp.ok else None


def normalize_url(url: str, base_url: str) -> str:
    parsed = urlparse(urljoin(base_url, url))
    path = parsed.path or "/"
    if path != "/" and not path.endswith("/"):
        path += "/"
    return f"{parsed.scheme}://{parsed.netloc}{path}"


def is_internal(url: str, base_url: str) -> bool:
    return urlparse(urljoin(base_url, url)).netloc == urlparse(base_url).netloc


def is_content_url(url: str, base_url: str) -> bool:
    if not is_internal(url, base_url):
        return False
    path = urlparse(url).path.lower()
    if not path or path == "/":
        return False
    blocked = ("/wp-content/", "/wp-includes/", "/wp-json/", "/static/",
               "/assets/", "/media/", "/_next/", "/_nuxt/")
    if any(path.startswith(b) for b in blocked):
        return False
    seg = path.rsplit("/", 2)[-2] if path.endswith("/") else path.rsplit("/", 1)[-1]
    return "." not in seg


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


def severity_index(severity: str) -> int:
    return SEVERITY_ORDER.index(severity)


def has_findings_at_or_above(findings: list[Finding], severity: str) -> bool:
    threshold = severity_index(severity)
    return any(severity_index(f.severity) <= threshold for f in findings)


def write_json_atomic(output_path: str, payload: dict) -> None:
    directory = _os.path.dirname(_os.path.abspath(output_path)) or "."
    _os.makedirs(directory, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(prefix=".site-audit-", suffix=".tmp", dir=directory)
    try:
        with _os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, sort_keys=True)
            fh.write("\n")
        _os.replace(tmp_path, output_path)
    except Exception:
        try:
            _os.remove(tmp_path)
        except OSError:
            pass
        raise


def write_csv(output_path: str, findings: list[Finding]) -> None:
    """Write findings to CSV file."""
    directory = _os.path.dirname(_os.path.abspath(output_path)) or "."
    _os.makedirs(directory, exist_ok=True)
    
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        fieldnames = ["severity", "category", "title", "detail", "url", "status_code"]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for finding in findings:
            writer.writerow({
                "severity": finding.severity,
                "category": finding.category,
                "title": finding.title,
                "detail": finding.detail,
                "url": finding.url,
                "status_code": finding.status_code or "",
            })


def write_xml(output_path: str, findings: list[Finding], target: str) -> None:
    """Write findings to XML file."""
    directory = _os.path.dirname(_os.path.abspath(output_path)) or "."
    _os.makedirs(directory, exist_ok=True)
    
    root = ET.Element("audit")
    root.set("target", target)
    root.set("timestamp", datetime.now(timezone.utc).isoformat())
    
    for finding in findings:
        item = ET.SubElement(root, "finding")
        ET.SubElement(item, "severity").text = finding.severity
        ET.SubElement(item, "category").text = finding.category
        ET.SubElement(item, "title").text = finding.title
        ET.SubElement(item, "detail").text = finding.detail
        ET.SubElement(item, "url").text = finding.url
        if finding.status_code:
            ET.SubElement(item, "status_code").text = str(finding.status_code)
    
    tree = ET.ElementTree(root)
    tree.write(output_path, encoding="utf-8", xml_declaration=True)


class InteractiveState(TypedDict):
    mode: str
    output: str | None
    min_severity: str
    workers: int
    timeout: int
    retries: int
    insecure: bool
    fail_on: str | None
    verbose: bool
    log_file: str | None


if HAS_PROMPT_TOOLKIT:
    class SiteAuditCompleter(PT_Completer):
        def get_completions(self, document: PT_Document, complete_event):
            text = document.text_before_cursor
            current = document.get_word_before_cursor(WORD=True)
            current_lower = current.lower()

            try:
                tokens = shlex.split(text)
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
                    elif key in ("min-severity", "fail-on"):
                        for sev in SEVERITY_ORDER:
                            if sev.lower().startswith(current_lower):
                                yield PT_Completion(sev, start_position=-len(current))
                    elif key in ("insecure", "verbose"):
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
    findings: list[Finding] = []
    for header, severity, message in SECURITY_HEADERS:
        if header not in response.headers:
            findings.append(Finding(
                severity=severity, category="header",
                title=f"Missing {header}",
                detail=message,
                url=str(response.url),
            ))
    return findings


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
        lower = raw.lower()

        if "secure" not in lower:
            findings.append(Finding(
                severity="MEDIUM", category="cookie",
                title=f"Cookie '{name}' missing Secure flag",
                detail="Cookie can be sent over HTTP",
                url=str(response.url),
            ))
        if "httponly" not in lower:
            findings.append(Finding(
                severity="MEDIUM", category="cookie",
                title=f"Cookie '{name}' missing HttpOnly flag",
                detail="Cookie accessible via JavaScript",
                url=str(response.url),
            ))
        if "samesite" not in lower:
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

    if acao == "*":
        findings.append(Finding(
            severity="MEDIUM", category="cors",
            title="CORS: wildcard origin allowed",
            detail="Access-Control-Allow-Origin: *",
            url=base_url,
        ))
    elif acao == "https://evil.example.com":
        severity = "CRITICAL" if acac.lower() == "true" else "HIGH"
        findings.append(Finding(
            severity=severity, category="cors",
            title="CORS: arbitrary origin reflected"
                  + (" with credentials" if acac.lower() == "true" else ""),
            detail=f"ACAO: {acao}  ACAC: {acac or 'not set'}",
            url=base_url,
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
    dangerous = [m for m in ("PUT", "DELETE", "TRACE", "CONNECT") if m in allow.upper()]
    if dangerous:
        findings.append(Finding(
            severity="MEDIUM", category="method",
            title=f"Dangerous HTTP methods allowed: {', '.join(dangerous)}",
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
            start = max(0, m.start() - 40)
            snippet = clean_snippet(resp.text[start: m.end() + 80])
            findings.append(Finding(
                severity=severity, category="body",
                title=title,
                detail=f"...{snippet}...",
                url=str(resp.url),
                status_code=resp.status_code,
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
) -> Finding | None:
    session = session_pool.get()
    url = urljoin(base_url, path.lstrip("/"))
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
        body_issues = [f.title for f in check_response_body(resp)]
        return Finding(
            severity=severity, category="endpoint",
            title=f"EXPOSED: {description}",
            detail=f"HTTP {sc} ({resp.headers.get('Content-Type', '').split(';')[0].strip()})",
            url=url, status_code=sc,
            extra={"body_issues": body_issues} if body_issues else {},
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
            severity="LOW", category="endpoint",
            title=f"PROTECTED: {description}",
            detail=f"HTTP {sc} — endpoint exists but access is blocked",
            url=url, status_code=sc,
        )

    if 500 <= sc <= 599:
        return Finding(
            severity="MEDIUM", category="endpoint",
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
) -> list[Finding]:
    seen: set[str] = set()
    tasks: list[tuple[str, str, str]] = []
    for path, sev, desc in COMMON_PATHS:
        if path not in seen:
            seen.add(path)
            tasks.append((path, sev, desc))
    for platform in platforms:
        for path, sev, desc in PLATFORM_PATHS.get(platform, []):
            if path not in seen:
                seen.add(path)
                tasks.append((path, sev, desc))

    findings: list[Finding] = []
    errors = 0
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(probe_path, session_pool, base_url, path, sev, desc, config): path
            for path, sev, desc in tasks
        }
        for future in as_completed(futures):
            try:
                result = future.result()
            except Exception as exc:
                errors += 1
                result = Finding(
                    severity="INFO", category="endpoint",
                    title="Probe task failed",
                    detail=str(exc),
                    url=urljoin(base_url, futures[future].lstrip("/")),
                )
            if result is not None:
                findings.append(result)

    if errors:
        findings.append(Finding(
            severity="INFO", category="endpoint",
            title="Some endpoint probes failed",
            detail=f"{errors} worker task(s) raised an exception",
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
# Discover mode helpers
# ---------------------------------------------------------------------------
def extract_sitemap_locs(xml_text: str) -> list[str]:
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return []
    return [e.text.strip() for e in root.iter() if e.tag.endswith("loc") and e.text]


def crawl_sitemaps(session: requests.Session, base_url: str, config: ScanConfig) -> set[str]:
    queue: list[str] = []
    robots = fetch_text(session, urljoin(base_url, "robots.txt"), config)
    if robots:
        for line in robots.splitlines():
            if line.lower().startswith("sitemap:"):
                queue.append(line.split(":", 1)[1].strip())
    for fallback in ("/sitemap.xml", "/sitemap_index.xml"):
        url = urljoin(base_url, fallback)
        if url not in queue:
            queue.append(url)

    seen_maps: set[str] = set()
    urls: set[str] = set()
    while queue:
        sm = queue.pop(0)
        if sm in seen_maps:
            continue
        seen_maps.add(sm)
        xml = fetch_text(session, sm, config)
        if not xml:
            continue
        for loc in extract_sitemap_locs(xml):
            if loc.endswith(".xml"):
                queue.append(loc)
            elif is_content_url(loc, base_url):
                urls.add(normalize_url(loc, base_url))
    return urls


def crawl_feeds(session: requests.Session, base_url: str, html: str, config: ScanConfig) -> set[str]:
    urls: set[str] = set()
    soup = BeautifulSoup(html, "html.parser")
    feed_urls = [urljoin(base_url, "feed/")]
    for tag in soup.find_all("link", href=True, type=re.compile("rss|atom", re.I)):
        href = str(tag["href"]).strip()
        if is_internal(href, base_url):
            feed_urls.append(urljoin(base_url, href))
    for feed_url in feed_urls:
        xml = fetch_text(session, feed_url, config)
        if not xml:
            continue
        try:
            root = ET.fromstring(xml)
        except ET.ParseError:
            continue
        for elem in root.iter():
            if elem.tag.endswith("link") and elem.text and is_content_url(elem.text, base_url):
                urls.add(normalize_url(elem.text, base_url))
    return urls


def fetch_api_urls(session: requests.Session, base_url: str, config: ScanConfig) -> set[str]:
    urls: set[str] = set()
    probes = [
        ("wp-json/wp/v2/posts?per_page=100&_fields=link", "link"),
        ("wp-json/wp/v2/pages?per_page=100&_fields=link", "link"),
        ("api/v1/posts", "url"), ("api/v1/pages", "url"),
        ("api/v2/posts", "url"), ("api/posts", "url"),
    ]
    for endpoint, _ in probes:
        resp, _ = fetch_response(session, urljoin(base_url, endpoint), config=config)
        if resp is None or not resp.ok:
            continue
        try:
            payload = resp.json()
        except ValueError:
            continue
        rows = payload if isinstance(payload, list) else payload.get("data", [])
        for item in rows:
            if isinstance(item, dict):
                for k in ("link", "url", "href", "permalink"):
                    val = item.get(k)
                    if isinstance(val, str):
                        target = val if val.startswith("http") else urljoin(base_url, val)
                        if is_content_url(target, base_url):
                            urls.add(normalize_url(target, base_url))
                        break
    return urls


def discover_mode(
    session: requests.Session,
    base_url: str,
    html: str,
    config: ScanConfig,
) -> dict:
    soup = BeautifulSoup(html, "html.parser")
    homepage_links: set[str] = set()
    for tag in soup.find_all("a", href=True):
        href = str(tag["href"]).strip()
        if href and not href.startswith(("#", "mailto:", "tel:", "javascript:")):
            if is_internal(href, base_url):
                homepage_links.add(normalize_url(href, base_url))

    sitemap_urls = crawl_sitemaps(session, base_url, config)
    feed_urls = crawl_feeds(session, base_url, html, config)
    api_urls = fetch_api_urls(session, base_url, config)

    all_discovered = sitemap_urls | feed_urls | api_urls
    hidden = sorted(all_discovered - homepage_links - {normalize_url(base_url, base_url)})

    print(f"Homepage internal links       : {len(homepage_links)}")
    print(f"Discovered (sitemap/feed/API) : {len(all_discovered)}")
    print(f"Not linked from homepage      : {len(hidden)}\n")
    for url in hidden:
        print(url)

    return {
        "homepage_internal_links": sorted(homepage_links),
        "discovered": sorted(all_discovered),
        "hidden": hidden,
    }


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------
SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "OK"]


def normalize_base_url(raw_url: str) -> str:
    url = raw_url.strip()
    if not url:
        raise ValueError("URL is empty")
    if "://" not in url:
        url = "https://" + url

    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("Only http and https URLs are supported")
    if not parsed.netloc:
        raise ValueError("URL host is missing")

    path = parsed.path or "/"
    if not path.endswith("/"):
        path += "/"
    return f"{parsed.scheme}://{parsed.netloc}{path}"


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
    print(f"\nSummary — {' | '.join(parts)}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="site-audit",
        description=(
            "Authorized web site exposure auditor.\n"
            "Inspired by nuclei, gobuster, wappalyzer, and nikto.\n\n"
            "Only use against targets you own or have explicit permission to test."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("url", nargs="?", default=None, help="Base URL to inspect (e.g. https://example.com) — omit to enter interactive mode")
    parser.add_argument(
        "--mode", choices=["audit", "discover"], default="audit",
        help="audit: headers/cookies/CORS/endpoints  discover: unlinked URL inventory",
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
        "--retries", type=int, default=RETRIES,
        help=f"Retries on transient HTTP errors (default: {RETRIES})",
    )
    parser.add_argument(
        "--insecure", action="store_true",
        help="Disable SSL certificate verification",
    )
    parser.add_argument(
        "--fail-on", choices=SEVERITY_ORDER, default=None,
        help="Exit with code 2 if findings at/above this severity exist (for CI)",
    )
    parser.add_argument(
        "--verbose", action="store_true",
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
        "--format", choices=["json", "csv", "xml"], default="json",
        help="Output format for --output file (default: json)",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Simulate scan without making requests (useful for configuration testing)",
    )
    return parser.parse_args()


def run_scan(args: argparse.Namespace) -> int:
    """Execute a single scan given a populated Namespace. Called from both CLI and interactive mode."""
    try:
        base_url = normalize_base_url(args.url)
    except ValueError as exc:
        print(c("CRITICAL", f"[ERROR] Invalid URL: {exc}"))
        return 1

    setup_logging(args.verbose, args.log_file)

    workers = max(1, min(args.workers, 200))
    timeout = max(1, args.timeout)
    retries = max(0, args.retries)
    min_idx = SEVERITY_ORDER.index(args.min_severity)
    
    # Parse custom headers
    custom_headers = {}
    if hasattr(args, 'headers') and args.headers:
        for header_str in args.headers:
            if ":" in header_str:
                key, val = header_str.split(":", 1)
                custom_headers[key.strip()] = val.strip()
    
    config = ScanConfig(
        timeout=timeout,
        retries=retries,
        verify_ssl=not args.insecure,
        proxy=getattr(args, 'proxy', None),
        custom_headers=custom_headers,
    )
    fail_on = args.fail_on
    output_format = getattr(args, 'format', 'json')
    dry_run = getattr(args, 'dry_run', False)

    # Suppress urllib3 warnings globally (connection pool, retries, etc)
    # They are logged but not useful to end users
    urllib3.disable_warnings()
    
    if args.insecure:
        LOGGER.warning("TLS certificate verification disabled")

    if dry_run:
        print(c("INFO", "[DRY-RUN MODE - No requests will be made]"))
        LOGGER.info("Dry-run mode enabled")

    LOGGER.info("Starting %s scan for %s", args.mode, base_url)

    with build_session(config) as session:
        if dry_run:
            homepage = None
            fetch_err = None
        else:
            homepage, fetch_err = fetch_response(session, base_url, config=config)
            
        if not dry_run:
            if homepage is None:
                print(c("CRITICAL", f"[ERROR] Could not connect to {base_url}"))
                # Simplify error message - show just the core issue, not full stack
                if fetch_err:
                    short_err = fetch_err.split(':')[0] if ':' in fetch_err else fetch_err
                    print(f"       {short_err}")
                    if "timeout" in fetch_err.lower():
                        print(f"       Tip: Try --timeout {max(int(args.timeout) + 5, 15)} for slow networks")
                if args.insecure:
                    print("       SSL verification is disabled (--insecure).")
                return 1
            if not homepage.ok:
                print(c("HIGH", f"[WARN] Homepage returned HTTP {homepage.status_code} for {base_url}"))
                print(f"       The tool will continue, but results may be incomplete.")
                LOGGER.warning("Homepage returned HTTP %s", homepage.status_code)

            if args.mode == "discover":
                print(f"Mode: public URL discovery\nTarget: {base_url}\n")
                result = discover_mode(session, base_url, homepage.text, config)
                if args.output:
                    report = {
                        "schema_version": REPORT_SCHEMA_VERSION,
                        "target": base_url,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "mode": "discover",
                        "settings": {
                            "workers": workers,
                            "timeout": timeout,
                            "retries": retries,
                            "verify_ssl": config.verify_ssl,
                        },
                        "result": result,
                    }
                    write_json_atomic(args.output, report)
                    print(f"JSON report written to {args.output}")
                LOGGER.info("Discover mode finished")
                return 0

        platforms, tech_findings = fingerprint(homepage, session) if (not dry_run and homepage) else ([], [])

        print(c("INFO", "=" * 64))
        print(c("INFO", f"  site-audit"))
        print(c("INFO", f"  Target   : {base_url}"))
        print(c("INFO", f"  Platform : {', '.join(platforms) or 'unknown'}"))
        print(c("INFO", f"  Time     : {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}"))
        print(c("INFO", f"  Workers  : {workers}"))
        print(c("INFO", f"  Timeout  : {timeout}s"))
        print(c("INFO", f"  Retries  : {retries}"))
        print(c("INFO", f"  Verify   : {'on' if config.verify_ssl else 'off'}"))
        if config.proxy:
            print(c("INFO", f"  Proxy    : {config.proxy}"))
        print(c("INFO", "=" * 64))
        print()

        all_findings: list[Finding] = []
        
        # Port scanning
        if getattr(args, 'ports', None):
            try:
                parsed_url = urlparse(base_url)
                host = parsed_url.hostname or ""
                port_list = get_ports_for_url(base_url, args.ports)
                print(f"Scanning {len(port_list)} ports on {host}...")
                port_results = scan_ports(host, port_list, timeout=2.0)
                open_ports = [p for p, is_open in port_results.items() if is_open]
                if open_ports:
                    print(f"Open ports: {', '.join(map(str, sorted(open_ports)))}")
            except Exception as e:
                LOGGER.error(f"Port scanning failed: {e}")
        
        if dry_run:
            print("[DRY-RUN] Skipping endpoint audits")
        else:
            all_findings += tech_findings
            if homepage:
                all_findings += audit_security_headers(homepage)
                all_findings += audit_cookies(homepage)
            all_findings += audit_cors(base_url, config)
            all_findings += audit_methods(session, base_url, config)

            print(f"Probing {len(COMMON_PATHS)} common + platform-specific paths "
                  f"({workers} workers)...")
            session_pool = ThreadLocalSessionPool(config=config, seed_cookies=session.cookies)
            try:
                all_findings += run_endpoint_audit(session_pool, base_url, platforms, workers, config)
            finally:
                session_pool.close()

        all_findings = deduplicate_findings(all_findings)

        filtered = [f for f in all_findings if severity_index(f.severity) <= min_idx]

        print()
        print_findings(filtered)
        print_summary(filtered)

        if args.output:
            if output_format == "json":
                report = {
                    "schema_version": REPORT_SCHEMA_VERSION,
                    "target": base_url,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "platforms": platforms,
                    "settings": {
                        "workers": workers,
                        "timeout": timeout,
                        "retries": retries,
                        "verify_ssl": config.verify_ssl,
                        "min_severity": args.min_severity,
                        "fail_on": fail_on,
                    },
                    "findings": [asdict(f) for f in filtered],
                }
                write_json_atomic(args.output, report)
                print(f"JSON report written to {args.output}")
            elif output_format == "csv":
                write_csv(args.output, filtered)
                print(f"CSV report written to {args.output}")
            elif output_format == "xml":
                write_xml(args.output, filtered, base_url)
                print(f"XML report written to {args.output}")

        if fail_on and has_findings_at_or_above(all_findings, fail_on):
            LOGGER.warning("Fail-on threshold hit: %s", fail_on)
            return 2

        LOGGER.info("Audit finished successfully")
        return 0


INTERACTIVE_HELP = """
Commands:
  scan <url> [options]      run scan using saved defaults + optional overrides
  audit <url> [options]     same as scan, forced --mode audit
  discover <url> [options]  same as scan, forced --mode discover
  set <key> <value>         persist default option (workers, timeout, ...)
  unset <key>               remove optional default (output, fail-on, log-file)
  show config               print current interactive defaults
  history                   show current session command history
  clear                     clear screen
  help                      show this message
  exit / quit / Ctrl-C      leave

Common keys for 'set':
  mode, min-severity, workers, timeout, retries, insecure,
  fail-on, verbose, log-file, output

Examples:
  set workers 40
  set mode audit
  show config
  scan https://example.com
  discover https://example.com --output discover.json
  audit https://example.com --fail-on HIGH
""".strip()


def parse_bool(value: str) -> bool:
    normalized = value.strip().lower()
    if normalized in ("1", "true", "yes", "y", "on"):
        return True
    if normalized in ("0", "false", "no", "n", "off"):
        return False
    raise ValueError("expected boolean value: true/false")


def build_interactive_tokens(url: str, state: InteractiveState, extra_tokens: list[str]) -> list[str]:
    tokens = [url]

    if state["mode"] != "audit":
        tokens += ["--mode", str(state["mode"])]
    if state["output"]:
        tokens += ["--output", str(state["output"])]
    if state["min_severity"] != "INFO":
        tokens += ["--min-severity", str(state["min_severity"])]
    if int(state["workers"]) != MAX_WORKERS:
        tokens += ["--workers", str(state["workers"])]
    if int(state["timeout"]) != TIMEOUT:
        tokens += ["--timeout", str(state["timeout"])]
    if int(state["retries"]) != RETRIES:
        tokens += ["--retries", str(state["retries"])]
    if bool(state["insecure"]):
        tokens += ["--insecure"]
    if state["fail_on"]:
        tokens += ["--fail-on", str(state["fail_on"])]
    if bool(state["verbose"]):
        tokens += ["--verbose"]
    if state["log_file"]:
        tokens += ["--log-file", str(state["log_file"])]

    tokens.extend(extra_tokens)
    return tokens


def update_interactive_setting(state: InteractiveState, key: str, value: str) -> str:
    k = key.strip().lower().replace("_", "-")
    if k == "mode":
        if value not in ("audit", "discover"):
            raise ValueError("mode must be audit or discover")
        state["mode"] = value
        return "mode"
    if k in ("min-severity", "minseverity"):
        if value not in SEVERITY_ORDER:
            raise ValueError(f"min-severity must be one of: {', '.join(SEVERITY_ORDER)}")
        state["min_severity"] = value
        return "min-severity"
    if k == "workers":
        state["workers"] = max(1, min(int(value), 200))
        return "workers"
    if k == "timeout":
        state["timeout"] = max(1, int(value))
        return "timeout"
    if k == "retries":
        state["retries"] = max(0, int(value))
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
    raise ValueError(f"Unknown setting: {key}")


def unset_interactive_setting(state: InteractiveState, key: str) -> str:
    k = key.strip().lower().replace("_", "-")
    if k in ("output", "fail-on", "failon", "log-file", "logfile"):
        if k == "output":
            state["output"] = None
            return "output"
        if k in ("fail-on", "failon"):
            state["fail_on"] = None
            return "fail-on"
        state["log_file"] = None
        return "log-file"
    raise ValueError("Only output, fail-on, and log-file can be unset")


def print_interactive_config(state: InteractiveState) -> None:
    print("Current defaults:")
    print(f"  mode         : {state['mode']}")
    print(f"  min-severity : {state['min_severity']}")
    print(f"  workers      : {state['workers']}")
    print(f"  timeout      : {state['timeout']}")
    print(f"  retries      : {state['retries']}")
    print(f"  insecure     : {state['insecure']}")
    print(f"  fail-on      : {state['fail_on'] or '-'}")
    print(f"  verbose      : {state['verbose']}")
    print(f"  log-file     : {state['log_file'] or '-'}")
    print(f"  output       : {state['output'] or '-'}")


def create_prompt_session(history_enabled: bool, history_path: str):
    if not HAS_PROMPT_TOOLKIT:
        return None
    pt_history = PT_FileHistory(history_path) if history_enabled else PT_DummyHistory()
    return PT_PromptSession(
        completer=SiteAuditCompleter(),
        history=pt_history,
        reserve_space_for_menu=3,
        complete_while_typing=True,
        complete_in_thread=False,
        enable_history_search=True,
        search_ignore_case=True
    )

def interactive_mode(default_workers: int, history_enabled: bool = False) -> None:
    print(c("INFO", "=" * 64))
    print(c("INFO", "  site-audit  —  interactive mode"))
    print(c("INFO", "  type a URL to scan, 'help' for options, 'exit' to quit"))
    print(c("INFO", "=" * 64))

    parser = argparse.ArgumentParser(exit_on_error=False, add_help=False)
    parser.add_argument("url")
    parser.add_argument("--mode", choices=["audit", "discover"], default="audit")
    parser.add_argument("--output", metavar="FILE", default=None)
    parser.add_argument("--min-severity", choices=SEVERITY_ORDER, default="INFO")
    parser.add_argument("--workers", type=int, default=default_workers)
    parser.add_argument("--timeout", type=int, default=TIMEOUT)
    parser.add_argument("--retries", type=int, default=RETRIES)
    parser.add_argument("--insecure", action="store_true")
    parser.add_argument("--fail-on", choices=SEVERITY_ORDER, default=None)
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--log-file", metavar="FILE", default=None)
    parser.add_argument("--history", action="store_true")

    state: InteractiveState = {
        "mode": "audit",
        "output": None,
        "min_severity": "INFO",
        "workers": default_workers,
        "timeout": TIMEOUT,
        "retries": RETRIES,
        "insecure": False,
        "fail_on": None,
        "verbose": False,
        "log_file": None,
    }
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
            print("\nGraceful exit triggered. Byeeee!")
            break

        if not line:
            continue
        if line.lower() in ("exit", "quit", "q"):
            print("Bye.")
            break
        if line.lower() in ("help", "?", "h"):
            print(INTERACTIVE_HELP)
            continue

        if history_enabled:
            # Keep runtime history array updated for the 'history' command to read
            history.append(line)
            
            # Only write to file manually if we aren't using prompt_toolkit's FileHistory
            if not HAS_PROMPT_TOOLKIT:
                try:
                    with open(history_path, "a", encoding="utf-8") as fh:
                        fh.write(line + "\n")
                except OSError:
                    pass

        if line.lower() == "show config" or line.lower() == "show":
            print_interactive_config(state)
            continue

        if line.lower() == "clear":
            _os.system("cls" if _os.name == "nt" else "clear")
            continue

        try:
            tokens = shlex.split(line)
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
                    print(f"{idx:>4}: {entry}")
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
            print(f"Set {normalized} = {value}")
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
            print(c("INFO", f"  (assumed https:// — use full URL to override)"))

        tokens = build_interactive_tokens(scan_url, state, extra_tokens)

        try:
            args = parser.parse_args(tokens)
        except (argparse.ArgumentError, SystemExit) as exc:
            print(f"Parse error: {exc}  — type 'help' for usage")
            continue

        try:
            exit_code = run_scan(args)
            print(f"Exit code: {exit_code}")
        except KeyboardInterrupt:
            print("\n[+] Graceful exit triggered. Scan aborted. Use 'exit' to quit the application.")
        except Exception as exc:
            print(f"\n[!] Unexpected scan error: {exc}")


def main() -> None:
    args = parse_args()

    if args.url is None:
        interactive_mode(default_workers=args.workers, history_enabled=args.history)
        return

    try:
        code = run_scan(args)
    except KeyboardInterrupt:
        print("\nInterrupted.")
        code = 130
    raise SystemExit(code)


if __name__ == "__main__":
    main()
