"""HTTP sessions, scoped fetch helpers, and TCP connectivity checks."""
from __future__ import annotations

import socket
import threading
from urllib.parse import urlparse

import pypac
import requests
from requests.adapters import HTTPAdapter
from requests.cookies import RequestsCookieJar

from .core import ScanRuntime, ScanScope, bounded_fetch, canonical_url
from .defaults import COMMON_PORTS, HEADERS, MAX_PORT_COUNT
from .models import ScanConfig

def build_session(config: ScanConfig) -> requests.Session:
    if config.proxy:
        # Explicit proxy overrides Windows/PAC settings
        session = requests.Session()
        session.proxies = {
            "http": config.proxy,
            "https": config.proxy,
        }
    elif config.system_proxy:
        # Use Windows PAC file if available, otherwise fallback to standard session
        try:
            pac = pypac.get_pac()
            if pac:
                session = pypac.PACSession(pac)
            else:
                session = requests.Session()
        except Exception:
            session = requests.Session()
    else:
        session = requests.Session()
    session.trust_env = config.system_proxy and not config.proxy

    session.headers.update(HEADERS)
    session.headers.update(config.custom_headers)
    if config.bearer_token and "Authorization" not in session.headers:
        session.headers["Authorization"] = f"Bearer {config.bearer_token}"
    if config.auth:
        session.auth = config.auth
    if config.cookies:
        session.cookies.update(config.cookies)

    # Retries belong to the shared transport so they consume rate/request limits.
    adapter = HTTPAdapter(max_retries=0, pool_connections=1, pool_maxsize=1)
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


def scan_ports(host: str, ports: list[int], timeout: float = 2.0, runtime: ScanRuntime | None = None) -> dict[int, bool | None]:
    """
    Scan a list of ports on a host.
    Returns dict mapping port -> is_open (True/False).
    """
    results = {}
    for port in ports:
        if runtime and (runtime.budget.exhausted() or runtime.stop.is_set()):
            runtime.mark_partial("time_budget")
            break
        try:
            remaining = runtime.budget.remaining() if runtime else None
            with socket.create_connection((host, port), timeout=min(timeout, remaining) if remaining is not None else timeout):
                results[port] = True
        except ConnectionRefusedError:
            results[port] = False
        except (socket.timeout, socket.error):
            results[port] = None
            if runtime:
                runtime.mark_partial("port_errors")
    return results


def get_ports_for_url(base_url: str, scan_type: str = "http") -> list[int]:
    """
    Get ports to scan based on URL scheme and scan_type.
    scan_type: 'http' (80,8080,etc), 'https' (443,8443,etc), 'services' (all common), or comma-separated ports.
    """
    if scan_type == "http":
        return COMMON_PORTS["http"]
    elif scan_type == "https":
        return COMMON_PORTS["https"]
    elif scan_type == "services":
        return COMMON_PORTS["services"]
    elif "," in scan_type or scan_type.strip().isdigit():
        ports: list[int] = []
        for raw_port in scan_type.split(","):
            raw_port = raw_port.strip()
            if not raw_port:
                raise ValueError("empty port in comma-separated port list")
            try:
                port = int(raw_port)
            except ValueError:
                raise ValueError(f"invalid port: {raw_port}") from None
            if port < 1 or port > 65535:
                raise ValueError(f"port out of range: {port}")
            if port not in ports:
                ports.append(port)
        if len(ports) > MAX_PORT_COUNT:
            raise ValueError(f"port list is limited to {MAX_PORT_COUNT} entries")
        return ports
    else:
        raise ValueError("ports must be one of http, https, services, or a comma-separated list")


def fetch_response(
    session: requests.Session,
    url: str,
    *,
    method: str = "GET",
    allow_redirects: bool = True,
    config: ScanConfig | None = None,
) -> tuple[requests.Response | None, str | None]:
    """Return (response, error_message). On success error_message is None."""
    cfg = config or ScanConfig(scope=ScanScope(url))
    return bounded_fetch(session, url, cfg, method=method, allow_redirects=allow_redirects)


def fetch_text(session: requests.Session, url: str, config: ScanConfig) -> str | None:
    resp, _ = fetch_response(session, url, config=config)
    return resp.text if resp is not None and resp.ok else None


def normalize_url(url: str, base_url: str) -> str:
    return canonical_url(url, base_url)


def is_internal(url: str, base_url: str) -> bool:
    try:
        return ScanScope(base_url).allows(canonical_url(url, base_url))
    except (ValueError, UnicodeError):
        return False


def is_content_url(url: str, base_url: str) -> bool:
    if not is_internal(url, base_url):
        return False
    path = urlparse(normalize_url(url, base_url)).path.lower()
    if not path or path == "/":
        return False
    blocked = ("/wp-content/", "/wp-includes/", "/wp-json/", "/static/",
               "/assets/", "/media/", "/_next/", "/_nuxt/")
    if any(path.startswith(b) for b in blocked):
        return False
    asset_extensions = (".css", ".js", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico", ".woff", ".woff2", ".ttf", ".mp4", ".mp3", ".zip", ".gz")
    return not path.endswith(asset_extensions)
