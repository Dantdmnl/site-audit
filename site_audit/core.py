"""Shared scope, request limits, and scan accounting for every HTTP check."""
from __future__ import annotations

import hashlib
import ipaddress
import re
import threading
import time
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor
from email.utils import parsedate_to_datetime
from urllib.parse import urljoin, urlsplit, urlunsplit

import requests
import tldextract
from urllib3.exceptions import HTTPError

EXTRACT_DOMAIN = tldextract.TLDExtract(
    suffix_list_urls=(), cache_dir=None, include_psl_private_domains=True,
)


def canonical_url(value: str, base: str = "") -> str:
    value = value.strip()
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        raise ValueError("URL contains control characters")
    parsed = urlsplit(urljoin(base, value))
    if parsed.scheme.lower() not in ("http", "https"):
        raise ValueError("Only http and https URLs are supported")
    if not parsed.hostname or parsed.username is not None or parsed.password is not None:
        raise ValueError("URL requires a hostname and must not contain credentials")
    host = parsed.hostname.lower()
    try:
        address = ipaddress.ip_address(host)
        host = f"[{address}]" if address.version == 6 else str(address)
    except ValueError:
        host = host.encode("idna").decode("ascii")
        labels = host.rstrip(".").split(".")
        if len(host) > 253 or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels):
            raise ValueError("Invalid URL hostname") from None
    port = parsed.port  # Access also validates numeric/range constraints.
    if port == 0:
        raise ValueError("URL port must be 1..65535")
    default = 443 if parsed.scheme.lower() == "https" else 80
    authority = host + (f":{port}" if port and port != default else "")
    return urlunsplit((parsed.scheme.lower(), authority, parsed.path or "/", parsed.query, ""))


def origin(url: str) -> tuple[str, str, int]:
    parsed = urlsplit(canonical_url(url))
    return parsed.scheme, parsed.hostname or "", parsed.port or (443 if parsed.scheme == "https" else 80)


@dataclass(frozen=True)
class ScanScope:
    target: str

    def allows(self, url: str) -> bool:
        try:
            return origin(url) == origin(self.target)
        except (ValueError, UnicodeError):
            return False

    def allows_upgrade(self, source: str, destination: str) -> bool:
        """Only the initial default-port HTTP to HTTPS upgrade expands scope."""
        try:
            old, new = origin(source), origin(destination)
            return old == origin(self.target) and old == ("http", new[1], 80) and new == ("https", old[1], 443)
        except ValueError:
            return False

    def allows_canonical_alias(self, source: str, destination: str) -> bool:
        """Allow only default-port apex/www aliases without an HTTPS downgrade."""
        try:
            old, new = origin(source), origin(destination)
            if old != origin(self.target) or old[1] == new[1]:
                return False
            if old[2] != (443 if old[0] == "https" else 80) or new[2] != (443 if new[0] == "https" else 80):
                return False
            if old[0] == "https" and new[0] != "https":
                return False
            domain = EXTRACT_DOMAIN(old[1]).top_domain_under_public_suffix
            return bool(domain) and {old[1], new[1]} == {domain, "www." + domain}
        except (ValueError, UnicodeError):
            return False


class TimeBudget:
    def __init__(self, seconds: float | None):
        self.seconds = seconds
        self._deadline = time.monotonic() + seconds if seconds is not None else None

    def remaining(self) -> float | None:
        return max(0.0, self._deadline - time.monotonic()) if self._deadline is not None else None

    def exhausted(self) -> bool:
        remaining = self.remaining()
        return remaining is not None and remaining <= 0


@dataclass
class ScanRuntime:
    budget: TimeBudget
    rate_limit: float = 10.0
    max_requests: int = 1000
    requests_sent: int = 0
    responses_received: int = 0
    network_errors: int = 0
    blocked_requests: int = 0
    bytes_received: int = 0
    endpoints_planned: int = 0
    endpoints_completed: int = 0
    reasons: set[str] = field(default_factory=set)
    stop: threading.Event = field(default_factory=threading.Event, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    _next_request: float = field(default=0.0, repr=False)

    def mark_partial(self, reason: str) -> None:
        with self._lock:
            self.reasons.add(reason)

    def acquire(self) -> bool:
        while not self.stop.is_set():
            with self._lock:
                if self.budget.exhausted():
                    self.reasons.add("time_budget")
                    return False
                if self.requests_sent >= self.max_requests:
                    self.reasons.add("request_limit")
                    return False
                delay = self._next_request - time.monotonic()
                if delay <= 0:
                    self._next_request = time.monotonic() + 1.0 / self.rate_limit
                    self.requests_sent += 1
                    return True
            remaining = self.budget.remaining()
            if self.stop.wait(min(max(0.0, delay), remaining if remaining is not None else delay, 0.1)):
                return False
        self.mark_partial("cancelled")
        return False

    def record(self, *, response: bool = False, error: bool = False, blocked: bool = False, size: int = 0) -> None:
        with self._lock:
            self.responses_received += int(response)
            self.network_errors += int(error)
            self.blocked_requests += int(blocked)
            self.bytes_received += size

    def endpoint_done(self) -> None:
        with self._lock:
            self.endpoints_completed += 1

    def snapshot(self, dry_run: bool = False) -> dict:
        with self._lock:
            reasons = set(self.reasons)
            if self.budget.exhausted() and not dry_run:
                reasons.add("time_budget")
            if self.network_errors:
                reasons.add("network_errors")
            return {
                "status": "dry_run" if dry_run else ("partial" if reasons else "complete"),
                "reasons": sorted(reasons),
                "requests_sent": self.requests_sent,
                "responses_received": self.responses_received,
                "network_errors": self.network_errors,
                "blocked_requests": self.blocked_requests,
                "bytes_received": self.bytes_received,
                "endpoints_planned": self.endpoints_planned,
                "endpoints_completed": self.endpoints_completed,
            }


class ScanExecutor(ThreadPoolExecutor):
    def __init__(self, workers: int, runtime: ScanRuntime | None):
        super().__init__(max_workers=workers)
        self.runtime = runtime

    def __exit__(self, exc_type, exc_value, traceback):
        if exc_type is not None and self.runtime:
            self.runtime.stop.set()
        self.shutdown(wait=True, cancel_futures=True)
        return False


def redacted_url(url: str) -> str:
    parsed = urlsplit(url)
    host = parsed.hostname or ""
    if ":" in host:
        host = f"[{host}]"
    if parsed.port:
        host += f":{parsed.port}"
    return urlunsplit((parsed.scheme, host, parsed.path, "", ""))


def finding_id(rule_id: str, url: str) -> str:
    return hashlib.sha256(f"{rule_id}\n{url}".encode()).hexdigest()[:20]


def retry_delay(header: str | None, attempt: int) -> float:
    try:
        if header and header.isdigit():
            return min(float(header), 5.0)
        if header:
            return min(max(0.0, parsedate_to_datetime(header).timestamp() - time.time()), 5.0)
    except (ValueError, TypeError, OverflowError):
        pass
    return min(0.4 * 2**attempt, 5.0)


def bounded_fetch(session: requests.Session, url: str, config, *, method: str = "GET", allow_redirects: bool = True):
    """Fetch with manual scoped redirects and retries, capped decoded response bytes.

    Requests timeouts bound socket inactivity, not DNS or total wall time. The
    shared deadline is checked before each request/read/wait; no hard SLA is implied.
    """
    runtime = config.runtime
    initial_upgrade = config.allow_initial_upgrade
    initial_alias = config.allow_initial_canonical_redirect
    # These permissions apply to this startup fetch only, including its redirect chain.
    config.allow_initial_upgrade = False
    config.allow_initial_canonical_redirect = False
    try:
        current = canonical_url(url)
    except (ValueError, UnicodeError) as exc:
        return None, f"Invalid URL: {exc}"
    history = []
    for _redirect in range(config.max_redirects + 1):
        if config.scope and not config.scope.allows(current):
            if runtime:
                runtime.record(blocked=True)
                runtime.mark_partial("scope_blocked")
            return None, "Out-of-scope URL blocked"
        response = None
        for attempt in range(config.retries + 1):
            if runtime and not runtime.acquire():
                return None, "Scan limit reached"
            remaining = runtime.budget.remaining() if runtime else None
            timeout = min(float(config.timeout), remaining) if remaining is not None else float(config.timeout)
            try:
                response = session.request(method, current, timeout=max(0.001, timeout), allow_redirects=False, stream=True)
                if runtime:
                    runtime.record(response=True)
                if response.status_code in (429, 502, 503, 504) and attempt < config.retries:
                    delay = retry_delay(response.headers.get("Retry-After"), attempt)
                    response.close()
                    if runtime:
                        remaining = runtime.budget.remaining()
                        if runtime.stop.wait(min(delay, remaining if remaining is not None else delay)):
                            return None, "Scan cancelled"
                    else:
                        time.sleep(delay)
                    continue
                break
            except requests.RequestException as exc:
                if attempt < config.retries and not isinstance(exc, requests.exceptions.SSLError):
                    if runtime:
                        delay = retry_delay(None, attempt)
                        remaining = runtime.budget.remaining()
                        if runtime.stop.wait(min(delay, remaining if remaining is not None else delay)):
                            return None, "Scan cancelled"
                    continue
                if runtime:
                    runtime.record(error=True)
                return None, type(exc).__name__ + ": request failed"
        if response is None:
            return None, "Request failed"
        location = response.headers.get("Location")
        if allow_redirects and response.status_code in (301, 302, 303, 307, 308) and location:
            response.close()
            try:
                destination = canonical_url(location, current)
            except (ValueError, UnicodeError):
                if runtime:
                    runtime.mark_partial("invalid_redirect")
                return None, "Invalid redirect URL"
            if config.scope and not config.scope.allows(destination):
                if initial_upgrade and config.scope.allows_upgrade(current, destination):
                    config.scope = ScanScope(destination)
                elif initial_alias and config.scope.allows_canonical_alias(current, destination):
                    sent_request = getattr(response, "request", None)
                    sent_headers = sent_request.headers if isinstance(sent_request, requests.PreparedRequest) else {}
                    has_credentials = bool(
                        config.auth or config.bearer_token or config.cookies or config.custom_headers
                        or session.auth or session.headers.get("Authorization")
                        or sent_headers.get("Authorization") or sent_headers.get("Cookie")
                    )
                    if has_credentials:
                        if runtime:
                            runtime.record(blocked=True)
                            runtime.mark_partial("scope_blocked")
                        return None, f"Canonical redirect blocked with authentication or custom headers; use {redacted_url(destination)} as the target"
                    # Do not carry cookies set by the previous origin across the alias.
                    session.cookies.clear()
                    config.scope = ScanScope(destination)
                else:
                    if runtime:
                        runtime.record(blocked=True)
                        runtime.mark_partial("scope_blocked")
                    if initial_alias:
                        # Keep the in-scope startup response for external consent/login walls.
                        response._content = b""
                        response._content_consumed = True
                        response.history = history
                        response._audit_blocked_redirect = redacted_url(destination)
                        return response, None
                    return None, f"Out-of-scope redirect blocked; use {redacted_url(destination)} as the target if intended"
            history.append(response)
            current = destination
            continue
        try:
            body = bytearray()
            while method != "HEAD":
                if runtime and (runtime.stop.is_set() or runtime.budget.exhausted()):
                    runtime.mark_partial("time_budget" if runtime.budget.exhausted() else "cancelled")
                    return None, "Scan stopped while reading response"
                # read1 returns available bytes instead of waiting to fill a large chunk.
                chunk = response.raw.read1(min(65536, config.max_body_bytes + 1 - len(body)), decode_content=True)
                if not chunk:
                    break
                body.extend(chunk)
                if len(body) > config.max_body_bytes:
                    if runtime:
                        runtime.record(size=len(body))
                        runtime.mark_partial("body_limit")
                    return None, "Response exceeds max-body-bytes"
            response._content = bytes(body)
            response._content_consumed = True
            response.history = history
            if runtime:
                runtime.record(size=len(body))
                if response.status_code == 429:
                    runtime.mark_partial("rate_limited")
                elif response.status_code >= 500:
                    runtime.mark_partial("server_errors")
            return response, None
        except (HTTPError, requests.RequestException, OSError):
            if runtime:
                runtime.record(error=True)
            return None, "Response read failed"
        finally:
            response.close()
    if runtime:
        runtime.mark_partial("redirect_limit")
    return None, "Redirect limit reached"
