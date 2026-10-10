"""Shared scan configuration, evidence, and severity helpers."""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from requests.cookies import RequestsCookieJar

from .core import ScanRuntime, ScanScope, finding_id
from .defaults import RETRIES, SEVERITY_ORDER, TIMEOUT, VERIFY_SSL

@dataclass
class Finding:
    severity: str
    category: str   # endpoint | header | cookie | cors | method | body | tech
    title: str
    detail: str
    url: str = ""
    status_code: int | None = None
    extra: dict = field(default_factory=dict)
    rule_id: str = ""
    confidence: str = "tentative"
    evidence: str = ""
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    id: str = ""

    def __post_init__(self) -> None:
        if not self.rule_id:
            self.rule_id = self.category + "." + re.sub(r"[^a-z0-9]+", "-", self.title.lower()).strip("-")
        if not self.id:
            self.id = finding_id(self.rule_id, self.url)


@dataclass
class ScanConfig:
    timeout: int = TIMEOUT
    retries: int = RETRIES
    verify_ssl: bool = VERIFY_SSL
    proxy: str | None = None
    custom_headers: dict[str, str] = field(default_factory=dict)
    auth: tuple[str, str] | None = None
    bearer_token: str | None = None
    cookies: RequestsCookieJar | None = None
    scope: ScanScope | None = None
    runtime: ScanRuntime | None = None
    max_body_bytes: int = 1_048_576
    max_redirects: int = 5
    system_proxy: bool = False
    allow_initial_upgrade: bool = False
    allow_initial_canonical_redirect: bool = False


@dataclass
class BodyFingerprint:
    content_type: str
    hash: str
    length: int
    visible_hash: str = ""
    visible_length: int = 0


def severity_index(severity: str) -> int:
    return SEVERITY_ORDER.index(severity)


def has_findings_at_or_above(findings: list[Finding], severity: str) -> bool:
    threshold = severity_index(severity)
    return any(severity_index(f.severity) <= threshold for f in findings)
