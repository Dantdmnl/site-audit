"""Validation for stored reports before exporting target-controlled content."""
from __future__ import annotations

import json
import math
from datetime import datetime

from .core import canonical_url

MAX_REPORT_BYTES = 10 * 1024 * 1024
SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "OK"}


def parse_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)


def validate_report(report: dict) -> dict:
    def require(condition: bool, message: str) -> None:
        if not condition:
            raise ValueError("Invalid report: " + message)

    require(isinstance(report, dict), "expected an object")
    require(report.get("schema_version", "1.0") in ("1.0", "1.1"), "unsupported schema version")
    require(report.get("mode", "audit") in ("audit", "discover"), "unknown mode")
    require(isinstance(report.get("target"), str), "target must be an HTTP URL")
    canonical_url(report["target"])
    require(isinstance(report.get("settings", {}), dict), "settings must be an object")
    platforms = report.get("platforms", [])
    require(isinstance(platforms, list) and all(isinstance(item, str) for item in platforms), "platforms must be strings")
    for key in ("started_at", "finished_at", "timestamp"):
        if report.get(key) is not None:
            require(isinstance(report[key], str), "timestamps must be strings")
            parse_timestamp(report[key])
    duration = report.get("duration_seconds")
    if duration is not None:
        require(type(duration) in (int, float) and math.isfinite(duration) and duration >= 0, "duration must be finite and nonnegative")
    findings = report.get("findings", [])
    require(isinstance(findings, list) and len(findings) <= 10000, "findings must be a bounded list")
    for item in findings:
        require(isinstance(item, dict), "finding must be an object")
        require(all(isinstance(item.get(key), str) for key in ("severity", "category", "title", "detail")), "finding fields must be strings")
        require(item["severity"] in SEVERITIES, "unknown severity")
        for key in ("url", "id", "rule_id", "confidence", "evidence", "remediation"):
            require(isinstance(item.get(key, ""), str), f"{key} must be a string")
        if item.get("url"):
            canonical_url(item["url"])
        require(item.get("confidence", "tentative") in ("tentative", "firm", "certain"), "unknown confidence")
        require(isinstance(item.get("extra", {}), dict), "finding extra must be an object")
        body_issues = item.get("extra", {}).get("body_issues", [])
        require(isinstance(body_issues, list) and all(isinstance(issue, str) for issue in body_issues), "body issues must be strings")
        references = item.get("references", [])
        require(isinstance(references, list) and all(isinstance(ref, str) for ref in references), "references must be strings")
        for ref in references:
            canonical_url(ref)
        status = item.get("status_code")
        require(status is None or (type(status) is int and 100 <= status <= 599), "invalid HTTP status")
    scan = report.get("scan")
    if scan is not None:
        require(isinstance(scan, dict), "scan must be an object")
        require(scan.get("status") in ("complete", "partial", "dry_run"), "unknown scan status")
        reasons = scan.get("reasons", [])
        require(isinstance(reasons, list) and all(isinstance(item, str) for item in reasons), "reasons must be strings")
        for key in ("requests_sent", "responses_received", "network_errors", "blocked_requests", "bytes_received", "endpoints_planned", "endpoints_completed"):
            require(type(scan.get(key, 0)) is int and scan.get(key, 0) >= 0, "invalid scan counter")
    ports = report.get("ports", {})
    require(isinstance(ports, dict), "ports must be an object")
    for key, value in ports.items():
        require(isinstance(key, str) and key.isdigit() and 1 <= int(key) <= 65535, "invalid port")
        require(value is None or type(value) is bool, "port state must be true, false or null")
    if report.get("mode") == "discover":
        result = report.get("result")
        require(isinstance(result, dict), "discovery result must be an object")
        for key in ("homepage_internal_links", "discovered", "subdomains", "hidden"):
            urls = result.get(key, [])
            require(isinstance(urls, list) and all(isinstance(url, str) for url in urls), "discovered URLs must be strings")
            for url in urls:
                canonical_url(url)
    return report


def load_report(path: str) -> dict:
    with open(path, "rb") as handle:
        content = handle.read(MAX_REPORT_BYTES + 1)
    if len(content) > MAX_REPORT_BYTES:
        raise ValueError("Stored report exceeds 10 MiB")
    return validate_report(json.loads(content))
