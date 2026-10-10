"""Atomic report writing and JSON/CSV/XML/HTML exports."""
from __future__ import annotations

import csv
import html
import io
import json
import os as _os
import tempfile
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

from .defaults import SEVERITY_ORDER
from .models import Finding, severity_index
from .report_validation import parse_timestamp, validate_report
from .version import APP_NAME, SCHEMA_VERSION as REPORT_SCHEMA_VERSION, VERSION as __version__

def write_text_atomic(
    output_path: str,
    content: str,
    *,
    newline: str | None = None,
    encoding: str = "utf-8",
) -> None:
    directory = _os.path.dirname(_os.path.abspath(output_path)) or "."
    _os.makedirs(directory, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(prefix=".site-audit-", suffix=".tmp", dir=directory)
    try:
        with _os.fdopen(fd, "w", encoding=encoding, newline=newline) as fh:
            fh.write(content)
        _os.replace(tmp_path, output_path)
    except Exception:
        try:
            _os.remove(tmp_path)
        except OSError:
            pass
        raise


def write_json_atomic(output_path: str, payload: dict) -> None:
    content = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    write_text_atomic(output_path, content)


def write_csv(output_path: str, findings: list[Finding]) -> None:
    """Write findings to CSV file."""
    buffer = io.StringIO(newline="")
    fieldnames = ["id", "rule_id", "severity", "confidence", "category", "title", "detail", "url", "status_code", "evidence", "remediation"]
    writer = csv.DictWriter(buffer, fieldnames=fieldnames)
    writer.writeheader()
    for finding in findings:
        row = {key: getattr(finding, key) for key in fieldnames}
        # Prevent spreadsheet formula execution when opening target-controlled data.
        writer.writerow({key: "'" + value if isinstance(value, str) and value.lstrip().startswith(("=", "+", "-", "@")) else value for key, value in row.items()})
    write_text_atomic(output_path, buffer.getvalue(), newline="")


def write_xml(output_path: str, findings: list[Finding], target: str, scan: dict | None = None, ports: dict | None = None) -> None:
    """Write findings to XML file."""
    root = ET.Element("audit")
    root.set("target", target)
    root.set("timestamp", datetime.now(timezone.utc).isoformat())
    root.set("schema_version", REPORT_SCHEMA_VERSION)
    root.set("tool_version", __version__)
    if scan:
        ET.SubElement(root, "scan").text = json.dumps(scan, sort_keys=True)
    if ports:
        ET.SubElement(root, "ports").text = json.dumps(ports, sort_keys=True)

    for finding in findings:
        item = ET.SubElement(root, "finding")
        ET.SubElement(item, "severity").text = finding.severity
        ET.SubElement(item, "category").text = finding.category
        ET.SubElement(item, "title").text = finding.title
        ET.SubElement(item, "detail").text = finding.detail
        for key in ("id", "rule_id", "confidence", "evidence", "remediation"):
            ET.SubElement(item, key).text = getattr(finding, key)
        ET.SubElement(item, "url").text = finding.url
        if finding.status_code:
            ET.SubElement(item, "status_code").text = str(finding.status_code)

    buffer = io.BytesIO()
    tree = ET.ElementTree(root)
    tree.write(buffer, encoding="utf-8", xml_declaration=True)
    write_text_atomic(output_path, buffer.getvalue().decode("utf-8"))


def _findings_from_report(report: dict) -> list[Finding]:
    findings: list[Finding] = []
    for item in report.get("findings", []) or []:
        if isinstance(item, dict):
            allowed = Finding.__dataclass_fields__
            if all(isinstance(item.get(key), str) for key in ("severity", "category", "title", "detail")):
                findings.append(Finding(**{key: value for key, value in item.items() if key in allowed}))
    return findings


def write_report(
    report: dict, output_path: str, output_format: str, *,
    report_title: str, report_brand: str, report_logo: str | None,
) -> int:
    validate_report(report)
    mode = report.get("mode", "audit")
    target = report.get("target", "-")
    settings = report.get("settings", {})
    platforms = report.get("platforms", [])
    findings = _findings_from_report(report)
    discover_result = report.get("result")
    started_at = None
    finished_at = None
    duration_seconds = report.get("duration_seconds")
    if report.get("started_at"):
        started_at = parse_timestamp(report["started_at"])
    if report.get("finished_at"):
        finished_at = parse_timestamp(report["finished_at"])

    if mode == "discover" and output_format not in ("json", "html"):
        print("[ERROR] Discover reports can only export to json or html")
        return 1

    if output_format == "json":
        write_json_atomic(output_path, report)
        print(f"JSON report written to {output_path}")
        return 0
    if output_format == "csv":
        write_csv(output_path, findings)
        print(f"CSV report written to {output_path}")
        return 0
    if output_format == "xml":
        write_xml(output_path, findings, target, report.get("scan"), report.get("ports"))
        print(f"XML report written to {output_path}")
        return 0
    if output_format == "html":
        write_html_report(
            output_path,
            mode=mode,
            target=target,
            platforms=platforms,
            settings=settings,
            findings=findings,
            discover_result=discover_result,
            started_at=started_at,
            finished_at=finished_at,
            duration_seconds=duration_seconds,
            report_title=report_title,
            report_brand=report_brand,
            report_logo=report_logo,
            scan=report.get("scan"), ports=report.get("ports"),
        )
        print(f"HTML report written to {output_path}")
        return 0

    print(f"[ERROR] Unsupported format: {output_format}")
    return 1


def _html_escape(value: object) -> str:
    return html.escape(str(value), quote=True)


def _format_timestamp(ts: datetime | None) -> str:
    if ts is None:
        return "-"
    return ts.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _format_duration(seconds: float | None) -> str:
    if seconds is None:
        return "-"
    if seconds < 60:
        return f"{seconds:.1f}s"
    minutes = int(seconds // 60)
    remainder = seconds % 60
    return f"{minutes}m {remainder:.1f}s"


def write_html_report(
    output_path: str,
    *,
    mode: str,
    target: str,
    platforms: list[str],
    settings: dict,
    findings: list[Finding] | None = None,
    discover_result: dict | None = None,
    started_at: datetime | None = None,
    finished_at: datetime | None = None,
    duration_seconds: float | None = None,
    report_title: str = "Security Exposure Report",
    report_brand: str = "site-audit",
    report_logo: str | None = None,
    scan: dict | None = None,
    ports: dict | None = None,
) -> None:
    findings = findings or []
    counts = {sev: 0 for sev in SEVERITY_ORDER}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    total = sum(counts.values())

    top_findings = sorted(
        findings,
        key=lambda f: (severity_index(f.severity), f.title, f.url),
    )[:5]

    started_label = _format_timestamp(started_at)
    finished_label = _format_timestamp(finished_at)
    duration_label = _format_duration(duration_seconds)
    platform_label = ", ".join(platforms) if platforms else "unknown"

    lines: list[str] = []
    lines.append("<!doctype html>")
    lines.append("<html lang=\"en\">")
    lines.append("<head>")
    lines.append("  <meta charset=\"utf-8\">")
    lines.append("  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">")
    lines.append(f"  <title>site-audit report - {_html_escape(target)}</title>")
    lines.append("  <style>")
    lines.append("    :root { --ink: #1b1d22; --muted: #5c6670; --bg: #f4f2ee; --card: #ffffff; --line: #e3e0da;")
    lines.append("      --critical: #8f1d14; --high: #b23b00; --medium: #b36f00; --low: #2a6f8f; --info: #4b5563; --ok: #1f7a3c; }")
    lines.append("    * { box-sizing: border-box; }")
    lines.append("    body { margin: 0; background: radial-gradient(circle at 15% 15%, #f7f1e7, #eef0f2 45%, #f4f2ee 100%); color: var(--ink); font-family: 'Source Serif 4', serif; }")
    lines.append("    h1, h2, h3, .brand { font-family: 'Space Grotesk', sans-serif; letter-spacing: 0.3px; }")
    lines.append("    .page { max-width: 1100px; margin: 28px auto 60px; padding: 0 22px; }")
    lines.append("    .hero { background: linear-gradient(130deg, #ffffff 0%, #f7f1e7 55%, #fffaf4 100%); border: 1px solid var(--line); border-radius: 18px; padding: 26px 28px; box-shadow: 0 12px 30px rgba(27, 29, 34, 0.08); }")
    lines.append("    .brand-row { display: flex; align-items: center; gap: 12px; }")
    lines.append("    .brand { font-size: 14px; text-transform: uppercase; color: var(--muted); margin-bottom: 8px; }")
    lines.append("    .logo { width: 44px; height: 44px; border-radius: 12px; object-fit: contain; background: #fff; border: 1px solid var(--line); padding: 6px; }")
    lines.append("    .hero h1 { margin: 0 0 6px; font-size: 30px; }")
    lines.append("    .hero .target { font-size: 16px; margin: 6px 0 12px; }")
    lines.append("    .hero .meta { color: var(--muted); font-size: 13px; }")
    lines.append("    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 18px; margin-top: 22px; }")
    lines.append("    .card { background: var(--card); border: 1px solid var(--line); border-radius: 16px; padding: 18px; box-shadow: 0 10px 24px rgba(27, 29, 34, 0.06); }")
    lines.append("    .kpi { font-size: 22px; margin: 10px 0 16px; }")
    lines.append("    .chips { display: flex; flex-wrap: wrap; gap: 8px; }")
    lines.append("    .chip { display: inline-flex; align-items: center; gap: 6px; font-size: 12px; font-family: 'Space Grotesk', sans-serif; padding: 6px 10px; border-radius: 999px; background: #f2f2f2; }")
    lines.append("    .sev-critical { background: rgba(143, 29, 20, 0.12); color: var(--critical); }")
    lines.append("    .sev-high { background: rgba(178, 59, 0, 0.12); color: var(--high); }")
    lines.append("    .sev-medium { background: rgba(179, 111, 0, 0.12); color: var(--medium); }")
    lines.append("    .sev-low { background: rgba(42, 111, 143, 0.12); color: var(--low); }")
    lines.append("    .sev-info { background: rgba(75, 85, 99, 0.12); color: var(--info); }")
    lines.append("    .sev-ok { background: rgba(31, 122, 60, 0.12); color: var(--ok); }")
    lines.append("    .kv { width: 100%; border-collapse: collapse; font-size: 13px; }")
    lines.append("    .kv th { text-align: left; color: var(--muted); font-weight: 600; padding: 6px 0; width: 45%; }")
    lines.append("    .kv td { padding: 6px 0; }")
    lines.append("    .block { margin-top: 26px; }")
    lines.append("    .block h2 { margin: 0 0 12px; font-size: 20px; }")
    lines.append("    .top-list { list-style: none; padding: 0; margin: 0; }")
    lines.append("    .top-list li { padding: 10px 12px; border: 1px solid var(--line); border-radius: 12px; background: #fff; margin-bottom: 10px; }")
    lines.append("    .pill { font-family: 'Space Grotesk', sans-serif; font-size: 11px; text-transform: uppercase; padding: 4px 8px; border-radius: 999px; margin-right: 8px; }")
    lines.append("    table.findings { width: 100%; border-collapse: collapse; background: #fff; border: 1px solid var(--line); border-radius: 14px; overflow: hidden; }")
    lines.append("    table.findings th, table.findings td { padding: 10px 12px; border-bottom: 1px solid var(--line); vertical-align: top; font-size: 13px; }")
    lines.append("    table.findings th { text-align: left; color: var(--muted); background: #faf8f3; font-weight: 600; }")
    lines.append("    table.findings tr:last-child td { border-bottom: none; }")
    lines.append("    a { color: #1a5787; text-decoration: none; }")
    lines.append("    a:hover { text-decoration: underline; }")
    lines.append("    details.list { background: #fff; border: 1px solid var(--line); border-radius: 12px; padding: 12px; margin-bottom: 12px; }")
    lines.append("    details.list summary { font-family: 'Space Grotesk', sans-serif; cursor: pointer; }")
    lines.append("    details.list ul { margin: 10px 0 0; padding-left: 18px; }")
    lines.append("    .foot { margin-top: 30px; color: var(--muted); font-size: 12px; }")
    lines.append("  </style>")
    lines.append("</head>")
    lines.append("<body>")
    lines.append("  <div class=\"page\">")
    lines.append("    <header class=\"hero\">")
    lines.append("      <div class=\"brand-row\">")
    if report_logo:
        logo = _html_escape(report_logo)
        lines.append(f"        <img class=\"logo\" src=\"{logo}\" alt=\"logo\">")
    lines.append(f"        <div class=\"brand\">{_html_escape(report_brand)}</div>")
    lines.append("      </div>")
    lines.append(f"      <h1>{_html_escape(report_title)}</h1>")
    lines.append(f"      <div class=\"target\">Target: {_html_escape(target)}</div>")
    lines.append(f"      <div class=\"meta\">Mode: {_html_escape(mode)} | Platform: {_html_escape(platform_label)}</div>")
    lines.append(f"      <div class=\"meta\">Started: {started_label} | Finished: {finished_label} | Duration: {duration_label}</div>")
    lines.append("    </header>")

    lines.append("    <section class=\"grid\">")
    lines.append("      <div class=\"card\">")
    lines.append("        <h2>Overview</h2>")
    lines.append(f"        <div class=\"kpi\">Total findings: {total}</div>")
    lines.append("        <div class=\"chips\">")
    for sev in SEVERITY_ORDER:
        css = f"sev-{sev.lower()}"
        lines.append(f"          <span class=\"chip {css}\">{sev}: {counts.get(sev, 0)}</span>")
    lines.append("        </div>")
    lines.append("      </div>")

    lines.append("      <div class=\"card\">")
    lines.append("        <h2>Scan settings</h2>")
    lines.append("        <table class=\"kv\">")
    time_budget_value = settings.get("time_budget")
    time_budget_label = f"{time_budget_value}s" if time_budget_value else "-"
    lines.append(f"          <tr><th>Profile</th><td>{_html_escape(settings.get('profile', '-'))}</td></tr>")
    lines.append(f"          <tr><th>Workers</th><td>{_html_escape(settings.get('workers', '-'))}</td></tr>")
    lines.append(f"          <tr><th>Timeout</th><td>{_html_escape(settings.get('timeout', '-'))}s</td></tr>")
    lines.append(f"          <tr><th>Retries</th><td>{_html_escape(settings.get('retries', '-'))}</td></tr>")
    lines.append(f"          <tr><th>Verify SSL</th><td>{'on' if settings.get('verify_ssl', True) else 'off'}</td></tr>")
    lines.append(f"          <tr><th>Min severity</th><td>{_html_escape(settings.get('min_severity', '-'))}</td></tr>")
    lines.append(f"          <tr><th>Fail on</th><td>{_html_escape(settings.get('fail_on') or '-')}</td></tr>")
    lines.append(f"          <tr><th>Time budget</th><td>{_html_escape(time_budget_label)}</td></tr>")
    lines.append(f"          <tr><th>Proxy</th><td>{_html_escape(settings.get('proxy') or '-')}</td></tr>")
    lines.append(f"          <tr><th>Custom headers</th><td>{_html_escape(settings.get('custom_headers', 0))}</td></tr>")
    lines.append("        </table>")
    lines.append("      </div>")
    lines.append("    </section>")

    if scan:
        lines.append("    <section class=\"block\"><h2>Scan coverage</h2>")
        lines.append(f"      <p>Status: {_html_escape(scan.get('status'))}. Reasons: {_html_escape(', '.join(scan.get('reasons', [])) or 'none')}.</p>")
        lines.append(f"      <p>Requests: {_html_escape(scan.get('requests_sent', 0))}; network errors: {_html_escape(scan.get('network_errors', 0))}; endpoint probes: {_html_escape(scan.get('endpoints_completed', 0))} / {_html_escape(scan.get('endpoints_planned', 0))}.</p></section>")
    if ports:
        lines.append("    <section class=\"block\"><h2>TCP ports</h2><ul>")
        for port, state in sorted(ports.items(), key=lambda item: int(item[0])):
            lines.append(f"      <li>{_html_escape(port)}: {'open' if state is True else 'closed' if state is False else 'unknown'}</li>")
        lines.append("    </ul></section>")

    if mode == "discover" and discover_result is not None:
        lines.append("    <section class=\"block\">")
        lines.append("      <h2>Discovery results</h2>")
        home_links = discover_result.get("homepage_internal_links", [])
        discovered = discover_result.get("discovered", [])
        hidden = discover_result.get("hidden", [])
        subdomains = discover_result.get("subdomains", [])
        lines.append("      <div class=\"card\" style=\"margin-bottom: 16px;\">")
        lines.append(f"        <div class=\"kpi\">Homepage links: {len(home_links)} | Discovered: {len(discovered)} | Hidden: {len(hidden)} | Subdomains: {len(subdomains)}</div>")
        lines.append("      </div>")

        def render_url_list(title: str, urls: list[str]) -> None:
            lines.append("      <details class=\"list\">")
            lines.append(f"        <summary>{_html_escape(title)} ({len(urls)})</summary>")
            lines.append("        <ul>")
            for u in urls:
                u_esc = _html_escape(u)
                lines.append(f"          <li><a href=\"{u_esc}\">{u_esc}</a></li>")
            lines.append("        </ul>")
            lines.append("      </details>")

        render_url_list("Hidden URLs (not linked from homepage)", hidden)
        render_url_list("Discovered URLs (sitemaps/feeds/API)", discovered)
        if subdomains:
            render_url_list("Resolved subdomains", subdomains)
        render_url_list("Homepage internal links", home_links)
        lines.append("    </section>")
    else:
        lines.append("    <section class=\"block\">")
        lines.append("      <h2>Top findings</h2>")
        if top_findings:
            lines.append("      <ul class=\"top-list\">")
            for f in top_findings:
                sev_class = f"sev-{f.severity.lower()}"
                url_text = _html_escape(f.url) if f.url else ""
                title_text = _html_escape(f.title)
                lines.append("        <li>")
                lines.append(f"          <span class=\"pill {sev_class}\">{_html_escape(f.severity)}</span>{title_text}")
                if url_text:
                    lines.append(f"          <div><a href=\"{url_text}\">{url_text}</a></div>")
                lines.append("        </li>")
            lines.append("      </ul>")
        else:
            lines.append("      <div class=\"card\">No findings at the selected severity threshold.</div>")
        lines.append("    </section>")

        for sev in SEVERITY_ORDER:
            group = [f for f in findings if f.severity == sev]
            if not group:
                continue
            lines.append("    <section class=\"block\">")
            lines.append(f"      <h2>{_html_escape(sev)} findings ({len(group)})</h2>")
            lines.append("      <table class=\"findings\">")
            lines.append("        <thead><tr><th>Title</th><th>Category</th><th>URL</th><th>Status</th><th>Detail</th></tr></thead>")
            lines.append("        <tbody>")
            for f in group:
                url_text = _html_escape(f.url) if f.url else ""
                status_text = _html_escape(f.status_code) if f.status_code is not None else ""
                detail_text = f.detail
                detail_text += f" | Confidence: {f.confidence} | Evidence: {f.evidence} | Remediation: {f.remediation}"
                body_issues = f.extra.get("body_issues", []) if f.extra else []
                if body_issues:
                    detail_text = f"{detail_text} | body: {', '.join(body_issues)}"
                lines.append("          <tr>")
                lines.append(f"            <td>{_html_escape(f.title)}</td>")
                lines.append(f"            <td>{_html_escape(f.category)}</td>")
                if url_text:
                    lines.append(f"            <td><a href=\"{url_text}\">{url_text}</a></td>")
                else:
                    lines.append("            <td></td>")
                lines.append(f"            <td>{status_text}</td>")
                lines.append(f"            <td>{_html_escape(detail_text)}</td>")
                lines.append("          </tr>")
            lines.append("        </tbody>")
            lines.append("      </table>")
            lines.append("    </section>")

    lines.append(f"    <div class=\"foot\">Generated by {_html_escape(APP_NAME)} v{_html_escape(__version__)}. Use only on targets you own or have explicit permission to test.</div>")
    lines.append("  </div>")
    lines.append("</body>")
    lines.append("</html>")

    write_text_atomic(output_path, "\n".join(lines))
