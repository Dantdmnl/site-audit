# Research And Design Decisions

Reviewed 2026-10-10 using upstream project documentation and repositories. These are adaptations for an exposure utility, not a claim of parity with commercial scanners.

## Community Projects

### Nuclei

[Matchers](https://docs.projectdiscovery.io/templates/reference/matchers) combine status, words, regexes, and other response properties with AND/OR and negative conditions. [Running Nuclei](https://docs.projectdiscovery.io/opensource/nuclei/running) separates global rate limits from concurrency and documents template selection/exclusions.

Decision: require successful status plus recognizable sensitive content. Generic success remains informational. Separate global requests/second from workers; count redirects and retries. Do not import the whole [template collection](https://github.com/projectdiscovery/nuclei-templates): active checks exceed this utility's intended scope, and reuse needs provenance/licensing review.

### ZAP

[Automation Framework](https://www.zaproxy.org/docs/automate/automation-framework/) separates scan jobs, reports, and configuration. [Alert job tests](https://www.zaproxy.org/docs/desktop/addons/automation-framework/test-alert/) validate presence and absence of alerts using rule IDs.

Decision: stable rule IDs and paired positive/negative fixtures. Test expected findings, absence of false critical alerts, and end-to-end exit behavior. File-existence smoke tests cannot validate scanner accuracy.

### ffuf

The [upstream documentation](https://github.com/ffuf/ffuf) describes matching/filtering, calibration, rate limits, and execution-time controls.

Decision: retain negative controls for soft-404 filtering; treat catch-all pages as uncertainty. Test dynamic layouts against genuine content before extending calibration. Discovery observations differ from vulnerabilities.

## Professional Projects

### Burp Suite / Burp Suite DAST

[Issue results](https://portswigger.net/burp/documentation/desktop/running-scans/results/issues) expose severity, confidence, remediation, and request/response evidence. [Audit settings](https://portswigger.net/burp/documentation/scanner/scan-configurations/audit-settings) describe evidence thresholds and accuracy tradeoffs. [Audit items](https://portswigger.net/burp/documentation/desktop/running-scans/results/audit-items) track completion, request counts, and network errors.

Decision: severity and confidence are separate. Preserve reproducible evidence while withholding credentials. Report errors/coverage independently of findings. Missing CSP does not confirm XSS; advertised methods do not prove unsafe execution. Empty findings on a failed/WAF-blocked scan cannot imply assurance.

## Implementation Guidance

- [OWASP HTTP Headers Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html): consider document/API context and policy equivalents such as CSP frame-ancestors. Check values, not just presence.
- [Requests advanced usage](https://requests.readthedocs.io/en/latest/user/advanced/): streaming responses must be consumed or closed. Timeouts measure inactivity rather than total runtime. Use bounded streaming, manual scoped redirects, and explicit proxy behavior; document DNS/socket limitations.
- [urllib3 response API](https://urllib3.readthedocs.io/en/stable/reference/urllib3.response.html): read1 supports bounded decoded reads; cap decoded bytes so compression does not bypass limits.
- [Python executors](https://docs.python.org/3/library/concurrent.futures.html): running futures cannot be cancelled, and shutdown can wait. Stop scheduling, cap timeouts, signal cancellation, and preserve in-flight results. Do not promise hard deadlines.
- [tldextract](https://github.com/john-kurkowski/tldextract): use public/private suffix data, not the final two labels. Disable remote fetching/cache writes for deterministic offline runs.
- [Python packaging](https://packaging.python.org/en/latest/guides/writing-pyproject-toml/): define metadata/dependencies/console entry point in pyproject.toml; build and install artifacts independently of the checkout.

## Architecture

- `site_audit/core.py`: URL identity, scope, shared limits, transport, cancellation, accounting.
- `site_audit/rules.py`: content/policy checks with evidence and remediation.
- `site_audit/report_validation.py`: bounded JSON loading and schema/type validation before export.
- `site_audit/network.py`, `models.py`, `defaults.py`, and `catalog.py`: shared sessions/configuration and inventories.
- `site_audit/discovery.py` and `reporting.py`: inventories and report exports independent of the CLI.
- `site_audit/cli.py`: CLI/interactive orchestration. Root `site_audit.py`: compatibility launcher only.

The CLI remains compatible while shared risk-sensitive behavior moves into focused modules; the dependency graph is tested for cycles. [Architecture](ARCHITECTURE.md) documents ownership. Full browser crawling and exploit engines introduce substantial maintenance obligations; established tools already cover them. Prioritize correctness in selected checks.

## Release Criteria

Before a stable release: pass offline positive/negative fixtures, verify cross-origin credential containment, test request/body/deadline limits, preserve evidence/coverage, build/install packages, review advisories, and run the supported platform/Python matrix. Authorized live scans supplement deterministic tests.
