# Site Audit

Scoped HTTP exposure checks and public URL discovery for websites you own or are authorized to test.

Current release candidate: **v1.1.0-rc.1** (Python package version `1.1.0rc1`). Published v1.0.0 remains experimental. This utility checks common exposed files, HTTP policies, cookies, CORS observations, and public inventories. It does not establish that a website is secure or replace a browser-based DAST scanner or penetration test.

## Install

Python 3.10 or newer is required. CI tests Windows/Linux with Python 3.10, 3.12, and 3.14. macOS is not currently CI-verified.

Download the wheel or source from [GitHub Releases](https://github.com/Dantdmnl/site-audit/releases). Verify the download against the release's `SHA256SUMS` file. This project is not published to PyPI; do not assume a similarly named PyPI package is this utility.

Install from a source checkout on Windows:

```powershell
python -m venv .venv
.venv\Scripts\python -m pip install .
.venv\Scripts\site-audit --help
```

Linux:

```sh
python -m venv .venv
.venv/bin/python -m pip install .
.venv/bin/site-audit --help
```

Windows source checkout launcher:

```powershell
.\run.ps1 https://example.com --profile quick
```

The launcher creates a virtual environment when necessary and installs dependencies when missing or when requirements change. It reuses an existing virtual-environment interpreter. For a wheel installation, replace `.` in the pip command with the downloaded wheel's path. Dependencies have compatible version bounds; development checks include vulnerability auditing.

## Use

```sh
site-audit https://example.com --profile quick
site-audit https://example.com --output report.json --strict --fail-on HIGH
site-audit https://example.com --output report.html --format html
site-audit https://example.com --mode discover --output inventory.json
site-audit https://example.com --ports 80,443,8443
site-audit https://example.com --rate-limit 5 --max-requests 300 --time-budget 60
site-audit https://example.com --dry-run --no-load-prefs --no-save-prefs --no-save-last
site-audit --export-last --format html --output previous.html
```

`python site_audit.py` accepts the same arguments. Without a URL it opens the interactive prompt; `help` lists commands.

Profiles configure workers, request timeout, retries, and path selection. Explicit CLI values take precedence over saved preferences and profile defaults. `quick` targets higher-priority paths; `standard` uses all applicable built-in paths; `deep` increases concurrency with a two-minute best-effort budget. More workers do not bypass the global rate.

### Request Controls

| Option | Default | Meaning |
| --- | --- | --- |
| `--rate-limit` | 10 | Global HTTP requests/second, including retries/redirects |
| `--max-requests` | 1000 | Total HTTP request attempts |
| `--max-body-bytes` | 1048576 | Maximum decoded response bytes, including compression |
| `--workers` | Profile-dependent | Endpoint workers, maximum 200 |
| `--timeout` | Profile-dependent | Socket inactivity timeout capped by remaining budget |
| `--retries` | Profile-dependent | Transient retries, maximum 10 |
| `--time-budget` | Profile-dependent | Cooperative HTTP/port deadline |

DNS resolution, OS networking, PAC discovery, and an already-blocked socket call can exceed the deadline. Requests does not provide hard wall-clock cancellation. The utility stops scheduling work and reduces subsequent request timeouts; reports identify partial scans.

Startup follows same-origin redirects, default-port HTTP-to-HTTPS upgrades, and anonymous apex/`www` canonical redirects, up to five hops. An apex/`www` redirect is blocked when authentication, cookies, or custom headers were supplied/sent; the error shows the canonical URL to target explicitly. Cookies received from the previous origin are cleared before crossing to its alias. HTTPS downgrades, arbitrary subdomains, unrelated domains, and alternate ports remain blocked. An external consent/login redirect at startup produces a warning and partial coverage; checks continue on the last in-scope origin and skip document-header checks on the redirect response. After startup, scope is the resolved target's exact scheme, hostname, and effective port; endpoint and discovery redirects cannot expand it. Foreign sitemap URLs are ignored. `--discover-subdomains` performs DNS-only observations using a bundled Public Suffix List including private suffixes; it does not HTTP-scan those hosts or download suffix data at runtime.

TLS verification is on by default. `--insecure` disables it explicitly. Proxy discovery is opt-in with `--system-proxy`; `--proxy http://proxy:8080` overrides system settings. TCP checks use direct connections, independent of the HTTP proxy. An open port is a connectivity observation, not service identification or a vulnerability.

### Authentication

```sh
site-audit https://example.com --basic-user user --basic-pass password
site-audit https://example.com --bearer-token token
site-audit https://example.com --bearer-token-env SITE_AUDIT_TOKEN
site-audit https://example.com --basic-user user --basic-pass-env SITE_AUDIT_PASSWORD
site-audit https://example.com --cookie 'session=abc'
site-audit https://example.com --header 'X-Custom:value'
```

Command-line credentials may be visible in process inspection or shell history. Prefer the environment-variable options for automation. Auth values, cookies, custom header values, and proxy credentials are not saved as preferences. Sensitive-file evidence records structure/key names and withholds values.

### Interactive Sessions

```text
site-audit> set profile quick
site-audit> set rate-limit 2
site-audit> set max-requests 100
site-audit> set strict true
site-audit> show config
site-audit> example.com --output report.json
site-audit> export report.html --format html
site-audit> unset strict
site-audit> version
```

Session settings include all request controls, ports, proxy selection, and discovery options. Numeric settings are validated, not silently clamped. `set`/`unset` respect `--no-save-prefs`; `--no-load-prefs`, `--no-save-last`, and authentication supplied at startup carry into scans. Explicit flags override session defaults; `--no-strict`, `--no-insecure`, `--no-system-proxy`, and other boolean negatives disable saved true values. Quote paths containing spaces; Windows backslashes are preserved.

`--history` opts into persistent interactive history. New entries and displayed legacy entries redact recognized credential flags and credential-bearing URLs. This is not a guarantee against arbitrary secrets embedded in URLs or command values; old history files are not rewritten automatically. `history clear` deletes the configured history file. Your external shell's history is unaffected.

## Findings And Reports

Findings have stable `id`/`rule_id`, separate severity and confidence, evidence, remediation, and optional references. Sensitive-file detections require recognizable content: environment assignments, Git metadata, SQL dump statements, or sensitive configuration structures. Generic HTML, login pages, and HTTP 200 alone do not prove a leak. A 403 does not prove a file exists. WAF challenge pages mark coverage as partial.

Header checks consider response type and policy values. CSP `frame-ancestors` can satisfy framing protection without X-Frame-Options; JSON does not need document CSP/framing headers. Missing hardening headers do not prove XSS. Public wildcard CORS is not automatically a vulnerability; reflected origins require confirmation with a second origin, and authenticated data exposure still needs manual review. OPTIONS advertisements are informational, not proof of usable unsafe methods.

JSON schema **1.1** adds `scan` coverage and `ports`. Status is `complete`, `partial`, or `dry_run`, with reasons and request/error/probe counters. `complete` means selected built-in checks ran, not that all website security was assessed. TCP results are `true` (open), `false` (refused), or `null` (unknown).

`--min-severity` filters console output. Saved reports retain all findings for later review. JSON/HTML include full metadata; XML includes coverage/ports. CSV is a findings-only export with confidence/evidence/remediation and spreadsheet formula protection. HTML uses no external fonts; a custom `--report-logo` URL is an optional external resource.

Stored JSON exports accept schema 1.0 and 1.1, with a 10 MiB input limit and validation of finding types, URLs, timestamps, and coverage. Invalid/unsupported reports fail clearly instead of producing misleading exports. See the [report contract](docs/REPORTS.md).

| Exit | Meaning |
| --- | --- |
| 0 | No configured failure condition; inspect coverage status |
| 1 | Invalid configuration, initial connection failure, or operational error |
| 2 | `--fail-on` threshold matched |
| 3 | `--strict` scan is partial, with no threshold match taking precedence |
| 130 | Interrupted |

For CI use `--strict --no-load-prefs --no-save-prefs --no-save-last` with the desired threshold.

Preferences: `~/.site_audit_config.json` and `./.site_audit.json` (project overrides user). `--no-load-prefs` ignores both; `--no-save-prefs` prevents saving; `--prefs-scope user|project|both` selects the location. Last reports use `~/.site_audit_last.json` and `./.site_audit_last.json`; control them with `--no-save-last` and `--last-scope`. Reports may describe sensitive infrastructure even when values are withheld.

## Development

```sh
python -m pip install -e '.[dev]'
python -m unittest discover -s tests -v
python -m ruff check .
python -m coverage run -m unittest discover -s tests
python -m coverage report
python -m build
python scripts/smoke_package.py
python -m pip_audit --local --skip-editable
```

Tests use local HTTP fixtures and mocks, never public websites. CI runs Windows/Linux on Python 3.10/3.12/3.14 with lint, tests, per-module coverage gates, package builds, clean wheel installations, and dependency auditing.

- [Research and design](docs/RESEARCH.md)
- [Quality roadmap](docs/ROADMAP.md)
- [Validation results](docs/VALIDATION.md)
- [Contributing](CONTRIBUTING.md)
- [Changelog](CHANGELOG.md)

## Limits

Discovery combines homepage links, bounded sitemaps, RSS/Atom feeds, and a small API inventory. Sitemap indexes are recognized structurally, including extensionless/query URLs; document links such as HTML/PHP/PDF are retained. XML parsing rejects entity expansion. Discovery does not render JavaScript, recursively crawl HTML, paginate arbitrary APIs, or validate authentication workflows. Content matchers are conservative and can miss unknown formats. This project does not test SQL injection, XSS exploitation, authorization bypass, TLS cipher suites, or known CVEs. Use established complementary tools for those capabilities.
