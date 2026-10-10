# Site Audit v1.1.0-rc.1

Release candidate for scoped HTTP exposure checks and public URL discovery. Python package version: `1.1.0rc1`. This is a GitHub prerelease, not a security certification.

## Highlights

- Exact-origin transport, safe startup canonical redirects, credential containment, and global rate/request/body limits.
- Content-confirmed sensitive exposures, conservative header/CORS/method observations, finding confidence and redacted evidence.
- Coverage and TCP results in schema 1.1 reports, full saved findings, strict partial-result handling, and validated legacy/current exports.
- Complete interactive controls, preference/privacy precedence, Windows paths, and redacted credential history.
- Safe XML parsing, RSS/Atom feeds, structural sitemap indexes, and useful document URL retention.
- Installable packages, offline regression/integration tests, and six Windows/Linux Python CI combinations with clean wheel installation checks.

## Install

Download the wheel, verify its SHA-256 checksum, and install it into a Python 3.10+ virtual environment:

```sh
python -m pip install ./site_audit-1.1.0rc1-py3-none-any.whl
site-audit --version
site-audit https://example.com --profile quick --strict --output report.json
```

The source ZIP and source distribution include tests and documentation. Windows source users can run `./run.ps1`. This repository is not currently published to PyPI.

## Compatibility

Proxy/PAC discovery now requires `--system-proxy`; explicit `--proxy` takes precedence. Startup may follow anonymous apex/www aliases and default-port HTTP-to-HTTPS upgrades, but authenticated alias redirects and later cross-origin redirects are blocked. `--min-severity` affects display only. Review old severity-based CI thresholds. Stored exports accept only schemas 1.0/1.1.

## Validation And Limits

The release is published only after local checks and the remote CI matrix pass; the published release records the actual results and CI link. See `docs/VALIDATION.md` for the local record and prior authorized live acceptance check. Runtime budgets are cooperative, not hard process deadlines. macOS is not CI-verified. No JavaScript rendering, exploit engine, arbitrary API pagination, or authentication-workflow validation is included. Whole-project coverage still trails the focused transport/rule/report modules.

Assets: wheel, source distribution, source ZIP, release notes, validation record, and SHA-256 checksums. Never treat no findings as proof that a website is secure.
