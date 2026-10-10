# Project Architecture

The repository uses a conventional Python package layout. Runtime code belongs in `site_audit/`, automated tests in `tests/`, design/contracts in `docs/`, and verification tooling in `scripts/`. Root files contain packaging metadata, project policies, and source-checkout launchers.

## Module Ownership

| Module | Responsibility |
| --- | --- |
| `version.py` | Dependency-free distribution name/version and report schema version |
| `defaults.py` | Built-in request, profile, preference, and display defaults |
| `catalog.py` | Endpoint inventories and passive technology/body pattern data |
| `core.py` | URL identity, exact-origin scope, shared limits, bounded transport, cancellation/accounting |
| `models.py` | Shared findings, scan configuration, body fingerprints, severity ordering |
| `network.py` | Session setup/pooling, scoped fetch wrappers, URL helpers, TCP checks |
| `rules.py` | Content-confirmed exposures and contextual HTTP policy checks |
| `report_validation.py` | Bounded JSON loading and report-contract validation |
| `reporting.py` | Atomic writes and JSON/CSV/XML/HTML rendering |
| `discovery.py` | Bounded same-origin sitemaps, RSS/Atom, API inventories, DNS observations |
| `cli.py` | Argument parsing, preferences, interactive sessions, scan/check orchestration |

CLI orchestration imports lower-level modules, never the reverse. Discovery uses shared network/configuration helpers; reporting uses shared findings and contract validation. Both can be exercised without invoking the CLI. The tests validate that internal imports stay acyclic and configuration types are not duplicated.

`cli.py` still contains legacy check scheduling and interactive/preference code. Splitting those further should follow stronger behavior coverage, not a proliferation of tiny forwarding modules.

## Entry Points

- Installed command: `site-audit`, pointing to `site_audit.cli:main`.
- Module command: `python -m site_audit`, through `__main__.py`.
- Source compatibility: `python site_audit.py` and `run.ps1`.
- Old installed console commands targeting `site_audit:main` still work through a lazy compatibility function.

Package/version imports do not load Requests, the CLI, or perform environment bootstrapping. The root launcher alone retains the existing Windows `.venv` re-execution behavior, and only when explicitly executed. Importing it never starts a scan.

## Compatibility And Verification

This organization changes internal Python imports from flat modules to package modules. Those internal functions are not a stable public SDK. CLI flags, selected scan behavior, stored-report schemas, exit codes, and source launcher paths remain unchanged. Existing release tags/assets are not rewritten.

Tests patch the module that owns a dependency. The CI coverage gates target package paths for transport, detection, and report validation. Clean-package smoke tests build/install a wheel outside the checkout and test console/module/legacy commands plus report export, preventing the checkout from masking missing package files.
