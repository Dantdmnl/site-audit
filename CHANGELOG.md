# Changelog

## 1.1.0rc1 / v1.1.0-rc.1 - 2026-10-10

Release candidate, not a stable security certification. Consolidates the unreleased 1.1 development work below.

### Added

- Installable wheel/source distribution and `site-audit` console entry point.
- Shared exact-origin transport, request/rate/decoded-body limits, cooperative deadlines, and explicit proxy selection.
- Stable finding identities, confidence/evidence/remediation, schema 1.1 coverage, TCP observations, and strict partial-scan exit code 3.
- Environment-variable authentication, validated stored-report exports, and XML entity-expansion protection.
- RSS/Atom document discovery and structural sitemap-index parsing, including extensionless/query URLs.
- Complete interactive request controls, boolean negative overrides, Windows path handling, recoverable command errors, and credential redaction in interactive history.
- Offline regression/integration tests and Windows/Linux Python 3.10/3.12/3.14 CI with separate coverage gates, package builds, clean wheel installs, and dependency auditing.
- Installation, report-contract, security, research, validation, and contribution documentation.

### Fixed

- Startup canonical redirects without widening subsequent scan scope or forwarding credentials to aliases.
- False exposure claims from generic HTML, login/denial responses, and challenge pages.
- Context-sensitive HTTP policy checks and unsupported critical CORS/method conclusions.
- CLI/session/preference precedence, including explicitly selected profile-default values and privacy flags.
- Query identity, IPv6/IDNA URL handling, received-cookie containment, report metadata, CSV formulas, and monotonic durations.

### Migration

Proxy/PAC discovery is opt-in. Startup permits anonymous apex/www canonicalization and default-port HTTP-to-HTTPS upgrades; subsequent requests stay on one exact origin. `--min-severity` filters display only, not saved findings. Generic 200/403 responses and missing hardening headers carry conservative severities. Review old CI thresholds and enable `--strict` to fail partial scans. Only stored report schemas 1.0 and 1.1 are accepted.

## 1.1.0.dev1 - Unreleased Development History

- Resolve anonymous startup redirects between an apex hostname and its canonical www alias (for example nu.nl to www.nu.nl), including HTTP-to-HTTPS chains.
- Lock subsequent probes to the resolved origin; block authenticated/custom-header alias redirects with an actionable canonical-target message.
- Clear cookies received from the previous origin before an alias redirect; keep unrelated hosts, alternate ports, and HTTPS downgrades blocked.
- Preserve external consent/login startup redirects as partial coverage and continue checks on the last in-scope origin without auditing the redirect response as an HTML document.

## 1.1.0.dev0 - Unreleased Development History

- Scoped transport, global rate/request limits, decoded-body caps.
- Content-confirmed exposures; generic success/denial becomes informational.
- Finding IDs, confidence, evidence, remediation, and coverage metadata.
- Context-aware policies, parsed cookie flags, confirmed CORS observations.
- CLI preference precedence, preserved query identity, public suffix handling, scalar JSON fixes.
- Shared CLI/interactive option parser and environment-variable authentication inputs.
- TCP results/full findings in reports; strict partial-scan exit 3; schema 1.1.
- Installable package/console entry point, lint/coverage/build/dependency checks, platform CI.
- Offline HTTP integration and regression tests.

Behavior changes relative to v1.0.0 are described in the release candidate's migration notes above.

## 1.0.0 - Experimental

Initial versioned audit/discovery utility with reports, preferences, soft-404 filtering, and an initial test suite.
