# Quality Roadmap

## Implemented In 1.1 Release Candidate

- Scoped transport, bounded redirects, shared rate/request/body limits, explicit proxy opt-in.
- Content-confirmed exposures, separate confidence/severity, stable IDs, redacted evidence/remediation.
- Context-aware policies, cookie parsing, conservative CORS/method observations.
- Preserved query/path identity, public/private suffix handling, scalar JSON tolerance.
- Full saved findings, TCP results, structured coverage, strict partial-scan exit.
- Package metadata/console command, compatible dependency bounds, CI matrix.
- Offline HTTP integration and negative/positive regression tests.
- Validated legacy/current stored reports, XML entity protection, structural sitemaps, RSS/Atom document links.
- Interactive limits/boolean overrides, preference/privacy precedence, Windows paths, redacted history, and clean package smoke tests.

## Test Strategy

Unit tests cover detection positives/negatives, policy equivalence, configuration precedence, identity, and invalid data. Local HTTP fixtures cover redirects, credential containment, retries, gzip caps, slow responses, rate/request budgets, TCP observations, report contents, and exits. No public target is required.

Every high/critical rule needs a false-positive fixture. Track transport/rule coverage separately from legacy interactive/report code, so a large legacy module cannot obscure weak scan tests.

## Remaining Work

1. Run the remote OS/Python CI matrix; local Windows validation cannot prove portability.
2. Expand sensitive-format fixtures, keeping unsupported formats informational until verified.
3. Add authenticated-session validation and permission-aware file-based secret input; environment-variable input is implemented.
4. Extend API inventory and bounded pagination; recursive HTML crawling needs depth/URL/request limits. RSS/Atom parsing is implemented.
5. Separate legacy reporting/discovery modules after stronger integration coverage.
6. Add findings baseline comparison and future-schema migrations with explicit compatibility rules. Schema 1.0/1.1 validation is implemented.
7. Consider worker-process isolation if hard wall-clock termination becomes a requirement.
8. Verify HTML layout across viewports and align metadata contracts before adding export formats.

## Release Policy

The `v1.1.0-rc.*` versions are prereleases. Do not overwrite v1.0.0 or publish as stable before the research document's release criteria pass. Record compatibility changes in CHANGELOG.md. Build source/wheel artifacts from a reviewed commit, publish checksums, and retain validation results. Release notes record the actual remote CI outcome.
