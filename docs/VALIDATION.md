# Release Candidate Validation

Validated locally on 2026-10-10 using Windows and Python 3.12.14. Current package: `1.1.0rc1`, Git release: `v1.1.0-rc.1`. Earlier live checks are identified separately below. These are test results, not security certifications.

## Release Candidate Checks

- All 108 unittest tests passed, including local HTTP integration fixtures and positive/negative detection, configuration, interactive-session, discovery, and report-contract tests.
- Ruff and `git diff --check` passed.
- Branch-inclusive coverage: transport (`audit_core`) 88%, detection (`audit_rules`) 92%, report validation (`audit_reports`) 98%; whole project 69%.
- CI requires at least 85% separately for each focused module. Legacy orchestration still has coverage gaps.
- `pip check`: no broken dependencies. `pip-audit --local --skip-editable`: no known vulnerabilities in the installed dependency environment. Editable local project code is skipped by that advisory tool, not independently certified.
- Wheel and source distribution built successfully in isolated build environments.
- Fresh virtual environment outside the checkout installed the wheel with independently resolved dependencies; actual console version, zero-request dry run, project-scoped stored report, HTML export, and `pip check` passed.
- Windows PowerShell launcher passed setup/version verification with the existing virtual environment, revalidating dependencies after the requirements change.

The release gate also requires the six Windows/Linux Python 3.10/3.12/3.14 jobs to pass on the exact release commit. The published GitHub release and attached validation record include the actual CI outcome/link. macOS is not in the tested matrix. CI package smoke checks resolve dependencies afresh on each platform.

The sandbox prevented loopback networking and normal temporary-directory access. Integration tests, package installation/building, and dependency auditing were run with the required access instead of accepting sandbox-caused failures as results.

## Canonical Startup Follow-Up (1.1.0.dev1)

- 82 tests passed; Ruff checks passed.
- Added regression coverage for apex/www canonicalization, multi-hop HTTP upgrades, scope locking, credential/custom-header containment, clearing received cookies, and external consent redirects.
- An initial default-client request to nu.nl returned a 301 redirect to www.nu.nl. The utility's user agent received an external DPG Media consent redirect during verification.
- A homepage-only check through the fixed transport returned the in-scope nu.nl response with partial coverage (`scope_blocked`); the external consent service was not contacted. No NU.nl endpoint or port scan was performed.
- Startup aliases remain disallowed when credentials/custom headers were supplied. Ordinary endpoint and discovery redirects still cannot expand scan scope.

## Earlier Authorized Live Acceptance Check (1.1.0.dev0)

Target: `https://draicore.nl/`. Quick profile, 2 requests/second, 60-request cap, 45-second cooperative budget, 8-second inactivity timeout, no retries, strict partial-result handling. No TCP scan was requested.

- Completed in 24.7 seconds.
- 50 HTTP attempts/responses; no network errors or blocked requests.
- 46 of 46 selected endpoint probes completed.
- Coverage status: complete, with no partial reasons.
- Five LOW and nine INFO findings; no HIGH or CRITICAL findings.
- LOW: Server/X-Powered-By disclosure, missing/invalid nosniff, missing enforcing CSP, missing framing protection.
- INFO: non-explicit Referrer-Policy, access-denied responses for sensitive candidate paths, and public security.txt.

This confirms the selected checks completed under the configured limits. It does not establish that the site has no vulnerabilities. Access-denied paths do not prove the underlying files exist.

The local acceptance report is stored under ignored `dist/draicore-1.1.0-dev0.json`; it is not part of the public source distribution.

## Still Required Before Stable Release

Review release-candidate feedback, strengthen legacy orchestration coverage, and expand conservative detection fixtures before deciding on stable support. The time budget remains cooperative because DNS/OS/socket operations cannot be force-cancelled by Requests. See ROADMAP.md for capability gaps rather than interpreting the selected checks as comprehensive DAST.
