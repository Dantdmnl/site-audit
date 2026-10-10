# Report Contract

Reports describe selected observations, not a website-wide security guarantee. JSON is the authoritative interchange format. The tool version uses Python packaging syntax (`1.1.0rc1`); the Git release tag is `v1.1.0-rc.1`.

## Schema 1.1

- `schema_version`: `1.1`; `tool`: name/version; `target`: canonical HTTP(S) URL; `mode`: audit/discover.
- `timestamp`, `started_at`, `finished_at`: ISO timestamps. `duration_seconds`: nonnegative monotonic elapsed time.
- `settings`: effective scan settings, never authentication/header/cookie values. A proxy URL is redacted.
- `findings`: all findings regardless of console minimum severity. Each has severity/category/title/detail, with optional stable ID/rule ID, confidence, URL/status, evidence/remediation, and references.
- `scan`: status (`complete`, `partial`, `dry_run`), partial reasons, and nonnegative request/error/probe counters.
- `ports`: requested TCP ports mapped to true (open), false (refused), or null (unknown), when applicable.
- Discover reports include `result` URL inventories. Subdomain observations are DNS-only.

Severity is impact prioritization; confidence is strength of evidence (`tentative`, `firm`, `certain`). A high-confidence missing header is not a confirmed exploit. Some legacy informational checks lack detailed remediation; do not manufacture evidence from an empty field.

## Coverage And Exits

`complete` means the selected built-in work completed under configured limits. `partial` reasons include scope-blocked redirects, exhausted request/time budgets, failed requests, truncated bodies, or challenge pages. `dry_run` sends no requests. Inspect counters and reasons even when exit code is zero.

With `--strict`, a partial scan exits 3 unless a configured finding threshold takes precedence with exit 2. Initial connection/configuration/export failures exit 1. Interruption exits 130. A failed scan with no findings is not a clean security result.

## Stored Exports

`--export-last` accepts schema 1.0 (legacy) and 1.1. Input is limited to 10 MiB and 10,000 findings. Object types, finding severities/confidence, URLs, timestamps, port values, and coverage counters are validated. Unknown schemas and malformed input fail without overwriting the requested export. Legacy reports do not acquire invented coverage.

The first existing report in the selected scope is authoritative; a malformed project report does not silently fall back to an older user report. Use `--export-scope project|user|both` deliberately.

JSON/HTML retain detailed findings; XML includes coverage and ports. CSV contains findings only and neutralizes leading spreadsheet formulas. HTML escapes report text and uses no external fonts; supplying a report-logo URL can load an external resource. Discovery supports JSON/HTML exports only.

Reports are not cryptographically signed, and loading a valid report does not establish its provenance. Store them with appropriate permissions and review URLs/custom branding before sharing.
