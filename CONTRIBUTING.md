# Contributing

Install with `python -m pip install -e '.[dev]'`. Run `python -m ruff check .`, `python -m coverage run -m unittest discover -s tests -v`, and `python -m coverage report`. CI requires at least 85% branch-inclusive coverage separately for `site_audit/core.py`, `site_audit/rules.py`, and `site_audit/report_validation.py`. Whole-project coverage remains a visible metric, not an assurance claim.

Package changes need `python -m build` followed by `python scripts/smoke_package.py`. The smoke check creates a fresh virtual environment outside the checkout, resolves dependencies, runs the installed entry point, checks a zero-request dry run, and exports a stored HTML report. It needs package-index access. Also run `python -m pip check`, `python -m pip_audit --local --skip-editable`, and `git diff --check`.

Use local fixtures in automated tests. Each high/critical detection needs positive/negative examples, stable rule IDs, redacted evidence, and justified severity/confidence. Do not add exploit requests, public-target tests, or unbounded crawling incidentally.

All HTTP checks use `site_audit.core` through the shared `site_audit.network` helpers. Redirects, retries, auth, and discovery obey shared scope/limits. Keep shared models in `models.py`; discovery and reporting must not import CLI orchestration. Patch the owning module in tests, not a former flat-script global. The package tests check the import graph for cycles. See docs/ARCHITECTURE.md before introducing another module.

Document schema/exit changes and add regression tests for reported bugs. CI covers Windows/Linux and Python 3.10/3.12/3.14; local success does not replace that matrix. Package smoke checks run console, module, and legacy console entry points outside the checkout.

Record user-facing changes in CHANGELOG.md. Release candidates remain GitHub prereleases. Before tagging, pass the remote matrix on the exact release commit. Use an annotated tag, build immutable source/wheel artifacts, publish SHA-256 checksums and validation notes, and verify uploaded assets. Never overwrite an existing release/tag. Stable releases must satisfy docs/RESEARCH.md and accurately describe remaining limits.
