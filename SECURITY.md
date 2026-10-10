# Security

This utility sends GET/OPTIONS requests and optional TCP connections. Use only with authorization. Exposure checks do not guarantee website security.

Report vulnerabilities in the utility through the repository's private vulnerability reporting facility when available. Avoid publishing real tokens, cookies, infrastructure details, or sensitive reports in public issues. Use redacted local reproduction fixtures.

v1.1.0-rc.1 is a prerelease with scoped transport, evidence, report-validation, and history-redaction improvements. Experimental v1.0.0 lacks those protections; it is not maintained as a separate security branch. No version guarantees website security.

Prefer environment-variable authentication over literal command-line secrets. Interactive redaction covers recognized credential flags, not arbitrary data. Existing history files may still contain old secrets; clear them deliberately. Treat generated reports, custom output locations, and shared-machine file permissions as sensitive. JSON exports are bounded and validated, but are not authenticated or signed.
