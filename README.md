# Site Audit

Small Python CLI for authorized web exposure checks, port scanning, and URL discovery.
Inspired by Nuclei, Gobuster, Wappalyzer, and Nikto.

## Setup

**Automated setup using `run.ps1`** (recommended):

```powershell
.\run.ps1 https://example.com --mode audit
```

The script will:

- Check Python 3.10+ is installed
- Create `.venv` if needed
- Install dependencies from `requirements.txt`
- Run site_audit.py with your arguments

**Manual setup**:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python site_audit.py --help
```

## Production Features

- **Thread-safe concurrency**: ThreadLocalSessionPool for worker isolation
- **Exit codes for CI/CD**: 0 (success), 1 (error), 2 (fail-on threshold hit), 130 (interrupted)
- **Atomic JSON writes**: Prevents corrupt reports on crash
- **Port scanning**: Service enumeration on common/custom ports
- **Proxy & custom headers**: Enterprise network support
- **Multiple output formats**: JSON, CSV, XML
- **Dry-run mode**: Configuration testing without requests
- **Finding deduplication**: Eliminates duplicate results
- **Tab completion**: Command-based interactive mode with history

## CLI Usage

```powershell
# Basic audit
python site_audit.py https://example.com

# Discover mode (URL inventory)
python site_audit.py https://example.com --mode discover

# Port scanning
python site_audit.py https://example.com --ports http
python site_audit.py https://example.com --ports 80,443,8080,8443
python site_audit.py https://example.com --ports services  # scan common services

# Custom headers and proxy
python site_audit.py https://example.com --header "X-Custom:value" --proxy "http://proxy:8080"

# Multiple output formats
python site_audit.py https://example.com --output report.json
python site_audit.py https://example.com --output report.csv --format csv
python site_audit.py https://example.com --output report.xml --format xml

# Filtering & thresholds
python site_audit.py https://example.com --min-severity HIGH
python site_audit.py https://example.com --fail-on CRITICAL  # Exit 2 if critical found

# Concurrency tuning
python site_audit.py https://example.com --workers 50 --timeout 20 --retries 3

# Logging
python site_audit.py https://example.com --verbose --log-file audit.log

# SSL/TLS options
python site_audit.py https://example.com --insecure  # Disable SSL verification

# Dry-run (test config, no requests)
python site_audit.py https://example.com --dry-run

# via run.ps1
.\run.ps1 https://example.com --ports http --output report.csv --format csv
```

## Interactive Mode

Run without URL to enter interactive command-based REPL:

```powershell
python site_audit.py
# or
python site_audit.py --history
```

Commands:

```text
scan <url> [options]        # Run audit (respects saved defaults)
audit <url> [options]       # Same as scan, force --mode audit
discover <url> [options]    # Same as scan, force --mode discover
set <key> <value>           # Persist default (workers, timeout, output, ports, proxy, etc)
unset <key>                 # Remove saved default
show config                 # Show current interactive defaults
history                     # Display session command history
clear                       # Clear screen
help                        # Show help
exit / quit                 # Leave (or Ctrl-C)
```

Examples:

```text
set workers 40
set min-severity HIGH
set output results.json
set ports http
set proxy http://proxy:8080
show config
scan https://example.com
discover https://example.com --output discover.csv --format csv
audit https://example.com --fail-on MEDIUM
```

**Tab completion supported** for commands, keys, flags, and severity levels.

## Exit Codes

- `0` — Success (findings detected or none, depending on --fail-on)
- `1` — Error (e.g., invalid URL, network failure, configuration error)
- `2` — Fail-on threshold hit (e.g., `--fail-on HIGH` and HIGH+ findings found)
- `130` — Interrupted (Ctrl-C)

Use `--history` to persist command history to `~/.site_audit_history`.

## CI / Exit Codes

- `0`: scan succeeded and fail threshold not hit
- `1`: invalid input or target could not be reached
- `2`: findings at or above `--fail-on` threshold were found
- `130`: interrupted by user (Ctrl-C)

## Quick Run (PowerShell)

```powershell
.\run.ps1 --help
.\run.ps1 https://example.com
.\run.ps1 https://example.com --mode discover
```

`run.ps1` automatically creates `.venv` when missing and runs `site_audit.py` with that interpreter.

## Notes

- Use only on targets you own or are explicitly authorized to test.
- Running without a URL starts interactive prompt mode.
- `--timeout`, `--retries`, and `--workers` help tune slow or unstable targets.
- `--insecure` skips TLS cert validation (only for testing environments).
- `--output` now also writes JSON reports in discover mode.
- `--fail-on` makes the tool suitable for pipeline gating.
- `--verbose` + `--log-file` adds operational logging for troubleshooting.
