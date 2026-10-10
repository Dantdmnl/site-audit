"""Install the built wheel in a fresh environment and exercise its real command."""
from __future__ import annotations

import importlib.metadata
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


def run(args: list[str], cwd: Path) -> str:
    result = subprocess.run(args, cwd=cwd, capture_output=True, text=True, timeout=240, check=False)
    if result.returncode:
        raise RuntimeError(f"Command failed ({result.returncode}): {args[0]}\n{result.stdout}\n{result.stderr}")
    return result.stdout


def main() -> None:
    version = importlib.metadata.version("site-audit")
    wheel = (Path("dist") / f"site_audit-{version}-py3-none-any.whl").resolve()
    if not wheel.is_file():
        raise SystemExit(f"Build the wheel first: missing {wheel.name}")
    with tempfile.TemporaryDirectory(prefix="site-audit-package-smoke-") as directory:
        root = Path(directory).resolve()
        assert root.is_relative_to(Path(tempfile.gettempdir()).resolve())
        run([sys.executable, "-m", "venv", str(root / "venv")], root)
        commands = root / "venv" / ("Scripts" if os.name == "nt" else "bin")
        python = str(commands / ("python.exe" if os.name == "nt" else "python"))
        cli = str(commands / ("site-audit.exe" if os.name == "nt" else "site-audit"))
        run([python, "-m", "pip", "install", "--upgrade", "pip"], root)
        run([python, "-m", "pip", "install", str(wheel)], root)
        version_output = run([cli, "--version"], root).strip()
        assert version_output == f"site-audit {version}", version_output
        assert "No broken requirements" in run([python, "-m", "pip", "check"], root)
        report_path = root / "report.json"
        run([cli, "https://example.invalid/", "--dry-run", "--strict", "--no-load-prefs", "--no-save-prefs", "--last-scope", "project", "--output", str(report_path)], root)
        report = json.loads(report_path.read_text(encoding="utf-8"))
        assert report["tool"]["version"] == version
        assert report["scan"]["status"] == "dry_run"
        assert report["scan"]["requests_sent"] == 0
        html_path = root / "report.html"
        run([cli, "--export-last", "--export-scope", "project", "--no-load-prefs", "--format", "html", "--output", str(html_path)], root)
        assert f"site-audit v{version}" in html_path.read_text(encoding="utf-8")
    print(f"Clean wheel installation, entry point, dry run, preferences isolation, and HTML export passed: {version}")


if __name__ == "__main__":
    main()
