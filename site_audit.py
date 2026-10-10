"""Compatibility launcher for a source checkout; prefer python -m site_audit."""
from __future__ import annotations

import os
import sys
from pathlib import Path


def main() -> None:
    root = Path(__file__).resolve().parent
    venv_python = root / ".venv" / "Scripts" / "python.exe"
    if (venv_python.is_file() and sys.prefix == sys.base_prefix
            and os.path.normcase(sys.executable) != os.path.normcase(str(venv_python))):
        os.execv(str(venv_python), [str(venv_python), str(root / "site_audit.py"), *sys.argv[1:]])
    from site_audit.cli import main as run
    run()


if __name__ == "__main__":
    main()
