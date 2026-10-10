from __future__ import annotations

import ast
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from site_audit import __version__, cli, discovery, models, network

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "site_audit"


class PackageLayoutTests(unittest.TestCase):
    def command(self, arguments, cwd=ROOT):
        result = subprocess.run(
            [sys.executable, *arguments], cwd=cwd, capture_output=True,
            text=True, check=False, timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.strip()

    def test_metadata_import_needs_no_third_party_dependencies(self):
        output = self.command([
            "-S", "-c", "import sys, site_audit; print(site_audit.__version__); "
            "assert 'site_audit.cli' not in sys.modules; assert 'requests' not in sys.modules",
        ])
        self.assertEqual(output, __version__)

    def test_entry_points_agree_on_version(self):
        for args in (["site_audit.py", "--version"], ["-m", "site_audit", "--version"],
                     ["-c", "import site_audit; site_audit.main()", "--version"]):
            with self.subTest(args=args):
                self.assertEqual(self.command(args), f"site-audit {__version__}")

    def test_module_dry_run_preserves_the_report_contract(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            self.command([
                "-m", "site_audit", "https://example.invalid/", "--dry-run", "--strict",
                "--output", str(path), "--no-load-prefs", "--no-save-prefs", "--no-save-last",
            ])
            report = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(report["tool"]["version"], __version__)
        self.assertEqual(report["schema_version"], "1.1")
        self.assertEqual(report["scan"]["status"], "dry_run")
        self.assertEqual(report["scan"]["requests_sent"], 0)

    def test_importing_compatibility_launcher_does_not_execute_it(self):
        spec = importlib.util.spec_from_file_location("checkout_launcher", ROOT / "site_audit.py")
        module = importlib.util.module_from_spec(spec)
        with patch("os.execv") as execute, patch("site_audit.cli.main") as run:
            spec.loader.exec_module(module)
        execute.assert_not_called()
        run.assert_not_called()

    def test_configuration_models_are_shared_across_boundaries(self):
        self.assertIs(cli.ScanConfig, models.ScanConfig)
        self.assertIs(network.ScanConfig, models.ScanConfig)
        self.assertIs(discovery.ScanConfig, models.ScanConfig)
        self.assertIs(cli.Finding, models.Finding)

    def test_internal_import_graph_has_no_cycles(self):
        graph = {}
        for path in PACKAGE.glob("*.py"):
            if path.stem in ("__init__", "__main__"):
                continue
            tree = ast.parse(path.read_text(encoding="utf-8"))
            graph[path.stem] = {
                node.module.split(".")[0] for node in ast.walk(tree)
                if isinstance(node, ast.ImportFrom) and node.level == 1 and node.module
            }
        visited = set()

        def visit(name, active):
            self.assertNotIn(name, active, f"Circular imports through {name}")
            if name in visited:
                return
            for dependency in graph.get(name, set()):
                visit(dependency, active | {name})
            visited.add(name)

        for name in graph:
            visit(name, set())
        self.assertTrue(all("cli" not in dependencies for name, dependencies in graph.items() if name != "cli"))
