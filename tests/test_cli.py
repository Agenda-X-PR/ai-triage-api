"""Tests for CLI behavior — exit codes and output formats."""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCRIPT = HERE.parent / "sec_triage.py"


def run_cli(*args, stdin=None):
    """Run sec_triage.py with the given args. Returns CompletedProcess."""
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        capture_output=True,
        text=True,
        input=stdin,
        encoding="utf-8",
    )


class TestExitCodes(unittest.TestCase):

    def test_exit_0_on_clean_log(self):
        log = '1.1.1.1 - - [18/Oct/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 100\n'
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False, encoding="utf-8") as f:
            f.write(log)
            path = f.name
        try:
            result = run_cli(path)
            self.assertEqual(result.returncode, 0)
        finally:
            os.unlink(path)

    def test_exit_1_on_high_severity(self):
        log = "\n".join(
            f'1.1.1.1 - - [18/Oct/2026:10:00:0{i} +0000] "POST /login HTTP/1.1" 401 80'
            for i in range(5)
        ) + "\n"
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False, encoding="utf-8") as f:
            f.write(log)
            path = f.name
        try:
            result = run_cli(path)
            self.assertEqual(result.returncode, 1)
        finally:
            os.unlink(path)

    def test_exit_2_on_missing_file(self):
        result = run_cli("/does/not/exist.log")
        self.assertEqual(result.returncode, 2)
        self.assertIn("sec-triage", result.stderr)


class TestOutputFormats(unittest.TestCase):

    def test_json_output_parses(self):
        log = '1.1.1.1 - - [18/Oct/2026:10:00:00 +0000] "GET /.env HTTP/1.1" 404 100\n'
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False, encoding="utf-8") as f:
            f.write(log)
            log_path = f.name
        try:
            result = run_cli(log_path, "--format", "json")
            data = json.loads(result.stdout)
            self.assertIn("findings", data)
            self.assertIn("input_lines", data)
            self.assertEqual(data["findings_count"], 1)
        finally:
            os.unlink(log_path)

    def test_csv_output_has_header(self):
        log = '1.1.1.1 - - [18/Oct/2026:10:00:00 +0000] "GET /.env HTTP/1.1" 404 100\n'
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False, encoding="utf-8") as f:
            f.write(log)
            log_path = f.name
        try:
            result = run_cli(log_path, "--format", "csv")
            first_line = result.stdout.splitlines()[0]
            self.assertIn("severity", first_line)
            self.assertIn("rule", first_line)
        finally:
            os.unlink(log_path)

    def test_stdin_input(self):
        log = '1.1.1.1 - - [18/Oct/2026:10:00:00 +0000] "GET /.env HTTP/1.1" 404 100\n'
        result = run_cli("-", stdin=log)
        self.assertEqual(result.returncode, 0)
        self.assertIn("sensitive_path_probe", result.stdout)


if __name__ == "__main__":
    unittest.main()