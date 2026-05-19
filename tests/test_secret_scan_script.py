from __future__ import annotations

import io
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from scripts.check_no_secret_literals import main
from scripts.scan_artifacts_for_secrets import main as scan_main


class SecretScanScriptTests(unittest.TestCase):
    def test_clean_dir_returns_zero(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "report.md").write_text("clean", encoding="utf-8")

            self.assertEqual(main(["--root", tmp]), 0)

    def test_secret_literal_returns_nonzero(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "report.md").write_text("token ghp_must_not_leak", encoding="utf-8")

            self.assertEqual(main(["--root", tmp]), 1)

    def test_output_prints_pattern_type_not_secret(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "report.md").write_text("token ghp_must_not_leak", encoding="utf-8")
            stdout = io.StringIO()

            with redirect_stdout(stdout):
                code = main(["--root", tmp])

            self.assertEqual(code, 1)
            self.assertIn("pattern=github-classic-token", stdout.getvalue())
            self.assertNotIn("ghp_must_not_leak", stdout.getvalue())

    def test_scan_artifacts_wrapper_uses_same_scanner(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "report.md").write_text("clean", encoding="utf-8")

            self.assertEqual(scan_main(["--root", tmp]), 0)


if __name__ == "__main__":
    unittest.main()
