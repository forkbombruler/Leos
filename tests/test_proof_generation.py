from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

from leos_agent.proof import ProofCommand, generate_proofs, redact_secrets


class ProofGenerationTests(unittest.TestCase):
    def test_generate_proofs_records_pass_and_fail(self) -> None:
        commands = [
            ProofCommand("unit_tests", ["ok"], "ok"),
            ProofCommand("safety_evals", ["bad"], "bad"),
        ]

        def runner(command: ProofCommand) -> subprocess.CompletedProcess[str]:
            if command.name == "unit_tests":
                return subprocess.CompletedProcess(command.argv, 0, stdout="token=abc", stderr="")
            return subprocess.CompletedProcess(command.argv, 1, stdout="x" * 21000, stderr="failed")

        with tempfile.TemporaryDirectory() as tmp:
            manifest = generate_proofs(Path(tmp), commands=commands, runner=runner)
            manifest_path = Path(tmp) / "MANIFEST.json"
            index_path = Path(tmp) / "PROOF_INDEX.md"

            self.assertTrue(manifest_path.exists())
            self.assertTrue(index_path.exists())
            self.assertEqual(manifest.summary["failed"], 1)
            self.assertIn("TEST_RESULTS.md", index_path.read_text(encoding="utf-8"))
            self.assertIn("[REDACTED]", (Path(tmp) / "TEST_RESULTS.md").read_text(encoding="utf-8"))
            self.assertIn("[truncated]", (Path(tmp) / "SAFETY_EVAL_RESULTS.md").read_text(encoding="utf-8"))

    def test_redact_secrets_handles_common_secret_names(self) -> None:
        self.assertNotIn("abc", redact_secrets("api_key=abc password: abc token=abc"))


if __name__ == "__main__":
    unittest.main()
