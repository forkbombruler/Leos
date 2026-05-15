from __future__ import annotations

import json
import re
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from leos_agent import proof
from leos_agent.proof import exit_code_for_manifest, generate_proofs, redact_secrets


class ProofGenerationTests(unittest.TestCase):
    def test_allow_dirty_generates_precommit_manifest_and_docs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "proofs"
            with mock.patch(
                "leos_agent.proof._git_metadata",
                return_value={"available": True, "branch": "main", "commit_sha": "abc", "dirty_worktree": True},
            ):
                manifest = generate_proofs(out, allow_dirty=True, no_run=True, repo_root=Path.cwd())

            data = json.loads((out / "MANIFEST.json").read_text(encoding="utf-8"))
            index = (out / "PROOF_INDEX.md").read_text(encoding="utf-8")

        self.assertEqual(manifest.proof_status, "precommit_dirty")
        self.assertFalse(manifest.release_grade)
        self.assertEqual(data["proof_status"], "precommit_dirty")
        self.assertIn("SOURCE_SNAPSHOT.md", index)
        self.assertIn("TEST_INVENTORY.md", index)
        self.assertIn("dirty worktree", index)

    def test_require_clean_dirty_fails(self) -> None:
        with (
            tempfile.TemporaryDirectory() as tmp,
            mock.patch(
                "leos_agent.proof._git_metadata",
                return_value={"available": True, "branch": "main", "commit_sha": "abc", "dirty_worktree": True},
            ),
        ):
            manifest = generate_proofs(Path(tmp), require_clean=True, no_run=True, repo_root=Path.cwd())

        self.assertEqual(manifest.proof_status, "failed_dirty_worktree")
        self.assertEqual(exit_code_for_manifest(manifest), 2)

    def test_clean_worktree_is_release_grade(self) -> None:
        with (
            tempfile.TemporaryDirectory() as tmp,
            mock.patch(
                "leos_agent.proof._git_metadata",
                return_value={"available": True, "branch": "main", "commit_sha": "abc", "dirty_worktree": False},
            ),
        ):
            manifest = generate_proofs(Path(tmp), require_clean=True, no_run=True, repo_root=Path.cwd())

        self.assertEqual(manifest.proof_status, "release_grade")
        self.assertTrue(manifest.release_grade)

    def test_git_unavailable_does_not_crash(self) -> None:
        with (
            tempfile.TemporaryDirectory() as tmp,
            mock.patch(
                "leos_agent.proof._git_metadata",
                return_value={"available": False, "branch": None, "commit_sha": None, "dirty_worktree": None},
            ),
        ):
            manifest = generate_proofs(Path(tmp), no_run=True, repo_root=Path.cwd())

        self.assertEqual(manifest.proof_status, "git_unavailable")

    def test_source_snapshot_and_test_inventory_include_expected_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            manifest = generate_proofs(Path(tmp), no_run=True, repo_root=Path.cwd())

        sources = {snapshot.path: snapshot for snapshot in manifest.source_snapshot}
        tests = {snapshot.path: snapshot for snapshot in manifest.test_inventory}
        self.assertIn("src/leos_agent/proof.py", sources)
        self.assertIn("tests/test_proof_generation.py", tests)
        self.assertRegex(sources["src/leos_agent/proof.py"].sha256 or "", r"^[0-9a-f]{64}$")

    def test_missing_snapshot_file_is_recorded(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            missing = proof._snapshot_files(root, ["missing.py"])[0]

        self.assertFalse(missing.exists)
        self.assertIsNone(missing.sha256)

    def test_failed_command_recorded_as_failed(self) -> None:
        result = proof._run_command("false", ["python", "-c", "import sys; sys.exit(7)"], Path.cwd())

        self.assertEqual(result.status, "failed")
        self.assertEqual(result.exit_code, 7)

    def test_output_is_truncated(self) -> None:
        text, truncated = proof._excerpt("x" * (proof.MAX_EXCERPT + 10))

        self.assertTrue(truncated)
        self.assertEqual(len(text), proof.MAX_EXCERPT)

    def test_secret_like_strings_are_redacted(self) -> None:
        redacted = redact_secrets("token=abc api_key: def password secret")

        self.assertNotRegex(redacted, re.compile("abc|def"))
        self.assertIn("<redacted>", redacted)


if __name__ == "__main__":
    unittest.main()
