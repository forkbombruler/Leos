from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from leos_agent.dev_tools import (
    GitDiffTool,
    ListFilesTool,
    PatchFileTool,
    ReadFileTool,
    RunTestsTool,
    _safe_test_env,
    default_dev_registry,
)
from leos_agent.state import WorldState


class DevToolsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_list_files_excludes_git_and_pycache(self) -> None:
        (self.root / ".git").mkdir()
        (self.root / ".git" / "config").write_text("x", encoding="utf-8")
        (self.root / "__pycache__").mkdir()
        (self.root / "__pycache__" / "x.pyc").write_bytes(b"x")
        (self.root / "app.py").write_text("print(1)\n", encoding="utf-8")

        result = ListFilesTool(self.root).execute({}, WorldState())

        self.assertTrue(result.ok)
        self.assertEqual(result.observed_state_delta["files_listed"], ["app.py"])

    def test_read_file_reads_workspace_file(self) -> None:
        (self.root / "README.md").write_text("hello", encoding="utf-8")

        result = ReadFileTool(self.root).execute({"path": "README.md"}, WorldState())

        self.assertTrue(result.ok)
        self.assertEqual(result.observed_state_delta["content"], "hello")

    def test_read_file_blocks_escape(self) -> None:
        result = ReadFileTool(self.root).dry_run({"path": "../outside.txt"}, WorldState())

        self.assertFalse(result.ok)

    def test_patch_file_expected_previous_mismatch(self) -> None:
        (self.root / "a.txt").write_text("old", encoding="utf-8")

        result = PatchFileTool(self.root).dry_run(
            {"path": "a.txt", "expected_previous": "different", "new_content": "new"},
            WorldState(),
        )

        self.assertFalse(result.ok)

    def test_patch_file_execute_and_rollback(self) -> None:
        path = self.root / "a.txt"
        path.write_text("old", encoding="utf-8")
        tool = PatchFileTool(self.root)

        result = tool.execute({"path": "a.txt", "new_content": "new"}, WorldState())
        self.assertTrue(result.ok)
        self.assertEqual(path.read_text(encoding="utf-8"), "new")
        rollback = tool.rollback(result.rollback_token or {}, WorldState())

        self.assertTrue(rollback.ok)
        self.assertEqual(path.read_text(encoding="utf-8"), "old")

    def test_git_diff_non_repo_structured_failure(self) -> None:
        result = GitDiffTool(self.root).execute({}, WorldState())

        self.assertFalse(result.ok)
        self.assertIn("returncode", result.data)

    def test_run_tests_uses_argv_without_shell(self) -> None:
        tool = RunTestsTool(self.root)
        completed = subprocess.CompletedProcess(args=["python"], returncode=0, stdout="ok", stderr="")
        with mock.patch("subprocess.run", return_value=completed) as run:
            result = tool.execute({"argv": ["python", "-m", "unittest"]}, WorldState())

        self.assertTrue(result.ok)
        self.assertFalse(run.call_args.kwargs["shell"])
        self.assertIsInstance(run.call_args.args[0], list)

    def test_run_tests_timeout_returns_failure(self) -> None:
        tool = RunTestsTool(self.root)
        with mock.patch("subprocess.run", side_effect=subprocess.TimeoutExpired(["python"], 1)):
            result = tool.execute({"argv": ["python"], "timeout_seconds": 0.1}, WorldState())

        self.assertFalse(result.ok)
        self.assertFalse(result.observed_state_delta["tests_ok"])

    def test_safe_test_env_allowlists_path_not_secret(self) -> None:
        with mock.patch.dict(os.environ, {"PATH": "/bin", "SECRET_TOKEN": "x"}, clear=True):
            env = _safe_test_env()

        self.assertEqual(env["PATH"], "/bin")
        self.assertNotIn("SECRET_TOKEN", env)

    def test_default_dev_registry_execute_is_opt_in(self) -> None:
        self.assertNotIn("run_tests", default_dev_registry(self.root).names())
        self.assertIn("run_tests", default_dev_registry(self.root, include_execute=True).names())


if __name__ == "__main__":
    unittest.main()
