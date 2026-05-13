from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from leos_agent.dev_tools import (
    GitDiffTool,
    ListFilesTool,
    PatchFileTool,
    ReadFileTool,
    RunTestsTool,
    default_dev_registry,
)
from leos_agent.state import WorldState


class DevToolsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.ws = Path(self.tmp.name)
        (self.ws / "pkg").mkdir()
        (self.ws / "pkg" / "app.py").write_text("print('hi')\n", encoding="utf-8")
        (self.ws / ".git").mkdir()
        (self.ws / ".git" / "config").write_text("secret", encoding="utf-8")
        (self.ws / "__pycache__").mkdir()
        (self.ws / "__pycache__" / "x.pyc").write_bytes(b"pyc")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_list_files_excludes_git_and_pycache(self) -> None:
        result = ListFilesTool(self.ws).execute({}, WorldState())

        self.assertTrue(result.ok)
        self.assertIn("pkg/app.py", result.observed_state_delta["files_listed"])
        self.assertNotIn(".git/config", result.observed_state_delta["files_listed"])
        self.assertNotIn("__pycache__/x.pyc", result.observed_state_delta["files_listed"])

    def test_read_file_reads_workspace_file(self) -> None:
        result = ReadFileTool(self.ws).execute({"path": "pkg/app.py"}, WorldState())

        self.assertTrue(result.ok)
        self.assertEqual(result.observed_state_delta["file_read"], "pkg/app.py")
        self.assertIn("print", result.observed_state_delta["content"])

    def test_read_file_rejects_workspace_escape(self) -> None:
        result = ReadFileTool(self.ws).execute({"path": "../outside.txt"}, WorldState())

        self.assertFalse(result.ok)

    def test_patch_file_dry_run_detects_expected_previous_mismatch(self) -> None:
        result = PatchFileTool(self.ws).dry_run(
            {"path": "pkg/app.py", "expected_previous": "wrong", "new_content": "x"},
            WorldState(),
        )

        self.assertFalse(result.ok)

    def test_patch_file_execute_and_rollback(self) -> None:
        tool = PatchFileTool(self.ws)
        result = tool.execute({"path": "pkg/app.py", "new_content": "updated\n"}, WorldState())

        self.assertTrue(result.ok)
        self.assertEqual((self.ws / "pkg" / "app.py").read_text(encoding="utf-8"), "updated\n")
        rollback = tool.rollback(result.rollback_token or {}, WorldState())
        self.assertTrue(rollback.ok)
        self.assertEqual((self.ws / "pkg" / "app.py").read_text(encoding="utf-8"), "print('hi')\n")

    def test_git_diff_non_repo_returns_structured_failure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = GitDiffTool(Path(tmp)).execute({}, WorldState())
        self.assertFalse(result.ok)

    def test_run_tests_uses_argv_without_shell(self) -> None:
        completed = subprocess.CompletedProcess(["python", "-m", "unittest"], 0, stdout="ok", stderr="")
        with patch("subprocess.run", return_value=completed) as run:
            result = RunTestsTool(self.ws).execute({}, WorldState())

        self.assertTrue(result.ok)
        kwargs = run.call_args.kwargs
        self.assertNotIn("shell", kwargs)
        self.assertIsInstance(run.call_args.args[0], list)

    def test_run_tests_timeout_returns_failed_result(self) -> None:
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(["python"], 1)):
            result = RunTestsTool(self.ws).execute({"timeout_seconds": 0.1}, WorldState())

        self.assertFalse(result.ok)
        self.assertEqual(result.observed_state_delta["tests_ok"], False)

    def test_default_dev_registry_execute_tool_is_opt_in(self) -> None:
        self.assertNotIn("run_tests", default_dev_registry(self.ws).names())
        self.assertIn("run_tests", default_dev_registry(self.ws, include_execute=True).names())


if __name__ == "__main__":
    unittest.main()
