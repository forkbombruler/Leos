from __future__ import annotations

import os
import subprocess
import sys
import unittest
from pathlib import Path

from examples.github_rest_agent.run_real_write_gated import _production_github_policy, _tool_mediated_get_file
from leos_agent import AgentKernel, AuditLog, GitHubGetFileTool, InMemoryGitHubClient, LeosError, Secret, ToolRegistry
from leos_agent.github_tools import GitHubUpdateFileTool, _token_or_error
from leos_agent.state import WorldState


class GitHubRealWriteGatedTests(unittest.TestCase):
    def test_real_write_script_disabled_by_default(self) -> None:
        script = Path("examples/github_rest_agent/run_real_write_gated.py")
        env = dict(os.environ)
        env.pop("LEOS_ENABLE_REAL_GITHUB_WRITES", None)
        result = subprocess.run(  # noqa: S603
            [sys.executable, str(script)],
            check=False,
            text=True,
            capture_output=True,
            env=env,
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("real write disabled", result.stdout)

    def test_protected_branch_cleanup_rejected(self) -> None:
        client = InMemoryGitHubClient()
        with self.assertRaises(LeosError):
            client.delete_branch("owner/repo", "main", token="token")

    def test_update_without_expected_guard_blocked(self) -> None:
        tool = GitHubUpdateFileTool(InMemoryGitHubClient())
        result = tool.dry_run(
            {"repo": "owner/repo", "path": "x.txt", "branch": "b", "content": "x", "message": "m"},
            WorldState(),
        )
        self.assertFalse(result.ok)

    def test_plain_token_rejected_before_client_use(self) -> None:
        token, error = _token_or_error({"token": "ghp_plain_token_value"})
        self.assertIsNone(token)
        self.assertIsNotNone(error)

    def test_secret_token_records_only_fingerprint(self) -> None:
        client = InMemoryGitHubClient()
        client.seed_issue("owner/repo", 1, title="t", body="b")
        client.read_issue("owner/repo", 1, token=Secret("token-value").unwrap())
        self.assertEqual(client.accepted_token_count, 1)
        self.assertNotIn("token-value", repr(client))

    def test_tool_mediated_preread_records_audit_event(self) -> None:
        client = InMemoryGitHubClient()
        client.seed_file("owner/repo", "main", "x.txt", "content")
        kernel = _github_get_file_kernel(client)

        result = _tool_mediated_get_file(
            kernel,
            repo="owner/repo",
            path="x.txt",
            ref="main",
            token=Secret("ghp_test_secret"),
            purpose="preread",
            allow_missing=False,
        )

        self.assertEqual(result["content"], "content")
        event_types = [event.event_type for event in kernel.audit_log.events]
        self.assertIn("github.real_write.tool_mediated_preread", event_types)
        self.assertNotIn("github.real_write.readback_direct_client_call", event_types)
        self.assertNotIn("ghp_test_secret", repr(kernel.audit_log.records()))

    def test_tool_mediated_preread_missing_can_proceed(self) -> None:
        kernel = _github_get_file_kernel(InMemoryGitHubClient())

        result = _tool_mediated_get_file(
            kernel,
            repo="owner/repo",
            path="new.txt",
            ref="main",
            token=Secret("ghp_test_secret"),
            purpose="preread",
            allow_missing=True,
        )

        self.assertIsNone(result)
        event_types = [event.event_type for event in kernel.audit_log.events]
        self.assertIn("github.real_write.tool_mediated_preread_missing", event_types)

    def test_tool_mediated_readback_missing_fails(self) -> None:
        kernel = _github_get_file_kernel(InMemoryGitHubClient())

        with self.assertRaises(LeosError):
            _tool_mediated_get_file(
                kernel,
                repo="owner/repo",
                path="missing.txt",
                ref="branch",
                token=Secret("ghp_test_secret"),
                purpose="readback",
                allow_missing=False,
            )


def _github_get_file_kernel(client: InMemoryGitHubClient) -> AgentKernel:
    registry = ToolRegistry()
    registry.register(GitHubGetFileTool(client))
    return AgentKernel(
        registry=registry,
        policy=_production_github_policy(),
        audit_log=AuditLog(),
    )


if __name__ == "__main__":
    unittest.main()
