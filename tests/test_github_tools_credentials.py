from __future__ import annotations

import time
import unittest

from leos_agent.credentials import InMemoryCredentialVault
from leos_agent.github_tools import GitHubCreateBranchTool, InMemoryGitHubClient
from leos_agent.state import WorldState
from leos_agent.tools import Secret


class GitHubToolCredentialTests(unittest.TestCase):
    def test_create_branch_uses_vault_for_rollback_token(self) -> None:
        client = InMemoryGitHubClient()
        client.seed_file("o/r", "main", "app.py", "old")
        vault = InMemoryCredentialVault()
        tool = GitHubCreateBranchTool(client, credential_vault=vault)

        result = tool.execute(
            {"repo": "o/r", "branch": "agent/fix", "base": "main", "token": Secret("ghp_secret")},
            WorldState(),
        )
        rollback = tool.rollback(result.rollback_token or {}, WorldState())

        self.assertTrue(result.ok)
        self.assertTrue(rollback.ok)
        self.assertIn("auth_handle", result.rollback_token or {})
        self.assertNotIn("ghp_secret", repr(result.rollback_token))
        self.assertEqual(client.accepted_token_count, 2)
        self.assertNotIn("ghp_secret", repr(client))

    def test_wrong_scope_handle_rollback_fails_cleanly(self) -> None:
        client = InMemoryGitHubClient()
        vault = InMemoryCredentialVault()
        handle = vault.put(Secret("ghp_secret"), scope="github:o/r")
        tool = GitHubCreateBranchTool(client, credential_vault=vault)

        result = tool.rollback(
            {"repo": "other/repo", "branch": "agent/fix", "auth_handle": handle.to_dict()}, WorldState()
        )

        self.assertFalse(result.ok)
        self.assertIn("Rollback credential unavailable", result.message)

    def test_no_vault_legacy_behavior_still_works(self) -> None:
        client = InMemoryGitHubClient()
        client.seed_file("o/r", "main", "app.py", "old")
        tool = GitHubCreateBranchTool(client)

        result = tool.execute(
            {"repo": "o/r", "branch": "agent/fix", "base": "main", "token": Secret("ghp_secret")},
            WorldState(),
        )
        rollback = tool.rollback(result.rollback_token or {}, WorldState())

        self.assertTrue(rollback.ok)
        self.assertIn("auth_token_id", result.rollback_token or {})

    def test_secret_token_not_in_rollback_or_repr(self) -> None:
        client = InMemoryGitHubClient()
        vault = InMemoryCredentialVault()
        tool = GitHubCreateBranchTool(client, credential_vault=vault)

        result = tool.execute(
            {"repo": "o/r", "branch": "agent/fix", "base": "main", "token": Secret("ghp_secret")},
            WorldState(),
        )

        self.assertNotIn("ghp_secret", repr(result.rollback_token))
        self.assertNotIn("ghp_secret", repr(vault))

    def test_revoked_handle_rollback_fails_cleanly(self) -> None:
        vault = InMemoryCredentialVault()
        handle = vault.put(Secret("ghp_secret"), scope="github:o/r")
        vault.revoke(handle)
        tool = GitHubCreateBranchTool(InMemoryGitHubClient(), credential_vault=vault)

        result = tool.rollback({"repo": "o/r", "branch": "agent/fix", "auth_handle": handle.to_dict()}, WorldState())

        self.assertFalse(result.ok)

    def test_expired_handle_rollback_fails_cleanly(self) -> None:
        vault = InMemoryCredentialVault()
        handle = vault.put(Secret("ghp_secret"), scope="github:o/r", expires_at=time.time() - 1)
        tool = GitHubCreateBranchTool(InMemoryGitHubClient(), credential_vault=vault)

        result = tool.rollback({"repo": "o/r", "branch": "agent/fix", "auth_handle": handle.to_dict()}, WorldState())

        self.assertFalse(result.ok)


if __name__ == "__main__":
    unittest.main()
