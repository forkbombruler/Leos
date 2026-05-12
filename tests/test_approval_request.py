from __future__ import annotations

import unittest

from leos_agent import ActionStep, Permission, Reversibility, RiskLevel, StateCondition, build_approval_request


class ApprovalRequestTests(unittest.TestCase):
    def test_build_approval_request_contains_human_review_fields(self) -> None:
        step = ActionStep(
            "safe_file_write",
            {"path": "README.md", "content": "updated"},
            "Update project documentation",
            risk=RiskLevel.MEDIUM,
            reversibility=Reversibility.REVERSIBLE,
            required_permissions=(Permission.WRITE_FILES,),
            preconditions=(StateCondition("path_inside_workspace"),),
            idempotency_key="goal-1-readme-v1",
        )

        request = build_approval_request(step, goal="Update README")
        payload = request.as_dict()

        self.assertEqual(payload["goal"], "Update README")
        self.assertIn("safe_file_write", payload["action"])
        self.assertIn("README.md", payload["action"])
        self.assertIn("write_files", payload["minimal_permissions"])
        self.assertIn("medium", payload["risk"])
        self.assertIn("reversible", payload["reversibility"])
        self.assertIn("precondition:path_inside_workspace", payload["evidence"])
        self.assertIn("idempotency_key:goal-1-readme-v1", payload["evidence"])
        self.assertIn("deny and leave state unchanged", payload["alternatives"])

    def test_build_approval_request_summarizes_non_permission_and_empty_steps(self) -> None:
        argument_step = ActionStep("echo", {"message": "hello"}, "Return message")
        empty_step = ActionStep("noop", {}, "No external action")

        argument_request = build_approval_request(argument_step)
        empty_request = build_approval_request(empty_step)

        self.assertEqual(argument_request.impact, "uses arguments: message")
        self.assertEqual(empty_request.impact, "no external permission declared")
        self.assertEqual(argument_request.minimal_permissions, [])


if __name__ == "__main__":
    unittest.main()
