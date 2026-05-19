from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from leos_agent.audit import AuditLog
from leos_agent.cli import _trace_html
from leos_agent.credentials import SecretHandle
from leos_agent.trace_viewer import render_trace_html, render_trace_markdown


class TraceViewerTests(unittest.TestCase):
    def test_render_trace_html_escapes_payload(self) -> None:
        records = [
            {
                "event_type": "step.executed",
                "message": "<script>alert(1)</script>",
                "payload": {"observed": "<img src=x onerror=alert(1)>"},
            }
        ]

        rendered = render_trace_html(records)

        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", rendered)
        self.assertIn("&lt;img src=x onerror=alert(1)&gt;", rendered)
        self.assertNotIn("<script>alert(1)</script>", rendered)

    def test_trace_html_cli_writes_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "audit.jsonl"
            output_path = Path(tmp) / "trace.html"
            audit = AuditLog(log_path)
            audit.record("goal.created", "created", goal_id="g1")

            code = _trace_html(str(log_path), output=str(output_path), title="Test Trace")

            self.assertEqual(code, 0)
            rendered = output_path.read_text(encoding="utf-8")
            self.assertIn("Test Trace", rendered)
            self.assertIn("goal.created", rendered)

    def test_markdown_handles_empty_audit(self) -> None:
        markdown = render_trace_markdown([])

        self.assertIn("Total events: 0", markdown)

    def test_markdown_contains_event_types(self) -> None:
        markdown = render_trace_markdown([{"event_type": "step.blocked", "message": "blocked"}])

        self.assertIn("`step.blocked`", markdown)

    def test_markdown_contains_key_runtime_fields(self) -> None:
        markdown = render_trace_markdown(
            [
                {
                    "event_type": "step.blocked",
                    "message": "blocked",
                    "payload": {
                        "goal_id": "goal-1",
                        "plan_id": "plan-1",
                        "step_id": "step-1",
                        "risk": "high",
                        "permissions": ["write_files"],
                        "decision": "needs_human",
                        "goal_status": "blocked",
                    },
                }
            ]
        )

        self.assertIn("goal-1", markdown)
        self.assertIn("plan-1", markdown)
        self.assertIn("write_files", markdown)
        self.assertIn("needs_human", markdown)
        self.assertIn("Final goal status: `blocked`", markdown)

    def test_markdown_contains_goal_evaluation_fields(self) -> None:
        markdown = render_trace_markdown(
            [
                {
                    "event_type": "loop.goal_evaluated",
                    "message": "evaluated",
                    "payload": {
                        "goal_id": "goal-1",
                        "evaluation_status": "succeeded",
                        "satisfied_criteria": ["tests pass"],
                        "unsatisfied_criteria": [],
                        "explanation": "Test success criterion satisfied by tests_ok=True.",
                    },
                }
            ]
        )

        self.assertIn("evaluation_status=succeeded", markdown)
        self.assertIn("tests pass", markdown)
        self.assertIn("tests_ok=True", markdown)

    def test_goal_evaluation_html_escapes_explanation(self) -> None:
        rendered = render_trace_html(
            [
                {
                    "event_type": "loop.goal_evaluated",
                    "message": "evaluated",
                    "payload": {
                        "evaluation_status": "failed",
                        "explanation": "<script>alert(1)</script>",
                    },
                }
            ]
        )

        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", rendered)
        self.assertNotIn("<script>alert(1)</script>", rendered)

    def test_markdown_redacts_token_like_payloads(self) -> None:
        rendered = render_trace_markdown(
            [{"event_type": "tool.output", "message": "done", "payload": {"token": "ghp_must_not_leak"}}]
        )

        self.assertIn("[REDACTED]", rendered)
        self.assertNotIn("ghp_must_not_leak", rendered)

    def test_html_redacts_token_like_payloads(self) -> None:
        rendered = render_trace_html(
            [{"event_type": "tool.output", "message": "done", "payload": {"token": "ghp_must_not_leak"}}]
        )

        self.assertIn("[REDACTED]", rendered)
        self.assertNotIn("ghp_must_not_leak", rendered)

    def test_secret_handle_renders_without_secret(self) -> None:
        handle = SecretHandle(handle_id="h1", scope="github:o/r", created_at=1.0)

        rendered = render_trace_markdown(
            [{"event_type": "tool.rollback", "message": "handle", "payload": {"auth_handle": handle}}]
        )

        self.assertIn("h1", rendered)
        self.assertIn("github:o/r", rendered)
        self.assertNotIn("must-not-leak", rendered)


if __name__ == "__main__":
    unittest.main()
