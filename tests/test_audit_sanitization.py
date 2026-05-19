from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from leos_agent.audit import AuditLog
from leos_agent.tools import Secret


class AuditSanitizationTests(unittest.TestCase):
    def test_record_normal_payload(self) -> None:
        audit = AuditLog()

        event = audit.record("goal.created", "created", goal_id="g1")

        self.assertEqual(event.event_type, "goal.created")
        self.assertEqual(event.payload["goal_id"], "g1")

    def test_record_secret_payload_is_blocked(self) -> None:
        audit = AuditLog()

        event = audit.record("tool.output", "payload", token=Secret("must-not-leak"))

        self.assertEqual(event.event_type, "audit.secret_blocked")
        self.assertEqual(event.payload["original_event_type"], "tool.output")
        self.assertNotIn("must-not-leak", repr(audit.records()))

    def test_record_token_string_payload_is_blocked(self) -> None:
        audit = AuditLog()

        event = audit.record("tool.output", "payload", token="ghp_must_not_leak")

        self.assertEqual(event.event_type, "audit.secret_blocked")
        self.assertNotIn("ghp_must_not_leak", repr(audit.records()))

    def test_jsonl_file_does_not_contain_secret(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "audit.jsonl"
            audit = AuditLog(path)

            audit.record("tool.output", "payload", token="ghp_must_not_leak")

            content = path.read_text(encoding="utf-8")
            self.assertIn("audit.secret_blocked", content)
            self.assertNotIn("ghp_must_not_leak", content)

    def test_error_reason_does_not_contain_secret_value(self) -> None:
        audit = AuditLog()

        event = audit.record("tool.output", "payload", token="ghp_must_not_leak")

        self.assertIn("reason", event.payload)
        self.assertNotIn("ghp_must_not_leak", event.payload["reason"])


if __name__ == "__main__":
    unittest.main()
