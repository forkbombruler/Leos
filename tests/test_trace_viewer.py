from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from leos_agent.audit import AuditLog
from leos_agent.cli import _trace_html
from leos_agent.trace_viewer import render_trace_html


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


if __name__ == "__main__":
    unittest.main()
