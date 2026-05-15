"""Tests for CLI operator subcommands."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from leos_agent.audit import AuditLog
from leos_agent.cli import (
    _eval,
    _inspect_audit,
    _manifest,
    _proof_generate,
    _queue_demo,
    _validate_task,
)


class ValidateTaskTests(unittest.TestCase):
    def test_valid_task_passes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "task.json"
            path.write_text(
                json.dumps(
                    {
                        "goal": {"description": "t", "success_criteria": ["ok"]},
                        "steps": [{"tool_name": "echo", "arguments": {"message": "hi"}, "reason": "test"}],
                    }
                )
            )
            self.assertEqual(_validate_task(str(path), tmp), 0)

    def test_invalid_schema_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "task.json"
            path.write_text(json.dumps({"goal": "not_an_object"}))
            self.assertEqual(_validate_task(str(path), tmp), 1)

    def test_unknown_tool_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "task.json"
            path.write_text(
                json.dumps(
                    {
                        "goal": {"description": "t", "success_criteria": ["ok"]},
                        "steps": [{"tool_name": "nonexistent", "arguments": {}, "reason": "test"}],
                    }
                )
            )
            self.assertEqual(_validate_task(str(path), tmp), 1)


class ManifestTests(unittest.TestCase):
    def test_outputs_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(_manifest(tmp), 0)


class InspectAuditTests(unittest.TestCase):
    def test_on_small_audit_log(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "audit.jsonl"
            log = AuditLog(path=path)
            log.record("step.executed", "ok", observed={"key": "val"})
            self.assertEqual(_inspect_audit(str(path)), 0)


class QueueDemoTests(unittest.TestCase):
    def test_exits_zero(self) -> None:
        self.assertEqual(_queue_demo(), 0)


class EvalCliTests(unittest.TestCase):
    def test_eval_safety_exits_zero(self) -> None:
        self.assertEqual(_eval("safety", output_format="text"), 0)


class ProofCliTests(unittest.TestCase):
    def test_proof_generate_no_run_writes_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            code = _proof_generate(tmp, require_clean=False, allow_dirty=True, no_run=True)

            self.assertIn(code, {0, 2})
            self.assertTrue((Path(tmp) / "MANIFEST.json").exists())


if __name__ == "__main__":
    unittest.main()
