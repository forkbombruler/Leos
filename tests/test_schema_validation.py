"""Tests for JSON Schema validation of task files and LLM proposals."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from leos_agent.errors import LLMOutputValidationError
from leos_agent.manifest import (
    load_tool_manifest_file,
    tool_manifest_from_mapping,
    validate_json_schema,
    validate_task_file,
    validate_tool_manifest,
)
from leos_agent.planner import validate_llm_proposals


class TaskFileSchemaTests(unittest.TestCase):
    def _valid_task(self) -> dict:
        return {
            "goal": {
                "description": "Test goal",
                "success_criteria": ["success"],
            },
            "steps": [{"tool_name": "echo", "arguments": {"message": "hi"}, "reason": "test"}],
        }

    def test_valid_task_passes(self) -> None:
        self.assertEqual(validate_task_file(self._valid_task()), [])

    def test_missing_goal_description_fails(self) -> None:
        data = self._valid_task()
        del data["goal"]["description"]
        issues = validate_task_file(data)
        self.assertTrue(any(i["reason"] == "required" for i in issues), f"Issues: {issues}")

    def test_empty_success_criteria_fails(self) -> None:
        data = self._valid_task()
        data["goal"]["success_criteria"] = []
        issues = validate_task_file(data)
        self.assertTrue(len(issues) > 0)

    def test_step_missing_tool_name_fails(self) -> None:
        data = self._valid_task()
        del data["steps"][0]["tool_name"]
        issues = validate_task_file(data)
        self.assertTrue(len(issues) > 0)

    def test_step_empty_reason_fails(self) -> None:
        data = self._valid_task()
        data["steps"][0]["reason"] = ""
        issues = validate_task_file(data)
        self.assertTrue(len(issues) > 0)

    def test_missing_steps_fails(self) -> None:
        data = self._valid_task()
        data["steps"] = []
        issues = validate_task_file(data)
        self.assertTrue(len(issues) > 0)

    def test_additional_property_rejected(self) -> None:
        data = self._valid_task()
        data["unknown_field"] = True
        issues = validate_task_file(data)
        self.assertTrue(any(i["reason"] == "additionalProperties" for i in issues), f"Issues: {issues}")

    def test_nested_schema_error_path_is_readable(self) -> None:
        data = self._valid_task()
        data["goal"]["priority"] = "not_an_integer"
        issues = validate_task_file(data)
        self.assertTrue(len(issues) > 0)
        self.assertTrue(any("priority" in i["path"] for i in issues))

    def test_empty_schema_returns_empty(self) -> None:
        self.assertEqual(validate_json_schema({"anything": 1}, {}), [])


class PlanProposalSchemaTests(unittest.TestCase):
    def _valid_proposal(self) -> dict:
        return {
            "steps": [{"tool_name": "echo", "arguments": {"message": "hi"}, "reason": "test"}],
            "rationale": "A valid proposal",
        }

    def test_valid_proposal_passes(self) -> None:
        proposals = validate_llm_proposals([self._valid_proposal()], {"echo"})
        self.assertEqual(len(proposals), 1)

    def test_unknown_tool_rejected(self) -> None:
        with self.assertRaises(LLMOutputValidationError):
            validate_llm_proposals([self._valid_proposal()], {"safe_file_write"})

    def test_non_object_arguments_rejected(self) -> None:
        data = self._valid_proposal()
        data["steps"][0]["arguments"] = "not_an_object"
        with self.assertRaises(LLMOutputValidationError):
            validate_llm_proposals([data], {"echo"})

    def test_empty_rationale_rejected(self) -> None:
        data = self._valid_proposal()
        data["rationale"] = ""
        with self.assertRaises(LLMOutputValidationError):
            validate_llm_proposals([data], {"echo"})

    def test_missing_steps_rejected(self) -> None:
        data = self._valid_proposal()
        del data["steps"]
        with self.assertRaises(LLMOutputValidationError):
            validate_llm_proposals([data], {"echo"})

    def test_proposal_must_be_object(self) -> None:
        with self.assertRaises(LLMOutputValidationError):
            validate_llm_proposals(["not_an_object"], {"echo"})  # type: ignore[arg-type]

    def test_step_reason_cannot_be_empty(self) -> None:
        data = self._valid_proposal()
        data["steps"][0]["reason"] = "   "
        with self.assertRaises(LLMOutputValidationError):
            validate_llm_proposals([data], {"echo"})

    def test_non_list_proposals_rejected(self) -> None:
        with self.assertRaises(LLMOutputValidationError):
            validate_llm_proposals({"not": "list"}, {"echo"})  # type: ignore[arg-type]

    def test_negative_cost_rejected(self) -> None:
        data = self._valid_proposal()
        data["estimated_cost"] = -1.0
        with self.assertRaises(LLMOutputValidationError):
            validate_llm_proposals([data], {"echo"})


class ConditionSchemaTests(unittest.TestCase):
    def _task_with_precondition(self, condition: dict) -> dict:
        return {
            "goal": {"description": "t", "success_criteria": ["ok"]},
            "steps": [
                {
                    "tool_name": "echo",
                    "arguments": {"message": "hi"},
                    "reason": "test",
                    "preconditions": [condition],
                }
            ],
        }

    def test_valid_condition_passes(self) -> None:
        data = self._task_with_precondition({"variable": "ready", "operator": "equals", "value": True})
        issues = validate_task_file(data)
        self.assertEqual(issues, [])

    def test_invalid_operator_fails(self) -> None:
        data = self._task_with_precondition({"variable": "x", "operator": "invalid_op"})
        issues = validate_task_file(data)
        self.assertTrue(len(issues) > 0, f"Expected issues for invalid operator, got: {issues}")

    def test_invalid_trust_level_fails(self) -> None:
        data = self._task_with_precondition({"variable": "x", "trust_level": "super_trusted"})
        issues = validate_task_file(data)
        self.assertTrue(len(issues) > 0, f"Expected issues for invalid trust_level, got: {issues}")

    def test_missing_variable_fails(self) -> None:
        data = self._task_with_precondition({"operator": "exists"})
        issues = validate_task_file(data)
        self.assertTrue(len(issues) > 0, f"Expected issues for missing variable, got: {issues}")

    def test_additional_property_fails(self) -> None:
        data = self._task_with_precondition({"variable": "x", "unknown_field": True})
        issues = validate_task_file(data)
        self.assertTrue(len(issues) > 0, f"Expected issues for additional property, got: {issues}")


class ToolManifestSchemaTests(unittest.TestCase):
    def _valid_manifest(self) -> dict:
        return {
            "name": "network_fetch",
            "version": "0.1.0",
            "permissions": ["network"],
            "risk": "medium",
            "reversibility": "irreversible",
            "input_schema": {"type": "object"},
            "output_schema": {"type": "object"},
            "network_access": True,
            "filesystem_scope": "none",
            "secrets_allowed": False,
            "sandbox_policy": "none",
            "requires_human_for": ["external_network"],
            "rollback_reliability": 1.0,
            "compensation_strategy": "none",
        }

    def test_valid_tool_manifest_loads_from_mapping(self) -> None:
        manifest = tool_manifest_from_mapping(self._valid_manifest())

        self.assertEqual(manifest.name, "network_fetch")
        self.assertEqual([permission.value for permission in manifest.permissions], ["network"])
        self.assertTrue(manifest.network_access)

    def test_invalid_tool_manifest_reports_schema_issues(self) -> None:
        data = self._valid_manifest()
        data["permissions"] = ["delete_everything"]

        issues = validate_tool_manifest(data)

        self.assertTrue(any(issue["reason"] == "enum" for issue in issues), f"Issues: {issues}")

    def test_tool_manifest_loads_from_json_file(self) -> None:
        import json

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "tool.json"
            path.write_text(json.dumps(self._valid_manifest()), encoding="utf-8")

            manifest = load_tool_manifest_file(path)

        self.assertEqual(manifest.name, "network_fetch")

    def test_tool_manifest_file_must_be_object(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "tool.json"
            path.write_text("[]", encoding="utf-8")

            with self.assertRaises(ValueError):
                load_tool_manifest_file(path)


if __name__ == "__main__":
    unittest.main()
