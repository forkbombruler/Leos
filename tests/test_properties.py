"""Property-based tests for Leos agent safety invariants.

Uses stdlib random for randomised property checks — no external dependency.
"""

from __future__ import annotations

import json
import random
import tempfile
import unittest
from pathlib import Path
from typing import Any

from leos_agent.audit import AuditLog
from leos_agent.enums import GoalStatus, RiskLevel, SandboxPolicy
from leos_agent.goals import Goal
from leos_agent.policy import PolicyEngine, PolicyProfile
from leos_agent.tools import Secret, ToolSpec, _redact_secrets
from leos_agent.transactions import TransactionManager

_SEED = 20260509


class PropertyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        random.seed(_SEED)

    # -- audit event hash chain -------------------------------------------

    def test_any_sequence_of_records_produces_verifiable_chain(self) -> None:
        for _ in range(20):
            audit = AuditLog()
            count = random.randint(1, 10)
            for i in range(count):
                audit.record(
                    f"test.event.{random.choice(['a','b','c'])}",
                    f"msg {i}",
                    value=random.randint(0, 100),
                )
            self.assertTrue(audit.verify_integrity().ok, f"chain failed at count={count}")

    def test_any_single_tampered_record_is_detected(self) -> None:
        for _ in range(20):
            audit = AuditLog()
            for i in range(random.randint(2, 8)):
                audit.record("test.ev", f"msg {i}", val=i)
            records = audit.records()
            idx = random.randint(0, len(records) - 1)
            field = random.choice(["payload", "event_type", "previous_hash"])
            if field == "payload":
                records[idx] = {**records[idx], "payload": {"tampered": True}}
            elif field == "event_type":
                records[idx] = {**records[idx], "event_type": "test.tampered"}
            else:
                records[idx] = {**records[idx], "previous_hash": "f" * 64}
            self.assertFalse(AuditLog.verify_event_records(records).ok)

    # -- secret redaction -------------------------------------------------

    def test_any_dict_with_secrets_is_redacted(self) -> None:
        for _ in range(30):
            keys = [f"k{i}" for i in range(random.randint(1, 6))]
            d = {}
            secret_keys = set()
            for k in keys:
                if random.random() < 0.3:
                    d[k] = Secret(f"secret-{k}")
                    secret_keys.add(k)
                else:
                    d[k] = random.choice(["val", 42, True, None])
            redacted = _redact_secrets(d)
            for k in d:
                if k in secret_keys:
                    self.assertEqual(redacted[k], "<secret>", f"key {k} not redacted")
                else:
                    self.assertEqual(redacted[k], d[k], f"key {k} wrongly changed")

    # -- sandbox enforcement ----------------------------------------------

    def test_any_container_microvm_tool_is_blocked(self) -> None:
        for policy in (SandboxPolicy.CONTAINER, SandboxPolicy.MICROVM):
            for _ in range(5):
                spec = ToolSpec(
                    name=f"test_{random.randint(0,999)}",
                    description="test",
                    permissions=(),
                    sandbox_policy=policy,
                )
                tool = _FakeTool(spec)
                result = TransactionManager._enforce_sandbox(tool)
                self.assertIsNotNone(result, f"{policy.value} not blocked")

    def test_any_tool_with_network_access_is_blocked(self) -> None:
        for _ in range(10):
            spec = ToolSpec(
                name=f"nettool_{random.randint(0,999)}",
                description="test",
                permissions=(),
                network_access=True,
            )
            result = TransactionManager._enforce_sandbox(_FakeTool(spec))
            self.assertIsNotNone(result)

    # -- goal transition validity -----------------------------------------

    def test_any_valid_transition_sequence_is_accepted(self) -> None:
        valid_from = {
            GoalStatus.CREATED: {GoalStatus.CLARIFYING, GoalStatus.PLANNING, GoalStatus.CANCELLED, GoalStatus.ARCHIVED},
            GoalStatus.PLANNING: {GoalStatus.AWAITING_APPROVAL, GoalStatus.RUNNING, GoalStatus.BLOCKED, GoalStatus.CANCELLED},
            GoalStatus.RUNNING: {GoalStatus.PAUSED, GoalStatus.BLOCKED, GoalStatus.FAILED, GoalStatus.PARTIALLY_DONE, GoalStatus.SUCCEEDED, GoalStatus.CANCELLED},
            GoalStatus.BLOCKED: {GoalStatus.PLANNING, GoalStatus.RUNNING, GoalStatus.FAILED, GoalStatus.CANCELLED, GoalStatus.ARCHIVED},
            GoalStatus.FAILED: {GoalStatus.PLANNING, GoalStatus.ARCHIVED},
            GoalStatus.SUCCEEDED: {GoalStatus.ARCHIVED},
        }
        for _ in range(30):
            current = GoalStatus.CREATED
            goal = Goal(description="property test", success_criteria=["ok"], stop_conditions=["done"])
            length = random.randint(1, 6)
            for _ in range(length):
                options = list(valid_from.get(current, set()))
                if not options:
                    break
                next_status = random.choice(options)
                goal = goal.transition(next_status)
                current = next_status
            self.assertIsInstance(goal.status, GoalStatus)

    # -- policy round-trip ------------------------------------------------

    def test_policy_profile_from_mapping_round_trips(self) -> None:
        profiles = [
            {"name": "p1", "granted_permissions": ["read_files"], "max_auto_risk": "low"},
            {"name": "p2", "granted_permissions": ["write_files"], "rules": [{"name": "r1", "when": {"tool": "echo"}, "decision": "denied"}]},
            {"name": "p3", "max_auto_risk": "high", "deny_permissions": ["network"]},
            {"name": "p4", "grants": [{"principal": "alice", "permissions": ["write_files"], "tools": ["safe_file_write"]}]},
        ]
        for mapping in profiles:
            profile = PolicyProfile.from_mapping(mapping)
            engine = PolicyEngine.from_profile(profile)
            self.assertEqual(engine.profile_name, mapping["name"])


class _FakeTool:
    def __init__(self, spec: Any) -> None:
        self.spec = spec


if __name__ == "__main__":
    unittest.main()
