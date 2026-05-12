"""Dependency-free fuzz smoke checks for parser and safety boundaries."""

from __future__ import annotations

import random
import string
import tempfile
from pathlib import Path
from typing import Any

from leos_agent.audit import AuditLog
from leos_agent.goals import Goal
from leos_agent.manifest import validate_task_file
from leos_agent.policy import validate_policy_config
from leos_agent.replay import AuditReplayer
from leos_agent.tools import SafeFileWriteTool

SEED = 20260512
ITERATIONS = 200


def _rand_text(rng: random.Random, max_len: int = 24) -> str:
    alphabet = string.ascii_letters + string.digits + "./_- \n\t\x00"
    return "".join(rng.choice(alphabet) for _ in range(rng.randint(0, max_len)))


def _rand_json(rng: random.Random, depth: int = 0) -> Any:
    if depth > 3:
        return rng.choice([None, True, False, rng.randint(-100, 100), _rand_text(rng)])
    kind = rng.choice(["scalar", "list", "dict"])
    if kind == "scalar":
        return rng.choice([None, True, False, rng.randint(-100, 100), _rand_text(rng)])
    if kind == "list":
        return [_rand_json(rng, depth + 1) for _ in range(rng.randint(0, 4))]
    return {_rand_text(rng, 10): _rand_json(rng, depth + 1) for _ in range(rng.randint(0, 4))}


def fuzz_task_schema(rng: random.Random) -> None:
    valid = {
        "goal": {"description": "fuzz", "success_criteria": ["ok"], "stop_conditions": ["done"]},
        "steps": [{"tool_name": "echo", "arguments": {"message": "hi"}, "reason": "test"}],
    }
    for _ in range(ITERATIONS):
        candidate = valid if rng.random() < 0.25 else _rand_json(rng)
        issues = validate_task_file(candidate if isinstance(candidate, dict) else {"payload": candidate})
        if candidate is valid and issues:
            raise AssertionError(f"valid task rejected: {issues}")


def fuzz_policy_config(rng: random.Random) -> None:
    safe = {
        "name": "fuzz",
        "rules": [{"name": "deny_network", "when": {"permission": "network"}, "decision": "denied"}],
    }
    unsafe = {"name": "unsafe", "rules": [{"name": "approve", "when": {"tool": "echo"}, "decision": "approved"}]}
    for _ in range(ITERATIONS):
        candidate = rng.choice([safe, unsafe, _rand_json(rng)])
        issues = validate_policy_config(candidate if isinstance(candidate, dict) else {"payload": candidate})
        if candidate is safe and issues:
            raise AssertionError(f"safe policy rejected: {issues}")
        if candidate is unsafe and not issues:
            raise AssertionError("unsafe direct-approval policy was accepted")


def fuzz_workspace_paths(rng: random.Random) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        workspace = Path(tmp)
        tool = SafeFileWriteTool(workspace)
        for _ in range(ITERATIONS):
            raw_path = rng.choice(
                [
                    _rand_text(rng),
                    f"../{_rand_text(rng)}",
                    f"nested/{_rand_text(rng)}",
                    "/tmp/absolute",
                    "",
                ]
            )
            result = tool.dry_run({"path": raw_path, "content": "x"}, state=None)  # type: ignore[arg-type]
            if result.ok:
                resolved = (workspace / raw_path).resolve()
                if not str(resolved).startswith(str(workspace)):
                    raise AssertionError(f"path escaped workspace: {raw_path!r}")


def fuzz_audit_replay(rng: random.Random) -> None:
    replayer = AuditReplayer()
    for _ in range(ITERATIONS):
        audit = AuditLog()
        count = rng.randint(1, 6)
        for index in range(count):
            audit.record(
                rng.choice(["step.executed", "step.blocked", "memory.written", _rand_text(rng, 12)]),
                _rand_text(rng, 20),
                observed={"key": _rand_text(rng, 10)} if rng.random() < 0.5 else _rand_json(rng),
                key=f"k{index}",
                value=_rand_json(rng),
            )
        records = audit.records()
        if rng.random() < 0.5:
            records[rng.randrange(len(records))]["payload"] = _rand_json(rng)
        result = replayer.replay_records(records, verify_integrity=False)
        if not result.ok:
            raise AssertionError("replay without integrity verification should not hard fail")


def fuzz_goal_inputs(rng: random.Random) -> None:
    for _ in range(ITERATIONS):
        try:
            Goal(
                description=_rand_text(rng),
                success_criteria=[_rand_text(rng)] if rng.random() < 0.8 else [],
                constraints=[_rand_text(rng) for _ in range(rng.randint(0, 3))],
                stop_conditions=[_rand_text(rng) for _ in range(rng.randint(0, 3))],
            )
        except Exception as exc:  # noqa: BLE001 - fuzz target should surface unexpected constructor failures
            raise AssertionError(f"goal constructor failed for fuzz input: {exc}") from exc


def main() -> int:
    rng = random.Random(SEED)
    fuzz_task_schema(rng)
    fuzz_policy_config(rng)
    fuzz_workspace_paths(rng)
    fuzz_audit_replay(rng)
    fuzz_goal_inputs(rng)
    print(f"Fuzz smoke passed with seed={SEED}, iterations={ITERATIONS}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
