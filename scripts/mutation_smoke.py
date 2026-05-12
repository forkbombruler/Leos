"""Targeted mutation smoke checks for safety-critical runtime boundaries.

This script is intentionally small and dependency-free. It copies the repository
to a temporary directory, applies one focused mutation at a time, and expects the
unit test suite to fail. A passing test suite after a safety mutation means the
mutation survived and the boundary needs stronger tests.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class Mutation:
    name: str
    path: str
    original: str
    mutated: str


MUTATIONS = (
    Mutation(
        name="approval_gate_inverted",
        path="src/leos_agent/transactions.py",
        original="if decision is not Decision.APPROVED:",
        mutated="if decision is Decision.APPROVED:",
    ),
    Mutation(
        name="workspace_escape_check_inverted",
        path="src/leos_agent/tools.py",
        original="if os.path.commonpath([self.workspace_root, resolved]) != str(self.workspace_root):",
        mutated="if os.path.commonpath([self.workspace_root, resolved]) == str(self.workspace_root):",
    ),
    Mutation(
        name="audit_hash_mismatch_ignored",
        path="src/leos_agent/audit.py",
        original="if event_hash != computed_hash:",
        mutated="if False and event_hash != computed_hash:",
    ),
    Mutation(
        name="policy_rule_direct_approval_allowed",
        path="src/leos_agent/policy.py",
        original="if self.decision is Decision.APPROVED:",
        mutated="if False and self.decision is Decision.APPROVED:",
    ),
    Mutation(
        name="secret_boundary_disabled",
        path="src/leos_agent/transactions.py",
        original="if _contains_secrets(step.arguments) and not tool.spec.secrets_allowed:",
        mutated="if False and _contains_secrets(step.arguments) and not tool.spec.secrets_allowed:",
    ),
)


def _ignore(dir_name: str, names: list[str]) -> set[str]:
    ignored = {
        ".git",
        ".ai",
        ".coverage",
        ".hypothesis",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".venv",
        "__pycache__",
        "htmlcov",
    }
    return {name for name in names if name in ignored or name.endswith(".pyc")}


def _copy_repo(destination: Path) -> None:
    shutil.copytree(ROOT, destination, ignore=_ignore)


def _apply_mutation(worktree: Path, mutation: Mutation) -> None:
    target = worktree / mutation.path
    text = target.read_text(encoding="utf-8")
    if mutation.original not in text:
        raise RuntimeError(f"Mutation target not found for {mutation.name}: {mutation.path}")
    target.write_text(text.replace(mutation.original, mutation.mutated, 1), encoding="utf-8")


def _run_tests(worktree: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "unittest", "discover", "-s", "tests"],
        cwd=worktree,
        env={"PYTHONPATH": "src"},
        text=True,
        capture_output=True,
        check=False,
    )


def main() -> int:
    survived: list[str] = []
    with tempfile.TemporaryDirectory(prefix="leos-mutation-smoke-") as tmp:
        tmp_root = Path(tmp)
        for mutation in MUTATIONS:
            worktree = tmp_root / mutation.name
            _copy_repo(worktree)
            _apply_mutation(worktree, mutation)
            result = _run_tests(worktree)
            if result.returncode == 0:
                survived.append(mutation.name)
                print(f"[SURVIVED] {mutation.name}: tests passed unexpectedly")
                continue
            print(f"[KILLED]   {mutation.name}: tests failed as expected")

    if survived:
        print("\nSurviving mutations:")
        for name in survived:
            print(f"- {name}")
        return 1
    print("\nAll targeted safety mutations were killed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
