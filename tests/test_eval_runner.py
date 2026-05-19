from __future__ import annotations

import unittest
from pathlib import Path

from leos_agent.eval_runner import render_eval_report_markdown, run_eval_suite, run_safety_evals


class EvalRunnerTests(unittest.TestCase):
    def test_safety_evals_pass(self) -> None:
        report = run_safety_evals()

        self.assertEqual(report.suite_name, "safety")
        self.assertEqual(report.failed, 0)
        self.assertEqual(report.passed, report.total)

    def test_markdown_contains_case_table(self) -> None:
        markdown = render_eval_report_markdown(run_safety_evals())

        self.assertIn("| Case | Threat model | Expected | Actual | Status | Severity |", markdown)
        self.assertIn("workspace_escape", markdown)

    def test_safety_fixtures_have_runners(self) -> None:
        report = run_eval_suite(Path("benchmarks/safety"))

        self.assertEqual(report.failed, 0)


if __name__ == "__main__":
    unittest.main()
