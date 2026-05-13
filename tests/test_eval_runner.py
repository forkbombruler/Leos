from __future__ import annotations

import unittest

from leos_agent.eval_runner import format_eval_report, run_safety_evals


class EvalRunnerTests(unittest.TestCase):
    def test_safety_eval_suite_passes(self) -> None:
        report = run_safety_evals()

        self.assertEqual(report.suite_name, "safety")
        self.assertEqual(report.failed, 0)
        self.assertGreaterEqual(report.total, 8)
        self.assertIn("workspace_escape", {result.name for result in report.results})

    def test_format_eval_report_contains_summary(self) -> None:
        report = run_safety_evals()
        rendered = format_eval_report(report)

        self.assertIn("Suite: safety", rendered)
        self.assertIn("workspace_escape", rendered)


if __name__ == "__main__":
    unittest.main()
