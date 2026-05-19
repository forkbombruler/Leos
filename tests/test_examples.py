from __future__ import annotations

import subprocess
import sys
import unittest


class ExampleTests(unittest.TestCase):
    def test_software_engineering_agent_demo_runs(self) -> None:
        proc = subprocess.run(  # nosec B603
            [sys.executable, "examples/software_engineering_agent/run_demo.py"],
            capture_output=True,
            text=True,
            timeout=30,
            shell=False,
        )

        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("selected plan:", proc.stdout)
        self.assertIn("test result: True", proc.stdout)
        self.assertIn("goal evaluation: succeeded", proc.stdout)
        self.assertIn("final goal status: succeeded", proc.stdout)

    def test_github_rest_agent_dry_run_demo_runs(self) -> None:
        proc = subprocess.run(  # nosec B603
            [sys.executable, "examples/github_rest_agent/run_dry_run.py"],
            capture_output=True,
            text=True,
            timeout=30,
            shell=False,
        )

        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("github rest agent dry-run", proc.stdout)
        self.assertIn("no write performed", proc.stdout)
        self.assertIn("token not printed", proc.stdout)

    def test_github_rest_agent_orchestration_demo_runs(self) -> None:
        proc = subprocess.run(  # nosec B603
            [sys.executable, "examples/github_rest_agent/run_orchestration.py"],
            capture_output=True,
            text=True,
            timeout=30,
            shell=False,
        )

        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("github issue agent-loop dry-run orchestration", proc.stdout)
        self.assertIn("no real GitHub write performed", proc.stdout)
        self.assertIn("goal evaluation: succeeded", proc.stdout)
        self.assertIn("stop reason: goal_succeeded", proc.stdout)
        self.assertIn("token not printed", proc.stdout)


if __name__ == "__main__":
    unittest.main()
