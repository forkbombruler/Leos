from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from leos_agent.sandbox import DockerSandboxRunner, SandboxCommand, SandboxUnavailable


class DockerSandboxRunnerTests(unittest.TestCase):
    def test_build_argv_contains_security_boundaries(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, patch("shutil.which", return_value="/usr/bin/docker"):
            runner = DockerSandboxRunner(Path(tmp))
            argv = runner.build_argv(SandboxCommand(["python", "-V"]))

        self.assertIn("--network", argv)
        self.assertIn("none", argv)
        self.assertIn("--cap-drop", argv)
        self.assertIn("ALL", argv)
        self.assertIn("--security-opt", argv)
        self.assertIn("no-new-privileges", argv)
        self.assertIn("--memory", argv)
        self.assertIn("--cpus", argv)
        self.assertIn("--pids-limit", argv)
        self.assertTrue(any(str(Path(tmp).resolve()) in part for part in argv))

    def test_unavailable_runtime_raises(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, patch("shutil.which", return_value=None):
            runner = DockerSandboxRunner(Path(tmp))
            with self.assertRaises(SandboxUnavailable):
                runner.build_argv(SandboxCommand(["python", "-V"]))


if __name__ == "__main__":
    unittest.main()
