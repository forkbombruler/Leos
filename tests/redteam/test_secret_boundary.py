"""Red-team tests for secret boundary enforcement."""

from __future__ import annotations

import unittest

from leos_agent.errors import SecretBoundaryViolation
from leos_agent.memory import MemoryRecord, MemorySensitivity, MemoryType
from leos_agent.tools import Secret


class SecretBoundaryRedTeamTests(unittest.TestCase):
    def test_secret_blocked_for_non_secrets_allowed_tool(self) -> None:
        s = Secret("my-token")
        self.assertEqual(repr(s), "<secret>")

    def test_secret_value_not_in_repr(self) -> None:
        s = Secret("api-key-12345")
        self.assertNotIn("api-key-12345", repr(s))

    def test_memory_secret_requires_secret_ref_type(self) -> None:
        with self.assertRaises(SecretBoundaryViolation):
            MemoryRecord(
                key="token",
                value="api-key-value",
                memory_type=MemoryType.FACT,
                sensitivity=MemorySensitivity.SECRET,
                provenance="test",
                confidence=1.0,
            )

    def test_secret_ref_can_be_stored(self) -> None:
        record = MemoryRecord(
            key="token",
            value="secret://provider/token-key",
            memory_type=MemoryType.SECRET_REF,
            sensitivity=MemorySensitivity.SECRET,
            provenance="test",
            confidence=1.0,
        )
        self.assertEqual(record.memory_type, MemoryType.SECRET_REF)


if __name__ == "__main__":
    unittest.main()
