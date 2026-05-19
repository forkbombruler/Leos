from __future__ import annotations

import unittest
from dataclasses import dataclass

from leos_agent.credentials import SecretHandle
from leos_agent.sanitization import (
    SanitizationError,
    SanitizationMode,
    assert_no_secrets,
    redact_secrets,
    safe_json_dumps,
    sanitize_for_boundary,
)
from leos_agent.tools import Secret


@dataclass(frozen=True)
class SecretCarrier:
    token: object


class SanitizationTests(unittest.TestCase):
    def test_secret_rejected(self) -> None:
        with self.assertRaises(SanitizationError):
            sanitize_for_boundary(Secret("must-not-leak"), mode=SanitizationMode.REJECT)

    def test_secret_redacted(self) -> None:
        self.assertEqual(redact_secrets({"token": Secret("must-not-leak")}), {"token": "<secret>"})

    def test_nested_secret_detected(self) -> None:
        with self.assertRaisesRegex(SanitizationError, r"\$\.outer\[0\]\.token"):
            assert_no_secrets({"outer": [{"token": Secret("must-not-leak")}]})

    def test_dataclass_secret_detected(self) -> None:
        with self.assertRaisesRegex(SanitizationError, r"\$\.token"):
            assert_no_secrets(SecretCarrier(Secret("must-not-leak")))

    def test_secret_marker_substring_rejected(self) -> None:
        with self.assertRaises(SanitizationError):
            assert_no_secrets("prefix <secret> suffix")

    def test_token_like_strings_rejected(self) -> None:
        for value in (
            "ghp_1234567890",
            "github_pat_1234567890",
            "sk-1234567890",
            "-----BEGIN PRIVATE KEY-----\nabc",
        ):
            with self.subTest(value=value[:8]), self.assertRaises(SanitizationError):
                assert_no_secrets(value)

    def test_secret_handle_serializes_safely(self) -> None:
        handle = SecretHandle(handle_id="h1", scope="github:o/r", created_at=1.0)

        rendered = redact_secrets({"handle": handle})

        self.assertEqual(rendered["handle"]["handle_id"], "h1")
        self.assertNotIn("must-not-leak", repr(rendered))

    def test_bytes_do_not_leak_content(self) -> None:
        rendered = redact_secrets({"blob": b"ghp_secret"})

        self.assertEqual(rendered["blob"], {"type": "bytes", "length": 10})
        self.assertNotIn("ghp_secret", repr(rendered))

    def test_error_message_has_path_without_secret(self) -> None:
        try:
            assert_no_secrets({"nested": {"token": "ghp_must_not_leak"}})
        except SanitizationError as exc:
            message = str(exc)
        else:  # pragma: no cover - assertion guard
            self.fail("expected SanitizationError")

        self.assertIn("$.nested.token", message)
        self.assertNotIn("ghp_must_not_leak", message)

    def test_safe_json_dumps_redacts_secret_like_values(self) -> None:
        dumped = safe_json_dumps({"token": Secret("must-not-leak"), "plain": "ghp_must_not_leak"})

        self.assertIn("<secret>", dumped)
        self.assertIn("[REDACTED]", dumped)
        self.assertNotIn("must-not-leak", dumped)


if __name__ == "__main__":
    unittest.main()
