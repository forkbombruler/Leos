"""Secret hygiene helpers for audit, trace, and persistence boundaries."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import fields, is_dataclass
from enum import Enum
from pathlib import Path
from typing import Any

from .credentials import SecretHandle
from .errors import LeosError
from .tools import Secret

SECRET_MARKER = "<secret>"  # nosec B105
REDACTED = "[REDACTED]"
TOKEN_REGEXES = (
    ("github-classic-token", re.compile(r"(?<![A-Za-z0-9])ghp_[A-Za-z0-9_]{8,}")),
    ("github-fine-grained-token", re.compile(r"(?<![A-Za-z0-9])github_pat_[A-Za-z0-9_]{8,}")),
    ("openai-token", re.compile(r"(?<![A-Za-z0-9])sk-[A-Za-z0-9_-]{8,}")),
    ("slack-bot-token", re.compile(r"(?<![A-Za-z0-9])xoxb-[A-Za-z0-9_-]{8,}")),
    ("slack-user-token", re.compile(r"(?<![A-Za-z0-9])xoxp-[A-Za-z0-9_-]{8,}")),
)


class SanitizationError(LeosError):
    """Raised when secret-like data crosses a rejecting boundary."""


class SanitizationMode(str, Enum):
    REJECT = "reject"
    REDACT = "redact"


def sanitize_for_boundary(value: Any, *, mode: SanitizationMode, path: str = "$") -> Any:
    """Return a JSON-safe representation or reject secret-like data."""

    mode = SanitizationMode(mode)
    if isinstance(value, Secret):
        return _secret_value(mode, path)
    if isinstance(value, SecretHandle):
        return value.to_dict()
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Path):
        return sanitize_for_boundary(str(value), mode=mode, path=path)
    if isinstance(value, bytes):
        return {"type": "bytes", "length": len(value)}
    if isinstance(value, str):
        return _string_value(value, mode, path)
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    if isinstance(value, Mapping):
        safe_mapping: dict[str, Any] = {}
        for key, item in value.items():
            safe_key = sanitize_for_boundary(str(key), mode=mode, path=f"{path}.<key>")
            safe_mapping[str(safe_key)] = sanitize_for_boundary(item, mode=mode, path=f"{path}.{safe_key}")
        return safe_mapping
    if isinstance(value, (list, tuple, set, frozenset)):
        return [sanitize_for_boundary(item, mode=mode, path=f"{path}[{index}]") for index, item in enumerate(value)]
    if is_dataclass(value) and not isinstance(value, type):
        safe_dataclass: dict[str, Any] = {}
        for field in fields(value):
            safe_dataclass[field.name] = sanitize_for_boundary(
                getattr(value, field.name), mode=mode, path=f"{path}.{field.name}"
            )
        return safe_dataclass
    return {"type": type(value).__name__}


def assert_no_secrets(value: Any) -> None:
    sanitize_for_boundary(value, mode=SanitizationMode.REJECT)


def redact_secrets(value: Any) -> Any:
    return sanitize_for_boundary(value, mode=SanitizationMode.REDACT)


def safe_json_dumps(value: Any) -> str:
    return json.dumps(redact_secrets(value), ensure_ascii=False, sort_keys=True)


def _secret_value(mode: SanitizationMode, path: str) -> str:
    if mode is SanitizationMode.REJECT:
        raise SanitizationError(f"{path}: secret value is not allowed")
    return SECRET_MARKER


def _string_value(value: str, mode: SanitizationMode, path: str) -> str:
    reason = _secret_string_reason(value)
    if reason is None:
        return value
    if mode is SanitizationMode.REJECT:
        raise SanitizationError(f"{path}: secret-like string is not allowed ({reason})")
    return REDACTED


def _secret_string_reason(value: str) -> str | None:
    if SECRET_MARKER in value:
        return "redacted-secret-marker"
    for label, pattern in TOKEN_REGEXES:
        if pattern.search(value):
            return label
    if "-----BEGIN PRIVATE KEY-----" in value:
        return "private-key"
    return None
