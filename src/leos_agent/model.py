"""Vendor-neutral LLM model abstraction.

Defines the ModelClient Protocol so Leos can accept any LLM backend
(cloud API, local model, fake mock) without binding to a specific provider.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Protocol

from .errors import LeosError

# -- errors ----------------------------------------------------------------


class ModelCallError(LeosError):
    """Raised when an underlying model call fails (network, auth, etc.)."""


class StructuredOutputError(LeosError):
    """Raised when an LLM fails to produce valid structured JSON output."""


# -- data classes ----------------------------------------------------------


@dataclass
class ModelUsage:
    """Token and cost metrics for a single model call."""

    input_tokens: int = 0
    output_tokens: int = 0
    total_tokens: int = 0
    cost_usd: float | None = None


@dataclass
class ModelRequest:
    """A single model generation request."""

    prompt: str
    system: str | None = None
    schema: dict[str, Any] | None = None
    model: str = "unknown"
    temperature: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ModelResponse:
    """A single model generation response."""

    text: str
    parsed_json: Any | None = None
    model: str = "unknown"
    usage: ModelUsage | None = None
    raw: Any | None = None


# -- protocol --------------------------------------------------------------


class ModelClient(Protocol):
    """Vendor-neutral LLM client protocol.

    Implementations must accept a `ModelRequest` and return a `ModelResponse`.
    Structured output (JSON mode) is optional: set `request.schema` and
    populate `response.parsed_json` when the backend supports it.
    """

    def generate(self, request: ModelRequest) -> ModelResponse: ...


# -- fake / test client ----------------------------------------------------


class FakeModelClient:
    """Deterministic fake model client for tests.

    Pre-configure responses via `set_response()` or pass raw JSON text.
    Records the last request for inspection.
    """

    def __init__(self) -> None:
        self._text: str = "[]"
        self._parsed: Any | None = None
        self._model: str = "fake"
        self.last_request: ModelRequest | None = None

    def set_response(self, *, text: str = "[]", parsed: Any = None, model: str = "fake") -> None:
        self._text = text
        self._parsed = parsed
        self._model = model

    def set_parsed_json(self, data: Any) -> None:
        self._parsed = data
        self._text = json.dumps(data, default=str)

    def generate(self, request: ModelRequest) -> ModelResponse:
        self.last_request = request
        parsed = self._parsed if self._parsed is not None else json.loads(self._text)
        return ModelResponse(
            text=self._text,
            parsed_json=parsed,
            model=self._model,
            usage=ModelUsage(input_tokens=10, output_tokens=5, total_tokens=15),
        )
