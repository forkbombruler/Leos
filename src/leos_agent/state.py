"""World-state model."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class TrustLevel(str, Enum):
    VERIFIED = "verified"
    OBSERVED = "observed"
    USER_PROVIDED = "user_provided"
    TOOL_REPORTED = "tool_reported"
    MODEL_INFERRED = "model_inferred"
    UNTRUSTED_EXTERNAL = "untrusted_external"


@dataclass
class WorldState:
    """The agent's explicit belief state.

    `facts` should contain verified claims. `assumptions` should contain beliefs
    that still need validation. Treating these as separate fields prevents the
    agent from silently confusing guesses with reality.
    """

    facts: dict[str, Any] = field(default_factory=dict)
    assumptions: dict[str, Any] = field(default_factory=dict)
    uncertainty: dict[str, float] = field(default_factory=dict)
    trust: dict[str, TrustLevel] = field(default_factory=dict)

    def snapshot(self) -> dict[str, Any]:
        return {
            "facts": dict(self.facts),
            "assumptions": dict(self.assumptions),
            "uncertainty": dict(self.uncertainty),
            "trust": {key: value.value for key, value in self.trust.items()},
        }

    def set_fact(self, key: str, value: Any, *, trust_level: TrustLevel = TrustLevel.VERIFIED) -> None:
        self.facts[key] = value
        self.trust[key] = trust_level

    def observe(self, delta: dict[str, Any], *, trust_level: TrustLevel = TrustLevel.TOOL_REPORTED) -> None:
        for key, value in delta.items():
            self.set_fact(key, value, trust_level=trust_level)

    def mark_trust(self, keys: Any, trust_level: TrustLevel) -> None:
        for key in keys:
            if key in self.facts:
                self.trust[key] = trust_level

    def set_assumption(
        self,
        key: str,
        value: Any,
        *,
        trust_level: TrustLevel = TrustLevel.MODEL_INFERRED,
        uncertainty: float | None = None,
    ) -> None:
        self.assumptions[key] = value
        self.trust[key] = trust_level
        if uncertainty is not None:
            self.uncertainty[key] = uncertainty

    def promote_assumption(self, key: str, *, trust_level: TrustLevel = TrustLevel.VERIFIED) -> None:
        if key not in self.assumptions:
            raise KeyError(f"Unknown assumption: {key}")
        self.set_fact(key, self.assumptions.pop(key), trust_level=trust_level)
        self.uncertainty.pop(key, None)
