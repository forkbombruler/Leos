"""Persistent memory store."""

from __future__ import annotations

import json
import time
from collections.abc import Sequence
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from .errors import SecretBoundaryViolation


class MemoryType(str, Enum):
    PREFERENCE = "preference"
    FACT = "fact"
    PROCEDURE = "procedure"
    FAILURE = "failure"
    POLICY = "policy"
    HYPOTHESIS = "hypothesis"
    SECRET_REF = "secret_ref"  # nosec B105


class MemorySensitivity(str, Enum):
    PUBLIC = "public"
    INTERNAL = "internal"
    SENSITIVE = "sensitive"
    SECRET = "secret"  # nosec B105


@dataclass(frozen=True)
class MemoryRecord:
    key: str
    value: Any
    confidence: float
    provenance: str
    memory_type: MemoryType = MemoryType.FACT
    sensitivity: MemorySensitivity = MemorySensitivity.INTERNAL
    scope: str = "global"
    source: str | None = None
    ttl: float | None = None
    last_verified_at: float | None = None
    conflicts_with: Sequence[str] = ()
    supersedes: Sequence[str] = ()
    embedding_id: str | None = None
    access_policy: str | None = None
    forget_policy: str | None = None
    created_at: float = field(default_factory=time.time)

    def __post_init__(self) -> None:
        object.__setattr__(self, "memory_type", MemoryType(self.memory_type))
        object.__setattr__(self, "sensitivity", MemorySensitivity(self.sensitivity))
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be between 0.0 and 1.0")
        if self.ttl is not None and self.ttl < 0:
            raise ValueError("ttl must be non-negative")
        if self.sensitivity is MemorySensitivity.SECRET and self.memory_type is not MemoryType.SECRET_REF:
            raise SecretBoundaryViolation(
                "Secret values must not be stored in memory; store a secret reference instead"
            )

    @property
    def expires_at(self) -> float | None:
        return None if self.ttl is None else self.created_at + self.ttl

    def is_expired(self, now: float | None = None) -> bool:
        expires_at = self.expires_at
        return expires_at is not None and (now if now is not None else time.time()) >= expires_at

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["memory_type"] = self.memory_type.value
        data["sensitivity"] = self.sensitivity.value
        data["expires_at"] = self.expires_at
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> MemoryRecord:
        payload = dict(data)
        payload.pop("expires_at", None)
        return cls(**payload)


class MemoryStore:
    """Small persistent memory store with explicit confidence and provenance.

    Uses an index dict (key → list of MemoryRecord) so recall() is O(1)
    key lookup instead of O(n) full scan.
    """

    def __init__(self, path: Path | None = None) -> None:
        self.path = path
        self._index: dict[str, list[MemoryRecord]] = {}
        self.items: list[MemoryRecord] = []
        if path and path.exists():
            self.items = [MemoryRecord.from_dict(item) for item in json.loads(path.read_text(encoding="utf-8"))]
            for item in self.items:
                self._index.setdefault(item.key, []).append(item)

    def remember(
        self,
        key: str,
        value: Any,
        *,
        confidence: float,
        provenance: str,
        memory_type: MemoryType = MemoryType.FACT,
        sensitivity: MemorySensitivity = MemorySensitivity.INTERNAL,
        scope: str = "global",
        source: str | None = None,
        ttl: float | None = None,
        last_verified_at: float | None = None,
        conflicts_with: Sequence[str] = (),
        supersedes: Sequence[str] = (),
        embedding_id: str | None = None,
        access_policy: str | None = None,
        forget_policy: str | None = None,
    ) -> MemoryRecord:
        record = MemoryRecord(
            key=key,
            value=value,
            confidence=confidence,
            provenance=provenance,
            memory_type=memory_type,
            sensitivity=sensitivity,
            scope=scope,
            source=source,
            ttl=ttl,
            last_verified_at=last_verified_at,
            conflicts_with=tuple(conflicts_with),
            supersedes=tuple(supersedes),
            embedding_id=embedding_id,
            access_policy=access_policy,
            forget_policy=forget_policy,
        )
        self.items.append(record)
        self._index.setdefault(key, []).append(record)
        self._persist()
        return record

    def recall(
        self,
        key: str,
        *,
        include_expired: bool = False,
        scope: str | None = None,
        memory_type: MemoryType | None = None,
    ) -> list[dict[str, Any]]:
        now = time.time()
        candidates = self._index.get(key, ())
        target_type = MemoryType(memory_type) if memory_type is not None else None
        records = []
        for item in candidates:
            if scope is not None and item.scope != scope:
                continue
            if target_type is not None and item.memory_type is not target_type:
                continue
            if not include_expired and item.is_expired(now):
                continue
            records.append(item.to_dict())
        return records

    def purge_expired(self, *, now: float | None = None) -> int:
        before = len(self.items)
        self.items = [item for item in self.items if not item.is_expired(now)]
        # Rebuild index
        self._index = {}
        for item in self.items:
            self._index.setdefault(item.key, []).append(item)
        removed = before - len(self.items)
        if removed:
            self._persist()
        return removed

    def _persist(self) -> None:
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(
                json.dumps([item.to_dict() for item in self.items], indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
