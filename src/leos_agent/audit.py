"""Append-only audit log with hash-chain integrity checks."""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from .errors import VerificationFailed
from .tools import ToolResult


@dataclass(frozen=True)
class AuditEvent:
    event_type: str
    message: str
    payload: dict[str, Any]
    sequence: int = 0
    previous_hash: str = ""
    event_hash: str = ""
    created_at: float = field(default_factory=time.time)
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))


class AuditLog:
    """Append-only JSONL audit log."""

    GENESIS_HASH = "0" * 64

    def __init__(self, path: Path | None = None) -> None:
        self.path = path
        self.events: list[AuditEvent] = []
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)

    def record(self, event_type: str, message: str, **payload: Any) -> AuditEvent:
        previous_hash = self.events[-1].event_hash if self.events else self.GENESIS_HASH
        event = AuditEvent(
            event_type=event_type,
            message=message,
            payload=payload,
            sequence=len(self.events) + 1,
            previous_hash=previous_hash,
        )
        object.__setattr__(event, "event_hash", self._hash_event_record(asdict(event)))
        self.events.append(event)
        if self.path:
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(asdict(event), ensure_ascii=False, default=str) + "\n")
        return event

    def verify_integrity(self) -> ToolResult:
        return self.verify_event_records(self.records())

    def records(self) -> list[dict[str, Any]]:
        return self._records_from_path() if self.path else [asdict(event) for event in self.events]

    @classmethod
    def verify_event_records(cls, records: Sequence[Mapping[str, Any]]) -> ToolResult:
        issues = []
        expected_sequence = 1
        expected_previous_hash = cls.GENESIS_HASH
        for index, record in enumerate(records):
            sequence = record.get("sequence")
            previous_hash = record.get("previous_hash")
            event_hash = record.get("event_hash")
            computed_hash = cls._hash_event_record(record)
            if sequence != expected_sequence:
                issues.append(
                    {
                        "index": index,
                        "reason": "sequence_mismatch",
                        "expected": expected_sequence,
                        "observed": sequence,
                    }
                )
            if previous_hash != expected_previous_hash:
                issues.append(
                    {
                        "index": index,
                        "reason": "previous_hash_mismatch",
                        "expected": expected_previous_hash,
                        "observed": previous_hash,
                    }
                )
            if event_hash != computed_hash:
                issues.append(
                    {
                        "index": index,
                        "reason": "event_hash_mismatch",
                        "expected": computed_hash,
                        "observed": event_hash,
                    }
                )
            expected_sequence += 1
            expected_previous_hash = str(event_hash or "")
        if issues:
            return ToolResult(
                False,
                "Audit integrity verification failed",
                {"issues": issues},
                error=VerificationFailed("Audit integrity verification failed"),
            )
        return ToolResult(True, "Audit integrity verification passed")

    def _records_from_path(self) -> list[dict[str, Any]]:
        if not self.path or not self.path.exists():
            return []
        records = []
        with self.path.open("r", encoding="utf-8") as handle:
            for line in handle:
                if line.strip():
                    records.append(json.loads(line))
        return records

    @staticmethod
    def _hash_event_record(record: Mapping[str, Any]) -> str:
        hashable = {key: value for key, value in record.items() if key != "event_hash"}
        encoded = json.dumps(hashable, ensure_ascii=False, sort_keys=True, default=str, separators=(",", ":")).encode(
            "utf-8"
        )
        return hashlib.sha256(encoded).hexdigest()


class AnomalyFinding:
    def __init__(self, rule: str, severity: str, message: str, evidence: dict[str, Any]) -> None:
        self.rule = rule
        self.severity = severity
        self.message = message
        self.evidence = evidence


class AuditAnomalyDetector:
    def __init__(self, burst_window_seconds: float = 60.0, burst_threshold: int = 5) -> None:
        self.burst_window = burst_window_seconds
        self.burst_threshold = burst_threshold

    def detect(self, events: list[dict[str, Any]]) -> list[AnomalyFinding]:
        findings: list[AnomalyFinding] = []
        findings.extend(self._burst_check(events))
        findings.extend(self._rollback_loop_check(events))
        findings.extend(self._frequency_check(events))
        return findings

    def _burst_check(self, events: list[dict[str, Any]]) -> list[AnomalyFinding]:
        if len(events) < self.burst_threshold:
            return []
        fail_types = {"step.execution_failed", "step.blocked", "step.dry_run_failed"}
        failures: list[float] = []
        for e in events:
            if e.get("event_type") in fail_types:
                failures.append(float(e.get("created_at", 0)))
        if len(failures) < self.burst_threshold:
            return []
        failures.sort()
        for i in range(len(failures) - self.burst_threshold + 1):
            window = failures[i + self.burst_threshold - 1] - failures[i]
            if 0 < window <= self.burst_window:
                return [
                    AnomalyFinding(
                        rule="burst",
                        severity="high",
                        message=f"Burst of {self.burst_threshold} failures in {window:.1f}s",
                        evidence={"failure_count": len(failures), "window_seconds": window},
                    )
                ]
        return []

    def _rollback_loop_check(self, events: list[dict[str, Any]]) -> list[AnomalyFinding]:
        rollbacks = [e for e in events if e.get("event_type") == "rollback_attempted"]
        if len(rollbacks) < 3:
            return []
        tool_counts: dict[str, int] = {}
        for e in rollbacks:
            tool = str(e.get("payload", {}).get("tool", ""))
            tool_counts[tool] = tool_counts.get(tool, 0) + 1
        for tool, count in tool_counts.items():
            if count >= 3 and tool:
                return [
                    AnomalyFinding(
                        rule="rollback_loop",
                        severity="high",
                        message=f"Tool '{tool}' triggered {count} rollbacks",
                        evidence={"tool": tool, "rollback_count": count},
                    )
                ]
        return []

    def _frequency_check(self, events: list[dict[str, Any]]) -> list[AnomalyFinding]:
        if not events:
            return []
        findings: list[AnomalyFinding] = []
        blocked = sum(1 for e in events if e.get("event_type") == "step.blocked")
        total = len(events)
        if total >= 10 and blocked / total > 0.5:
            findings.append(
                AnomalyFinding(
                    rule="frequency",
                    severity="medium",
                    message=f"High block rate: {blocked}/{total} ({blocked / total:.0%})",
                    evidence={"blocked": blocked, "total": total},
                )
            )
        fail_count = sum(
            1
            for e in events
            if e.get("event_type") in {"step.execution_failed", "step.dry_run_failed", "step.verification_failed"}
        )
        if total >= 10 and fail_count / total > 0.5:
            findings.append(
                AnomalyFinding(
                    rule="frequency",
                    severity="high",
                    message=f"High failure rate: {fail_count}/{total} ({fail_count / total:.0%})",
                    evidence={"failures": fail_count, "total": total},
                )
            )
        return findings
