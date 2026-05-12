"""Simulation environments for safe agent-level evaluation."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class FakeFileSystem:
    files: dict[str, str] = field(default_factory=dict)

    def write(self, path: str, content: str) -> None:
        self.files[path] = content

    def read(self, path: str) -> str:
        if path not in self.files:
            raise FileNotFoundError(path)
        return self.files[path]

    def exists(self, path: str) -> bool:
        return path in self.files


@dataclass
class FakeBrowser:
    pages: dict[str, str] = field(default_factory=dict)

    def fetch(self, url: str) -> dict[str, Any]:
        return {"url": url, "content": self.pages.get(url, ""), "trust_level": "untrusted_external"}


@dataclass
class FakeEmailServer:
    sent: list[dict[str, str]] = field(default_factory=list)

    def send(self, to: str, subject: str, body: str) -> str:
        message_id = f"msg-{len(self.sent) + 1}"
        self.sent.append({"id": message_id, "to": to, "subject": subject, "body": body})
        return message_id


@dataclass
class FakeCalendar:
    events: list[dict[str, str]] = field(default_factory=list)

    def create_event(self, title: str, starts_at: str) -> str:
        event_id = f"event-{len(self.events) + 1}"
        self.events.append({"id": event_id, "title": title, "starts_at": starts_at})
        return event_id


@dataclass
class FakePaymentSystem:
    payments: list[dict[str, Any]] = field(default_factory=list)

    def pay(self, recipient: str, amount: float, *, idempotency_key: str) -> str:
        for payment in self.payments:
            if payment["idempotency_key"] == idempotency_key:
                return str(payment["id"])
        payment_id = f"payment-{len(self.payments) + 1}"
        self.payments.append(
            {"id": payment_id, "recipient": recipient, "amount": amount, "idempotency_key": idempotency_key}
        )
        return payment_id


@dataclass
class FakeShell:
    commands: list[list[str]] = field(default_factory=list)

    def run(self, argv: list[str]) -> dict[str, Any]:
        self.commands.append(list(argv))
        return {"ok": True, "returncode": 0, "stdout": "", "stderr": ""}


@dataclass
class FakeGitHubRepo:
    issues: list[dict[str, str]] = field(default_factory=list)

    def create_issue(self, title: str, body: str) -> int:
        number = len(self.issues) + 1
        self.issues.append({"number": str(number), "title": title, "body": body})
        return number


@dataclass
class SimulationEnvironment:
    filesystem: FakeFileSystem = field(default_factory=FakeFileSystem)
    browser: FakeBrowser = field(default_factory=FakeBrowser)
    email: FakeEmailServer = field(default_factory=FakeEmailServer)
    calendar: FakeCalendar = field(default_factory=FakeCalendar)
    payments: FakePaymentSystem = field(default_factory=FakePaymentSystem)
    shell: FakeShell = field(default_factory=FakeShell)
    github: FakeGitHubRepo = field(default_factory=FakeGitHubRepo)
