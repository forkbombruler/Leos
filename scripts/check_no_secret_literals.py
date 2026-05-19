#!/usr/bin/env python3
"""Scan generated text artifacts for test secret literals."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from pathlib import Path

IGNORED_DIRS = {".git", ".venv", "dist", "build", "__pycache__"}
SCANNED_SUFFIXES = {".jsonl", ".json", ".md", ".html"}
PATTERNS = {
    "github-classic-token": "ghp_",
    "github-fine-grained-token": "github_pat_",
    "openai-token": "sk-",
    "demo-secret": "demo-secret-value",
    "token-value": "token-value",
    "must-not-store": "must-not-store",
    "must-not-leak": "must-not-leak",
}


def scan(root: Path) -> list[tuple[Path, str]]:
    findings: list[tuple[Path, str]] = []
    for path in root.rglob("*"):
        if any(part in IGNORED_DIRS for part in path.parts):
            continue
        if not path.is_file() or path.suffix not in SCANNED_SUFFIXES:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for label, pattern in PATTERNS.items():
            if pattern in text:
                findings.append((path, label))
    return findings


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=".", help="Repository or artifact directory to scan")
    args = parser.parse_args(argv)

    root = Path(args.root).resolve()
    findings = scan(root)
    for path, label in findings:
        print(f"{path.relative_to(root)}: pattern={label}")
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
