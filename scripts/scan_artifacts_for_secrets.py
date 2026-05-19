#!/usr/bin/env python3
"""Scan repository artifacts for secret-like literals."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.check_no_secret_literals import main

if __name__ == "__main__":
    raise SystemExit(main())
