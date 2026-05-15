#!/usr/bin/env python3
"""Generate Leos proof documents."""

from __future__ import annotations

import argparse
from pathlib import Path

from leos_agent.proof import exit_code_for_manifest, generate_proofs


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate Leos proof documents.")
    parser.add_argument("--output", default="docs/proofs", help="Output directory.")
    parser.add_argument("--require-clean", action="store_true", help="Fail if the Git worktree is dirty.")
    parser.add_argument(
        "--allow-dirty",
        action="store_true",
        help="Allow dirty worktree proofs as local review evidence.",
    )
    parser.add_argument("--no-run", action="store_true", help="Skip commands and render docs from metadata only.")
    args = parser.parse_args()
    manifest = generate_proofs(
        Path(args.output),
        require_clean=args.require_clean,
        allow_dirty=args.allow_dirty,
        no_run=args.no_run,
    )
    print(f"proof_status={manifest.proof_status} release_grade={manifest.release_grade}")
    return exit_code_for_manifest(manifest)


if __name__ == "__main__":
    raise SystemExit(main())
