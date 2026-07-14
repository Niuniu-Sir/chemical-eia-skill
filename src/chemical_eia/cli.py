"""Installed command-line interface for the chemical EIA pipeline."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .pipeline import run_pipeline


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="chemical-eia",
        description="Run the deterministic chemical EIA process pipeline.",
    )
    parser.add_argument("model", help="Path to the project model YAML/JSON file.")
    parser.add_argument(
        "--output-dir",
        required=True,
        help="Directory where the four output artifacts will be written.",
    )
    parser.add_argument(
        "--decisions",
        default=None,
        help="Optional path to an expert decisions JSON/YAML file.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run the installed CLI and return a process exit code.

    Exit codes:
    - 0: pipeline completed and four artifact paths were printed.
    - 1: the requested model file does not exist.
    - 2: argument parsing or pipeline execution failed.
    """
    args = _build_parser().parse_args(argv)
    model_path = Path(args.model)

    if not model_path.is_file():
        print(f"model file not found: {model_path}", file=sys.stderr)
        return 1

    try:
        artifacts = run_pipeline(
            model_path=model_path,
            output_dir=Path(args.output_dir),
            decisions_path=(Path(args.decisions) if args.decisions else None),
        )
    except (ValueError, OSError, KeyError, TypeError) as exc:
        print(f"chemical-eia failed: {exc}", file=sys.stderr)
        return 2

    for key in (
        "project_model",
        "process_flow",
        "diagnostic_balance",
        "review_report",
    ):
        print(f"{key}={Path(artifacts[key]).resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
