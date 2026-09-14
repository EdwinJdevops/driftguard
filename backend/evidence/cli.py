from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from pydantic import ValidationError

from .models import IaCEngine
from .terraform_plan import PlanEvidenceError, analyze_plan_json


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m backend.evidence",
        description=(
            "Analyze Terraform/OpenTofu plan JSON locally and emit a redacted "
            "DriftGuard Evidence Bundle. Raw before/after values are never emitted."
        ),
    )
    parser.add_argument("plan_json", type=Path, help="Path produced by `terraform show -json` or `tofu show -json`.")
    parser.add_argument(
        "--engine",
        choices=("terraform", "opentofu", "unknown"),
        default="unknown",
        help="IaC engine that produced the plan JSON.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Write the redacted Evidence Bundle to this file instead of stdout.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)

    try:
        raw = args.plan_json.read_text(encoding="utf-8")
    except OSError as exc:
        print(f"error: could not read plan JSON: {exc}", file=sys.stderr)
        return 2

    try:
        plan = json.loads(raw)
    except json.JSONDecodeError as exc:
        print(
            f"error: invalid JSON at line {exc.lineno}, column {exc.colno}",
            file=sys.stderr,
        )
        return 2

    try:
        bundle = analyze_plan_json(plan, iac_engine=args.engine)
    except (PlanEvidenceError, ValidationError) as exc:
        print(f"error: plan cannot be adjudicated: {exc}", file=sys.stderr)
        return 2

    serialized = bundle.model_dump_json(indent=2) + "\n"

    if args.output is None:
        sys.stdout.write(serialized)
        return 0

    try:
        args.output.write_text(serialized, encoding="utf-8")
    except OSError as exc:
        print(f"error: could not write evidence output: {exc}", file=sys.stderr)
        return 2

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
