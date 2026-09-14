#!/usr/bin/env python3
"""Verify DriftGuard against a provider-generated Terraform/OpenTofu drift plan.

This script intentionally inspects only structural expectations and the
redacted Evidence Bundle. Raw plan values stay inside the ephemeral CI worker.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from backend.evidence import analyze_plan_json  # noqa: E402

EXPECTED_DRIFT = {
    'module.files.local_file.counted[1]',
    'module.files.local_file.keyed["green"]',
    "module.files.local_sensitive_file.secret",
}

EXPECTED_UNCHANGED = {
    "module.files.local_file.counted[0]",
    'module.files.local_file.keyed["blue"]',
}

SENTINEL_VALUES = {
    "driftguard-fixture-secret-v1",
    "driftguard-fixture-secret-tampered",
    "tampered-count-1",
}


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("plan_json", type=Path)
    parser.add_argument("--engine", choices=("terraform", "opentofu"), required=True)
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    plan = json.loads(args.plan_json.read_text())
    bundle = analyze_plan_json(plan, iac_engine=args.engine)

    raw_managed_addresses = {
        entry["address"]
        for entry in plan.get("resource_drift", [])
        if entry.get("mode") == "managed"
    }
    evidence_addresses = {finding.resource_address for finding in bundle.findings}

    if evidence_addresses != raw_managed_addresses:
        raise SystemExit(
            "Evidence addresses diverged from provider-native resource_drift addresses: "
            f"raw={sorted(raw_managed_addresses)!r} evidence={sorted(evidence_addresses)!r}"
        )

    missing = EXPECTED_DRIFT - evidence_addresses
    if missing:
        raise SystemExit(f"Provider fixture did not produce the required drift addresses: {sorted(missing)!r}")

    unexpected = EXPECTED_UNCHANGED & evidence_addresses
    if unexpected:
        raise SystemExit(f"Unmodified resources were reported as drift: {sorted(unexpected)!r}")

    by_address = {finding.resource_address: finding for finding in bundle.findings}

    counted = by_address['module.files.local_file.counted[1]']
    if counted.module_address != "module.files" or counted.resource_index != 1:
        raise SystemExit("Counted-resource identity was not preserved exactly.")

    keyed = by_address['module.files.local_file.keyed["green"]']
    if keyed.module_address != "module.files" or keyed.resource_index != "green":
        raise SystemExit("for_each resource identity was not preserved exactly.")

    secret = by_address["module.files.local_sensitive_file.secret"]
    if not secret.sensitive_paths:
        raise SystemExit("Provider-generated sensitive-value metadata was lost from the evidence bundle.")

    serialized = bundle.model_dump_json()
    leaked = sorted(value for value in SENTINEL_VALUES if value in serialized)
    if leaked:
        raise SystemExit(f"Raw fixture values leaked into redacted evidence: {leaked!r}")

    summary = {
        "engine": bundle.iac_engine,
        "engine_version": bundle.iac_engine_version,
        "source_format_version": bundle.source_format_version,
        "finding_count": bundle.finding_count,
        "findings": [
            {
                "address": finding.resource_address,
                "actions": finding.actions,
                "changed_paths": finding.changed_paths,
                "sensitive_paths": finding.sensitive_paths,
            }
            for finding in bundle.findings
        ],
    }
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
