#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 <terraform|opentofu> <terraform|tofu binary>" >&2
  exit 64
fi

engine_name="$1"
iac_bin="$2"

if [[ "$engine_name" != "terraform" && "$engine_name" != "opentofu" ]]; then
  echo "unsupported engine name: $engine_name" >&2
  exit 64
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fixture_root="$repo_root/tests/iac/provider-drift"
work_dir="$(mktemp -d)"

cleanup() {
  rm -rf "$work_dir"
}
trap cleanup EXIT

cp -R "$fixture_root/." "$work_dir/"
mkdir -p "$work_dir/runtime"

cd "$work_dir"

"$iac_bin" init -input=false -no-color >init.stdout 2>init.stderr || {
  cat init.stderr >&2
  exit 1
}

"$iac_bin" apply -auto-approve -input=false -no-color >apply.stdout 2>apply.stderr || {
  cat apply.stderr >&2
  exit 1
}

# Create three independent out-of-band changes while leaving two sibling
# instances untouched. This exercises module, count, for_each and sensitive
# resource identity using a real provider refresh.
printf '%s\n' 'tampered-count-1' >runtime/counted-1.txt
rm runtime/keyed-green.txt
printf '%s\n' 'driftguard-fixture-secret-tampered' >runtime/secret.txt

set +e
"$iac_bin" plan \
  -input=false \
  -no-color \
  -detailed-exitcode \
  -out=drift.plan \
  >plan.stdout 2>plan.stderr
plan_rc=$?
set -e

if [[ $plan_rc -ne 2 ]]; then
  echo "expected provider-native drift plan exit code 2, got $plan_rc" >&2
  cat plan.stderr >&2
  exit 1
fi

# `show -json` may contain sensitive values in plaintext. Keep it only in the
# ephemeral work directory; never print it or upload it as a CI artifact.
"$iac_bin" show -json drift.plan >drift.json

cd "$repo_root"
PYTHONPATH="$repo_root" python scripts/verify_provider_drift_contract.py \
  "$work_dir/drift.json" \
  --engine "$engine_name"
