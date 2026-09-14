# Provider-native drift contract validation — 2026-09-14

## Purpose

This validation establishes whether DriftGuard Evidence Core v1 can consume
**real provider-refreshed drift output** from both Terraform and OpenTofu
without reconstructing resource identity, manufacturing drift, or persisting
raw infrastructure values.

This is a semantic contract test, not an AWS integration test.

## Tested revision

- DriftGuard branch: `feat/evidence-core-v1`
- DriftGuard commit: `73dbb4c396eacf30d2f593a902062df67dddee5b`
- GitHub Actions run: `34838882930`
- Result: all six CI jobs passed

## Toolchain

The contract jobs use pinned production releases rather than prereleases:

- Terraform `1.16.2`
- OpenTofu `1.12.6`
- `hashicorp/local` provider `2.9.0`
- Python `3.12`

GitHub Actions are referenced by immutable commit SHA and the workflow token is
restricted to `contents: read`.

## Fixture topology

The fixture uses a nested module so DriftGuard must preserve absolute resource
identity rather than derive it from type/name fields.

```text
module.files
├── local_file.counted[0]
├── local_file.counted[1]
├── local_file.keyed["blue"]
├── local_file.keyed["green"]
└── local_sensitive_file.secret
```

After `apply`, the test performs three changes outside IaC:

1. overwrites `counted-1.txt`,
2. deletes `keyed-green.txt`,
3. overwrites `secret.txt` with a sensitive sentinel value.

The sibling instances `counted[0]` and `keyed["blue"]` are deliberately left
untouched and act as negative controls.

## Execution boundary

For each engine the harness performs:

```text
init
  → apply
  → out-of-band mutation
  → plan -detailed-exitcode -out=drift.plan
  → show -json drift.plan
  → DriftGuard analyze_plan_json(...)
```

The raw `show -json` document remains only in an ephemeral CI temp directory.
It is never printed, committed, cached as a DriftGuard artifact, or uploaded to
the DriftGuard API. The temp directory is removed on exit.

This boundary is intentional because plan JSON may contain sensitive values in
plaintext.

## Observed Terraform result

Terraform `1.16.2` produced `format_version = 1.2` and exactly three managed
`resource_drift` entries:

| Address | Action | DriftGuard changed path | Sensitive paths retained |
|---|---|---|---|
| `module.files.local_file.counted[1]` | `delete` | root (`""`) | `/sensitive_content` |
| `module.files.local_file.keyed["green"]` | `delete` | root (`""`) | `/sensitive_content` |
| `module.files.local_sensitive_file.secret` | `delete` | root (`""`) | `/content`, `/content_base64` |

The local provider reports an externally modified/deleted managed file as a
remote deletion and a subsequent configuration-driven recreation. DriftGuard
preserves the provider-native `resource_drift` action instead of inventing its
own cloud-state classification.

## Observed OpenTofu result

OpenTofu `1.12.6` also produced `format_version = 1.2` and the same three
managed drift addresses, actions, changed-path roots, and sensitivity paths.

For this fixture, Terraform and OpenTofu therefore exposed equivalent
`resource_drift` semantics to DriftGuard.

This is evidence for compatibility of this contract surface, not a claim that
all future Terraform/OpenTofu plan formats or providers are identical.

## Assertions proven by CI

The verifier fails unless all of the following hold:

1. Evidence Bundle addresses exactly equal the managed addresses emitted by
   the engine's own `resource_drift` collection.
2. `module.files.local_file.counted[1]` preserves integer index `1`.
3. `module.files.local_file.keyed["green"]` preserves string index `green`.
4. Both preserve module address `module.files`.
5. Untouched `counted[0]` and `keyed["blue"]` are absent from drift evidence.
6. Sensitive-path metadata survives conversion into Evidence Bundle v1.
7. Known raw sentinel values are absent from serialized DriftGuard evidence.
8. The plan command must return detailed-exitcode `2`; a clean or failed plan
   cannot silently pass this contract test.

## What this validation does NOT prove

This run does not prove:

- AWS provider drift behavior,
- AWS API/STS behavior in a real account,
- CloudTrail attribution,
- source-code mapping for remediation,
- safe cloud-to-code rewriting,
- cost enrichment,
- finding lifecycle/deduplication,
- durable worker execution,
- multi-account scale or load behavior.

Those remain separate gates. Passing this contract is necessary but not
sufficient for production readiness.

## Result

**PASS.** Evidence Core v1 has now been validated against provider-generated
Terraform and OpenTofu drift, including nested-module identity, `count`,
`for_each`, negative-control sibling instances, and sensitivity metadata.

The next product gate is a local, redacted analysis interface. The legacy
state-vs-partial-AWS-collector path remains active and must not be described as
the production-grade detector until a controlled migration is complete.
