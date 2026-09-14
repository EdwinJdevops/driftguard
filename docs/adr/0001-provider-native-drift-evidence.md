# ADR 0001: Provider-native drift evidence core

- Status: Accepted
- Date: 2026-09-14
- Scope: Drift detection semantics, evidence boundary, remediation preconditions

## Context

DriftGuard's legacy detector parses `terraform.tfstate`, collects a selected
subset of AWS attributes with handwritten boto3 collectors, then performs a
generic dictionary comparison. That design has two correctness failures that
make it unsuitable as the long-term production truth engine:

1. A Terraform-managed resource type that is not collected can be interpreted
   as deleted because absence from the live collector map is treated as proof
   of remote absence.
2. For supported resource types, Terraform state can contain many attributes
   that a partial collector never observes. Generic union-of-keys comparison
   can therefore interpret an unobserved attribute as `actual=None` drift.

The legacy parser also does not preserve Terraform's full absolute resource
identity across module paths and `count`/`for_each` instances.

Terraform and OpenTofu already perform provider-native refresh and expose
external changes in machine-readable plan JSON as `resource_drift`. Their JSON
formats preserve absolute resource addresses, module addresses, instance
indexes, provider identity, change actions and sensitivity metadata.

Authoritative references:

- Terraform JSON output format: https://developer.hashicorp.com/terraform/internals/json-format
- Terraform `show -json`: https://developer.hashicorp.com/terraform/cli/commands/show
- OpenTofu JSON output format: https://opentofu.org/docs/internals/json-format/

## Decision

DriftGuard will treat Terraform/OpenTofu plan JSON `resource_drift` as the
source of drift semantics.

Handwritten AWS collectors will no longer determine whether Terraform-managed
resources drifted. Cloud APIs remain useful as optional enrichment sources for
attribution, security context, cost context and independent evidence, but an
enrichment failure cannot manufacture a drift finding or a deletion.

The first production-facing core primitive is a versioned **Evidence Bundle**.
It contains resource identity, change actions, changed paths, sensitivity
paths, plan-format metadata and IaC-engine metadata. It deliberately omits raw
`before` and `after` values.

## Security boundary

`terraform show -json` may expose sensitive state/plan values in plaintext.
Therefore raw plan JSON is treated as sensitive execution-boundary data.

Evidence-core v1 follows these invariants:

1. Raw `before` and `after` values are never copied into the Evidence Bundle.
2. Changed locations are represented only as RFC 6901 JSON-pointer paths.
3. Terraform/OpenTofu sensitivity masks are preserved as path metadata, never
   as raw sensitive values.
4. An errored plan is rejected rather than converted into apparently complete
   evidence.
5. Unknown major JSON-format versions are rejected. Unknown minor fields are
   ignored for forward compatibility within major format v1.
6. Absolute resource addresses are opaque identifiers and are never rebuilt
   from `type`, `name`, module or index components.

## Initial Evidence Bundle v1 contract

Top level:

- `schema_version`: `1.0`
- `iac_engine`: `terraform`, `opentofu`, or `unknown`
- `iac_engine_version`: version reported by the input plan when available
- `source_format_version`: Terraform/OpenTofu JSON format version
- `plan_timestamp`: observation timestamp when present
- `redaction_policy`: `omit_change_values`
- `findings`: zero or more drift-evidence records
- `skipped_nonmanaged`: number of non-managed entries intentionally skipped

Each finding contains:

- exact `resource_address`
- optional exact `module_address`
- `resource_type`, `resource_name`, optional `resource_index`
- optional `provider_name`
- provider-native change `actions`
- `changed_paths` as JSON pointers
- `sensitive_paths` as JSON pointers

No raw infrastructure values are part of this schema.

## Failure semantics

Evidence generation fails closed when:

- the input is not plan JSON,
- `format_version` is missing or has an unsupported major version,
- the plan reports `errored=true`,
- a `resource_drift` entry is structurally malformed,
- a sensitivity mask has an unsupported shape.

A failure to adjudicate is not converted to "no drift".

## Remediation contract

No remediation engine may treat an Evidence Bundle as permission to mutate
infrastructure.

Future remediation paths are intentionally separate:

- **REVERT_CLOUD_TO_CODE**: prove with a fresh provider-native plan that the
  existing configuration would remove the target drift without unrelated
  changes.
- **ACCEPT_CLOUD_INTO_CODE**: edit source only when source mapping is
  unambiguous; then require format, validate and a fresh plan proving that the
  target drift disappears without unintended changes.

Ambiguous cases must return an explicit non-automatable state rather than a
guessed patch.

## Rejected alternatives

### Expand handwritten AWS collectors

Rejected. It creates an endless parity race against provider schemas and still
requires DriftGuard to recreate Terraform semantics for computed values,
provider defaults, modules, aliases, nested blocks and lifecycle behavior.

### Continue comparing raw Terraform state to cloud dictionaries

Rejected for the correctness failures described above. State is an input to
Terraform's reconciliation model, not a sufficient standalone desired-state
specification for a generic external diff engine.

### Persist complete plan JSON in DriftGuard SaaS

Rejected as the default architecture because plan/state JSON may contain
plaintext secrets. Local-first redaction is the required direction.

### Auto-apply remediation

Rejected for the initial production architecture. DriftGuard will produce
reviewable and independently validated evidence/remediation artifacts; human
approval remains the execution boundary.

## Migration sequence

1. Stabilize current CI and security P0s.
2. Introduce Evidence Bundle v1 and plan-JSON analyzer behind tests.
3. Add real Terraform/OpenTofu-generated fixture plans for modules, `count`,
   `for_each`, deletions, updates, sensitive values and partial failures.
4. Add a local CLI entry point that analyzes an existing plan JSON without
   uploading raw state/plan values.
5. Introduce finding lifecycle identity and deduplication on evidence records.
6. Add optional CloudTrail/security/cost enrichers that cannot change the
   provider-native drift verdict.
7. Replace the legacy collector-based scan path only after equivalence and
   adversarial tests pass.
8. Build remediation validation after detection correctness is proven.

## Release gate

The legacy detector must not be presented as production-grade while it remains
the authoritative scan path. The evidence core becomes eligible to replace it
only after real provider-generated fixtures prove correct behavior for modules,
`count`, `for_each`, sensitive paths, resource deletion, provider failure and
unsupported/unknown input states.
