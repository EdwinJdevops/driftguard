# ADR 0005: Carry only conservative cloud resource locators in evidence

Status: Accepted for Evidence Bundle v1.1.

## Context

Provider-native drift identity and CloudTrail attribution solve different
identity problems.

Terraform/OpenTofu absolute resource addresses identify the IaC object. AWS
audit APIs identify cloud resources using ARNs, provider IDs, names, regions and
service-specific request fields. Correlating the two without a cloud locator
would require guessing from Terraform block names or re-uploading raw plan
state, both of which are unacceptable.

Raw provider state can contain secrets and arbitrary customer data, so copying
whole resource objects into Evidence Bundles is also unacceptable.

## Decision

Evidence Bundle v1.1 adds an optional `cloud_locator` to each drift finding.

For the AWS provider the local analyzer may extract only these top-level fields:

- `arn`
- `id`
- `name`
- `region`

The locator is emitted only when at least one of ARN, ID or name is available.
Any candidate path marked sensitive or unknown by Terraform/OpenTofu is omitted.
If the whole resource is masked sensitive/unknown, no locator is emitted.

The extractor recognizes only the canonical HashiCorp AWS provider name. Other
providers remain unsupported until they receive an explicit locator contract.

This is infrastructure identity metadata, not arbitrary resource state.
`before`/`after` objects are still excluded from the Evidence Bundle.

## Compatibility

The ingestion model accepts Evidence Bundle schema versions `1.0` and `1.1`.
The local analyzer emits `1.1`. Existing v1.0 submissions remain valid.

## Non-goals

This ADR does not define CloudTrail event attribution itself. It only provides
the minimum non-sensitive locator required for a later attribution stage.

It does not claim that ARN/ID/name semantics are sufficient for every AWS
resource type. Service-specific attribution remains an explicit adapter
responsibility and unsupported resources must remain unsupported rather than
using heuristic matching.

## Verification

Unit tests prove that safe identity fields are retained while sensitive identity
fields are omitted. The real AWS SSM proof additionally requires the emitted
locator to match the actual parameter name, ID, region and ARN while raw
parameter values remain absent from evidence.
