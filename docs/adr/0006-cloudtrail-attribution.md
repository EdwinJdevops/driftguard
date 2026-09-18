# ADR 0006: Service-specific CloudTrail attribution with refusal states

Status: Accepted for the first attribution adapter.

## Context

CloudTrail Event History can be queried with `LookupEvents` for management
events in one region from the previous 90 days. AWS currently permits one
lookup attribute per request, returns at most 50 events per page, and limits
lookup requests to two per second per account per region.

The real SSM proof showed why a generic "latest event wins" rule is unsafe:
creating a parameter and mutating it both emit `PutParameter`. Earlier runs
contained two events for the same parameter within seconds.

Terraform resource addresses also cannot be matched directly to CloudTrail.
Evidence Bundle v1.1 therefore carries a conservative cloud locator before
attribution is attempted.

## Decision

Attribution is an optional enrichment stage. It does not participate in drift
truth and it does not run inside lifecycle database transactions.

The first adapter supports only:

- provider: canonical HashiCorp AWS provider;
- resource: `aws_ssm_parameter`;
- drift surface: findings that include `/value`.

The adapter queries CloudTrail by `EventName=PutParameter` inside a caller-
supplied, timezone-aware window, exhausts pagination, and then filters locally.

A candidate must satisfy all of:

- event source is `ssm.amazonaws.com`;
- event name is `PutParameter`;
- `requestParameters.name` exactly equals the evidence locator name/ID;
- `requestParameters.overwrite` is exactly `true`;
- event time is inside the bounded window.

`overwrite=false` is treated as creation and is not accepted as the mutation
source for this contract.

## Outcome states

- `attributed`: exactly one audit event matches the contract.
- `not_found`: no event matches.
- `ambiguous`: multiple events match; DriftGuard refuses to choose.
- `unsupported`: no explicit adapter/locator/changed-path contract exists.
- `error`: lookup or event interpretation could not be completed safely.

An `attributed` result means a unique matching audit event exists. It does not
claim to prove human intent or broader business causality.

## Data minimization

CloudTrail event JSON is parsed only in memory because request parameters may
contain sensitive resource values. The result retains only event ID, event name,
time, event source and actor session label. Raw event JSON and request
parameters are never returned or persisted by this adapter.

## Window ownership

The adapter requires explicit `start_time` and `end_time`; it does not invent
a global lookback. The future orchestrator should derive the narrowest justified
window from observation history (ideally the last known clean complete
observation through the current observation) and may widen only deliberately.

## Non-goals

This ADR does not generalize attribution to other AWS resource types. EC2, IAM,
RDS, S3 and other services require explicit service-specific event contracts.
It also does not persist attribution yet.

## Verification

Unit tests must prove exact-name matching, create-vs-mutate separation,
ambiguity refusal, pagination, malformed-event failure, data minimization and
unsupported-path refusal. A separate real-AWS proof is required before the SSM
adapter can be called verified.
