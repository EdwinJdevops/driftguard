# ADR 0002: Evidence finding identity and lifecycle

- Status: Accepted
- Date: 2026-09-14
- Scope: incident identity, recurrence, resolution, replay safety, remediation deduplication

## Context

The legacy `drift_findings` table stores one row per finding per scan. A new UUID
is generated every time the same drift is observed. GitHub remediation branches
are derived from that UUID, so recurrence can create a new branch and a new PR
for an unchanged underlying incident.

That behavior is unsuitable for Evidence Core. A provider-native observation
must have a stable identity across scans so DriftGuard can distinguish:

- a newly observed drift incident,
- the same unresolved incident seen again,
- an incident that disappeared from a complete observation,
- and a previously resolved incident that later reappeared.

The repository currently has no schema-migration system. `Base.metadata.create_all()`
creates missing tables but does not add columns to an already-existing table.
Therefore lifecycle data must not be introduced by silently adding fields to
`drift_findings`; that would work on a fresh database and fail on an existing
production database.

## Decision

Evidence Core uses separate lifecycle tables:

- `finding_incidents`: one workspace-scoped row per deterministic incident identity,
- `finding_occurrences`: one redacted observation of an incident in a scan,
- `evidence_reconciliations`: one exactly-once reconciliation marker per scan.

The legacy `drift_findings` table remains unchanged. The new lifecycle is not
wired to the legacy collector-based scan path.

## Identity v1

The incident fingerprint is the full lowercase SHA-256 digest of canonical JSON
containing:

- identity version,
- exact provider-native `resource_address`,
- optional Terraform/OpenTofu `deposed` key,
- resource type,
- provider source name,
- provider-native action sequence in its original order,
- sorted unique `changed_paths`.

The database uniqueness boundary is `(workspace_id, fingerprint)`. Workspace ID
is intentionally not embedded in the digest; tenancy is enforced by the unique
constraint and all lifecycle queries.

Sensitivity masks and `after_unknown` paths are excluded from identity. They
represent what can safely be known or disclosed about an observation, not the
underlying drift surface. A secret becoming masked or an unknown value becoming
known must not create a second incident when resource identity, actions and
changed paths are unchanged.

Raw infrastructure values are never inputs to lifecycle identity and are never
persisted by these tables.

## Resource moves

`previous_resource_address` is not part of identity v1. The current absolute
resource address is authoritative.

This means an explicit Terraform/OpenTofu resource move can produce a new
incident identity after the move. Preserving lifecycle across moves requires a
separate, explicit address-migration mapping. v1 does not guess that mapping,
because using `previous_resource_address` as a permanent canonical address would
make identity unstable once that field disappears from later plans.

## State machine

Lifecycle v1 has only two machine states:

- `open`
- `resolved`

Transitions:

1. unseen fingerprint -> `open`, `occurrence_count = 1`
2. `open` fingerprint observed again -> remain `open`, increment occurrence count
3. `open` fingerprint absent from a **complete** plan -> `resolved`
4. `resolved` fingerprint observed again -> `open`, increment `reopen_count`

Manual dispositions such as ignored/false-positive are intentionally not mixed
into this state machine yet. They are policy/user-decision states and need a
separate contract rather than overloading machine observation state.

## Completeness gate

Absence is evidence only when the IaC engine says the plan is complete.

Therefore DriftGuard resolves missing incidents only when:

```text
EvidenceBundle.plan_complete is True
```

If `plan_complete` is `False` or unavailable, observed incidents may be created
or refreshed, but missing incidents cannot be resolved. This prevents deferred
or partial planning from creating false recovery events.

## Exactly-once reconciliation

A background task or worker can be retried. Reprocessing the same scan must not:

- increment occurrence counts twice,
- reopen an incident twice,
- resolve an incident twice,
- or create a second remediation side effect.

`evidence_reconciliations` records one row per `scan_id` containing:

- workspace ID,
- SHA-256 digest of the sorted observed incident fingerprints,
- finding count,
- plan completeness,
- reconciliation timestamp.

A replay with the same scan ID and the same observation set/completeness is a
no-op. A replay with different evidence or different completeness fails closed.
This marker is required even for a clean scan with zero findings; occurrence rows
alone cannot make a zero-finding scan idempotent.

PostgreSQL reconciliation acquires a row lock on the workspace before mutation,
serializing lifecycle changes for concurrent scans of the same workspace. The
unique constraints remain the final integrity boundary.

## Occurrence audit trail

`finding_occurrences` is append-only redacted metadata. It stores:

- incident ID,
- workspace ID,
- scan ID,
- observation time,
- Evidence Bundle schema version,
- sensitive paths,
- unknown paths.

It never stores Terraform/OpenTofu `before` or `after` values.

The unique `(incident_id, scan_id)` constraint prevents one scan from recording
the same incident twice.

## Remediation deduplication key

Every incident receives one stable branch name:

```text
driftguard/fix-<full incident SHA-256 fingerprint>
```

The branch is persisted on the incident. Future Evidence Core GitHub automation
must use this branch and the incident-level PR metadata instead of a per-scan
finding UUID. This commit defines and tests that idempotency key but deliberately
does not attach new PR side effects to the legacy detector.

## Failure semantics

Reconciliation fails without partial commit when:

- the workspace does not exist,
- the scan does not belong to the workspace,
- the bundle contains duplicate incident identities,
- a replay disagrees with the already-reconciled evidence set/completeness,
- an incident contains an unsupported lifecycle status,
- or the supplied observation timestamp is timezone-naive.

The caller owns the surrounding transaction. A failure is not converted into a
clean scan or a resolved incident set.

## Migration sequence

1. Land lifecycle schema and reconciliation contract behind tests.
2. Keep the legacy scan pipeline unchanged.
3. Add redacted Evidence Bundle persistence from the provider-native scan path.
4. Reconcile Evidence Bundle findings into incidents transactionally.
5. Expose incident lifecycle through API/UI without treating scan snapshots as incidents.
6. Move GitHub remediation automation to incident-level idempotency.
7. Only then retire per-scan legacy finding behavior when the Evidence Core cutover gates pass.

## Explicit non-claims

This ADR does not claim:

- that the legacy collector detector now has lifecycle correctness,
- that GitHub remediation is already incident-aware,
- that resource moves preserve incident identity,
- that manual ignore/false-positive policy is implemented,
- or that Evidence Core has replaced the production scan path.
