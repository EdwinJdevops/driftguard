# ADR 0002: Evidence finding identity and lifecycle

- Status: Accepted
- Date: 2026-09-14
- Scope: incident identity, recurrence, resolution, replay safety, observation ordering, remediation deduplication

## Context

The legacy `drift_findings` table stores one row per finding per scan. A new UUID
is generated every time the same drift is observed. GitHub remediation branches
are derived from that UUID, so recurrence can create a new branch and a new PR
for an unchanged underlying incident.

Evidence Core needs stable identity across scans so DriftGuard can distinguish a
new incident, a recurrence, a verified resolution, and a later reappearance.
It must also remain correct when workers finish out of order: serialization alone
does not prevent an older observation from incorrectly resolving or reopening
state established by a newer observation.

The repository currently has no schema-migration system. `Base.metadata.create_all()`
creates missing tables but does not add columns to an existing table. Lifecycle
data therefore must not be introduced by silently adding fields to the existing
`drift_findings` table.

## Decision

Evidence Core uses separate lifecycle tables:

- `finding_incidents`: one workspace-scoped row per deterministic incident identity;
- `finding_occurrences`: one redacted observation for each lifecycle-applied scan;
- `evidence_reconciliations`: one exactly-once reconciliation marker per scan;
- `evidence_cursors`: one monotonic lifecycle watermark per workspace.

The legacy `drift_findings` table and legacy collector scan path remain unchanged.

## Identity v1

The incident fingerprint is the full lowercase SHA-256 digest of canonical JSON
containing:

- identity version;
- exact provider-native `resource_address`;
- optional Terraform/OpenTofu `deposed` key;
- resource type;
- provider source name;
- provider-native action sequence in its original order;
- sorted unique `changed_paths`.

The database uniqueness boundary is `(workspace_id, fingerprint)`. Workspace ID
is intentionally not embedded in the digest; tenancy is enforced by the unique
constraint and workspace-scoped queries.

Sensitivity masks and `after_unknown` paths are excluded from identity because
they describe observation/disclosure quality rather than the underlying drift
surface. Raw infrastructure values are never inputs to identity and are never
persisted by lifecycle tables.

`previous_resource_address` is also excluded. A resource move can therefore
produce a new v1 incident. Preserving lifecycle across explicit moves requires a
future address-migration contract; v1 does not guess one.

## State machine

Lifecycle v1 has two machine states:

- `open`
- `resolved`

Transitions for a lifecycle-applied observation are:

1. unseen fingerprint -> `open`, occurrence count 1;
2. `open` fingerprint observed again -> remain `open`, increment occurrence count;
3. `open` fingerprint absent from a complete plan -> `resolved`;
4. `resolved` fingerprint observed again -> `open`, increment reopen count.

Manual dispositions such as ignored or false-positive are policy decisions and
are intentionally not overloaded onto this machine-observation state.

## Completeness gate

Absence is evidence only when the IaC engine reports a complete plan. Missing
incidents are therefore resolved only when:

```text
EvidenceBundle.plan_complete is True
```

When `plan_complete` is `False` or unavailable, observed incidents may be
created/refreshed, but absence cannot resolve anything.

## Monotonic observation ordering

Each workspace has an `evidence_cursors` row containing the latest observation
time and scan ID that was allowed to mutate lifecycle state.

Reconciliation acquires a workspace row lock on PostgreSQL before reading the
cursor. If a different scan arrives with:

```text
observed_at <= latest_observed_at
```

it is stale or order-ambiguous. DriftGuard records an
`evidence_reconciliations` row with `applied_to_lifecycle = false` and performs
no incident creation, recurrence increment, resolution, reopen, occurrence
insert, or cursor movement.

This deliberately prefers a missed historical lifecycle transition over a
false current-state transition. A later Evidence Bundle persistence layer may
retain the stale bundle for historical analysis independently of lifecycle.

Callers must supply a timezone-aware observation time. Processing/arrival time
must not be substituted silently for infrastructure observation order.

## Exactly-once reconciliation

A worker retry must not increment counts or repeat transitions. Every scan gets
at most one `evidence_reconciliations` row containing workspace ID, the digest
of its sorted incident fingerprints, finding count, completeness, observation
time, whether it was applied to lifecycle, and reconciliation time.

Replaying the same scan with the same evidence/completeness/observation time is
a no-op. Replaying the same scan ID with different evidence, completeness, or
observation time fails closed. This marker is required even for zero-finding
scans; occurrence rows alone cannot make a clean scan idempotent.

## Occurrence semantics

`finding_occurrences` is append-only redacted metadata for lifecycle-applied
observations only. It stores incident ID, workspace ID, scan ID, observation
time, Evidence Bundle schema version, sensitive paths, and unknown paths.
It never stores Terraform/OpenTofu `before` or `after` values.

The unique `(incident_id, scan_id)` constraint prevents duplicate occurrence
records. Stale scans intentionally do not increment occurrence counts or create
occurrence rows because they were not allowed to affect the lifecycle timeline.

## Concurrency and integrity boundaries

PostgreSQL reconciliation locks the workspace row before lifecycle mutation,
serializing concurrent scans for one workspace. The monotonic cursor then
ensures serialized-but-out-of-order scans cannot roll state backward. Database
unique/check constraints remain the final integrity boundary.

All loaded incident states are validated before mutation; unknown lifecycle
states fail closed even if that incident is absent from the current bundle.

## Remediation deduplication key

Every incident receives one stable branch name:

```text
driftguard/fix-<full incident SHA-256 fingerprint>
```

Future Evidence Core GitHub automation must use this persisted incident-level
key rather than a per-scan finding UUID. This ADR defines and tests the key but
does not attach new GitHub side effects to the legacy detector.

## Failure semantics

Reconciliation fails without partial commit when:

- workspace does not exist;
- scan does not belong to workspace;
- bundle contains duplicate incident identities;
- same scan ID is replayed with different evidence/completeness/time;
- an incident contains an unsupported lifecycle status;
- observation time is timezone-naive.

The caller owns the surrounding transaction. Failure is never converted into a
clean scan or a resolved incident set.

## Migration sequence

1. Land lifecycle schema and reconciliation contract behind tests.
2. Keep the legacy scan pipeline unchanged.
3. Introduce a real database migration mechanism before lifecycle tables are a production dependency.
4. Persist redacted Evidence Bundles from the provider-native scan path.
5. Reconcile persisted Evidence Bundle findings transactionally into incidents.
6. Expose incidents through API/UI without treating scan snapshots as incidents.
7. Move GitHub remediation automation to incident-level idempotency.
8. Retire per-scan legacy finding behavior only after the Evidence Core cutover gates pass.

## Explicit non-claims

This ADR does not claim that the legacy detector has lifecycle correctness,
GitHub remediation is incident-aware, resource moves preserve incident identity,
manual ignore/false-positive policy is implemented, stale bundles are already
persisted for historical analytics, or Evidence Core has replaced production
scan execution.
