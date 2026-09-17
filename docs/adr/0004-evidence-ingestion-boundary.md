# ADR 0004: Provider-native evidence ingestion boundary

Status: Accepted on Evidence Core branch; disabled by default.

## Context

Evidence Core can now derive a redacted `EvidenceBundle` locally from Terraform/OpenTofu plan JSON and reconcile deterministic incident lifecycle state. The next boundary is transporting that sanitized evidence into DriftGuard without turning the service into a raw plan/state custodian or creating duplicate scans when CI retries a request.

Raw Terraform plan/state JSON is intentionally excluded from this API. Provider plan JSON may contain plaintext sensitive values even when Terraform marks them sensitive.

## Decision

Add an opt-in endpoint:

`POST /workspaces/{workspace_id}/evidence`

The request contains only:

- a caller-generated `submission_id` identifying one source execution/attempt;
- an `EvidenceBundle` whose Pydantic contract forbids unknown fields and contains no `before`/`after` values.

The endpoint is disabled unless `DRIFTGUARD_EVIDENCE_INGEST_ENABLED` is explicitly true.

### Idempotency

Every accepted submission persists a redacted provenance row keyed uniquely by `(workspace_id, submission_id)` and stores a canonical SHA-256 digest of the sanitized bundle.

- same submission ID + identical bundle: replay the existing scan safely;
- same submission ID + different bundle: return conflict and perform no lifecycle mutation.

A workspace row lock serializes same-workspace ingestion on PostgreSQL. The provenance row, scan row, lifecycle reconciliation, and incident transitions live in one request transaction.

### Observation ordering

Lifecycle ordering uses server receipt time, not the client-supplied plan timestamp. The plan timestamp is retained only as provenance. This prevents a client from poisoning the lifecycle cursor with an arbitrary future timestamp.

### Tenant isolation

The API resolves the workspace using both workspace ID and authenticated organization ID before any ingestion work starts. A workspace owned by another tenant is returned as not found.

### Persisted data

DriftGuard persists:

- IaC engine and version;
- source JSON format version;
- plan timestamp/applyable/complete metadata;
- redaction policy;
- finding and skipped-nonmanaged counts;
- deterministic bundle digest;
- resource identity, action and changed-path metadata through the incident lifecycle tables;
- sensitive/unknown *paths*, never their values.

It does not persist raw plan JSON or raw before/after values through this path.

## Deployment boundary

The endpoint is disabled by default because the current free Render service cannot run a deterministic pre-deploy migration hook. Enabling ingestion requires the target database to have been explicitly upgraded to Alembic head first.

## Rejected alternatives

### Upload raw Terraform plan/state to the API

Rejected because it expands secret custody and makes the service responsible for protecting values it does not need.

### Deduplicate by bundle digest globally

Rejected because two legitimate scans may observe identical drift. Idempotency belongs to a source execution key, not to the evidence contents alone.

### Generate a new scan on every HTTP retry

Rejected because retries would inflate occurrence counts and could later fan out into duplicate remediation work.

### Order lifecycle by client plan timestamp

Rejected because a malformed or malicious future timestamp could make subsequent valid observations appear stale.

## Verification gates

CI must prove:

- ingestion is disabled by default;
- raw/unknown change-value fields are rejected by validation;
- cross-tenant workspace ingestion returns not found;
- exact HTTP replay reuses one scan and one occurrence;
- conflicting reuse of a submission ID returns 409;
- migration head matches ORM metadata with the provenance table included;
- legacy Terraform/OpenTofu provider contract jobs remain green.
