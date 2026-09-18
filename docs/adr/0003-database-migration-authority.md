# ADR 0003: Make Alembic the schema authority

Status: Accepted; schema-authority cutover implemented for the current single-instance Render deployment.

## Context

DriftGuard historically called `Base.metadata.create_all()` at API startup. That is safe for creating missing tables in local development, but it is not a schema migration system: it does not alter existing tables, record migration history, or provide a deterministic upgrade path for deployed databases.

Evidence Core introduces persistent lifecycle tables. Depending on startup `create_all()` would make deployment order determine schema correctness and would make rollback/audit behavior impossible to reason about.

## Decision

Alembic is the authoritative production schema history.

Two revisions establish the transition:

- `0001_legacy_baseline` describes the schema that existed before Alembic.
- `0002_evidence_lifecycle` adds Evidence Core incident lifecycle persistence.
- `0003_evidence_submissions` adds redacted provider-native submission provenance and idempotency.

The bootstrap command classifies the database before taking action:

1. Empty database: create the current ORM schema, then `alembic stamp head`.
2. Recognized unversioned legacy DriftGuard database: require the exact five legacy tables and exact legacy column sets, stamp `0001_legacy_baseline`, then upgrade to head.
3. Versioned database: run `alembic upgrade head`.
4. Any partial, extra, or ambiguous unversioned schema: abort without stamping.

The classifier is intentionally strict. A failed deployment is preferable to writing a false migration history onto an unknown database.

## Deployment boundary

The current Render Blueprint uses a free, single-instance web service. Render's dedicated pre-deploy migration hook is unavailable on that tier, so the Blueprint performs the migration bootstrap as the first command in the service start sequence:

`python -m backend.migrations.bootstrap && uvicorn ...`

Uvicorn is therefore never started if schema bootstrap fails. FastAPI startup no longer calls `Base.metadata.create_all()`; the application process is not a schema authority.

This is intentionally scoped to the current single-instance deployment. Before DriftGuard is scaled to multiple API instances, the migration command must move to a one-shot release/pre-deploy job so multiple instances cannot race schema changes.

## Invariants

- No migration may infer that a partial schema is safe.
- Existing legacy rows must survive bootstrap unchanged.
- Re-running bootstrap at head is idempotent.
- ORM metadata and Alembic head must have zero pending schema operations under `alembic check`.
- `create_all()` may remain for local tests/development, but it is not the production migration authority.
- Uvicorn must not start if migration bootstrap fails.
- Evidence ingestion remains opt-in even after schema bootstrap; `DRIFTGUARD_EVIDENCE_INGEST_ENABLED` defaults to false.

## Rejected alternatives

### Continue using `create_all()`

Rejected because it cannot evolve existing schemas and records no history.

### Stamp every unversioned database as legacy

Rejected because a malformed or partially upgraded database would be declared valid without evidence.

### Run migrations in FastAPI startup

Rejected because concurrent application instances can race schema changes and because application availability would be coupled to migration execution.

### Add Render `preDeployCommand` immediately

Rejected for the current free service because the deployment tier does not provide that capability.

### Keep migrations inside FastAPI lifespan

Rejected. Schema mutation happens before the application process starts, not inside application startup.

## Verification gate

CI must continue proving:

- fresh bootstrap reaches Alembic head;
- recognized legacy bootstrap preserves existing data;
- a second bootstrap is a no-op upgrade;
- ambiguous schemas fail without creating `alembic_version`;
- `alembic check` passes after both fresh and legacy paths.
