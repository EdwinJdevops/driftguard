# ADR 0003: Make Alembic the schema authority

Status: Accepted for Evidence Core branch; production cutover remains gated.

## Context

DriftGuard historically called `Base.metadata.create_all()` at API startup. That is safe for creating missing tables in local development, but it is not a schema migration system: it does not alter existing tables, record migration history, or provide a deterministic upgrade path for deployed databases.

Evidence Core introduces persistent lifecycle tables. Depending on startup `create_all()` would make deployment order determine schema correctness and would make rollback/audit behavior impossible to reason about.

## Decision

Alembic is the authoritative production schema history.

Two revisions establish the transition:

- `0001_legacy_baseline` describes the schema that existed before Alembic.
- `0002_evidence_lifecycle` adds Evidence Core incident lifecycle persistence.

The bootstrap command classifies the database before taking action:

1. Empty database: create the current ORM schema, then `alembic stamp head`.
2. Recognized unversioned legacy DriftGuard database: require the exact five legacy tables and exact legacy column sets, stamp `0001_legacy_baseline`, then upgrade to head.
3. Versioned database: run `alembic upgrade head`.
4. Any partial, extra, or ambiguous unversioned schema: abort without stamping.

The classifier is intentionally strict. A failed deployment is preferable to writing a false migration history onto an unknown database.

## Deployment boundary

The existing Render Blueprint uses a free web service. Render's pre-deploy migration hook is not available on that tier. Therefore this ADR does **not** wire migrations into the free Render startup path and does not make the new lifecycle tables a production dependency yet.

Production cutover requires a deployment target that can run one migration command before the API version depending on that schema becomes active, or an equivalent explicitly controlled release step.

## Invariants

- No migration may infer that a partial schema is safe.
- Existing legacy rows must survive bootstrap unchanged.
- Re-running bootstrap at head is idempotent.
- ORM metadata and Alembic head must have zero pending schema operations under `alembic check`.
- `create_all()` may remain for local tests/development, but it is not the production migration authority.
- Evidence Core production code must not depend on a migration until the deployment path can execute that migration deterministically.

## Rejected alternatives

### Continue using `create_all()`

Rejected because it cannot evolve existing schemas and records no history.

### Stamp every unversioned database as legacy

Rejected because a malformed or partially upgraded database would be declared valid without evidence.

### Run migrations in FastAPI startup

Rejected because concurrent application instances can race schema changes and because application availability would be coupled to migration execution.

### Add Render `preDeployCommand` immediately

Rejected for the current free service because the deployment tier does not provide that capability.

## Verification gate

Before runtime cutover, CI must prove:

- fresh bootstrap reaches Alembic head;
- recognized legacy bootstrap preserves existing data;
- a second bootstrap is a no-op upgrade;
- ambiguous schemas fail without creating `alembic_version`;
- `alembic check` passes after both fresh and legacy paths.
