from __future__ import annotations

import argparse
import asyncio
import os
from collections.abc import Mapping
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import inspect
from sqlalchemy.ext.asyncio import create_async_engine

from backend.db_url import normalize_database_url
from backend.models import incidents as incident_models
from backend.models import models as core_models
from backend.models.base import Base

_REGISTERED_MODEL_MODULES = (core_models, incident_models)

LEGACY_REVISION = "0001_legacy_baseline"
HEAD_REVISION = "0003_evidence_submissions"

LEGACY_COLUMNS: Mapping[str, frozenset[str]] = {
    "organizations": frozenset({"id", "name", "slug", "plan", "github_org", "stripe_customer_id", "is_active", "max_workspaces", "max_resources", "created_at", "updated_at"}),
    "api_keys": frozenset({"id", "org_id", "name", "key_hash", "key_prefix", "is_active", "last_used_at", "expires_at", "created_at", "updated_at"}),
    "workspaces": frozenset({"id", "org_id", "name", "slug", "provider", "region", "state_backend", "s3_bucket", "s3_key", "s3_region", "github_repo", "github_branch", "terraform_dir", "github_app_installation_id", "aws_role_arn", "aws_external_id", "scan_interval_minutes", "auto_pr_enabled", "notifications_slack_webhook", "notifications_email", "is_active", "last_scanned_at", "created_at", "updated_at"}),
    "drift_scans": frozenset({"id", "workspace_id", "status", "triggered_by", "total_resources_checked", "drift_count", "security_findings_count", "cost_delta_monthly", "posture_score", "started_at", "completed_at", "error_message", "created_at", "updated_at"}),
    "drift_findings": frozenset({"id", "workspace_id", "scan_id", "resource_type", "resource_id", "resource_name", "region", "status", "severity", "drift_type", "expected_state", "actual_state", "diff_summary", "security_impact", "compliance_violations", "cost_delta_monthly", "terraform_patch", "github_pr_url", "github_pr_number", "resolved_at", "resolved_by", "created_at", "updated_at"}),
}

LIFECYCLE_TABLES = frozenset({
    "finding_incidents",
    "finding_occurrences",
    "evidence_cursors",
    "evidence_reconciliations",
    "evidence_submissions",
})


class MigrationBootstrapError(RuntimeError):
    """Raised when an existing schema cannot be identified safely."""


def _alembic_config(database_url: str) -> Config:
    repo_root = Path(__file__).resolve().parents[2]
    config = Config(str(repo_root / "alembic.ini"))
    config.attributes["connection_url"] = normalize_database_url(database_url)
    return config


async def _schema_snapshot(database_url: str) -> dict[str, frozenset[str]]:
    engine = create_async_engine(normalize_database_url(database_url), pool_pre_ping=True)
    try:
        async with engine.connect() as connection:
            def inspect_schema(sync_connection) -> dict[str, frozenset[str]]:
                inspector = inspect(sync_connection)
                return {
                    table: frozenset(column["name"] for column in inspector.get_columns(table))
                    for table in inspector.get_table_names()
                }

            return await connection.run_sync(inspect_schema)
    finally:
        await engine.dispose()


async def _create_current_schema(database_url: str) -> None:
    engine = create_async_engine(normalize_database_url(database_url), pool_pre_ping=True)
    try:
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
    finally:
        await engine.dispose()


def _validate_legacy_schema(snapshot: Mapping[str, frozenset[str]]) -> None:
    tables = frozenset(snapshot)
    expected = frozenset(LEGACY_COLUMNS)
    if tables & LIFECYCLE_TABLES:
        raise MigrationBootstrapError(
            "Unversioned database already contains Evidence lifecycle tables; refusing to guess migration history."
        )
    if tables != expected:
        missing = sorted(expected - tables)
        extra = sorted(tables - expected)
        raise MigrationBootstrapError(
            f"Unversioned schema is not the recognized DriftGuard legacy schema (missing_tables={missing}, extra_tables={extra})."
        )

    mismatches: list[str] = []
    for table, expected_columns in LEGACY_COLUMNS.items():
        actual_columns = snapshot[table]
        if actual_columns != expected_columns:
            missing = sorted(expected_columns - actual_columns)
            extra = sorted(actual_columns - expected_columns)
            mismatches.append(f"{table}: missing={missing}, extra={extra}")
    if mismatches:
        raise MigrationBootstrapError(
            "Unversioned DriftGuard schema has unexpected columns: " + "; ".join(mismatches)
        )


def bootstrap_database(database_url: str) -> str:
    """Bring a DriftGuard database under Alembic without guessing its history."""
    database_url = normalize_database_url(database_url)
    snapshot = asyncio.run(_schema_snapshot(database_url))
    config = _alembic_config(database_url)

    if "alembic_version" in snapshot:
        command.upgrade(config, "head")
        return "upgraded-versioned"
    if not snapshot:
        asyncio.run(_create_current_schema(database_url))
        command.stamp(config, "head")
        return "initialized-fresh"

    _validate_legacy_schema(snapshot)
    command.stamp(config, LEGACY_REVISION)
    command.upgrade(config, "head")
    return "upgraded-legacy"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Safely initialize or upgrade the DriftGuard database schema."
    )
    parser.add_argument(
        "--database-url",
        default=os.getenv("DATABASE_URL", "sqlite+aiosqlite:///./driftguard.db"),
    )
    args = parser.parse_args()
    result = bootstrap_database(args.database_url)
    print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
