from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest
from alembic import command
from sqlalchemy import create_engine, inspect, text

from backend.migrations.bootstrap import (
    HEAD_REVISION,
    MigrationBootstrapError,
    _alembic_config,
    bootstrap_database,
)
from backend.models.base import Base


def _url(path: Path) -> str:
    return f"sqlite+aiosqlite:///{path}"


def _sync_url(path: Path) -> str:
    return f"sqlite:///{path}"


def _current_revision(path: Path) -> str:
    engine = create_engine(_sync_url(path))
    try:
        with engine.connect() as connection:
            return connection.execute(
                text("SELECT version_num FROM alembic_version")
            ).scalar_one()
    finally:
        engine.dispose()


def _tables(path: Path) -> set[str]:
    engine = create_engine(_sync_url(path))
    try:
        return set(inspect(engine).get_table_names())
    finally:
        engine.dispose()


def _create_legacy_schema(path: Path) -> None:
    legacy_tables = [
        Base.metadata.tables["organizations"],
        Base.metadata.tables["api_keys"],
        Base.metadata.tables["workspaces"],
        Base.metadata.tables["drift_scans"],
        Base.metadata.tables["drift_findings"],
    ]
    engine = create_engine(_sync_url(path))
    try:
        Base.metadata.create_all(engine, tables=legacy_tables)
        with engine.begin() as connection:
            connection.execute(
                Base.metadata.tables["organizations"].insert().values(
                    id="org-1",
                    name="Migration Test",
                    slug="migration-test",
                    plan="FREE",
                    is_active=True,
                    max_workspaces=1,
                    max_resources=50,
                )
            )
    finally:
        engine.dispose()


def test_fresh_database_bootstrap_is_current_and_idempotent(tmp_path: Path):
    db_path = tmp_path / "fresh.db"
    assert bootstrap_database(_url(db_path)) == "initialized-fresh"
    assert _current_revision(db_path) == HEAD_REVISION
    assert {
        "finding_incidents",
        "finding_occurrences",
        "evidence_cursors",
        "evidence_reconciliations",
    }.issubset(_tables(db_path))

    assert bootstrap_database(_url(db_path)) == "upgraded-versioned"
    assert _current_revision(db_path) == HEAD_REVISION


def test_legacy_database_upgrades_without_destroying_existing_data(tmp_path: Path):
    db_path = tmp_path / "legacy.db"
    _create_legacy_schema(db_path)

    assert bootstrap_database(_url(db_path)) == "upgraded-legacy"
    assert _current_revision(db_path) == HEAD_REVISION

    engine = create_engine(_sync_url(db_path))
    try:
        with engine.connect() as connection:
            assert (
                connection.execute(
                    text("SELECT name FROM organizations WHERE id = 'org-1'")
                ).scalar_one()
                == "Migration Test"
            )
    finally:
        engine.dispose()


def test_partial_unversioned_schema_fails_closed_without_stamp(tmp_path: Path):
    db_path = tmp_path / "partial.db"
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            "CREATE TABLE organizations (id VARCHAR(36) PRIMARY KEY, name VARCHAR(255))"
        )

    with pytest.raises(MigrationBootstrapError, match="not the recognized"):
        bootstrap_database(_url(db_path))

    assert "alembic_version" not in _tables(db_path)


def test_alembic_metadata_check_passes_after_fresh_bootstrap(tmp_path: Path):
    db_path = tmp_path / "check.db"
    bootstrap_database(_url(db_path))
    command.check(_alembic_config(_url(db_path)))


def test_alembic_metadata_check_passes_after_legacy_upgrade(tmp_path: Path):
    db_path = tmp_path / "legacy-check.db"
    _create_legacy_schema(db_path)
    bootstrap_database(_url(db_path))
    command.check(_alembic_config(_url(db_path)))
