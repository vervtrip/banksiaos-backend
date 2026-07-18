"""
Banksia OS — Database migration framework.
Tracks schema versions in a `schema_migrations` table and applies
migrations in order. Each migration is a function that receives the DB
connection and performs schema/data changes.

Usage:
    python3 -c "from services.migration_service import migrate; migrate()"
"""
import os, re
from datetime import datetime

MIGRATIONS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "migrations")
os.makedirs(MIGRATIONS_DIR, exist_ok=True)


def ensure_migrations_table(db):
    """Create the schema_migrations tracking table if it doesn't exist."""
    db.execute("""
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            applied_at TEXT NOT NULL DEFAULT (datetime('now'))
        )
    """)


def get_applied_versions(db):
    """Return the set of already-applied migration version numbers."""
    ensure_migrations_table(db)
    rows = db.execute("SELECT version FROM schema_migrations ORDER BY version").fetchall()
    return {r["version"] for r in rows}


def mark_applied(db, version, name):
    """Record a migration as applied."""
    db.execute(
        "INSERT OR IGNORE INTO schema_migrations (version, name) VALUES (?, ?)",
        [version, name]
    )
    db.commit()


def migrate(db=None, target_version=None):
    """
    Run all unapplied migrations up to target_version (or latest).
    Returns list of applied migration info dicts.
    """
    from banksia_os_db import get_dict_db

    close_db = db is None
    if close_db:
        db = get_dict_db()

    try:
        applied_versions = get_applied_versions(db)
        migrations = sorted(MIGRATIONS.items(), key=lambda x: x[0])

        results = []
        for version, (name, fn) in migrations:
            if version in applied_versions:
                continue
            if target_version is not None and version > target_version:
                break
            print(f"  Applying migration v{version}: {name}...")
            try:
                fn(db)
                mark_applied(db, version, name)
                results.append({"version": version, "name": name, "status": "applied"})
            except Exception as e:
                db.rollback()
                results.append({"version": version, "name": name, "status": "failed", "error": str(e)})
                print(f"  ✗ FAILED: {e}")
                break

        return results
    finally:
        if close_db:
            db.close()


# ── Migration definitions ──
# Format: version: (name, function)
# Add new migrations at the END of this dict.

MIGRATIONS = {
    1: ("Create schema_migrations table", lambda db: ensure_migrations_table(db)),

    2: ("Add index on tenancies.status", lambda db: _run_safe(db, """
        CREATE INDEX IF NOT EXISTS idx_tenancies_status ON tenancies(status)
    """)),

    3: ("Add index on units.property_id", lambda db: _run_safe(db, """
        CREATE INDEX IF NOT EXISTS idx_units_property_id ON units(property_id)
    """)),

    4: ("Add index on tenancies.unit_id", lambda db: _run_safe(db, """
        CREATE INDEX IF NOT EXISTS idx_tenancies_unit_id ON tenancies(unit_id)
    """)),

    5: ("Add index on activity_log.entity_type_entity_id", lambda db: _run_safe(db, """
        CREATE INDEX IF NOT EXISTS idx_activity_log_entity
        ON activity_log(entity_type, entity_id)
    """)),

    6: ("Add index on change_log.created_at", lambda db: _run_safe(db, """
        CREATE INDEX IF NOT EXISTS idx_change_log_created
        ON change_log(created_at)
    """)),

    7: ("Add index on notifications.username", lambda db: _run_safe(db, """
        CREATE INDEX IF NOT EXISTS idx_notifications_username
        ON notifications(username)
    """)),
}


def _run_safe(db, sql):
    """Execute SQL safely, ignoring errors for IF NOT EXISTS equivalents."""
    try:
        db.execute(sql)
        db.commit()
    except Exception:
        db.rollback()
