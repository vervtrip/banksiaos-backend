#!/usr/bin/env python3
"""
Data Migration Script — Banksia OS
===================================
Creates the authoritative `deposits` table and populates it from
legacy fields in the existing units/tenancies tables.

Idempotent: safe to run multiple times. On re-runs, existing deposit
records are updated rather than duplicated.

Migration logic:
  1. Ensure the deposits table exists (CREATE TABLE IF NOT EXISTS).
  2. For each active tenancy (status IN ('Current','Periodic')):
       - Create/update a deposit record from tenancy deposit fields.
  3. For each unit with deposit_amount > 0 that has no active tenancy:
       - Create a default deposit record using unit-level deposit data.
  4. Touch the updated timestamp on any record that was migrated.

Usage:
    python run_data_migration.py          # runs and reports
    python run_data_migration.py --dry-run  # preview only, no writes
"""

import argparse
import os
import sqlite3
import sys
import threading
from datetime import datetime, timezone

# ── Same DB path as banksia_os_db.py ──────────────────────────────────
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "banksia_os.db")


def get_conn():
    """Get a writeable connection with the same pragmas as the app."""
    conn = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def create_deposits_table(conn, dry_run: bool) -> str:
    """
    Create the deposits table if it does not already exist.
    Returns a status message.
    """
    if dry_run:
        # Check if it exists
        cur = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='deposits'"
        )
        exists = cur.fetchone() is not None
        if exists:
            return "deposits table already exists (dry-run, skipped)"
        return "deposits table would be created (dry-run, skipped)"

    # The table DDL is defined here so this script is self-contained.
    # Note: We intentionally skip CREATE INDEX here because the indexes
    # are managed by banksia_os_db.py's SCHEMA_SQL / init_db(). If the table
    # didn't exist yet, it means init_db() hasn't been called with the
    # latest schema, so we create the table here but don't duplicate index
    # creation — init_db() will add them when called.
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS deposits (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            tenancy_id          INTEGER NOT NULL REFERENCES tenancies(id) ON DELETE CASCADE,
            tenant_id           INTEGER REFERENCES tenants(id) ON DELETE SET NULL,
            unit_id             INTEGER REFERENCES units(id) ON DELETE SET NULL,
            property_id         INTEGER REFERENCES properties(id) ON DELETE SET NULL,
            amount              REAL NOT NULL DEFAULT 0,
            registered_amount   REAL DEFAULT 0,
            deposit_type        TEXT DEFAULT 'cash',
            scheme              TEXT,
            protection_status   TEXT DEFAULT 'unprotected',
            protection_ref      TEXT,
            date_received       TEXT,
            date_protected      TEXT,
            date_returned       TEXT,
            amount_returned     REAL DEFAULT 0,
            deductions          REAL DEFAULT 0,
            status              TEXT DEFAULT 'held',
            source              TEXT DEFAULT 'migration',
            notes               TEXT,
            created             TEXT DEFAULT (datetime('now')),
            updated             TEXT DEFAULT (datetime('now'))
        );
    """)
    conn.commit()
    return "deposits table created / already exists"


def migrate_tenancy_deposits(conn, dry_run: bool) -> dict:
    """
    For each active tenancy (Current / Periodic), create or update
    a deposit record using the tenancy's deposit_ fields.

    Returns a dict of counts: {created, updated, skipped, errors}.
    """
    stats = {"created": 0, "updated": 0, "skipped": 0, "errors": 0}

    # Fetch active tenancies that have deposit data
    rows = conn.execute("""
        SELECT
            t.id AS tenancy_id,
            t.unit_id,
            t.property_id,
            COALESCE(t.deposit_registered_amount, 0) AS deposit_amount,
            t.deposit_scheme,
            t.deposit_registered,
            t.status,
            t.start_date
        FROM tenancies t
        WHERE t.status IN ('Current', 'Periodic')
          AND (t.deposit_registered_amount IS NOT NULL AND t.deposit_registered_amount > 0
               OR t.deposit_registered = 1
               OR t.deposit_scheme IS NOT NULL)
    """).fetchall()

    if not rows:
        stats["skipped"] = 0  # no tenancies to process — that's fine
        return stats

    now_iso = datetime.now(timezone.utc).isoformat()

    for row in rows:
        tenancy_id = row["tenancy_id"]
        unit_id = row["unit_id"]
        property_id = row["property_id"]
        amount = row["deposit_amount"] or 0.0
        scheme = row["deposit_scheme"]
        is_registered = row["deposit_registered"] or 0
        status_str = row["status"]
        start_date = row["start_date"]

        # Resolve unit property_id if property_id is NULL on tenancy
        resolved_property_id = property_id
        if resolved_property_id is None and unit_id:
            u = conn.execute(
                "SELECT property_id FROM units WHERE id = ?", (unit_id,)
            ).fetchone()
            if u:
                resolved_property_id = u["property_id"]

        # Determine protection status and deposit status from tenancy data
        protection_status = "unprotected"
        dep_status = "held"
        date_received = None
        date_protected = None

        if is_registered:
            protection_status = "protected"
        if amount > 0 and start_date:
            date_received = start_date  # best guess

        # Check if a deposit record already exists for this tenancy
        existing = conn.execute(
            "SELECT id, amount, updated FROM deposits WHERE tenancy_id = ?",
            (tenancy_id,),
        ).fetchone()

        if not dry_run:
            if existing:
                # UPDATE existing — don't clobber notes/source if already set
                conn.execute(
                    """
                    UPDATE deposits SET
                        unit_id = ?,
                        property_id = ?,
                        amount = ?,
                        registered_amount = ?,
                        scheme = ?,
                        protection_status = ?,
                        status = ?,
                        date_received = COALESCE(?, date_received),
                        date_protected = COALESCE(?, date_protected),
                        updated = ?
                    WHERE id = ?
                    """,
                    (
                        unit_id,
                        resolved_property_id,
                        amount,
                        amount,  # registered_amount mirrors amount initially
                        scheme,
                        protection_status,
                        dep_status,
                        date_received,
                        date_protected,
                        now_iso,
                        existing["id"],
                    ),
                )
                stats["updated"] += 1
            else:
                conn.execute(
                    """
                    INSERT INTO deposits
                        (tenancy_id, unit_id, property_id, amount, registered_amount,
                         deposit_type, scheme, protection_status, date_received,
                         date_protected, status, source, created, updated)
                    VALUES (?, ?, ?, ?, ?, 'cash', ?, ?, ?, ?, ?, 'migration', ?, ?)
                    """,
                    (
                        tenancy_id,
                        unit_id,
                        resolved_property_id,
                        amount,
                        amount,
                        scheme,
                        protection_status,
                        date_received,
                        date_protected,
                        dep_status,
                        now_iso,
                        now_iso,
                    ),
                )
                stats["created"] += 1
        else:
            # Dry-run: just count
            if existing:
                stats["updated"] += 1
            else:
                stats["created"] += 1

    if not dry_run:
        conn.commit()

    return stats


def migrate_unit_deposits(conn, dry_run: bool) -> dict:
    """
    For each unit that has deposit_amount > 0 AND does NOT have
    an active tenancy, create a default deposit record.

    Strategy:
    1. Find the most recent tenancy (any status) on that unit.
    2. If one exists, link the deposit to that tenancy.
    3. If no tenancy exists at all, create a minimal tenancy placeholder
       so the NOT NULL FK constraint on deposits.tenancy_id is satisfied.

    Returns a dict of counts.
    """
    stats = {"created": 0, "updated": 0, "skipped": 0, "errors": 0}
    now_iso = datetime.now(timezone.utc).isoformat()

    rows = conn.execute("""
        SELECT u.id AS unit_id, u.property_id, u.deposit_amount, u.unit_ref
        FROM units u
        WHERE u.deposit_amount IS NOT NULL AND u.deposit_amount > 0
          AND u.id NOT IN (
              SELECT DISTINCT t.unit_id FROM tenancies t
              WHERE t.unit_id IS NOT NULL
                AND t.status IN ('Current', 'Periodic')
          )
        ORDER BY u.id
    """).fetchall()

    for row in rows:
        unit_id = row["unit_id"]
        property_id = row["property_id"]
        amount = row["deposit_amount"] or 0.0
        unit_ref = row["unit_ref"] or ""

        # ── Find the most recent tenancy on this unit (any status) ──
        last_tenancy = conn.execute("""
            SELECT id, property_id
            FROM tenancies
            WHERE unit_id = ?
            ORDER BY COALESCE(end_date, start_date, '1970-01-01') DESC
            LIMIT 1
        """, (unit_id,)).fetchone()

        tenancy_id = None
        resolved_property_id = property_id

        if last_tenancy:
            tenancy_id = last_tenancy["id"]
            if resolved_property_id is None and last_tenancy["property_id"]:
                resolved_property_id = last_tenancy["property_id"]
        else:
            # ── No tenancy at all — create a placeholder tenancy ──
            if resolved_property_id is None:
                stats["errors"] += 1
                continue  # cannot create a tenancy without a property

            tenancy_ref = f"MIGRATED-DEPOSIT-UNIT-{unit_id}"
            existing_placeholder = conn.execute(
                "SELECT id FROM tenancies WHERE ref = ?", (tenancy_ref,)
            ).fetchone()

            if existing_placeholder:
                tenancy_id = existing_placeholder["id"]
            elif not dry_run:
                cur = conn.execute(
                    """
                    INSERT INTO tenancies
                        (unit_id, property_id, ref, status, start_date, notes)
                    VALUES (?, ?, ?, 'Ended', ?, 'Auto-created placeholder for deposit migration')
                    """,
                    (unit_id, resolved_property_id, tenancy_ref, now_iso[:10]),
                )
                tenancy_id = cur.lastrowid
            else:
                # dry-run: just simulate
                tenancy_id = -1

        if tenancy_id is None or tenancy_id == -1:
            continue

        # ── Check if a deposit record already exists for this tenancy ──
        existing = conn.execute(
            "SELECT id FROM deposits WHERE tenancy_id = ?",
            (tenancy_id,),
        ).fetchone()

        if existing:
            # Update existing record
            if not dry_run:
                conn.execute(
                    """
                    UPDATE deposits SET
                        unit_id = ?,
                        property_id = ?,
                        amount = ?,
                        registered_amount = ?,
                        updated = ?
                    WHERE id = ?
                    """,
                    (unit_id, resolved_property_id, amount, amount, now_iso, existing["id"]),
                )
                stats["updated"] += 1
            else:
                stats["updated"] += 1
            continue

        if not dry_run:
            conn.execute(
                """
                INSERT INTO deposits
                    (tenancy_id, unit_id, property_id, amount, registered_amount,
                     deposit_type, protection_status, date_received, status,
                     source, notes, created, updated)
                VALUES (?, ?, ?, ?, ?, 'cash', 'unprotected', ?, 'held',
                        'migration', 'Migrated from unit deposit_amount', ?, ?)
                """,
                (
                    tenancy_id,
                    unit_id,
                    resolved_property_id,
                    amount,
                    amount,
                    now_iso,
                    now_iso,
                    now_iso,
                ),
            )
            stats["created"] += 1
        else:
            stats["created"] += 1

    if not dry_run and (stats["created"] > 0 or stats["updated"] > 0):
        conn.commit()

    return stats


def run_data_migration(conn=None, dry_run: bool = False) -> dict:
    """
    Main migration entry point.

    If no connection is provided, opens one internally.
    Returns a report dict with all sub-stats.
    """
    close_on_exit = False
    if conn is None:
        conn = get_conn()
        close_on_exit = True

    report = {
        "table_status": None,
        "tenancy_deposits": None,
        "unit_deposits": None,
        "total_created": 0,
        "total_updated": 0,
        "total_errors": 0,
    }

    try:
        # Step 1: Create table
        report["table_status"] = create_deposits_table(conn, dry_run)

        # Step 2: Migrate tenancy deposits
        t_stats = migrate_tenancy_deposits(conn, dry_run)
        report["tenancy_deposits"] = t_stats

        # Step 3: Migrate unit deposits (no active tenancy)
        u_stats = migrate_unit_deposits(conn, dry_run)
        report["unit_deposits"] = u_stats

        report["total_created"] = t_stats["created"] + u_stats["created"]
        report["total_updated"] = t_stats["updated"] + u_stats["updated"]
        report["total_errors"] = t_stats["errors"] + u_stats["errors"]

    finally:
        if close_on_exit:
            conn.close()

    return report


def print_report(report: dict, dry_run: bool):
    """Pretty-print migration results."""
    tag = " [DRY-RUN]" if dry_run else ""
    print(f"{'='*60}")
    print(f"DEPOSIT DATA MIGRATION REPORT{tag}")
    print(f"{'='*60}")
    print(f"  Table status:  {report['table_status']}")
    print(f"")

    t = report["tenancy_deposits"]
    if t:
        print(f"  Tenancy deposits:")
        print(f"    Created:  {t['created']}")
        print(f"    Updated:  {t['updated']}")
        print(f"    Skipped:  {t['skipped']}")
        print(f"    Errors:   {t['errors']}")

    u = report["unit_deposits"]
    if u:
        print(f"  Unit-level deposits (no active tenancy):")
        print(f"    Created:  {u['created']}")
        print(f"    Updated:  {u['updated']}")
        print(f"    Skipped:  {u['skipped']}")
        print(f"    Errors:   {u['errors']}")

    print(f"  ─────────────────────────────")
    print(f"  Total created: {report['total_created']}")
    print(f"  Total updated: {report['total_updated']}")
    print(f"  Total errors:  {report['total_errors']}")
    print(f"{'='*60}")


# ── Command-line entry point ──────────────────────────────────────


def main():
    global DB_PATH
    parser = argparse.ArgumentParser(
        description="Banksia OS — deposits data migration"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview what would happen without writing anything",
    )
    parser.add_argument(
        "--db",
        default=DB_PATH,
        help=f"Path to the SQLite database (default: {DB_PATH})",
    )
    args = parser.parse_args()

    DB_PATH = args.db

    if not os.path.exists(DB_PATH):
        print(f"Error: Database not found at {DB_PATH}")
        print("Run 'python banksia_os_db.py' first to initialise the database.")
        sys.exit(1)

    report = run_data_migration(dry_run=args.dry_run)
    print_report(report, dry_run=args.dry_run)


if __name__ == "__main__":
    main()
