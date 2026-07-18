#!/usr/bin/env python3
"""
Schema v3 — Polymorphic Entity Documents system.

- Upgrades `documents` table from simple related_to/related_id to a full
  polymorphic entity_documents table that supports any entity type.
- Migrates existing records.
"""
import sys, os
sys.path.insert(0, os.path.dirname(__file__))
from banksia_os_db import get_db, get_dict_db, DB_PATH


def migrate():
    db = get_db()
    print(f"[migrate] Running schema v3 on {DB_PATH}")

    # ── 1. Create polymorphic entity_documents table ──
    db.executescript("""
        CREATE TABLE IF NOT EXISTS entity_documents (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            entity_type     TEXT NOT NULL,       -- 'tenant' | 'guarantor' | 'applicant' | 'property' | 'unit' | 'tenancy' | 'maintenance_job' | 'referencing_form'
            entity_id       INTEGER NOT NULL,
            original_filename TEXT NOT NULL,
            stored_filename TEXT NOT NULL,
            file_path       TEXT NOT NULL,
            file_type       TEXT,                -- extension e.g. 'pdf', 'jpg', 'png', 'docx'
            file_size       INTEGER,
            mime_type       TEXT,
            category        TEXT DEFAULT 'general',  -- 'id', 'contract', 'invoice', 'photo', 'certificate', 'general'
            notes           TEXT,
            uploaded_by     TEXT,                -- username or 'applicant' or 'whatsapp' or 'email'
            is_verified     INTEGER DEFAULT 0,
            created         TEXT DEFAULT (datetime('now')),
            updated         TEXT DEFAULT (datetime('now'))
        );

        CREATE INDEX IF NOT EXISTS idx_entity_docs_entity
            ON entity_documents(entity_type, entity_id);
        CREATE INDEX IF NOT EXISTS idx_entity_docs_category
            ON entity_documents(entity_type, category);
        CREATE INDEX IF NOT EXISTS idx_entity_docs_uploaded
            ON entity_documents(uploaded_by);
    """)
    db.commit()
    print("  ✅ Created entity_documents table")

    # ── 2. Migrate existing documents table records ──
    existing = db.execute(
        "SELECT id, filename, file_path, file_type, category, related_to, related_id, notes, created "
        "FROM documents WHERE related_to IS NOT NULL AND related_to != ''"
    ).fetchall()

    migrated = 0
    for row in existing:
        r = dict(row)
        entity_type = r["related_to"]
        # Normalise entity type names
        type_map = {
            "tenancy": "tenancy", "tenancies": "tenancy",
            "tenant": "tenant", "tenants": "tenant",
            "property": "property", "properties": "property",
            "applicant": "applicant", "applicants": "applicant",
        }
        et = type_map.get(entity_type, entity_type)
        try:
            eid = int(r["related_id"])
        except (ValueError, TypeError):
            continue

        # Check if already migrated
        exists = db.execute(
            "SELECT id FROM entity_documents WHERE entity_type=? AND entity_id=? AND file_path=?",
            (et, eid, r["file_path"])
        ).fetchone()
        if exists:
            continue

        db.execute(
            "INSERT INTO entity_documents (entity_type, entity_id, original_filename, stored_filename, "
            "file_path, file_type, category, notes, uploaded_by, created) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'team', ?)",
            (et, eid, r["filename"], r["filename"], r["file_path"],
             r["file_type"], r["category"] or "general", r["notes"], r["created"])
        )
        migrated += 1

    db.commit()
    print(f"  ✅ Migrated {migrated} existing documents records")

    # ── 3. Verify ──
    count = db.execute("SELECT COUNT(*) AS cnt FROM entity_documents").fetchone()["cnt"]
    print(f"  📊 Total entity_documents: {count}")
    print("[migrate] Schema v3 complete ✅")


if __name__ == "__main__":
    migrate()
