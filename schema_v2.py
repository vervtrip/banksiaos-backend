#!/usr/bin/env python3
"""
Verv OS Schema Update v2 — adds applicant pipeline, access management, property gallery tables.
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from verv_os_db import get_db, init_db, _lock

SCHEMA_V2 = """
CREATE TABLE IF NOT EXISTS applicants (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    first_name TEXT, last_name TEXT, full_name TEXT,
    phone TEXT, email TEXT, photo_url TEXT,
    property_id INTEGER, unit_id INTEGER,
    stage TEXT DEFAULT 'new',
    -- new, viewing_booked, application_received, referencing, guarantor,
    -- approved, agreement_sent, awaiting_signature, move_in_booked, current_tenant, rejected
    viewing_date TEXT, application_date TEXT,
    employment_reference TEXT, landlord_reference TEXT,
    credit_check INTEGER DEFAULT 0, income_verified INTEGER DEFAULT 0,
    identity_verified INTEGER DEFAULT 0, right_to_rent_verified INTEGER DEFAULT 0,
    referencing_status TEXT DEFAULT 'pending',
    outstanding_items TEXT,
    decision_history TEXT,
    internal_notes TEXT,
    approval_status TEXT DEFAULT 'pending',
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS guarantors (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    applicant_id INTEGER REFERENCES applicants(id) ON DELETE SET NULL,
    tenant_id INTEGER REFERENCES tenants(id) ON DELETE SET NULL,
    first_name TEXT, last_name TEXT, full_name TEXT,
    phone TEXT, email TEXT, photo_url TEXT,
    relationship TEXT, employer TEXT, income REAL,
    address TEXT,
    reference_documents TEXT,
    guarantee_agreement_signed INTEGER DEFAULT 0,
    approved INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS access_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    property_id INTEGER NOT NULL REFERENCES properties(id) ON DELETE CASCADE,
    unit_id INTEGER,
    entry_type TEXT NOT NULL,
    -- key, key_code, key_safe, intercom, door_code, alarm_code, smart_lock, fob, parking_permit
    label TEXT,
    value TEXT,
    location TEXT,
    current_holder TEXT,
    notes TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS access_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    access_record_id INTEGER REFERENCES access_records(id) ON DELETE CASCADE,
    action TEXT NOT NULL,
    holder_name TEXT,
    issued_date TEXT,
    returned_date TEXT,
    notes TEXT,
    created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS property_images (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    property_id INTEGER NOT NULL REFERENCES properties(id) ON DELETE CASCADE,
    category TEXT NOT NULL,
    -- main, bedroom, bathroom, kitchen, living_room, communal, exterior,
    -- floorplan, video, tour_360, inspection, move_in, move_out
    title TEXT,
    file_url TEXT,
    file_type TEXT,
    is_primary INTEGER DEFAULT 0,
    sort_order INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_applicants_property ON applicants(property_id);
CREATE INDEX IF NOT EXISTS idx_applicants_stage ON applicants(stage);
CREATE INDEX IF NOT EXISTS idx_access_property ON access_records(property_id);
CREATE INDEX IF NOT EXISTS idx_prop_images_property ON property_images(property_id);
"""

def migrate():
    with _lock:
        conn = get_db()
        try:
            conn.executescript(SCHEMA_V2)
            conn.commit()
            print("Schema v2 applied successfully.")
            # Check tables
            tables = conn.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name").fetchall()
            for t in tables:
                cnt = conn.execute(f"SELECT COUNT(*) FROM {t['name']}").fetchone()[0]
                print(f"  {t['name']}: {cnt} rows")
        finally:
            conn.close()

if __name__ == "__main__":
    migrate()