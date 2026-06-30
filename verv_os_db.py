#!/usr/bin/env python3
"""
Verv OS — Banksia Operations Database Layer.
SQLite-backed persistent store for all HMO operations.
One object, one truth — never duplicate information.
"""
import json, os, sqlite3, time, uuid
from datetime import datetime, timezone
from threading import Lock

DB_PATH = os.path.join(os.path.dirname(__file__), "verv_os.db")
_lock = Lock()

SCHEMA_SQL = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS properties (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    arthur_id TEXT UNIQUE,
    name TEXT NOT NULL,
    address TEXT, postcode TEXT, city TEXT,
    owner TEXT, manager TEXT,
    property_type TEXT DEFAULT 'HMO',
    hmo_licence TEXT, hmo_licence_expiry TEXT,
    photo_url TEXT, landlord_id INTEGER, arthur_ref TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS units (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    arthur_id TEXT UNIQUE,
    property_id INTEGER NOT NULL REFERENCES properties(id) ON DELETE CASCADE,
    name TEXT NOT NULL, unit_ref TEXT,
    status TEXT DEFAULT 'vacant',
    rent_amount REAL DEFAULT 0, rent_frequency TEXT DEFAULT 'pcm',
    deposit_amount REAL DEFAULT 0, deposit_protected INTEGER DEFAULT 0,
    deposit_scheme TEXT, bedroom_count INTEGER DEFAULT 1,
    floor TEXT, notes TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS tenancies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    arthur_id TEXT UNIQUE,
    unit_id INTEGER NOT NULL REFERENCES units(id) ON DELETE CASCADE,
    start_date TEXT, end_date TEXT,
    status TEXT DEFAULT 'active',
    rent_amount REAL, rent_frequency TEXT DEFAULT 'pcm',
    deposit_amount REAL, deposit_protected INTEGER DEFAULT 0,
    deposit_scheme TEXT, notice_date TEXT, notice_period TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS tenants (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    arthur_person_id TEXT,
    tenancy_id INTEGER REFERENCES tenancies(id) ON DELETE SET NULL,
    first_name TEXT, last_name TEXT, full_name TEXT,
    phone TEXT, email TEXT, photo_url TEXT,
    passport_number TEXT, nationality TEXT,
    visa_type TEXT, visa_expiry TEXT,
    right_to_rent_verified INTEGER DEFAULT 0,
    right_to_rent_expiry TEXT,
    emergency_contact_name TEXT, emergency_contact_phone TEXT,
    employer TEXT, occupation TEXT,
    move_in_date TEXT, move_out_date TEXT,
    outstanding_balance REAL DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS landlords (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL, company TEXT,
    email TEXT, phone TEXT, photo_url TEXT,
    notes TEXT, bank_account TEXT, sort_code TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS contractors (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    company TEXT NOT NULL, contact_name TEXT,
    email TEXT, phone TEXT, trade TEXT,
    insurance_expiry TEXT, qualifications TEXT,
    areas_covered TEXT, rating REAL DEFAULT 0,
    avg_response_time_hours REAL, notes TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS maintenance (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    unit_id INTEGER, property_id INTEGER,
    tenant_id INTEGER, contractor_id INTEGER,
    title TEXT NOT NULL, description TEXT,
    priority TEXT DEFAULT 'normal',
    status TEXT DEFAULT 'reported',
    reported_by TEXT, reported_date TEXT,
    completed_date TEXT, quote_amount REAL,
    actual_cost REAL, invoice_ref TEXT,
    photos TEXT, videos TEXT,
    tenant_confirmed INTEGER DEFAULT 0,
    landlord_confirmed INTEGER DEFAULT 0,
    warranty_expiry TEXT, notes TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS compliance (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    property_id INTEGER, unit_id INTEGER,
    cert_type TEXT NOT NULL, cert_ref TEXT,
    issue_date TEXT, expiry_date TEXT,
    provider TEXT, status TEXT DEFAULT 'valid',
    notes TEXT, file_url TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS documents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    object_type TEXT NOT NULL, object_id INTEGER NOT NULL,
    category TEXT NOT NULL, title TEXT,
    file_url TEXT, file_type TEXT,
    file_size INTEGER, notes TEXT,
    created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS communications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    object_type TEXT NOT NULL, object_id INTEGER NOT NULL,
    channel TEXT NOT NULL, direction TEXT DEFAULT 'inbound',
    subject TEXT, body TEXT,
    from_name TEXT, from_address TEXT,
    to_name TEXT, to_address TEXT,
    attachments TEXT, voice_note_url TEXT, ai_summary TEXT,
    created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS timeline (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    object_type TEXT NOT NULL, object_id INTEGER NOT NULL,
    event_type TEXT NOT NULL, title TEXT NOT NULL,
    description TEXT, actor TEXT,
    created_at TEXT DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_timeline_obj ON timeline(object_type, object_id);
CREATE INDEX IF NOT EXISTS idx_timeline_time ON timeline(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_units_property ON units(property_id);
CREATE INDEX IF NOT EXISTS idx_tenancies_unit ON tenancies(unit_id);
CREATE INDEX IF NOT EXISTS idx_tenants_tenancy ON tenants(tenancy_id);
CREATE INDEX IF NOT EXISTS idx_maint_unit ON maintenance(unit_id);
CREATE INDEX IF NOT EXISTS idx_compliance_prop ON compliance(property_id);
CREATE INDEX IF NOT EXISTS idx_comms_obj ON communications(object_type, object_id);
CREATE INDEX IF NOT EXISTS idx_docs_obj ON documents(object_type, object_id);
"""

def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn

def init_db():
    with _lock:
        conn = get_db()
        try:
            conn.executescript(SCHEMA_SQL)
            conn.commit()
        finally:
            conn.close()

def dict_from_row(row):
    return None if row is None else dict(row)

def insert(table, data):
    keys = [k for k in data if data[k] is not None]
    vals = [data[k] for k in keys]
    cols = ", ".join(keys)
    ph = ", ".join(["?" for _ in keys])
    with _lock:
        conn = get_db()
        try:
            cur = conn.execute(f"INSERT INTO {table} ({cols}) VALUES ({ph})", vals)
            conn.commit()
            return cur.lastrowid
        finally:
            conn.close()

def update(table, row_id, data):
    now = datetime.now(timezone.utc).isoformat()
    data["updated_at"] = now
    items = [(k, data[k]) for k in data if data[k] is not None]
    if not items:
        return
    sc = ", ".join([f"{k} = ?" for k, _ in items])
    vals = [v for _, v in items] + [row_id]
    with _lock:
        conn = get_db()
        try:
            conn.execute(f"UPDATE {table} SET {sc} WHERE id = ?", vals)
            conn.commit()
        finally:
            conn.close()

def get(table, row_id):
    with _lock:
        conn = get_db()
        try:
            return dict_from_row(conn.execute(f"SELECT * FROM {table} WHERE id = ?", (row_id,)).fetchone())
        finally:
            conn.close()

def get_by_field(table, field, value):
    with _lock:
        conn = get_db()
        try:
            return [dict(r) for r in conn.execute(f"SELECT * FROM {table} WHERE {field} = ?", (value,)).fetchall()]
        finally:
            conn.close()

def list_all(table, order="id DESC", limit=500, off=0):
    with _lock:
        conn = get_db()
        try:
            return [dict(r) for r in conn.execute(f"SELECT * FROM {table} ORDER BY {order} LIMIT ? OFFSET ?", (limit, off)).fetchall()]
        finally:
            conn.close()

def count(table, where="1=1", params=None):
    if params is None: params = []
    with _lock:
        conn = get_db()
        try:
            row = conn.execute(f"SELECT COUNT(*) as cnt FROM {table} WHERE {where}", params).fetchone()
            return row["cnt"] if row else 0
        finally:
            conn.close()

def raw_query(sql, params=None):
    if params is None: params = []
    with _lock:
        conn = get_db()
        try:
            return [dict(r) for r in conn.execute(sql, params).fetchall()]
        finally:
            conn.close()

def raw_execute(sql, params=None):
    if params is None: params = []
    with _lock:
        conn = get_db()
        try:
            conn.execute(sql, params)
            conn.commit()
        finally:
            conn.close()

def search_objects(query):
    q = f"%{query}%"
    results = []
    with _lock:
        conn = get_db()
        try:
            for sql, fields in [
                ("SELECT id, name, address, 'property' as obj_type FROM properties WHERE name LIKE ? OR address LIKE ?", (q, q)),
                ("SELECT u.id, u.name||' @ '||COALESCE(p.name,'') as name, u.status, 'unit' as obj_type FROM units u LEFT JOIN properties p ON u.property_id=p.id WHERE u.name LIKE ?", (q,)),
                ("SELECT id, full_name as name, COALESCE(email,'') as address, 'tenant' as obj_type FROM tenants WHERE full_name LIKE ? OR email LIKE ? OR phone LIKE ?", (q, q, q)),
                ("SELECT id, name, COALESCE(company,'') as address, 'landlord' as obj_type FROM landlords WHERE name LIKE ? OR company LIKE ? OR email LIKE ?", (q, q, q)),
                ("SELECT id, company as name, COALESCE(trade,'') as address, 'contractor' as obj_type FROM contractors WHERE company LIKE ? OR contact_name LIKE ? OR trade LIKE ?", (q, q, q)),
            ]:
                results.extend([dict(r) for r in conn.execute(sql, fields).fetchall()])
        finally:
            conn.close()
    return results

def add_timeline(object_type, object_id, event_type, title, description=None, actor=None):
    return insert("timeline", {
        "object_type": object_type, "object_id": object_id,
        "event_type": event_type, "title": title,
        "description": description, "actor": actor,
        "created_at": datetime.now(timezone.utc).isoformat(),
    })

def get_timeline(object_type, object_id, limit=50):
    return raw_query(
        "SELECT * FROM timeline WHERE object_type=? AND object_id=? ORDER BY created_at DESC LIMIT ?",
        (object_type, object_id, limit))

def get_property_timeline(property_id, limit=100):
    return raw_query("""
        SELECT t.* FROM timeline t
        WHERE (t.object_type='property' AND t.object_id=?)
           OR (t.object_type='unit' AND t.object_id IN (SELECT id FROM units WHERE property_id=?))
        ORDER BY t.created_at DESC LIMIT ?
    """, (property_id, property_id, limit))

def attention_score(object_type, object_id):
    score = 0
    reasons = []
    if object_type == "property":
        units = get_by_field("units", "property_id", object_id)
        total = len(units)
        vacant = sum(1 for u in units if u["status"]=="vacant")
        attn = sum(1 for u in units if u["status"]=="attention")
        if total > 0:
            score += int((vacant/total)*30)
            if vacant: reasons.append(f"{vacant} vacant")
        score += attn * 10
        if attn: reasons.append(f"{attn} need attention")
        exp = count("compliance", "property_id=? AND status IN ('expiring_soon','expired','overdue')", [object_id])
        score += exp * 8
        if exp: reasons.append(f"{exp} compliance items expiring")
        om = count("maintenance", "property_id=? AND status NOT IN ('completed','confirmed')", [object_id])
        score += om * 5
        if om: reasons.append(f"{om} open jobs")
    elif object_type == "unit":
        u = get("units", object_id)
        if u:
            if u["status"]=="vacant": score+=30; reasons.append("Vacant")
            elif u["status"]=="attention": score+=40; reasons.append("Needs attention")
            elif u["status"]=="notice_served": score+=20; reasons.append("Notice served")
            om = count("maintenance", "unit_id=? AND status NOT IN ('completed','confirmed')", [object_id])
            score += om * 8
            if om: reasons.append(f"{om} open jobs")
    return min(score, 100), reasons

# ─── REAL PORTFOLIO DATA ─────────────────────────────────────

PROPERTIES_DATA = [
    {"name": "4 Studd Street", "address": "4 Studd Street, Islington, London N1 0QJ", "postcode": "N1 0QJ"},
    {"name": "2 Claremont Square", "address": "2 Claremont Square, Islington, London N1 9LX", "postcode": "N1 9LX"},
    {"name": "5 Brookes Court", "address": "5 Brookes Court, London", "postcode": ""},
    {"name": "4 Manilla Street", "address": "4 Manilla Street, London", "postcode": ""},
    {"name": "525 Finchley Road", "address": "525 Finchley Road, London NW3 7BH", "postcode": "NW3 7BH"},
    {"name": "11 Wraysbury Drive", "address": "11 Wraysbury Drive, London", "postcode": ""},
    {"name": "25 Carrol Close", "address": "25 Carrol Close, London", "postcode": ""},
    {"name": "46 Harrold House", "address": "46 Harrold House, London", "postcode": ""},
    {"name": "The Angel Hub", "address": "Angel, Islington, London", "postcode": ""},
    {"name": "The Canary Hub", "address": "4 Manilla Street, London", "postcode": ""},
    {"name": "Central London Hub", "address": "Central London", "postcode": ""},
    {"name": "The Lake Hub", "address": "Lake Close, London", "postcode": ""},
    {"name": "Cosy Angel Hub", "address": "Angel, Islington, London", "postcode": ""},
    {"name": "Angel x Kings Cross Hub", "address": "Kings Cross, London", "postcode": ""},
    {"name": "Angel F2", "address": "2 Claremont Square, London", "postcode": ""},
]

UNITS_DATA = {
    "4 Studd Street": ["Room 1 Studd", "Room 2 Studd", "Room 3 Studd", "Studio 4 Studd", "Studio 6 Studd"],
    "2 Claremont Square": ["Angel F1", "Angel F2", "Angel F3", "Angel F4", "Angel F5"],
    "5 Brookes Court": ["Central Room 1", "Central Room 2", "Central Room 3", "Central Room 4", "Central Room 5"],
    "4 Manilla Street": ["Flat 26", "Flat 27"],
    "525 Finchley Road": ["Flat 6 - Room 1", "Flat 6 - Room 2", "Flat 6 - Room 3", "Flat 6 - Room 4"],
}

def seed_portfolio():
    """Seed the database with known properties and units if empty."""
    if count("properties") > 0:
        return
    for p in PROPERTIES_DATA:
        pid = insert("properties", {
            "name": p["name"],
            "address": p.get("address", ""),
            "postcode": p.get("postcode", ""),
            "property_type": "HMO",
            "manager": "Banksia Lettings",
        })
        units = UNITS_DATA.get(p["name"], [])
        for uname in units:
            insert("units", {
                "property_id": pid,
                "name": uname,
                "status": "vacant",
                "bedroom_count": 1,
            })
        if units:
            add_timeline("property", pid, "created", f"Property created with {len(units)} units",
                        f"Seeded from portfolio data", "Neo")

if __name__ == "__main__":
    init_db()
    seed_portfolio()
    print(f"Database initialised at {DB_PATH}")
    print(f"Properties: {count('properties')}")
    print(f"Units: {count('units')}")
    print("Portfolio seeded successfully.")
