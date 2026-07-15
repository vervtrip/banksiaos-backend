#!/usr/bin/env python3
"""
Verv OS Database Layer.
SQLite-backed persistent store mirroring
the HMO rental operations data model.
Complete schema with all fields.
"""
import json, os, sqlite3, time, uuid, threading
from datetime import datetime, timezone
from threading import Lock

DB_PATH = os.path.join(os.path.dirname(__file__), "verv_os.db")
_lock = Lock()
# Per-thread connections for request-scoped use
_vos_local = threading.local()

def get_db():
    """Per-thread database connection. Each thread keeps its own connection
    — never shared across threads. check_same_thread=False only disables
    SQLite's Python ownership check, not thread safety.
    """
    if not hasattr(_vos_local, 'conn') or _vos_local.conn is None:
        conn = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=5000")
        _vos_local.conn = conn
    try:
        _vos_local.conn.execute("SELECT 1")
    except (sqlite3.ProgrammingError, sqlite3.OperationalError):
        # Connection was closed (e.g. by init_db). Reopen it.
        conn = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=5000")
        _vos_local.conn = conn
    return _vos_local.conn


def get_dict_db():
    """Get DB connection with dict row factory.
    Uses a separate thread-local connection so the main get_db() row factory
    is never mutated. This prevents a dict query from leaking its row_factory
    to a subsequent Row-query in the same request.
    """
    if not hasattr(_vos_local, 'dict_conn') or _vos_local.dict_conn is None:
        conn = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=30)
        conn.row_factory = lambda c, r: {col[0]: r[idx] for idx, col in enumerate(c.description)}
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=5000")
        _vos_local.dict_conn = conn
    return _vos_local.dict_conn


# ═══════════════════════════════════════════════
# IMPORTANT: The helper functions below (insert, update, get, etc.)
# use a module-level Lock (_lock) for their CREATE-/UPDATE-/DELETE-
# operations. This is intentional: these functions are called from
# background sync scripts (arthur_sync.py) that may share a connection
# across invocations, and the lock serialises writes from multiple
# sources. The request-scoped endpoints in banksia_os.py use
# get_dict_db() directly without the lock, which is safe because each
# request creates its own thread-local connection.
# ═══════════════════════════════════════════════

SCHEMA_SQL = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

-- ── 1. PROPERTIES ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS properties (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    arthur_id       TEXT UNIQUE,
    ref             TEXT,
    name            TEXT,
    address_line_1  TEXT,
    address_line_2  TEXT,
    city            TEXT,
    county          TEXT,
    postcode        TEXT,
    country         TEXT,
    lat             REAL,
    lng             REAL,
    property_type   TEXT DEFAULT 'HMO',
    total_units     INTEGER DEFAULT 0,
    rentable_units  INTEGER DEFAULT 0,
    property_owner_id       TEXT,
    property_owner_name     TEXT,
    max_occupancy   INTEGER,
    bathrooms       INTEGER,
    bedrooms        INTEGER,
    council_tax_band        TEXT,
    council_account_no      TEXT,
    main_image_url  TEXT,
    image_urls      TEXT,
    epc_urls        TEXT,
    floor_plan_urls TEXT,
    thumbnail_urls  TEXT,
    features        TEXT,
    notes           TEXT,
    tags            TEXT,
    custom_fields   TEXT,
    modified        TEXT,
    created         TEXT
);

-- ── 2. UNITS ──────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS units (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    arthur_id       TEXT UNIQUE,
    property_id     INTEGER NOT NULL REFERENCES properties(id) ON DELETE CASCADE,
    unit_type       TEXT,
    unit_status     TEXT DEFAULT 'Available',
    unit_ref        TEXT,
    unit_vacant     INTEGER DEFAULT 1,
    available_from  TEXT,
    market_rent     REAL,
    market_rent_frequency TEXT DEFAULT 'pcm',
    deposit_amount  REAL,
    owner_name      TEXT,
    full_address    TEXT,
    short_description TEXT,
    description     TEXT,
    furnished       TEXT,
    max_occupancy   INTEGER,
    bathrooms       INTEGER,
    bedrooms        INTEGER,
    council_tax_band TEXT,
    main_image_url  TEXT,
    image_urls      TEXT,
    features        TEXT,
    notes           TEXT,
    tags            TEXT,
    days_vacant     INTEGER DEFAULT 0,
    modified        TEXT,
    created         TEXT
);

-- ── 3. TENANCIES ──────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS tenancies (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    arthur_id       TEXT UNIQUE,
    property_id     INTEGER,
    unit_id         INTEGER NOT NULL REFERENCES units(id) ON DELETE CASCADE,
    ref             TEXT,
    status          TEXT DEFAULT 'Active',
    full_address    TEXT,
    tenancy_type    TEXT,
    contract_type   TEXT,
    start_date      TEXT,
    end_date        TEXT,
    renewal_start   TEXT,
    renewal_end     TEXT,
    is_renewed      INTEGER DEFAULT 0,
    break_clause_date       TEXT,
    rolling_break_date      TEXT,
    notice_period   TEXT,
    move_in_date    TEXT,
    move_out_date   TEXT,
    rent_amount     REAL,
    rent_frequency  TEXT DEFAULT 'pcm',
    deposit_held_by TEXT,
    deposit_scheme  TEXT,
    deposit_registered       INTEGER DEFAULT 0,
    deposit_registered_amount REAL,
    rent_review_date         TEXT,
    section_21_served        INTEGER DEFAULT 0,
    rent_payment_bank        TEXT,
    main_tenant_name         TEXT,
    tenants         TEXT,
    notes           TEXT,
    tags            TEXT,
    modified        TEXT,
    created         TEXT
);

-- ── 4. TENANTS ────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS tenants (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    arthur_id       TEXT UNIQUE,
    arthur_person_id TEXT,
    tenancy_id      INTEGER REFERENCES tenancies(id) ON DELETE SET NULL,
    unit_id         INTEGER,
    property_id     INTEGER,
    full_address    TEXT,
    title           TEXT,
    first_name      TEXT,
    last_name       TEXT,
    date_of_birth   TEXT,
    gender          TEXT,
    citizen         TEXT,
    email           TEXT,
    phone_home      TEXT,
    phone_work      TEXT,
    mobile          TEXT,
    passport_number TEXT,
    visa_number     TEXT,
    visa_type       TEXT,
    visa_years      INTEGER,
    country_of_origin TEXT,
    ni_number       TEXT,
    main_tenant     INTEGER DEFAULT 0,
    status          TEXT,
    has_guarantor   INTEGER DEFAULT 0,
    guarantor_first_name    TEXT,
    guarantor_last_name     TEXT,
    guarantor_date_of_birth TEXT,
    guarantor_address       TEXT,
    guarantor_city          TEXT,
    guarantor_postcode      TEXT,
    guarantor_country       TEXT,
    guarantor_phone         TEXT,
    guarantor_mobile        TEXT,
    guarantor_email         TEXT,
    guarantor_relation      TEXT,
    guarantor_profession    TEXT,
    guarantor_home_owner    INTEGER,
    kin_first_name  TEXT,
    kin_last_name   TEXT,
    kin_mobile      TEXT,
    employment_company      TEXT,
    employment_address      TEXT,
    employment_salary       REAL,
    employment_length       TEXT,
    student_status  TEXT,
    university      TEXT,
    course_name     TEXT,
    bank_name       TEXT,
    bank_account_name       TEXT,
    bank_account_number     TEXT,
    bank_sort_code  TEXT,
    ref_name        TEXT,
    ref_email       TEXT,
    ref_contact     TEXT,
    latest_credit_score         TEXT,
    latest_credit_description   TEXT,
    applicant_note  TEXT,
    manager_note    TEXT,
    move_in_date    TEXT,
    move_out_date   TEXT,
    custom_fields   TEXT,
    modified        TEXT,
    created         TEXT
);

-- ── 5. APPLICANTS ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS applicants (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    arthur_id       TEXT UNIQUE,
    person_id       TEXT,
    status          TEXT DEFAULT 'Active',
    first_name      TEXT,
    last_name       TEXT,
    date_of_birth   TEXT,
    gender          TEXT,
    email           TEXT,
    mobile          TEXT,
    phone           TEXT,
    full_address    TEXT,
    viewing_count   INTEGER DEFAULT 0,
    last_viewing_date TEXT,
    passport_number TEXT,
    visa_number     TEXT,
    visa_type       TEXT,
    visa_years      INTEGER,
    country_of_origin TEXT,
    ni_number       TEXT,
    student_status  TEXT,
    university      TEXT,
    course_name     TEXT,
    employment_company      TEXT,
    employment_address      TEXT,
    employment_salary       REAL,
    employment_length       TEXT,
    has_guarantor   INTEGER DEFAULT 0,
    guarantor_first_name    TEXT,
    guarantor_last_name     TEXT,
    guarantor_date_of_birth TEXT,
    guarantor_address       TEXT,
    guarantor_city          TEXT,
    guarantor_postcode      TEXT,
    guarantor_country       TEXT,
    guarantor_phone         TEXT,
    guarantor_mobile        TEXT,
    guarantor_email         TEXT,
    guarantor_relation      TEXT,
    guarantor_profession    TEXT,
    kin_first_name  TEXT,
    kin_last_name   TEXT,
    kin_mobile      TEXT,
    bank_name       TEXT,
    ref_name        TEXT,
    ref_email       TEXT,
    ref_contact     TEXT,
    latest_credit_score         TEXT,
    latest_credit_description   TEXT,
    applicant_note  TEXT,
    manager_note    TEXT,
    source          TEXT,
    assigned_to     TEXT,
    matched_unit_ids TEXT,
    image_urls      TEXT,
    tags            TEXT,
    custom_fields   TEXT,
    modified        TEXT,
    created         TEXT
);

-- ── 6. TRANSACTIONS ───────────────────────────────────────────
CREATE TABLE IF NOT EXISTS transactions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    arthur_id       TEXT UNIQUE,
    ref             TEXT,
    transaction_type TEXT,
    payment_type    TEXT,
    description     TEXT,
    property_id     INTEGER,
    unit_id         INTEGER,
    tenancy_id      INTEGER,
    payee_tenant_id INTEGER,
    payee_name      TEXT,
    amount          REAL,
    amount_charged  REAL,
    amount_paid     REAL,
    amount_outstanding REAL,
    amount_net      REAL,
    amount_vat      REAL,
    date            TEXT,
    due_date        TEXT,
    is_overdue      INTEGER DEFAULT 0,
    is_outstanding  INTEGER DEFAULT 0,
    invoice_ref     TEXT,
    source          TEXT,
    created_by      TEXT,
    modified        TEXT,
    created         TEXT
);

-- ── 7. ACCESS RECORDS ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS access_records (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    property_id     INTEGER REFERENCES properties(id) ON DELETE CASCADE,
    unit_id         INTEGER REFERENCES units(id) ON DELETE SET NULL,
    type            TEXT,
    label           TEXT,
    identifier      TEXT,
    notes           TEXT,
    assigned_to     TEXT,
    issued_date     TEXT,
    returned_date   TEXT,
    created_at      TEXT DEFAULT (datetime('now')),
    updated_at      TEXT DEFAULT (datetime('now'))
);

-- ── 8. PROPERTY IMAGES ────────────────────────────────────────
CREATE TABLE IF NOT EXISTS property_images (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    property_id     INTEGER REFERENCES properties(id) ON DELETE CASCADE,
    unit_id         INTEGER REFERENCES units(id) ON DELETE SET NULL,
    category        TEXT,
    image_url       TEXT,
    caption         TEXT,
    sort_order      INTEGER DEFAULT 0,
    created_at      TEXT DEFAULT (datetime('now'))
);

-- ── INDEXES ───────────────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_properties_arthur_id ON properties(arthur_id);
CREATE INDEX IF NOT EXISTS idx_units_arthur_id     ON units(arthur_id);
CREATE INDEX IF NOT EXISTS idx_units_property_id   ON units(property_id);
CREATE INDEX IF NOT EXISTS idx_tenancies_arthur_id ON tenancies(arthur_id);
CREATE INDEX IF NOT EXISTS idx_tenancies_unit_id   ON tenancies(unit_id);
CREATE INDEX IF NOT EXISTS idx_tenants_arthur_id   ON tenants(arthur_id);
CREATE INDEX IF NOT EXISTS idx_tenants_tenancy_id  ON tenants(tenancy_id);
CREATE INDEX IF NOT EXISTS idx_applicants_arthur_id ON applicants(arthur_id);
CREATE INDEX IF NOT EXISTS idx_transactions_arthur_id   ON transactions(arthur_id);
CREATE INDEX IF NOT EXISTS idx_transactions_property_id ON transactions(property_id);
CREATE INDEX IF NOT EXISTS idx_transactions_unit_id     ON transactions(unit_id);
CREATE INDEX IF NOT EXISTS idx_transactions_tenancy_id  ON transactions(tenancy_id);
CREATE INDEX IF NOT EXISTS idx_access_records_property_id ON access_records(property_id);
CREATE INDEX IF NOT EXISTS idx_access_records_unit_id     ON access_records(unit_id);
CREATE INDEX IF NOT EXISTS idx_property_images_property_id ON property_images(property_id);
CREATE INDEX IF NOT EXISTS idx_property_images_unit_id     ON property_images(unit_id);

-- ── 9. MAINTENANCE JOBS (Operations Board) ──────────────────
CREATE TABLE IF NOT EXISTS maintenance_jobs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    monday_id       TEXT UNIQUE,
    reference       TEXT,
    property_id     INTEGER REFERENCES properties(id) ON DELETE SET NULL,
    address         TEXT,
    title           TEXT NOT NULL,
    description     TEXT,
    type            TEXT,
    priority        TEXT DEFAULT 'Medium',
    status          TEXT DEFAULT 'PENDING',
    location        TEXT,
    contractor      TEXT,
    labour_cost     REAL DEFAULT 0,
    materials_cost  REAL DEFAULT 0,
    total_cost      REAL DEFAULT 0,
    bill_ll         INTEGER DEFAULT 0,
    ll_informed     INTEGER DEFAULT 0,
    ll_informed_via TEXT,
    ll_notes        TEXT,
    reporter_name   TEXT,
    reporter_email  TEXT,
    emergency       INTEGER DEFAULT 0,
    source          TEXT DEFAULT 'board',
    photo_paths     TEXT,
    invoice_paths   TEXT,
    team_notes      TEXT,
    tenant_id       INTEGER REFERENCES tenants(id) ON DELETE SET NULL,
    created         TEXT DEFAULT (datetime('now')),
    modified        TEXT DEFAULT (datetime('now')),
    start_date      TEXT,
    completed_date  TEXT
);

-- ── 10. MAINTENANCE ORDERS ───────────────────────────────────
CREATE TABLE IF NOT EXISTS maintenance_orders (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id          INTEGER REFERENCES maintenance_jobs(id) ON DELETE CASCADE,
    item_name       TEXT NOT NULL,
    supplier        TEXT,
    order_ref       TEXT,
    cost            REAL DEFAULT 0,
    status          TEXT DEFAULT 'ordered',
    tracking_url    TEXT,
    estimated_delivery TEXT,
    delivered_at    TEXT,
    received_by     TEXT,
    notes           TEXT,
    created         TEXT DEFAULT (datetime('now')),
    modified        TEXT DEFAULT (datetime('now'))
);

-- ── 11. LANDLORD COMMUNICATIONS ──────────────────────────────
CREATE TABLE IF NOT EXISTS ll_communications (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id          INTEGER REFERENCES maintenance_jobs(id) ON DELETE CASCADE,
    contact_method  TEXT NOT NULL,
    contact_ref     TEXT,
    summary         TEXT,
    ll_response     TEXT,
    sent_at         TEXT,
    responded_at    TEXT,
    created         TEXT DEFAULT (datetime('now'))
);

-- ── 12. DEPOSITS ─────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS deposits (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    tenancy_id          INTEGER NOT NULL REFERENCES tenancies(id) ON DELETE CASCADE,
    tenant_id           INTEGER REFERENCES tenants(id) ON DELETE SET NULL,
    unit_id             INTEGER REFERENCES units(id) ON DELETE SET NULL,
    property_id         INTEGER REFERENCES properties(id) ON DELETE SET NULL,
    amount              REAL NOT NULL DEFAULT 0,
    deposit_type        TEXT NOT NULL DEFAULT 'cash',  -- 'cash', 'reposit', 'guarantee'
    scheme              TEXT,  -- 'MyDeposits', 'DPS', 'TDS', 'Reposit'
    protection_status   TEXT NOT NULL DEFAULT 'unprotected',  -- 'protected', 'unprotected', 'returned', 'deducted'
    protection_reference TEXT,
    date_received       TEXT,
    date_protected      TEXT,
    date_returned       TEXT,
    amount_returned     REAL DEFAULT 0,
    deductions          REAL DEFAULT 0,
    current_status      TEXT NOT NULL DEFAULT 'held',  -- 'held', 'returned', 'deducted', 'pending'
    source              TEXT DEFAULT 'tenancy',  -- 'tenancy', 'manual', 'migration'
    notes               TEXT,
    created             TEXT NOT NULL DEFAULT (datetime('now')),
    modified            TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_deposits_tenancy_id   ON deposits(tenancy_id);
CREATE INDEX IF NOT EXISTS idx_deposits_tenant_id    ON deposits(tenant_id);
CREATE INDEX IF NOT EXISTS idx_deposits_unit_id      ON deposits(unit_id);
CREATE INDEX IF NOT EXISTS idx_deposits_property_id  ON deposits(property_id);
CREATE INDEX IF NOT EXISTS idx_deposits_current_status ON deposits(current_status);
CREATE INDEX IF NOT EXISTS idx_deposits_protection_status ON deposits(protection_status);
"""

def init_db():
    with _lock:
        conn = get_db()
        try:
            conn.executescript(SCHEMA_SQL)
            conn.commit()
        finally:
            conn.close()
            _vos_local.conn = None


def dict_from_row(row):
    return None if row is None else dict(row)


def insert(table, data):
    keys = [k for k in data if data[k] is not None]
    vals = [data[k] for k in keys]
    cols = ", ".join(keys)
    ph = ", ".join(["?" for _ in keys])
    with _lock:
        conn = get_db()
        cur = conn.execute(f"INSERT INTO {table} ({cols}) VALUES ({ph})", vals)
        conn.commit()
        return cur.lastrowid


def _log_sync_conflict(table, row_id, detail=""):
    """Record that an inbound overwrite was blocked to protect a local edit."""
    try:
        conn = get_db()
        arthur_id = ""
        r = conn.execute(f"SELECT arthur_id FROM {table} WHERE id = ?", (row_id,)).fetchone()
        if r:
            arthur_id = str(r[0] or "")
        conn.execute(
            "INSERT INTO sync_conflicts (table_name,row_id,arthur_id,detected_at,direction,detail) "
            "VALUES (?,?,?,?,?,?)",
            (table, row_id, arthur_id, datetime.now(timezone.utc).isoformat(), "pull_blocked", detail),
        )
        conn.commit()
    except Exception:
        pass


def update(table, row_id, data, mark_dirty=False):
    now = datetime.now(timezone.utc).isoformat()
    data["modified"] = now
    if mark_dirty:
        # Local (Banksia OS) edit: flag for push-back to Arthur and protect
        # this record from being overwritten by the next inbound pull sync.
        data["sync_dirty"] = 1
        data["local_modified"] = now
        data["sync_origin"] = "banksia_os"
    else:
        # Inbound/programmatic update. Never clobber a local edit that has not
        # yet been pushed back to Arthur (sync_dirty=1). Skip and log instead.
        try:
            _c = get_db()
            _r = _c.execute(f"SELECT sync_dirty FROM {table} WHERE id = ?", (row_id,)).fetchone()
            if _r and (_r[0] or 0) == 1:
                _log_sync_conflict(table, row_id, "inbound pull blocked; local edit pending push")
                return
        except sqlite3.OperationalError:
            pass  # table has no sync_dirty column (e.g. transactions) -> proceed
    items = [(k, data[k]) for k in data if data[k] is not None]
    if not items:
        return
    sc = ", ".join([f"{k} = ?" for k, _ in items])
    vals = [v for _, v in items] + [row_id]
    with _lock:
        conn = get_db()
        conn.execute(f"UPDATE {table} SET {sc} WHERE id = ?", vals)
        conn.commit()


def get(table, row_id):
    with _lock:
        conn = get_db()
        return dict_from_row(conn.execute(f"SELECT * FROM {table} WHERE id = ?", (row_id,)).fetchone())


def get_by_field(table, field, value):
    with _lock:
        conn = get_db()
        return [dict(r) for r in conn.execute(f"SELECT * FROM {table} WHERE {field} = ?", (value,)).fetchall()]


def list_all(table, order="id DESC", limit=500, off=0):
    with _lock:
        conn = get_db()
        return [dict(r) for r in conn.execute(f"SELECT * FROM {table} ORDER BY {order} LIMIT ? OFFSET ?", (limit, off)).fetchall()]


def count(table, where="1=1", params=None):
    if params is None: params = []
    with _lock:
        conn = get_db()
        row = conn.execute(f"SELECT COUNT(*) as cnt FROM {table} WHERE {where}", params).fetchone()
        return row["cnt"] if row else 0


def raw_query(sql, params=None):
    if params is None: params = []
    with _lock:
        conn = get_db()
        return [dict(r) for r in conn.execute(sql, params).fetchall()]


def raw_execute(sql, params=None):
    if params is None: params = []
    with _lock:
        conn = get_db()
        conn.execute(sql, params)
        conn.commit()


if __name__ == "__main__":
    init_db()
    print(f"Database initialised at {DB_PATH}")
    for tbl in ["properties","units","tenancies","tenants","applicants","transactions","access_records","property_images"]:
        print(f"  {tbl}: {count(tbl)}")