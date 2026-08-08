#!/usr/bin/env python3
"""
Banksia OS Database Layer.
SQLite-backed persistent store mirroring
the HMO rental operations data model.
Complete schema with all fields.
"""
import json, os, sqlite3, time, uuid, threading
from datetime import datetime, timezone
from threading import Lock

DB_PATH = os.path.join(os.path.dirname(__file__), "banksia_os.db")
_lock = Lock()
# Per-thread connections for request-scoped use
_vos_local = threading.local()
# Track connection age for automatic eviction
_MAX_CONN_AGE = 300  # 5 minutes — recycle threads older than this
_CONN_MAX_PER_WORKER = 2  # Max 2 connections per thread (one Row, one dict)

def _reconnect_if_stale(conn_key):
    """Check if the thread-local connection is too old and replace it.
    Prevents connections from accumulating stale transaction state."""
    conn = getattr(_vos_local, conn_key, None)
    if conn is not None:
        try:
            conn.execute("SELECT 1")
            return
        except (sqlite3.ProgrammingError, sqlite3.OperationalError):
            pass
        try:
            conn.close()
        except Exception:
            pass
        setattr(_vos_local, conn_key, None)
    # Connection was stale or missing — create new one

def get_db():
    """Per-thread database connection. Each thread keeps its own connection
    — never shared across threads. check_same_thread=False only disables
    SQLite's Python ownership check, not thread safety.
    Automatically reconnects if the connection has gone stale.
    """
    _reconnect_if_stale('conn')
    if not hasattr(_vos_local, 'conn') or _vos_local.conn is None:
        conn = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=15000")
        _vos_local.conn = conn
    return _vos_local.conn


def get_dict_db():
    """Get DB connection with dict row factory.
    Uses a separate thread-local connection so the main get_db() row factory
    is never mutated. This prevents a dict query from leaking its row_factory
    to a subsequent Row-query in the same request.
    Automatically reconnects if the connection has gone stale.
    """
    _reconnect_if_stale('dict_conn')
    if not hasattr(_vos_local, 'dict_conn') or _vos_local.dict_conn is None:
        conn = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=30)
        conn.row_factory = lambda c, r: {col[0]: r[idx] for idx, col in enumerate(c.description)}
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=15000")
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
    created         TEXT,
    status          TEXT DEFAULT 'active'
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

-- ── 13. MIGRATION LOG ────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS migration_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    version TEXT NOT NULL,
    start_time TEXT NOT NULL,
    completion_time TEXT,
    user_process TEXT,
    records_reviewed INTEGER DEFAULT 0,
    records_inserted INTEGER DEFAULT 0,
    records_skipped INTEGER DEFAULT 0,
    records_updated INTEGER DEFAULT 0,
    errors INTEGER DEFAULT 0,
    checksum TEXT,
    status TEXT NOT NULL DEFAULT 'in_progress',
    notes TEXT
);

-- ── 14. ACTIVITY LOG ───────────────────────────────────────────
CREATE TABLE IF NOT EXISTS activity_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    entity_type TEXT NOT NULL,
    entity_id INTEGER NOT NULL,
    action TEXT NOT NULL,
    field_changed TEXT,
    old_value TEXT,
    new_value TEXT,
    user_name TEXT NOT NULL DEFAULT 'system',
    notes TEXT,
    created TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_activity_entity ON activity_log(entity_type, entity_id);
CREATE INDEX IF NOT EXISTS idx_activity_created ON activity_log(created);

-- ── 15. FIELD OVERRIDES (Arthur sync protection) ────────────────
-- One row per field a member of staff has edited inside Banksia OS.
-- The inbound Arthur pull strips these fields out of its update, so a
-- local edit is never overwritten, while every field nobody has touched
-- keeps syncing from Arthur normally.
CREATE TABLE IF NOT EXISTS field_overrides (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    table_name  TEXT NOT NULL,
    row_id      INTEGER NOT NULL,
    field       TEXT NOT NULL,
    local_value TEXT,
    set_at      TEXT NOT NULL,
    set_by      TEXT NOT NULL DEFAULT 'system',
    released_at TEXT,
    UNIQUE(table_name, row_id, field)
);
CREATE INDEX IF NOT EXISTS idx_field_overrides_row ON field_overrides(table_name, row_id);
CREATE INDEX IF NOT EXISTS idx_field_overrides_live ON field_overrides(table_name, row_id, released_at);

-- ── 16. ARTHUR SHADOW (last value Arthur sent, per row) ─────────
-- The baseline for detecting a local edit. If the live row no longer matches
-- the shadow on a field, somebody changed it inside Banksia OS, whichever of
-- the ~70 write paths they used. That is how a local edit is detected without
-- every endpoint having to remember to flag itself.
CREATE TABLE IF NOT EXISTS arthur_shadow (
    table_name  TEXT NOT NULL,
    row_id      INTEGER NOT NULL,
    payload     TEXT NOT NULL,
    updated_at  TEXT NOT NULL,
    PRIMARY KEY (table_name, row_id)
);
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


# Tables mirrored from Arthur. Only these carry sync tracking columns.
SYNCED_TABLES = {"properties", "units", "tenancies", "tenants", "applicants"}
# Never claimable as a local override — identity and tracking columns.
_NEVER_OVERRIDE = {"id", "arthur_id", "sync_dirty", "local_modified",
                   "sync_origin", "pushed_at", "modified", "created"}


def record_field_override(table, row_id, field, value, actor="system"):
    """Claim one field on one row as locally owned.

    After this, the inbound Arthur pull will leave that field alone for good.
    Called by every staff-initiated write path. Safe to call repeatedly — the
    latest local value simply replaces the stored one.
    """
    if table not in SYNCED_TABLES or field in _NEVER_OVERRIDE or not row_id:
        return
    try:
        conn = get_db()
        conn.execute(
            "INSERT INTO field_overrides (table_name,row_id,field,local_value,set_at,set_by,released_at) "
            "VALUES (?,?,?,?,?,?,NULL) "
            "ON CONFLICT(table_name,row_id,field) DO UPDATE SET "
            "  local_value=excluded.local_value, set_at=excluded.set_at, "
            "  set_by=excluded.set_by, released_at=NULL",
            (table, int(row_id), field, None if value is None else str(value),
             datetime.now(timezone.utc).isoformat(), actor or "system"),
        )
        conn.commit()
    except Exception:
        pass


def record_field_overrides(table, row_id, data, actor="system", only_fields=None):
    """Claim several fields at once. `data` is the dict that was just written."""
    if table not in SYNCED_TABLES or not row_id:
        return
    for k, v in (data or {}).items():
        if only_fields is not None and k not in only_fields:
            continue
        record_field_override(table, row_id, k, v, actor)


def release_field_override(table, row_id, field):
    """Hand a field back to Arthur — it will be overwritten by the next pull.

    The shadow has to move with it. Otherwise the live value still differs from
    the last thing Arthur sent, the next pull reads that as a fresh local edit
    and immediately re-claims the field, which is the permanent freeze this
    whole design exists to avoid.
    """
    try:
        conn = get_db()
        conn.execute(
            "UPDATE field_overrides SET released_at = ? "
            "WHERE table_name = ? AND row_id = ? AND field = ? AND released_at IS NULL",
            (datetime.now(timezone.utc).isoformat(), table, int(row_id), field),
        )
        conn.commit()
        cur = get(table, row_id) or {}
        shadow = get_shadow(table, row_id)
        shadow[field] = _shadow_val(cur.get(field))
        set_shadow(table, row_id, shadow)
    except Exception:
        pass


def overridden_fields(table, row_id):
    """Set of field names on this row that Banksia OS owns."""
    if table not in SYNCED_TABLES or not row_id:
        return set()
    try:
        conn = get_db()
        rows = conn.execute(
            "SELECT field FROM field_overrides "
            "WHERE table_name = ? AND row_id = ? AND released_at IS NULL",
            (table, int(row_id)),
        ).fetchall()
        return {r[0] for r in rows}
    except Exception:
        return set()


def overridden_fields_bulk(table):
    """{row_id: {field, ...}} for a whole table — one query per sync run
    instead of one per record, which matters at 7,000+ transactions."""
    out = {}
    if table not in SYNCED_TABLES:
        return out
    try:
        conn = get_db()
        for r in conn.execute(
            "SELECT row_id, field FROM field_overrides "
            "WHERE table_name = ? AND released_at IS NULL", (table,)
        ).fetchall():
            out.setdefault(r[0], set()).add(r[1])
    except Exception:
        pass
    return out


def get_shadow(table, row_id):
    """The field values Arthur last sent for this row, or {} if never seen."""
    try:
        conn = get_db()
        r = conn.execute(
            "SELECT payload FROM arthur_shadow WHERE table_name = ? AND row_id = ?",
            (table, int(row_id)),
        ).fetchone()
        return json.loads(r[0]) if r and r[0] else {}
    except Exception:
        return {}


def set_shadow(table, row_id, payload):
    """Store what Arthur just sent, as the baseline for the next pull."""
    try:
        conn = get_db()
        conn.execute(
            "INSERT INTO arthur_shadow (table_name,row_id,payload,updated_at) VALUES (?,?,?,?) "
            "ON CONFLICT(table_name,row_id) DO UPDATE SET "
            "  payload=excluded.payload, updated_at=excluded.updated_at",
            (table, int(row_id), json.dumps({k: _shadow_val(v) for k, v in (payload or {}).items()}),
             datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()
    except Exception:
        pass


def _shadow_val(v):
    """Compare everything as text — SQLite is loosely typed and Arthur sends
    numbers as strings about half the time."""
    return "" if v is None else str(v)


def guarded_update(table, row_id, data, actor="arthur_sync"):
    """Apply an inbound Arthur payload, keeping any field staff have changed.

    Compares the live row against the shadow (what Arthur last sent). A field
    that no longer matches was edited inside Banksia OS, so it is claimed as a
    local override and dropped from this update. Everything nobody has touched
    syncs normally.

    This is deliberately done here rather than in each of the ~70 endpoints that
    write to these tables: an endpoint can forget to flag itself, a value that
    differs from Arthur cannot.

    Returns (applied_fields, kept_local_fields).
    """
    if table not in SYNCED_TABLES:
        update(table, row_id, dict(data))
        return list(data.keys()), []
    shadow = get_shadow(table, row_id)
    current = get(table, row_id) or {}
    kept = []
    if shadow:
        for field in list(data.keys()):
            if field in _NEVER_OVERRIDE or field not in shadow:
                continue
            if _shadow_val(current.get(field)) != _shadow_val(shadow.get(field)):
                # Live value drifted from Arthur's last -> a person changed it.
                record_field_override(table, row_id, field, current.get(field), actor="banksia_os")
                kept.append(field)
    # Anything already claimed stays claimed even if the values happen to agree.
    owned = overridden_fields(table, row_id)
    payload = {k: v for k, v in data.items() if k not in owned and k not in kept}
    if payload:
        update(table, row_id, dict(payload))
    if kept:
        _log_sync_conflict(table, row_id, "kept local value for: " + ", ".join(sorted(set(kept))))
    # Baseline is always what Arthur said, including fields we chose not to
    # apply — so a field stays protected for as long as it differs from Arthur.
    set_shadow(table, row_id, data)
    return list(payload.keys()), sorted(set(kept))


def update(table, row_id, data, mark_dirty=False, _owned=None):
    now = datetime.now(timezone.utc).isoformat()
    data["modified"] = now
    if mark_dirty:
        # Local (Banksia OS) edit: flag for push-back to Arthur and claim every
        # field written here so the next inbound pull cannot undo it.
        data["sync_dirty"] = 1
        data["local_modified"] = now
        data["sync_origin"] = "banksia_os"
        record_field_overrides(table, row_id, data)
    else:
        # Inbound pull from Arthur. Drop any field Banksia OS owns and write the
        # rest, so a record keeps syncing on the fields nobody has touched.
        # `_owned` lets a sync run pass in a pre-fetched set (see
        # overridden_fields_bulk) rather than hitting the DB per row.
        owned = overridden_fields(table, row_id) if _owned is None else set(_owned or ())
        if owned:
            blocked = [k for k in data if k in owned]
            if blocked:
                for k in blocked:
                    data.pop(k, None)
                _log_sync_conflict(
                    table, row_id,
                    "inbound pull kept local value for: " + ", ".join(sorted(blocked)))
        if not [k for k in data if k not in ("modified",)]:
            return  # nothing left but the timestamp — don't touch the row
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