#!/usr/bin/env python3
"""
Banksia OS — HMO Operations API Blueprint.
Provides all HMO operations endpoints for daily team use.
Mounts at /api/banksia-os/
"""
import json, os, sys
from datetime import datetime, timezone, timedelta

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from flask import Blueprint, jsonify, request, session
from functools import wraps

from verv_os_db import get_db, get_dict_db, count, dict_from_row, raw_query

banksia_os_bp = Blueprint("banksia_os", __name__, url_prefix="/api/banksia-os")


# ── Global auth for the entire blueprint ──
@banksia_os_bp.before_request
def _require_banksia_auth():
    """All routes in this blueprint require a logged-in session."""
    # Public routes that don't need auth
    public_prefixes = ("/submissions/public", "/applicants/public", "/tenancies/public")
    if request.path.startswith(public_prefixes):
        return None
    user = session.get("user")
    if not user:
        return jsonify({"success": False, "error": "Not logged in"}), 401
    request.current_user = user


# ── Helpers ──

def bool_fields(row, *fields):
    """Convert 0/1 int fields to bool in-place."""
    for f in fields:
        if f in row:
            row[f] = bool(row[f])
    return row


def paginate(query, count_query, params, page, per_page):
    """Run a paginated query returning (rows, total)."""
    db = get_dict_db()
    try:
        total = db.execute(count_query, params).fetchone()["cnt"]
        offset = (page - 1) * per_page
        rows = db.execute(query + " LIMIT ? OFFSET ?", params + [per_page, offset]).fetchall()
        return rows, total
    finally:
        db.close()


def json_success(data, total=None, page=None, per_page=None):
    """Standard success response."""
    resp = {"success": True, "data": data}
    if total is not None:
        resp["total"] = total
        resp["page"] = page or 1
        resp["per_page"] = per_page or 20
    return jsonify(resp)


def json_error(msg, status=400):
    return jsonify({"success": False, "error": msg}), status


def clean_none(row):
    """Replace all None values in a dict with empty string, recursing into nested dicts/lists."""
    if row is None:
        return ""
    if isinstance(row, dict):
        return {k: clean_none(v) for k, v in row.items()}
    if isinstance(row, list):
        return [clean_none(v) for v in row]
    if row is None:
        return ""
    return row


# ── User helpers ──
USERS_FILE = os.path.join(os.path.dirname(__file__), "users.json")

def _load_users():
    if not os.path.exists(USERS_FILE):
        return {"Sami": {"password": "Newpassword1323!", "role": "super_admin"}}
    return json.load(open(USERS_FILE))

def _save_users(users):
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=2)


def int_param(val, default=1):
    try:
        return max(1, int(val))
    except (TypeError, ValueError):
        return default


def build_search_clause(fields, search_term):
    """Build a WHERE clause fragment for searching across multiple TEXT fields."""
    if not search_term:
        return "", []
    clauses = [f"{f} LIKE ?" for f in fields]
    like_val = f"%{search_term}%"
    params = [like_val] * len(fields)
    return f"({' OR '.join(clauses)})", params


def api_update_resource(table, item_id):
    """Generic PATCH handler — updates any field on any table by item ID."""
    data = request.get_json()
    if not data:
        return json_error("No data provided")
    # Build SET clause from provided fields
    set_parts = []
    params = []
    valid_tables = {"properties", "units", "tenancies", "tenants", "applicants", "property_owners", "message_threads"}
    if table not in valid_tables:
        return json_error(f"Invalid table: {table}", 400)
    # Tables mirrored from Arthur carry dirty-tracking columns. Any local edit
    # must flag the row so (a) the inbound pull sync won't overwrite it and
    # (b) the push-back sync knows to send the change to Arthur.
    SYNCED_TABLES = {"properties", "units", "tenancies", "tenants", "applicants"}
    protected_keys = {"sync_dirty", "local_modified", "sync_origin", "pushed_at", "arthur_id", "id"}
    # Introspect the real columns so an unknown field from the client is ignored
    # rather than crashing the UPDATE with a 500 "no such column" error.
    _col_db = get_dict_db()
    try:
        real_cols = {r["name"] for r in _col_db.execute(f"PRAGMA table_info({table})").fetchall()}
    finally:
        _col_db.close()
    ignored = []
    for key, val in data.items():
        if key in protected_keys:
            continue  # never let the client set tracking/identity fields directly
        if key not in real_cols:
            ignored.append(key)
            continue  # skip fields that don't exist on this table
        set_parts.append(f"{key} = ?")
        params.append(val)
    if not set_parts:
        return json_error(f"No valid fields to update (ignored: {', '.join(ignored) or 'none'})")
    if table in SYNCED_TABLES:
        _now = datetime.now(timezone.utc).isoformat()
        set_parts.append("sync_dirty = ?");    params.append(1)
        set_parts.append("local_modified = ?"); params.append(_now)
        set_parts.append("sync_origin = ?");    params.append("banksia_os")
    params.append(item_id)
    db = get_dict_db()
    try:
        db.execute(f"UPDATE {table} SET {', '.join(set_parts)} WHERE id = ?", params)
        db.commit()
        updated_fields = [k for k in data.keys() if k in real_cols and k not in protected_keys]
        return json_success({"updated": True, "id": item_id, "fields": updated_fields, "ignored": ignored})
    except Exception as e:
        return json_error(str(e), 500)
    finally:
        db.close()


# ═══════════════════════════════════════════════
# 1. DASHBOARD SUMMARY
# ═══════════════════════════════════════════════

@banksia_os_bp.route("/dashboard")
def api_dashboard():
    db = get_dict_db()
    try:
        # Total properties
        total_properties = db.execute("SELECT COUNT(*) AS cnt FROM properties").fetchone()["cnt"]

        # Total units
        total_units = db.execute("SELECT COUNT(*) AS cnt FROM units").fetchone()["cnt"]

        # Occupied / vacant units
        occupied_units = db.execute(
            "SELECT COUNT(*) AS cnt FROM units WHERE unit_vacant = 0"
        ).fetchone()["cnt"]
        vacant_units = db.execute(
            "SELECT COUNT(*) AS cnt FROM units WHERE unit_vacant = 1"
        ).fetchone()["cnt"]

        # Total tenancies & tenants
        total_tenancies = db.execute("SELECT COUNT(*) AS cnt FROM tenancies").fetchone()["cnt"]
        total_tenants = db.execute("SELECT COUNT(*) AS cnt FROM tenants").fetchone()["cnt"]
        total_applicants = db.execute("SELECT COUNT(*) AS cnt FROM applicants").fetchone()["cnt"]

        # Active tenancies — Arthur statuses: Current, Periodic, Active
        active_statuses = ("'Current', 'current', 'Periodic', 'periodic', 'Active', 'active'")
        active_tenancies = db.execute(
            f"SELECT COUNT(*) AS cnt FROM tenancies WHERE status IN ({active_statuses})"
        ).fetchone()["cnt"]

        # Monthly rent roll — active tenancies only
        monthly_rent_roll = db.execute(
            f"SELECT COALESCE(SUM(rent_amount), 0) AS total FROM tenancies "
            f"WHERE status IN ({active_statuses})"
        ).fetchone()["total"]

        # Total arrears
        total_arrears = db.execute(
            "SELECT COALESCE(SUM(amount_outstanding), 0) AS total FROM transactions "
            "WHERE is_outstanding = 1"
        ).fetchone()["total"]

        # Pending applicants
        pending_applicants = db.execute(
            "SELECT COUNT(*) AS cnt FROM applicants WHERE status IN ('Active', 'active', 'Pending', 'pending', 'New', 'new', 'Viewing', 'viewing', 'Application', 'application', 'Referencing', 'referencing')"
        ).fetchone()["cnt"]

        # Deposits — currently held (from deposits table)
        currently_held = db.execute(
            "SELECT COALESCE(SUM(amount), 0) AS total FROM deposits WHERE current_status = 'held'"
        ).fetchone()["total"]

        all_time_deposits = db.execute(
            "SELECT COALESCE(SUM(amount), 0) AS total FROM deposits"
        ).fetchone()["total"]

        deposits_unregistered = db.execute(
            "SELECT COUNT(*) AS cnt FROM deposits WHERE protection_status != 'protected' AND current_status = 'held'"
        ).fetchone()["cnt"]

        now = datetime.now(timezone.utc)
        month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0).isoformat()
        if now.month == 12:
            next_month = now.replace(year=now.year + 1, month=1, day=1)
        else:
            next_month = now.replace(month=now.month + 1, day=1)
        month_end = next_month.isoformat()

        tenants_moving_in_this_month = db.execute(
            "SELECT COUNT(*) AS cnt FROM tenancies "
            "WHERE move_in_date >= ? AND move_in_date < ? "
            "AND status IN ('Active', 'active', 'Periodic', 'periodic')",
            (month_start, month_end)
        ).fetchone()["cnt"]

        tenants_moving_out_this_month = db.execute(
            "SELECT COUNT(*) AS cnt FROM tenancies "
            "WHERE move_out_date >= ? AND move_out_date < ? "
            "AND status IN ('Active', 'active', 'Periodic', 'periodic')",
            (month_start, month_end)
        ).fetchone()["cnt"]

        # Unit occupancy rate
        unit_occupancy_rate = round((occupied_units / total_units * 100) if total_units > 0 else 0, 1)

        # ── Portal / referencing submissions awaiting the team ──
        # Referencing forms the applicant has actually submitted but nobody has reviewed
        pending_referencing_submissions = db.execute(
            "SELECT COUNT(*) AS cnt FROM referencing_forms "
            "WHERE submitted_at IS NOT NULL AND reviewed_at IS NULL "
            "AND status IN ('submitted', 'Submitted')"
        ).fetchone()["cnt"]
        # Tenant-portal maintenance requests still open
        open_maintenance_requests = db.execute(
            "SELECT COUNT(*) AS cnt FROM maintenance_requests "
            "WHERE LOWER(COALESCE(status, 'open')) IN ('open', 'new', '')"
        ).fetchone()["cnt"]
        # Portal message threads still open
        open_message_threads = db.execute(
            "SELECT COUNT(*) AS cnt FROM message_threads "
            "WHERE LOWER(COALESCE(status, 'open')) IN ('open', 'new', '')"
        ).fetchone()["cnt"]
        # Applicant-uploaded documents awaiting the team to verify
        pending_document_uploads = db.execute(
            "SELECT COUNT(*) AS cnt FROM referencing_documents "
            "WHERE LOWER(COALESCE(uploaded_by, '')) = 'applicant' "
            "AND COALESCE(is_verified, 0) = 0"
        ).fetchone()["cnt"]
        new_submissions_total = (
            pending_referencing_submissions + open_maintenance_requests
            + open_message_threads + pending_document_uploads
        )

        # Leading property (highest total rent)
        leading = db.execute(
            "SELECT p.id, COALESCE(NULLIF(p.ref, ''), NULLIF(p.address_line_1, ''), p.name) AS name, "
            "SUM(t.rent_amount) AS total_rent FROM tenancies t "
            "JOIN properties p ON t.property_id = p.id "
            "WHERE t.status IN ('Current', 'Active', 'Periodic', 'current', 'active', 'periodic') "
            "GROUP BY p.id ORDER BY total_rent DESC LIMIT 1"
        ).fetchone()

        # ── Phase 2 additions ──

        # Vacant units list with property names
        vacant_units_list = db.execute(
            "SELECT u.id, u.unit_ref, u.market_rent, u.property_id, "
            "COALESCE(NULLIF(p.ref, ''), NULLIF(p.address_line_1, ''), p.name) AS property_name "
            "FROM units u "
            "JOIN properties p ON u.property_id = p.id "
            "WHERE u.unit_vacant = 1 "
            "ORDER BY p.name ASC, u.sort_order ASC, u.unit_ref ASC"
        ).fetchall()

        # Upcoming move-ins with tenant/property/unit details (this calendar month only)
        month_end_exclusive = next_month.isoformat()
        upcoming_move_ins = db.execute(
            "SELECT t.id AS tenancy_id, t.move_in_date, t.main_tenant_name, "
            "t.property_id, t.unit_id, "
            "COALESCE(NULLIF(p.ref, ''), NULLIF(p.address_line_1, ''), p.name) AS property_name, "
            "u.unit_ref "
            "FROM tenancies t "
            "JOIN properties p ON t.property_id = p.id "
            "JOIN units u ON t.unit_id = u.id "
            "WHERE t.move_in_date >= ? AND t.move_in_date < ? "
            "AND t.status IN ('Active', 'active', 'Periodic', 'periodic') "
            "ORDER BY t.move_in_date ASC",
            (month_start, month_end_exclusive)
        ).fetchall()

        # Upcoming move-outs with tenant/property/unit details (this calendar month only)
        upcoming_move_outs = db.execute(
            "SELECT t.id AS tenancy_id, t.move_out_date, t.main_tenant_name, "
            "t.property_id, t.unit_id, "
            "COALESCE(NULLIF(p.ref, ''), NULLIF(p.address_line_1, ''), p.name) AS property_name, "
            "u.unit_ref "
            "FROM tenancies t "
            "JOIN properties p ON t.property_id = p.id "
            "JOIN units u ON t.unit_id = u.id "
            "WHERE t.move_out_date >= ? AND t.move_out_date < ? "
            "AND t.status IN ('Active', 'active', 'Periodic', 'periodic') "
            "ORDER BY t.move_out_date ASC",
            (month_start, month_end_exclusive)
        ).fetchall()

        # Referencing pipeline breakdown
        referencing_pipeline_raw = db.execute(
            "SELECT status, COUNT(*) AS count FROM referencing_forms GROUP BY status"
        ).fetchall()
        pipeline_map = {}
        for r in referencing_pipeline_raw:
            st = (r["status"] or "unknown").lower()
            pipeline_map[st] = r["count"]
        referencing_pipeline = {
            "new": pipeline_map.get("draft", 0) + pipeline_map.get("sent", 0),
            "submitted": pipeline_map.get("submitted", 0),
            "under_review": pipeline_map.get("under_review", 0),
            "approved": pipeline_map.get("approved", 0),
            "rejected": pipeline_map.get("rejected", 0),
            "declined": pipeline_map.get("rejected", 0) + pipeline_map.get("declined", 0),
            "tenancy_created": pipeline_map.get("tenancy_created", 0),
            "total": sum(pipeline_map.values()),
        }

        # Arrears by tenancy — count of affected tenancies and top arrears list
        tenancies_in_arrears_count = db.execute(
            "SELECT COUNT(DISTINCT tenancy_id) AS cnt FROM transactions "
            "WHERE is_outstanding = 1 AND tenancy_id IS NOT NULL "
            "AND amount_outstanding > 0"
        ).fetchone()["cnt"]

        arrears_by_tenancy = db.execute(
            "SELECT txn.tenancy_id, t.id AS local_tenancy_id, t.ref AS tenancy_ref, "
            "t.main_tenant_name, "
            "COALESCE(NULLIF(p.ref, ''), NULLIF(p.address_line_1, ''), p.name) AS property_name, "
            "SUM(COALESCE(txn.amount_outstanding, 0)) AS arrears_total "
            "FROM transactions txn "
            "LEFT JOIN tenancies t ON t.arthur_id = txn.tenancy_id "
            "LEFT JOIN properties p ON t.property_id = p.id "
            "WHERE txn.is_outstanding = 1 AND txn.amount_outstanding > 0 "
            "AND txn.tenancy_id IS NOT NULL "
            "GROUP BY txn.tenancy_id "
            "ORDER BY arrears_total DESC "
            "LIMIT 20"
        ).fetchall()
        arrears_by_tenancy_list = [
            {
                "tenancy_id": r["tenancy_id"],
                "tenancy_ref": r["tenancy_ref"],
                "tenant_name": r["main_tenant_name"],
                "property_name": r["property_name"],
                "arrears_total": round(r["arrears_total"], 2),
            }
            for r in arrears_by_tenancy
        ]

        return json_success({
            "total_properties": total_properties,
            "total_units": total_units,
            "occupied_units": occupied_units,
            "vacant_units": vacant_units,
            "total_tenancies": total_tenancies,
            "active_tenancies": active_tenancies,
            "total_tenants": total_tenants,
            "total_applicants": total_applicants,
            "monthly_rent_roll": round(monthly_rent_roll, 2),
            "monthly_rent_income": round(monthly_rent_roll, 2),
            "total_arrears": round(total_arrears, 2),
            "total_deposits_held": round(currently_held, 2),
            "total_deposits": round(currently_held, 2),
            "total_deposits_all_time": round(all_time_deposits, 2),
            "pending_applicants": pending_applicants,
            "total_pending_applicants": pending_applicants,
            "unit_occupancy_rate": unit_occupancy_rate,
            "recent_arrivals_count": tenants_moving_in_this_month,
            "upcoming_move_outs_count": tenants_moving_out_this_month,
            "tenants_moving_in_this_month": tenants_moving_in_this_month,
            "tenants_moving_out_this_month": tenants_moving_out_this_month,
            "deposits_unregistered": deposits_unregistered,
            "leading_property": ({"id": leading["id"], "name": leading["name"], "total_rent": round(leading["total_rent"] or 0, 2)} if leading and leading["name"] else None),
            "pending_referencing_submissions": pending_referencing_submissions,
            "open_maintenance_requests": open_maintenance_requests,
            "open_message_threads": open_message_threads,
            "pending_document_uploads": pending_document_uploads,
            "new_submissions_total": new_submissions_total,
            # Phase 2 additions
            "vacant_units_list": [{"id": r["id"], "unit_ref": r["unit_ref"], "market_rent": r["market_rent"], "property_id": r["property_id"], "property_name": r["property_name"]} for r in vacant_units_list],
            "upcoming_move_ins": [{"tenancy_id": r["tenancy_id"], "move_in_date": r["move_in_date"], "tenant_name": r["main_tenant_name"], "property_name": r["property_name"], "property_id": r["property_id"], "unit_ref": r["unit_ref"], "unit_id": r["unit_id"]} for r in upcoming_move_ins],
            "upcoming_move_outs": [{"tenancy_id": r["tenancy_id"], "move_out_date": r["move_out_date"], "tenant_name": r["main_tenant_name"], "property_name": r["property_name"], "property_id": r["property_id"], "unit_ref": r["unit_ref"], "unit_id": r["unit_id"]} for r in upcoming_move_outs],
            "referencing_pipeline": referencing_pipeline,
            "tenancies_in_arrears_count": tenancies_in_arrears_count,
            "arrears_by_tenancy": arrears_by_tenancy_list,
        })
    except Exception as e:
        return json_error(str(e), 500)
    finally:
        db.close()


# ═══════════════════════════════════════════════
# 1a. RECENT ACTIVITY FEED
#     Synthetic union of recent events across submissions, referencing,
#     maintenance requests, and tenancy changes. No new table required.
# ═══════════════════════════════════════════════

@banksia_os_bp.route("/dashboard/activity")
def api_dashboard_activity():
    db = get_dict_db()
    try:
        limit = int_param(request.args.get("limit", 30), 30)
        since = request.args.get("since")
        activity = []
        has_since = bool(since)

        # Build the WHERE/NULLIF based on whether 'since' param is provided
        def build_activity_query(base_select, base_from, date_col, extra_where="", extra_join=""):
            if has_since:
                where_clause = f"WHERE {date_col} IS NOT NULL AND {date_col} >= ?{extra_where}"
                params = [since]
            else:
                where_clause = f"WHERE {date_col} IS NOT NULL{extra_where}"
                params = []
            return f"{base_select} FROM {base_from} {extra_join} {where_clause}", params

        # 1. Referencing form submissions
        sql, params = build_activity_query(
            "SELECT id, 'referencing_submitted' AS event_type, submitted_at AS ts, "
            "COALESCE(NULLIF(first_name, ''), 'Applicant') || ' ' || COALESCE(NULLIF(last_name, ''), '') AS title, "
            "'Referencing form submitted' AS description, "
            "'referencing' AS category, 'referencing_form' AS link_type, id AS link_id, "
            "applicant_id AS related_id",
            "referencing_forms", "submitted_at"
        )
        rows = db.execute(sql, params).fetchall()
        for r in rows:
            activity.append(dict(r))

        # 2. Referencing reviews
        sql, params = build_activity_query(
            "SELECT id, 'referencing_reviewed' AS event_type, reviewed_at AS ts, "
            "COALESCE(NULLIF(first_name, ''), 'Applicant') || ' ' || COALESCE(NULLIF(last_name, ''), '') AS title, "
            "'Referencing reviewed by ' || COALESCE(reviewed_by, 'team') AS description, "
            "'referencing' AS category, 'referencing_form' AS link_type, id AS link_id, "
            "applicant_id AS related_id",
            "referencing_forms", "reviewed_at"
        )
        rows = db.execute(sql, params).fetchall()
        for r in rows:
            activity.append(dict(r))

        # 3. Maintenance requests
        sql, params = build_activity_query(
            "SELECT id, 'maintenance_created' AS event_type, created AS ts, "
            "COALESCE(title, 'Maintenance request') AS title, "
            "COALESCE(category, 'General') || ' - ' || COALESCE(reporter_name, 'Tenant') AS description, "
            "'maintenance' AS category, 'maintenance_request' AS link_type, id AS link_id, "
            "property_id AS related_id",
            "maintenance_requests", "created"
        )
        rows = db.execute(sql, params).fetchall()
        for r in rows:
            activity.append(dict(r))

        # 4. Tenancy changes (new tenancies created)
        sql, params = build_activity_query(
            "SELECT t.id, 'tenancy_created' AS event_type, t.created AS ts, "
            "COALESCE(t.main_tenant_name, 'Tenant') || ' - ' || "
            "COALESCE(NULLIF(p.ref, ''), NULLIF(p.address_line_1, ''), p.name) AS title, "
            "'New tenancy created' AS description, "
            "'tenancy' AS category, 'tenancy' AS link_type, t.id AS link_id, "
            "t.property_id AS related_id",
            "tenancies t", "t.created",
            extra_join="JOIN properties p ON t.property_id = p.id"
        )
        rows = db.execute(sql, params).fetchall()
        for r in rows:
            activity.append(dict(r))

        # 5. Message threads
        sql, params = build_activity_query(
            "SELECT id, 'message_created' AS event_type, created AS ts, "
            "COALESCE(title, 'Message thread') AS title, "
            "'New message thread opened' AS description, "
            "'message' AS category, 'message_thread' AS link_type, id AS link_id, "
            "property_id AS related_id",
            "message_threads", "created"
        )
        rows = db.execute(sql, params).fetchall()
        for r in rows:
            activity.append(dict(r))

        # Sort by timestamp descending and limit.
        # Timestamps arrive in two shapes across source tables: tz-aware ISO
        # ('2026-07-12T17:06:22+00:00') and naive ('2026-07-12 17:28:05').
        # Normalise both to 'YYYY-MM-DD HH:MM:SS' so same-day events from
        # different sources order truly chronologically, not by raw byte value.
        def _norm_ts(item):
            ts = item.get("ts") or ""
            ts = ts.replace("T", " ")
            if len(ts) >= 20 and ts[19] in "+-":
                ts = ts[:19]
            elif ts.endswith("Z"):
                ts = ts[:-1]
            return ts[:19]

        activity.sort(key=_norm_ts, reverse=True)
        activity = activity[:limit]

        return json_success(activity, total=len(activity), page=1, per_page=limit)
    except Exception as e:
        return json_error(str(e), 500)
    finally:
        db.close()


# ═══════════════════════════════════════════════
# 1b. SUBMISSIONS INBOX
#     Unified feed of everything submitted via the tenant portal and the
#     referencing portal, so the team can find it all from one screen.
# ═══════════════════════════════════════════════
@banksia_os_bp.route("/submissions")
def api_submissions():
    db = get_dict_db()
    try:
        limit = int_param(request.args.get("limit", 60), 60)
        stype = (request.args.get("type") or "all").lower()      # all|referencing|maintenance|message
        only_new = str(request.args.get("new", "")).lower() in ("1", "true", "yes")
        items = []

        # 1. Referencing form submissions — only those the applicant actually submitted
        if stype in ("all", "referencing"):
            rows = db.execute(
                "SELECT id, applicant_id, status, submitted_at, reviewed_at, reviewed_by, "
                "first_name, last_name, email, mobile_phone, preferred_move_in_date "
                "FROM referencing_forms WHERE submitted_at IS NOT NULL "
                "ORDER BY submitted_at DESC"
            ).fetchall()
            for r in rows:
                st = (r["status"] or "").lower()
                needs = (r["reviewed_at"] is None) and st == "submitted"
                name = f"{(r['first_name'] or '').strip()} {(r['last_name'] or '').strip()}".strip()
                items.append({
                    "kind": "referencing",
                    "kind_label": "Referencing",
                    "id": r["id"],
                    "ref": "REF-%05d" % r["id"],
                    "title": name or "Applicant referencing",
                    "subtitle": r["email"] or r["mobile_phone"] or "",
                    "status": r["status"] or "submitted",
                    "needs_attention": needs,
                    "timestamp": r["submitted_at"],
                    "link_type": "referencing_form",
                    "link_id": r["id"],
                    "applicant_id": r["applicant_id"],
                })

        # 2. Maintenance requests raised from the tenant portal
        if stype in ("all", "maintenance"):
            rows = db.execute(
                "SELECT id, reference, tenancy_id, property_id, reporter_name, reporter_email, "
                "category, title, priority, status, created "
                "FROM maintenance_requests ORDER BY created DESC"
            ).fetchall()
            for r in rows:
                needs = (r["status"] or "open").lower() in ("open", "new", "")
                items.append({
                    "kind": "maintenance",
                    "kind_label": "Maintenance",
                    "id": r["id"],
                    "ref": r["reference"] or ("MR-%05d" % r["id"]),
                    "title": r["title"] or "Maintenance request",
                    "subtitle": "%s · %s" % ((r["reporter_name"] or "Tenant"), (r["category"] or "General")),
                    "status": r["status"] or "open",
                    "priority": r["priority"],
                    "needs_attention": needs,
                    "timestamp": r["created"],
                    "link_type": "maintenance_request",
                    "link_id": r["id"],
                    "property_id": r["property_id"],
                    "tenancy_id": r["tenancy_id"],
                })

        # 3. Portal message threads
        if stype in ("all", "message"):
            rows = db.execute(
                "SELECT t.id, t.title, t.status, t.property_id, t.tenancy_id, t.created, "
                "COUNT(m.id) AS msg_count, MAX(m.created) AS last_message "
                "FROM message_threads t "
                "LEFT JOIN messages m ON m.thread_id = t.id "
                "AND (m.is_deleted IS NULL OR m.is_deleted = 0) "
                "GROUP BY t.id ORDER BY COALESCE(MAX(m.created), t.created) DESC"
            ).fetchall()
            for r in rows:
                needs = (r["status"] or "open").lower() in ("open", "new", "")
                cnt = r["msg_count"] or 0
                items.append({
                    "kind": "message",
                    "kind_label": "Message",
                    "id": r["id"],
                    "ref": "MSG-%05d" % r["id"],
                    "title": r["title"] or "Message thread",
                    "subtitle": "%d message%s" % (cnt, "" if cnt == 1 else "s"),
                    "status": r["status"] or "open",
                    "needs_attention": needs,
                    "timestamp": r["last_message"] or r["created"],
                    "link_type": "message_thread",
                    "link_id": r["id"],
                    "property_id": r["property_id"],
                    "tenancy_id": r["tenancy_id"],
                })

        # 4. Documents uploaded by the applicant via the tenant / referencing portal
        if stype in ("all", "document"):
            rows = db.execute(
                "SELECT d.id, d.form_id, d.category, d.original_filename, d.file_size, "
                "d.mime_type, d.uploaded_at, d.is_verified, "
                "f.first_name, f.last_name, f.email "
                "FROM referencing_documents d "
                "LEFT JOIN referencing_forms f ON f.id = d.form_id "
                "WHERE LOWER(COALESCE(d.uploaded_by, '')) = 'applicant' "
                "ORDER BY d.uploaded_at DESC"
            ).fetchall()
            for r in rows:
                needs = not bool(r["is_verified"])
                name = f"{(r['first_name'] or '').strip()} {(r['last_name'] or '').strip()}".strip()
                cat = (r["category"] or "document").replace("_", " ")
                items.append({
                    "kind": "document",
                    "kind_label": "Document",
                    "id": r["id"],
                    "ref": "DOC-%05d" % r["id"],
                    "title": r["original_filename"] or "Uploaded document",
                    "subtitle": "%s · %s" % ((name or r["email"] or "Applicant"), cat),
                    "status": "verified" if r["is_verified"] else "awaiting review",
                    "needs_attention": needs,
                    "timestamp": r["uploaded_at"],
                    "link_type": "referencing_document",
                    "link_id": r["id"],
                    "form_id": r["form_id"],
                })

        # Unified feed — newest first (rows with no timestamp fall to the bottom)
        items.sort(key=lambda x: (x["timestamp"] or ""), reverse=True)
        if only_new:
            items = [i for i in items if i["needs_attention"]]
        counts = {
            "referencing": sum(1 for i in items if i["kind"] == "referencing"),
            "maintenance": sum(1 for i in items if i["kind"] == "maintenance"),
            "message": sum(1 for i in items if i["kind"] == "message"),
            "document": sum(1 for i in items if i["kind"] == "document"),
            "needs_attention": sum(1 for i in items if i["needs_attention"]),
        }
        items = items[:limit]
        return json_success({"items": items, "counts": counts}, total=len(items))
    except Exception as e:
        return json_error(str(e), 500)
    finally:
        db.close()


# ═══════════════════════════════════════════════
# 3. MAINTENANCE OPERATIONS PORTAL
# ═══════════════════════════════════════════════

MAINT_STATUSES = [
    "PENDING", "IN PROGRESS", "LIVE", "ON HOLD", "CANCELLED",
    "COMPLETED", "ACKNOWLEDGED", "WAITING INVOICE", "No Invoice Found", "Invoice Uploaded"
]

MAINT_TYPES = [
    "Heating", "Plumbing", "Electrical", "Utilities", "Furniture", "NA", "Cleaning",
    "Structural", "Appliances", "Refurbishment", "Certificate", "Orders",
    "Wall Repairs", "Painting", "Removal", "Locksmith", "Pest Control",
    "Small Repair", "Licenses", "Inspection", "Gardening"
]

MAINT_PRIORITIES = ["Emergency", "Critical", "High", "Medium", "Low"]


@banksia_os_bp.route("/maintenance/jobs", methods=["GET", "POST"])
def api_maintenance_jobs():
    if request.method == "POST":
        return api_create_maintenance_job()
    db = get_dict_db()
    try:
        page = int_param(request.args.get("page"))
        per_page = int_param(request.args.get("per_page"), 50)
        search = (request.args.get("search") or "").strip()
        status_filter = request.args.get("status", "")
        type_filter = request.args.get("type", "")
        priority_filter = request.args.get("priority", "")
        contractor_filter = request.args.get("contractor", "")
        bill_ll_only = request.args.get("bill_ll", "") == "1"
        ll_not_informed = request.args.get("ll_uninformed", "") == "1"

        where = ["1=1"]
        params = []

        if status_filter:
            where.append("mj.status = ?")
            params.append(status_filter)
        if type_filter:
            where.append("mj.type = ?")
            params.append(type_filter)
        if priority_filter:
            where.append("mj.priority = ?")
            params.append(priority_filter)
        if contractor_filter:
            where.append("mj.contractor = ?")
            params.append(contractor_filter)
        if bill_ll_only:
            where.append("mj.bill_ll = 1")
        if ll_not_informed:
            where.append("mj.bill_ll = 1 AND mj.ll_informed = 0")
        if search:
            where.append("(mj.title LIKE ? OR mj.description LIKE ? OR mj.address LIKE ? OR mj.reference LIKE ? OR mj.contractor LIKE ? OR mj.type LIKE ? OR mj.reporter_name LIKE ? OR mj.team_notes LIKE ?)")
            s = f"%{search}%"
            params.extend([s, s, s, s, s, s, s, s])

        where_clause = " AND ".join(where)

        total = db.execute(
            f"SELECT COUNT(*) AS cnt FROM maintenance_jobs mj WHERE {where_clause}",
            params
        ).fetchone()["cnt"]

        offset = (page - 1) * per_page
        rows = db.execute(
            f"""SELECT mj.*, p.name AS property_name
                FROM maintenance_jobs mj
                LEFT JOIN properties p ON mj.property_id = p.id
                WHERE {where_clause}
                ORDER BY
                    CASE mj.priority
                        WHEN 'Emergency' THEN 0 WHEN 'Critical' THEN 1
                        WHEN 'High' THEN 2 WHEN 'Medium' THEN 3 WHEN 'Low' THEN 4
                    END,
                    mj.created DESC
                LIMIT ? OFFSET ?""",
            params + [per_page, offset]
        ).fetchall()

        for r in rows:
            r["bill_ll"] = bool(r["bill_ll"])
            r["emergency"] = bool(r["emergency"])
            r["ll_informed"] = bool(r["ll_informed"])
            # Fetch order count
            o = db.execute(
                "SELECT COUNT(*) AS cnt FROM maintenance_orders WHERE job_id = ?",
                [r["id"]]
            ).fetchone()
            r["order_count"] = o["cnt"] if o else 0

        counts = {}
        for s in MAINT_STATUSES:
            c = db.execute("SELECT COUNT(*) AS cnt FROM maintenance_jobs WHERE status = ?", [s]).fetchone()
            counts[s] = c["cnt"] if c else 0

        return json_success(rows, total=total, page=page, per_page=per_page)
    except Exception as e:
        return json_error(str(e), 500)
    finally:
        db.close()


def api_create_maintenance_job():
    data = request.get_json(force=True, silent=True) or {}
    required = ["title"]
    for f in required:
        if not data.get(f):
            return json_error(f"'{f}' is required")
    db = get_dict_db()
    try:
        ref_prefix = "MJ"
        count = db.execute("SELECT COUNT(*) AS cnt FROM maintenance_jobs").fetchone()["cnt"]
        reference = f"{ref_prefix}-{str(count + 1).zfill(4)}"

        cur = db.execute(
            """INSERT INTO maintenance_jobs
               (reference, title, description, type, priority, status, location,
                property_id, address, contractor, labour_cost, materials_cost,
                bill_ll, emergency, reporter_name, reporter_email, team_notes, source)
               VALUES (?, ?, ?, ?, ?, 'PENDING', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            [
                reference,
                data.get("title"),
                data.get("description", ""),
                data.get("type"),
                data.get("priority", "Medium"),
                data.get("location"),
                data.get("property_id"),
                data.get("address"),
                data.get("contractor"),
                float(data.get("labour_cost", 0)),
                float(data.get("materials_cost", 0)),
                1 if data.get("bill_ll") else 0,
                1 if data.get("emergency") else 0,
                data.get("reporter_name", ""),
                data.get("reporter_email", ""),
                data.get("team_notes", ""),
                data.get("source", "board"),
            ]
        )
        db.commit()
        job_id = cur.lastrowid
        job = db.execute(
            """SELECT mj.*, p.name AS property_name
               FROM maintenance_jobs mj
               LEFT JOIN properties p ON mj.property_id = p.id
               WHERE mj.id = ?""",
            [job_id]
        ).fetchone()
        return json_success(dict(job)), 201
    except Exception as e:
        db.rollback()
        return json_error(str(e), 500)
    finally:
        db.close()


@banksia_os_bp.route("/maintenance/jobs/<int:job_id>", methods=["GET", "PATCH"])
def api_maintenance_job(job_id):
    db = get_dict_db()
    try:
        if request.method == "GET":
            job = db.execute(
                """SELECT mj.*, p.name AS property_name
                   FROM maintenance_jobs mj
                   LEFT JOIN properties p ON mj.property_id = p.id
                   WHERE mj.id = ?""",
                [job_id]
            ).fetchone()
            if not job:
                return json_error("Job not found", 404)
            # Get orders for this job
            orders = db.execute(
                "SELECT * FROM maintenance_orders WHERE job_id = ? ORDER BY created DESC",
                [job_id]
            ).fetchall()
            # Get LL communications
            ll_comms = db.execute(
                "SELECT * FROM ll_communications WHERE job_id = ? ORDER BY sent_at DESC",
                [job_id]
            ).fetchall()
            result = dict(job)
            result["orders"] = [dict(o) for o in orders]
            result["ll_comms"] = [dict(c) for c in ll_comms]
            result["bill_ll"] = bool(result["bill_ll"])
            result["emergency"] = bool(result["emergency"])
            result["ll_informed"] = bool(result["ll_informed"])
            return json_success(result)

        # PATCH
        data = request.get_json(force=True, silent=True) or {}
        allowed = [
            "title", "description", "type", "priority", "status", "location",
            "address", "contractor", "labour_cost", "materials_cost",
            "bill_ll", "ll_informed", "ll_informed_via", "ll_notes",
            "emergency", "reporter_name", "reporter_email", "photo_paths",
            "invoice_paths", "team_notes", "start_date", "completed_date"
        ]
        updates = []
        params = []
        for field in allowed:
            if field in data:
                val = data[field]
                if field in ("bill_ll", "emergency", "ll_informed"):
                    val = 1 if val else 0
                updates.append(f"{field} = ?")
                params.append(val)
        if not updates:
            return json_error("No valid fields to update")
        updates.append("modified = datetime('now')")
        params.append(job_id)
        db.execute(
            f"UPDATE maintenance_jobs SET {', '.join(updates)} WHERE id = ?",
            params
        )
        db.commit()

        # If status changed to COMPLETED, set completed_date
        if data.get("status") == "COMPLETED":
            db.execute(
                "UPDATE maintenance_jobs SET completed_date = datetime('now') WHERE id = ? AND completed_date IS NULL",
                [job_id]
            )
            db.commit()

        job = db.execute("SELECT * FROM maintenance_jobs WHERE id = ?", [job_id]).fetchone()
        # Mark for push-back to Monday (async sync will pick it up)
        try:
            db.execute(
                "UPDATE maintenance_jobs SET sync_pending = 1 WHERE id = ?",
                [job_id]
            )
            db.commit()
        except Exception:
            db.rollback()
        return json_success(dict(job))
    except Exception as e:
        db.rollback()
        return json_error(str(e), 500)
    finally:
        db.close()


# ── Promote portal maintenance request to tracked job ──
@banksia_os_bp.route("/maintenance/promote-from-portal", methods=["POST"])
def api_promote_portal_request():
    """Copy a maintenance_requests row into maintenance_jobs so it becomes
    visible on the team dashboard and can receive orders / LL comms / contractors."""
    data = request.get_json(force=True, silent=True) or {}
    req_id = data.get("request_id")
    if not req_id:
        return json_error("request_id is required")

    db = get_dict_db()
    try:
        req = db.execute(
            "SELECT * FROM maintenance_requests WHERE id = ?", [req_id]
        ).fetchone()
        if not req:
            return json_error("Portal request not found", 404)

        # Build reference
        ref_prefix = "MJ"
        count = db.execute("SELECT COUNT(*) AS cnt FROM maintenance_jobs").fetchone()["cnt"]
        reference = f"{ref_prefix}-{str(count + 1).zfill(4)}"

        cur = db.execute(
            """INSERT INTO maintenance_jobs
               (reference, title, description, type, priority, status, location,
                property_id, address, reporter_name, reporter_email, source, team_notes)
               VALUES (?, ?, ?, ?, ?, 'PENDING', ?, ?, ?, ?, ?, 'portal', ?)""",
            [
                reference,
                req.get("title") or req.get("category", "Maintenance request"),
                req.get("description", ""),
                req.get("category"),
                req.get("priority", "Medium"),
                req.get("location"),
                data.get("property_id") or req.get("property_id"),
                data.get("address", ""),
                req.get("reporter_name", ""),
                req.get("reporter_email", ""),
                data.get("notes", ""),
            ]
        )
        db.commit()
        job_id = cur.lastrowid

        # Update original request status to 'promoted'
        db.execute(
            "UPDATE maintenance_requests SET status = 'promoted' WHERE id = ?",
            [req_id]
        )
        db.commit()

        job = db.execute(
            "SELECT * FROM maintenance_jobs WHERE id = ?", [job_id]
        ).fetchone()
        return json_success(dict(job)), 201
    except Exception as e:
        db.rollback()
        return json_error(str(e), 500)
    finally:
        db.close()


# ── Maintenance Orders ──

@banksia_os_bp.route("/maintenance/orders", methods=["GET", "POST"])
def api_maintenance_orders():
    db = get_dict_db()
    try:
        if request.method == "POST":
            data = request.get_json(force=True, silent=True) or {}
            if not data.get("job_id"):
                return json_error("job_id is required")
            cur = db.execute(
                """INSERT INTO maintenance_orders
                   (job_id, item_name, supplier, order_ref, cost, status,
                    tracking_url, estimated_delivery, notes)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                [
                    data["job_id"], data.get("item_name"),
                    data.get("supplier"), data.get("order_ref"),
                    float(data.get("cost", 0)),
                    data.get("status", "ordered"),
                    data.get("tracking_url"),
                    data.get("estimated_delivery"),
                    data.get("notes", ""),
                ]
            )
            db.commit()
            return json_success({"id": cur.lastrowid}), 201

        # GET — list orders, optionally filtered by job_id
        job_id = request.args.get("job_id")
        if job_id:
            orders = db.execute(
                "SELECT * FROM maintenance_orders WHERE job_id = ? ORDER BY created DESC",
                [job_id]
            ).fetchall()
        else:
            orders = db.execute(
                """SELECT mo.*, mj.title AS job_title
                   FROM maintenance_orders mo
                   JOIN maintenance_jobs mj ON mo.job_id = mj.id
                   ORDER BY mo.created DESC LIMIT 100"""
            ).fetchall()
        return json_success([dict(o) for o in orders])
    except Exception as e:
        return json_error(str(e), 500)
    finally:
        db.close()


@banksia_os_bp.route("/maintenance/orders/<int:order_id>", methods=["PATCH"])
def api_maintenance_order(order_id):
    data = request.get_json(force=True, silent=True) or {}
    allowed = ["item_name", "supplier", "order_ref", "cost", "status",
               "tracking_url", "estimated_delivery", "delivered_at",
               "received_by", "notes"]
    updates = []
    params = []
    for field in allowed:
        if field in data:
            val = data[field]
            if field == "cost":
                val = float(val)
            updates.append(f"{field} = ?")
            params.append(val)
    if not updates:
        return json_error("No valid fields")
    updates.append("modified = datetime('now')")
    params.append(order_id)
    db = get_dict_db()
    try:
        db.execute(
            f"UPDATE maintenance_orders SET {', '.join(updates)} WHERE id = ?",
            params
        )
        db.commit()
        order = db.execute("SELECT * FROM maintenance_orders WHERE id = ?", [order_id]).fetchone()
        return json_success(dict(order))
    except Exception as e:
        return json_error(str(e), 500)
    finally:
        db.close()


# ── LL Communications ──

@banksia_os_bp.route("/maintenance/ll-comms", methods=["GET", "POST"])
def api_ll_comms():
    db = get_dict_db()
    try:
        if request.method == "POST":
            data = request.get_json(force=True, silent=True) or {}
            if not data.get("job_id"):
                return json_error("job_id is required")
            cur = db.execute(
                """INSERT INTO ll_communications
                   (job_id, contact_method, contact_ref, summary, ll_response, sent_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                [
                    data["job_id"], data.get("contact_method"),
                    data.get("contact_ref"), data.get("summary", ""),
                    data.get("ll_response", ""), data.get("sent_at"),
                ]
            )
            # Mark job as ll_informed
            db.execute(
                "UPDATE maintenance_jobs SET ll_informed = 1, ll_informed_via = ? WHERE id = ?",
                [data.get("contact_method"), data["job_id"]]
            )
            db.commit()
            return json_success({"id": cur.lastrowid}), 201

        job_id = request.args.get("job_id")
        if not job_id:
            return json_error("job_id is required")
        comms = db.execute(
            "SELECT * FROM ll_communications WHERE job_id = ? ORDER BY sent_at DESC",
            [job_id]
        ).fetchall()
        return json_success([dict(c) for c in comms])
    except Exception as e:
        return json_error(str(e), 500)
    finally:
        db.close()


# ── Maintenance lookup data ──

@banksia_os_bp.route("/maintenance/lookup")
def api_maintenance_lookup():
    return json_success({
        "statuses": MAINT_STATUSES,
        "types": MAINT_TYPES,
        "priorities": MAINT_PRIORITIES,
    })


# ── Monday.com sync endpoint ──

def _monday_graphql(mtok, query):
    """Execute a Monday.com GraphQL query and return the parsed result."""
    import urllib.request
    req = urllib.request.Request(
        "https://api.monday.com/v2",
        data=json.dumps({"query": query}).encode(),
        headers={"Authorization": mtok, "Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read())


def _parse_monday_cols(column_values):
    """Build a flat dict of {column_id: text} from Monday column_values list."""
    cols = {}
    for cv in column_values:
        cols[cv["id"]] = cv.get("text") or ""
    return cols


def _safe_status(val):
    if val not in MAINT_STATUSES:
        return "PENDING"
    return val


def _safe_priority(val):
    if val not in MAINT_PRIORITIES:
        return "Medium"
    return val


def _parse_photo_paths(cols):
    """Extract photo evidence URLs (comma-separated)."""
    val = cols.get("file_mm0v10xk", "")
    if not val:
        return ""
    # Multiple URLs are comma-separated in the text field
    return val


def _parse_invoice_paths(cols):
    """Extract contractor invoice URLs."""
    val = cols.get("file_mm0pryh", "")
    return val


@banksia_os_bp.route("/maintenance/sync-from-monday", methods=["POST"])
def api_sync_from_monday():
    """Pull jobs from Monday.com Maintenance Reports board into local DB.

    Performs a full re-sync:
      - Inserts new items (monday_id not seen before)
      - Updates existing items whose data has changed on Monday
      - Handles pagination (cursor-based) for boards with 200+ items
      - Maps the full set of columns to DB fields
    """
    mtok = None
    try:
        mtok = open("/root/.hermes/secrets/monday_token.txt").read().strip()
    except Exception:
        pass
    if not mtok:
        return json_error("Monday token not found")

    db = get_dict_db()
    try:
        # ── Fetch ALL items with cursor-based pagination ──
        all_items = []
        cursor = None
        page = 0

        while True:
            page_ql = f"items_page(limit:200" + (f',cursor:"{cursor}"' if cursor else "") + ")"
            q = (
                "{ boards(ids: [18401159622]) { id name "
                + page_ql
                + """ { cursor items {
                        id name column_values { id text value }
                    } } } }"""
            )
            data = _monday_graphql(mtok, q)
            page_data = (
                data.get("data", {})
                .get("boards", [{}])[0]
                .get("items_page", {})
            )
            items = page_data.get("items", [])
            cursor = page_data.get("cursor")
            all_items.extend(items)
            page += 1

            if not cursor or len(items) < 200:
                break

        # ── Process every item (INSERT or UPDATE) ──
        inserted = 0
        updated = 0
        unchanged = 0

        for item in all_items:
            cols = _parse_monday_cols(item.get("column_values", []))
            monday_id = item["id"]
            title = item.get("name", "")

            # Map Monday column IDs → DB fields
            status = _safe_status(cols.get("status", "PENDING"))
            priority = _safe_priority(cols.get("color_mm0p8qna", "Medium"))
            maint_type = cols.get("color_mm0vfxmq", "")
            address = (
                cols.get("short_text041ydfbp", "")
                or cols.get("long_text_mm50g0j6", "")
                or cols.get("board_relation_mm0p7cv6", "")
            )
            contractor = cols.get("color_mm0p4947", "")
            location = cols.get("dropdown_mm0p6nzm", "")

            # Labour & materials costs
            labour_raw = cols.get("numeric_mm0pndmj", "") or "0"
            materials_raw = cols.get("numeric_mm0p7jdn", "") or "0"
            try:
                labour_cost = float(labour_raw.replace("£", "").replace(",", "").strip())
            except (ValueError, AttributeError):
                labour_cost = 0.0
            try:
                materials_cost = float(materials_raw.replace("£", "").replace(",", "").strip())
            except (ValueError, AttributeError):
                materials_cost = 0.0

            # Boolean toggles
            bill_ll = 1 if cols.get("boolean_mm0phkaq", "") == "checked" else 0
            emergency = 1 if cols.get("boolean2hbqq7ey", "") == "checked" else 0

            # Reporter info
            reporter_name = cols.get("short_textcvckh2h3", "")
            reporter_email = cols.get("emailzit7svgb", "")

            # File paths (photo evidence + contractor invoices)
            photo_paths = _parse_photo_paths(cols)
            invoice_paths = _parse_invoice_paths(cols)

            # Check if this item already exists in local DB
            existing = db.execute(
                "SELECT id, status, priority, type, address, contractor, "
                "labour_cost, materials_cost, bill_ll, emergency, "
                "reporter_name, reporter_email, photo_paths, invoice_paths, "
                "location, description, team_notes "
                "FROM maintenance_jobs WHERE monday_id = ?",
                [monday_id],
            ).fetchone()

            if existing:
                # ── UPDATE existing row ──
                # Compare key fields to decide if an update is needed
                changed = False
                updates = {}
                compare_map = {
                    "title": title,
                    "status": status,
                    "priority": priority,
                    "type": maint_type,
                    "address": address,
                    "contractor": contractor,
                    "location": location,
                    "labour_cost": labour_cost,
                    "materials_cost": materials_cost,
                    "bill_ll": bill_ll,
                    "emergency": emergency,
                    "reporter_name": reporter_name,
                    "reporter_email": reporter_email,
                    "photo_paths": photo_paths,
                    "invoice_paths": invoice_paths,
                }
                for field, new_val in compare_map.items():
                    old_val = existing[field]
                    if old_val is None:
                        old_val = ""
                    # Normalise types for comparison
                    if isinstance(old_val, float) or isinstance(new_val, float):
                        if abs(float(old_val or 0) - float(new_val or 0)) > 0.001:
                            updates[field] = new_val
                            changed = True
                    elif str(old_val).strip() != str(new_val).strip():
                        updates[field] = new_val
                        changed = True

                if changed:
                    updates["modified"] = "datetime('now')"
                    set_clause = ", ".join(f"{k} = ?" for k in updates)
                    values = list(updates.values())
                    values.append(existing["id"])
                    db.execute(
                        f"UPDATE maintenance_jobs SET {set_clause} WHERE id = ?",
                        values,
                    )
                    updated += 1
                else:
                    unchanged += 1
            else:
                # ── INSERT new row ──
                db.execute(
                    """INSERT INTO maintenance_jobs
                       (monday_id, title, status, priority, type, address,
                        contractor, location, labour_cost, materials_cost,
                        bill_ll, emergency, reporter_name, reporter_email,
                        photo_paths, invoice_paths, source)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'monday')""",
                    [
                        monday_id,
                        title,
                        status,
                        priority,
                        maint_type,
                        address,
                        contractor,
                        location,
                        labour_cost,
                        materials_cost,
                        bill_ll,
                        emergency,
                        reporter_name,
                        reporter_email,
                        photo_paths,
                        invoice_paths,
                    ],
                )
                inserted += 1

        db.commit()
        return json_success(
            {
                "inserted": inserted,
                "updated": updated,
                "unchanged": unchanged,
                "total_on_monday": len(all_items),
            }
        )
    except Exception as e:
        return json_error(str(e), 500)
    finally:
        db.close()


# ═══════════════════════════════════════════════
# 2. PROPERTIES
# ═══════════════════════════════════════════════

@banksia_os_bp.route("/properties", methods=["GET", "POST"])
def api_properties():
    if request.method == "POST":
        return api_create_property()
    page = int_param(request.args.get("page"))
    per_page = int_param(request.args.get("per_page"), 20)
    search = request.args.get("search", "").strip()

    base_where = "1=1"
    base_params = []

    if search:
        search_clause, search_params = build_search_clause(
            ["name", "ref", "address_line_1", "city", "postcode"], search
        )
        base_where = search_clause
        base_params = search_params

    rows, total = paginate(
        f"SELECT *, "
        f"(SELECT COUNT(*) FROM units u WHERE u.property_id = properties.id) AS actual_units, "
        f"(SELECT COUNT(*) FROM units u WHERE u.property_id = properties.id AND u.unit_vacant = 0) AS occupied_units, "
        f"COALESCE((SELECT SUM(t.rent_amount) FROM tenancies t WHERE t.property_id = properties.id AND t.status IN ('Current','current','Periodic','periodic','Active','active')), 0) AS monthly_rent, "
        f"CASE WHEN (SELECT COUNT(*) FROM units u WHERE u.property_id = properties.id AND u.unit_vacant = 0) > 0 THEN 'Active' ELSE 'Vacant' END AS property_status "
        f"FROM properties WHERE {base_where} ORDER BY ref ASC",
        f"SELECT COUNT(*) AS cnt FROM properties WHERE {base_where}",
        base_params, page, per_page
    )

    return json_success(rows, total, page, per_page)


def api_create_property():
    """POST handler for creating a new property with onboarding details."""
    data = request.get_json()
    if not data:
        return json_error("No data provided")
    required = ["ref", "name"]
    for r in required:
        if not data.get(r):
            return json_error(f"'{r}' is required")

    db = get_dict_db()
    try:
        cols = ["ref", "name", "address_line_1", "address_line_2", "city", "county", "postcode", "country",
                "property_type", "total_units", "bedrooms", "bathrooms", "council_tax_band",
                "council_account_no", "property_owner_name", "features", "notes"]
        ins_cols = [c for c in cols if c in data]
        ins_vals = [data[c] for c in ins_cols]
        placeholders = ",".join(["?"] * len(ins_cols))
        cursor = db.execute(
            f"INSERT INTO properties ({','.join(ins_cols)}) VALUES ({placeholders})",
            ins_vals
        )
        db.commit()
        new_id = cursor.lastrowid
        return json_success({"id": new_id, "message": "Property created"}), 201
    except Exception as e:
        return json_error(str(e), 500)
    finally:
        db.close()


@banksia_os_bp.route("/properties/<int:prop_id>", methods=["GET", "PATCH"])
def api_property(prop_id):
    if request.method == "PATCH":
        return _api_patch_property(prop_id)
    db = get_dict_db()
    try:
        prop = db.execute("SELECT * FROM properties WHERE id = ?", (prop_id,)).fetchone()
        if not prop:
            return json_error("Property not found", 404)

        # ── Units (existing) ──
        units = db.execute("SELECT * FROM units WHERE property_id = ? ORDER BY sort_order ASC, unit_ref ASC", (prop_id,)).fetchall()
        for u in units:
            tn = db.execute("SELECT * FROM tenancies WHERE unit_id=? AND status IN ('Active','active','Periodic','periodic') ORDER BY id DESC LIMIT 1", (u["id"],)).fetchone()
            if tn:
                u["tenant_name"] = tn.get("main_tenant_name") or ""
                u["tenancy_id"] = tn["id"]
                u['tenancy_rent'] = tn.get('rent_amount', 0)
                u['tenancy_status'] = tn.get('status', '')
                u['deposit_amount'] = tn.get('deposit_registered_amount', 0) or 0
                cnt = db.execute("SELECT COUNT(*) AS cnt FROM tenants WHERE tenancy_id=?", (tn["id"],)).fetchone()
                u["occupant_count"] = cnt["cnt"] if cnt else 0
                first_t = db.execute("SELECT id FROM tenants WHERE tenancy_id=? LIMIT 1", (tn["id"],)).fetchone()
                u["tenant_id"] = first_t["id"] if first_t else None
            else:
                u["tenant_name"] = ""
                u["tenancy_id"] = None
                u["tenancy_rent"] = 0
                u["tenancy_status"] = ""
                u["occupant_count"] = 0
                u["tenant_id"] = None
        prop["units"] = units

        # ── Tenancies ──
        tenancies = db.execute(
            "SELECT t.*, u.unit_ref FROM tenancies t LEFT JOIN units u ON t.unit_id=u.id "
            "WHERE t.property_id=? AND t.status IN ('Active','active','Periodic','periodic') ORDER BY t.id DESC",
            (prop_id,)
        ).fetchall()
        prop["tenancies"] = [clean_none(dict(r)) for r in tenancies]

        # ── Tenants ──
        tenants = db.execute(
            "SELECT t.id, t.first_name, t.last_name, t.email, t.mobile, t.phone_home, "
            "t.title, t.date_of_birth, t.gender, t.main_tenant, t.tenancy_id, t.property_id, "
            "u.unit_ref, tn.start_date, tn.end_date, tn.rent_amount "
            "FROM tenants t "
            "JOIN tenancies tn ON t.tenancy_id=tn.id "
            "LEFT JOIN units u ON t.unit_id=u.id "
            "WHERE tn.property_id=? "
            "AND (t.main_tenant=1 OR t.status='active' OR t.status='Active') "
            "ORDER BY COALESCE(t.last_name,t.first_name)",
            (prop_id,)
        ).fetchall()
        # tenants use first_name/last_name — compose name
        for t in tenants:
            if not t.get("name") and t.get("first_name"):
                t["name"] = (t.get("first_name", "") or "") + " " + (t.get("last_name", "") or "")
        prop["tenants"] = [clean_none(dict(r)) for r in tenants]

        # ── Maintenance jobs ──
        maint = db.execute(
            "SELECT * FROM maintenance_jobs WHERE property_id=? ORDER BY created DESC LIMIT 20",
            (prop_id,)
        ).fetchall()
        prop["maintenance"] = [clean_none(dict(r)) for r in maint]

        # ── Documents ──
        docs = db.execute(
            "SELECT * FROM documents WHERE related_to='property' AND related_id=? ORDER BY created DESC LIMIT 20",
            (str(prop_id),)
        ).fetchall()
        prop["documents"] = [clean_none(dict(r)) for r in docs]

        # ── Activity ──
        activity = db.execute(
            "SELECT * FROM activity_log WHERE entity_type='property' AND entity_id=? ORDER BY created DESC LIMIT 20",
            (prop_id,)
        ).fetchall()
        prop["activity"] = [clean_none(dict(r)) for r in activity]

        return json_success(prop)
    except Exception as e:
        return json_error(str(e), 500)
    finally:
        db.close()


# ── Allowed fields for PATCH on properties (mass-assignment protection) ──
# All editable columns from the properties table except: id, arthur_id, created, modified,
# sync_dirty, local_modified, pushed_at, sync_origin, total_units, rentable_units.
ALLOWED_PROPERTY_FIELDS = {
    "name", "ref", "address_line_1", "address_line_2", "city", "county",
    "postcode", "country", "lat", "lng", "property_type",
    "property_owner_id", "property_owner_name",
    "max_occupancy", "bathrooms", "bedrooms", "kitchens", "floors",
    "council_tax_band", "council_account_no", "main_image_url", "image_urls", "epc_urls",
    "floor_plan_urls", "thumbnail_urls", "features", "notes", "tags",
    "custom_fields",
    # Extended HMO onboarding fields
    "status", "property_ref", "acquisition_date", "owner_company",
    "management_type", "monthly_property_rent", "management_fee",
    "contract_start", "contract_end", "notice_period_days",
    "deposit_paid_to_landlord", "responsible_manager",
    "is_hmo", "licence_number", "licence_expiry",
    "heating_type", "boiler_details", "utility_suppliers", "wifi_provider",
    "main_door_instructions", "keybox_location", "keybox_code",
    "smart_lock_provider", "smart_lock_code", "intercom_details",
    "alarm_details", "emergency_access_notes",
    "description", "internal_notes", "is_active",
}

SYNC_TABLES = {"properties", "units", "tenancies", "tenants", "applicants"}


def _api_patch_property(prop_id):
    """PATCH endpoint for properties with concurrency protection and audit logging."""
    data = request.get_json(silent=True)
    if not data:
        return json_error("No data provided", 400)

    # Separate concurrency token from payload
    provided_modified = data.pop("modified", None)

    db = get_dict_db()
    try:
        # 1. Fetch current property state
        prop = db.execute("SELECT * FROM properties WHERE id = ?", (prop_id,)).fetchone()
        if not prop:
            return json_error("Property not found", 404)

        # 2. Optimistic concurrency check
        if provided_modified is not None:
            current_modified = prop.get("modified")
            if current_modified and current_modified != provided_modified:
                return json_error({
                    "message": "Property was modified by another user. Please refresh and try again.",
                    "code": "CONCURRENCY_CONFLICT",
                    "current_modified": current_modified,
                    "your_modified": provided_modified,
                }, 409)

        # 3. Filter to allowed fields only (mass-assignment protection)
        real_cols = {r["name"] for r in db.execute("PRAGMA table_info(properties)").fetchall()}
        protected = {"id", "sync_dirty", "local_modified", "sync_origin", "pushed_at", "arthur_id"}

        updates = {}
        ignored = []
        for key, val in data.items():
            if key in protected:
                continue
            if key not in ALLOWED_PROPERTY_FIELDS:
                ignored.append(key)
                continue
            if key not in real_cols:
                continue
            updates[key] = val

        if not updates:
            return json_error(f"No valid fields to update (ignored: {', '.join(ignored) or 'none'})", 400)

        # 4. Build per-field activity descriptions and track changes
        activity_entries = []
        for key, val in updates.items():
            old_val = prop.get(key)
            # Convert to string for logging comparison
            old_str = str(old_val) if old_val is not None else None
            new_str = str(val) if val is not None else None
            if old_str != new_str:
                activity_entries.append({
                    "field_changed": key,
                    "old_value": old_str,
                    "new_value": new_str,
                })

        now = datetime.now(timezone.utc).isoformat()

        # 5. Apply update with sync tracking
        set_parts = [f"{k} = ?" for k in updates]
        params = list(updates.values())

        set_parts.append("modified = ?")
        params.append(now)

        if "properties" in SYNC_TABLES:
            set_parts.append("sync_dirty = ?")
            params.append(1)
            set_parts.append("local_modified = ?")
            params.append(now)
            set_parts.append("sync_origin = ?")
            params.append("banksia_os")

        params.append(prop_id)
        db.execute(
            f"UPDATE properties SET {', '.join(set_parts)} WHERE id = ?",
            params
        )
        db.commit()

        # 6. Log activity for each changed field
        user_name = getattr(request, "current_user", {}).get("username", "system")
        for entry in activity_entries:
            _log_activity(
                entity_type="property",
                entity_id=prop_id,
                action="update",
                field_changed=entry["field_changed"],
                old_value=entry["old_value"],
                new_value=entry["new_value"],
                notes=f"Property '{prop.get('name', '') or prop.get('ref', '')}' updated",
                db=db,
            )
        db.commit()

        return json_success({
            "updated": True,
            "id": prop_id,
            "fields": list(updates.keys()),
            "ignored": ignored,
            "modified": now,
        })
    except Exception as e:
        db.rollback()
        return json_error(str(e), 500)
    finally:
        db.close()


# ═══════════════════════════════════════════════
# 2b. PROPERTY DEPENDENCIES — for archive/delete UI
# ═══════════════════════════════════════════════

@banksia_os_bp.route("/properties/<int:prop_id>/dependencies", methods=["GET"])
def api_property_dependencies(prop_id):
    """Return counts of linked entities for archive/delete pre-checks."""
    db = get_dict_db()
    try:
        prop = db.execute("SELECT id FROM properties WHERE id = ?", (prop_id,)).fetchone()
        if not prop:
            return json_error("Property not found", 404)

        units = db.execute("SELECT COUNT(*) AS cnt FROM units WHERE property_id = ?", (prop_id,)).fetchone()["cnt"]

        active_statuses = ("'Current','current','Periodic','periodic','Active','active'")
        active_tenancies = db.execute(
            f"SELECT COUNT(*) AS cnt FROM tenancies WHERE property_id = ? AND status IN ({active_statuses})",
            (prop_id,)
        ).fetchone()["cnt"]

        total_tenancies = db.execute(
            "SELECT COUNT(*) AS cnt FROM tenancies WHERE property_id = ?",
            (prop_id,)
        ).fetchone()["cnt"]

        tenants = db.execute(
            "SELECT COUNT(*) AS cnt FROM tenants WHERE property_id = ?",
            (prop_id,)
        ).fetchone()["cnt"]

        # applicants don't have a property_id column — skip them
        applicants = 0

        documents = db.execute(
            "SELECT COUNT(*) AS cnt FROM documents WHERE related_to = 'property' AND related_id = ?",
            (str(prop_id),)
        ).fetchone()["cnt"]

        maintenance_jobs = db.execute(
            "SELECT COUNT(*) AS cnt FROM maintenance_jobs WHERE property_id = ?",
            (prop_id,)
        ).fetchone()["cnt"]

        # Also check for images
        images = db.execute(
            "SELECT COUNT(*) AS cnt FROM property_images WHERE property_id = ?",
            (prop_id,)
        ).fetchone()["cnt"]

        return json_success({
            "units": units,
            "active_tenancies": active_tenancies,
            "total_tenancies": total_tenancies,
            "tenants": tenants,
            "applicants": applicants,
            "documents": documents,
            "maintenance_jobs": maintenance_jobs,
            "images": images,
            "has_active_tenancies": active_tenancies > 0,
            "has_any_records": any([
                units, total_tenancies, tenants, applicants,
                documents, maintenance_jobs, images
            ]),
        })
    except Exception as e:
        return json_error(str(e), 500)
    finally:
        db.close()


# ═══════════════════════════════════════════════
# 2c. CREATE FULL PROPERTY — transactional multi-step
# ═══════════════════════════════════════════════

@banksia_os_bp.route("/properties/create-full", methods=["POST"])
def api_create_property_full():
    """Complete multi-step property creation in one transactional request.
    Creates the property record, optional units, access records, and property info.
    Rolls back entirely on any failure."""
    data = request.get_json(force=True, silent=True) or {}
    if not data:
        return json_error("No data provided")

    # Validate required fields
    required = ["name", "address_line_1", "postcode"]
    missing = [f for f in required if not data.get(f)]
    if missing:
        return json_error(f"Missing required fields: {', '.join(missing)}")

    db = get_dict_db()
    try:
        # ── 1. Build property insert ──
        property_fields = [
            "name", "address_line_1", "address_line_2", "city", "county",
            "postcode", "country", "property_ref", "property_type", "status",
            "acquisition_date", "property_owner_id", "owner_company",
            "management_type", "monthly_property_rent", "management_fee",
            "contract_start", "contract_end", "notice_period_days",
            "deposit_paid_to_landlord", "responsible_manager",
            "bedrooms", "bathrooms", "kitchens", "floors", "max_occupancy",
            "is_hmo", "licence_number", "licence_expiry",
            "notes",
        ]
        ins_cols = []
        ins_vals = []
        for f in property_fields:
            if f in data and data[f] is not None:
                val = data[f]
                if f == "is_hmo":
                    val = 1 if val else 0
                ins_cols.append(f)
                ins_vals.append(val)

        placeholders = ",".join(["?"] * len(ins_cols))
        cursor = db.execute(
            f"INSERT INTO properties ({','.join(ins_cols)}) VALUES ({placeholders})",
            ins_vals
        )
        property_id = cursor.lastrowid

        # ── 2. Create units if provided ──
        units_data = data.get("units", [])
        if units_data and isinstance(units_data, list):
            unit_fields = [
                "unit_ref", "unit_type", "floor", "bedrooms", "capacity",
                "market_rent", "furnished", "status", "unit_vacant", "sort_order",
            ]
            for u_data in units_data:
                u_ins_cols = ["property_id"]
                u_ins_vals = [property_id]
                for f in unit_fields:
                    if f in u_data and u_data[f] is not None:
                        val = u_data[f]
                        if f == "furnished":
                            val = 1 if val else 0
                        if f == "unit_vacant":
                            val = 1 if val else 0
                        u_ins_cols.append(f)
                        u_ins_vals.append(val)
                u_placeholders = ",".join(["?"] * len(u_ins_cols))
                db.execute(
                    f"INSERT INTO units ({','.join(u_ins_cols)}) VALUES ({u_placeholders})",
                    u_ins_vals
                )

        # ── 3. Create access record if provided ──
        access_data = data.get("access")
        if access_data and isinstance(access_data, dict):
            # Map the frontend fields to DB access_records columns
            access_field_map = {
                "main_door_instructions": "label",
                "keybox_location": "identifier",
                "keybox_code": "notes",
                "smart_lock_provider": "notes",
                "smart_lock_code": "notes",
                "intercom_details": "label",
                "alarm_details": "label",
                "keys_count": "notes",
                "key_holder": "assigned_to",
                "emergency_access_notes": "notes",
            }
            # Build a combined notes string and label from access data
            access_parts = []
            for k, v in access_data.items():
                if v and isinstance(v, str) and v.strip():
                    label = k.replace("_", " ").title()
                    access_parts.append(f"{label}: {v}")
            combined_notes = "; ".join(access_parts)

            db.execute(
                "INSERT INTO access_records (property_id, type, label, notes) VALUES (?, 'property_access', ?, ?)",
                [property_id, "Main Access", combined_notes]
            )

        # ── 4. Store property_info as notes if provided ──
        info_data = data.get("property_info")
        if info_data and isinstance(info_data, dict):
            info_parts = []
            for k, v in info_data.items():
                if v and isinstance(v, str) and v.strip():
                    label = k.replace("_", " ").title()
                    info_parts.append(f"{label}: {v}")
            if info_parts:
                info_str = "; ".join(info_parts)
                existing_notes = db.execute(
                    "SELECT notes FROM properties WHERE id = ?", (property_id,)
                ).fetchone()
                current_notes = existing_notes["notes"] or "" if existing_notes else ""
                if current_notes:
                    info_str = current_notes + "\n\n" + info_str
                db.execute(
                    "UPDATE properties SET notes = ? WHERE id = ?",
                    [info_str, property_id]
                )

        # ── 5. Create activity log ──
        _create_activity_log(db, "property_created", property_id,
                             f"Property '{data.get('name', '')}' created with {len(units_data) if units_data else 0} units")

        db.commit()
        return json_success({
            "id": property_id,
            "message": "Property created successfully",
            "units_created": len(units_data) if units_data else 0,
        }), 201

    except Exception as e:
        db.rollback()
        return json_error(str(e), 500)
    finally:
        db.close()


def _create_activity_log(db, action, resource_id, description, user=None):
    """Create an activity log entry. Writes to the activity_log table
    (used by the PATCH endpoint) as well as the legacy activity table."""
    if user is None:
        user = getattr(request, "current_user", {}).get("username", "system")
    try:
        now = datetime.now(timezone.utc).isoformat()

        # Write to activity_log table (primary, used by activity endpoints)
        try:
            db.execute(
                "INSERT INTO activity_log (entity_type, entity_id, action, user_name, notes, created) "
                "VALUES ('property', ?, ?, ?, ?, ?)",
                [resource_id, action, user, description, now]
            )
        except Exception:
            pass  # activity_log table may not exist

        # Legacy: Try activity table if it exists
        try:
            db.execute(
                "INSERT INTO activity (action, resource_type, resource_id, description, user, created_at) "
                "VALUES (?, 'property', ?, ?, ?, ?)",
                [action, resource_id, description, user, now]
            )
        except Exception:
            pass  # activity table doesn't exist — benign

        # Also try notifications table as a last fallback
        try:
            db.execute(
                "INSERT INTO notifications (type, title, message, created_at) "
                "VALUES ('activity', ?, ?, ?)",
                [f"{action}: {description}", f"Property #{resource_id}", now]
            )
        except Exception:
            pass  # No logging table at all — benign
    except Exception:
        pass  # Never let logging crash the main operation


# ── Sensitive fields that must be redacted from activity logs ──
SENSITIVE_FIELDS = {"keybox_code", "smart_lock_code", "alarm_code", "wifi_password"}


def _redact_if_sensitive(val):
    """Return '[REDACTED]' if val looks sensitive or is one of the sensitive fields."""
    return "[REDACTED]" if val is not None else None


def _log_activity(entity_type, entity_id, action, field_changed=None,
                  old_value=None, new_value=None, notes=None, db=None):
    """Log an activity entry to the activity_log table.

    Automatically redacts sensitive field values.
    If no db connection is provided, creates one (for use outside request context).
    
    For property updates, also creates notifications for the responsible_manager
    and all super_admin users.
    """
    # Redact sensitive fields
    if field_changed and field_changed in SENSITIVE_FIELDS:
        old_value = _redact_if_sensitive(old_value)
        new_value = _redact_if_sensitive(new_value)

    user_name = getattr(request, "current_user", {}).get("username", "system")
    own_conn = db is None
    if own_conn:
        db = get_dict_db()
    try:
        db.execute(
            "INSERT INTO activity_log (entity_type, entity_id, action, field_changed, "
            "old_value, new_value, user_name, notes) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            [entity_type, entity_id, action, field_changed, old_value, new_value, user_name, notes]
        )
        
        # For property updates, create notifications for responsible_manager + super_admins
        if entity_type == "property" and action == "update" and field_changed:
            try:
                now = datetime.now(timezone.utc).isoformat()
                prop = db.execute(
                    "SELECT name, ref, responsible_manager FROM properties WHERE id = ?",
                    (entity_id,)
                ).fetchone()
                if prop:
                    prop_label = prop.get("name") or prop.get("ref") or f"#{entity_id}"
                    rm = prop.get("responsible_manager") or ""
                    message = (f"{user_name} updated {field_changed} on property "
                               f"'{prop_label}' ({_format_value(old_value)} → {_format_value(new_value)})")
                    link = f"/banksia-os?entity=properties&id={entity_id}"
                    
                    # Notify responsible_manager
                    notified = set()
                    if rm and rm.strip():
                        db.execute(
                            "INSERT INTO notifications (username, message, link, read, created) "
                            "VALUES (?, ?, ?, 0, ?)",
                            (rm.strip(), message, link, now)
                        )
                        notified.add(rm.strip())
                    
                    # Notify super_admins (Sami, Roo, Norbert, Sadman) who aren't the updater
                    super_admins = ["Sami", "Roo", "Norbert", "Sadman"]
                    for sa in super_admins:
                        if sa not in notified and sa != user_name:
                            db.execute(
                                "INSERT INTO notifications (username, message, link, read, created) "
                                "VALUES (?, ?, ?, 0, ?)",
                                (sa, message, link, now)
                            )
                            notified.add(sa)
            except Exception:
                pass  # Never let notification creation crash logging
        
        if own_conn:
            db.commit()
    except Exception:
        pass  # Never let logging crash the main operation
    finally:
        if own_conn:
            db.close()


def _format_value(val):
    """Format a value for notification messages — truncate and clean up."""
    if val is None:
        return "∅"
    s = str(val)
    if len(s) > 60:
        s = s[:57] + "..."
    return s


# ═══════════════════════════════════════════════
# 2d. ARCHIVE PROPERTY — soft delete with dependency check
# ═══════════════════════════════════════════════

@banksia_os_bp.route("/properties/<int:prop_id>/archive", methods=["POST"])
def api_archive_property(prop_id):
    """Archive (soft delete) a property. Checks for active tenancies and
    other dependencies first. If dependencies exist, returns them so the
    UI can display what blocks archiving."""
    db = get_dict_db()
    try:
        prop = db.execute("SELECT * FROM properties WHERE id = ?", (prop_id,)).fetchone()
        if not prop:
            return json_error("Property not found", 404)

        # ── Aggregate all dependency counts ──
        active_statuses = ("'Current','current','Periodic','periodic','Active','active'")

        units_count = db.execute(
            "SELECT COUNT(*) AS cnt FROM units WHERE property_id = ?",
            (prop_id,)
        ).fetchone()["cnt"]

        tenants_count = db.execute(
            "SELECT COUNT(*) AS cnt FROM tenants WHERE property_id = ?",
            (prop_id,)
        ).fetchone()["cnt"]

        active_tenancies = db.execute(
            f"SELECT COUNT(*) AS cnt FROM tenancies "
            f"WHERE property_id = ? AND status IN ({active_statuses})",
            (prop_id,)
        ).fetchone()["cnt"]

        total_tenancies = db.execute(
            "SELECT COUNT(*) AS cnt FROM tenancies WHERE property_id = ?",
            (prop_id,)
        ).fetchone()["cnt"]

        active_jobs = db.execute(
            "SELECT COUNT(*) AS cnt FROM maintenance_jobs "
            "WHERE property_id = ? AND status NOT IN ('COMPLETED', 'CANCELLED', 'No Invoice Found')",
            (prop_id,)
        ).fetchone()["cnt"]

        total_jobs = db.execute(
            "SELECT COUNT(*) AS cnt FROM maintenance_jobs WHERE property_id = ?",
            (prop_id,)
        ).fetchone()["cnt"]

        dependencies = {
            "units": units_count,
            "tenants": tenants_count,
            "active_tenancies": active_tenancies,
            "total_tenancies": total_tenancies,
            "active_maintenance_jobs": active_jobs,
            "total_maintenance_jobs": total_jobs,
        }

        # ── If any blocking dependency exists, return dependency info ──
        blockers = []
        if active_tenancies > 0:
            blockers.append("active_tenancies")
        if active_jobs > 0:
            blockers.append("active_maintenance_jobs")

        if blockers:
            return json_success({
                "archived": False,
                "message": "Property has dependencies that prevent archiving",
                "dependencies": dependencies,
                "blockers": blockers,
            })

        # ── Perform archive ──
        db.execute(
            "UPDATE properties SET status = 'archived', modified = ? WHERE id = ?",
            [datetime.now(timezone.utc).isoformat(), prop_id]
        )

        _create_activity_log(db, "property_archived", prop_id,
                             f"Property '{prop.get('name', '') or prop.get('ref', '')}' archived")

        db.commit()
        return json_success({
            "id": prop_id,
            "message": "Property archived successfully",
            "status": "archived",
            "dependencies": dependencies,
        })

    except Exception as e:
        db.rollback()
        return json_error(str(e), 500)
    finally:
        db.close()


# ═══════════════════════════════════════════════
# 2e. RESTORE PROPERTY — undo archive
# ═══════════════════════════════════════════════

@banksia_os_bp.route("/properties/<int:prop_id>/restore", methods=["POST"])
def api_restore_property(prop_id):
    """Restore an archived property back to 'active' status."""
    db = get_dict_db()
    try:
        prop = db.execute("SELECT * FROM properties WHERE id = ?", (prop_id,)).fetchone()
        if not prop:
            return json_error("Property not found", 404)

        current_status = prop.get("status")
        if current_status != "archived":
            return json_error({
                "message": f"Property is not archived (current status: '{current_status}'). Only archived properties can be restored.",
                "code": "NOT_ARCHIVED",
                "current_status": current_status,
            }, 409)

        # Restore to active
        now = datetime.now(timezone.utc).isoformat()
        db.execute(
            "UPDATE properties SET status = 'active', modified = ? WHERE id = ?",
            [now, prop_id]
        )

        _create_activity_log(db, "property_restored", prop_id,
                             f"Property '{prop.get('name', '') or prop.get('ref', '')}' restored from archive")

        db.commit()
        return json_success({
            "id": prop_id,
            "message": "Property restored successfully",
            "status": "active",
        })

    except Exception as e:
        db.rollback()
        return json_error(str(e), 500)
    finally:
        db.close()


# ═══════════════════════════════════════════════
# 2f. DELETE PROPERTY — permanent removal (super_admin only)
# ═══════════════════════════════════════════════

@banksia_os_bp.route("/properties/<int:prop_id>/delete", methods=["POST"])
def api_delete_property(prop_id):
    """Permanently delete a property. Requires super_admin role,
    `?confirm=PROPERTY-NAME` query parameter, and no remaining
    operational records."""
    user = session.get("user", {})
    if user.get("role") != "super_admin":
        return json_error("Only super admins can permanently delete properties", 403)

    db = get_dict_db()
    try:
        prop = db.execute("SELECT * FROM properties WHERE id = ?", (prop_id,)).fetchone()
        if not prop:
            return json_error("Property not found", 404)

        # Require confirmation via ?confirm=<property-name>
        confirm = request.args.get("confirm", "")
        expected_name = prop.get("name", "") or prop.get("ref", "")
        if not confirm or confirm.strip() != expected_name:
            return json_error({
                "message": "Confirmation required. Pass ?confirm=<property-name> matching the property name.",
                "code": "CONFIRMATION_REQUIRED",
                "expected": expected_name,
                "provided": confirm,
            }, 400)

        # Check for any remaining records
        dependencies = {}

        units_count = db.execute(
            "SELECT COUNT(*) AS cnt FROM units WHERE property_id = ?", (prop_id,)
        ).fetchone()["cnt"]
        dependencies["units"] = units_count

        tenancies_count = db.execute(
            "SELECT COUNT(*) AS cnt FROM tenancies WHERE property_id = ?", (prop_id,)
        ).fetchone()["cnt"]
        dependencies["tenancies"] = tenancies_count

        tenants_count = db.execute(
            "SELECT COUNT(*) AS cnt FROM tenants WHERE property_id = ?", (prop_id,)
        ).fetchone()["cnt"]
        dependencies["tenants"] = tenants_count

        # applicants don't have a property_id column — skip them
        dependencies["applicants"] = 0

        documents_count = db.execute(
            "SELECT COUNT(*) AS cnt FROM documents WHERE related_to = 'property' AND related_id = ?",
            (str(prop_id),)
        ).fetchone()["cnt"]
        dependencies["documents"] = documents_count

        maintenance_count = db.execute(
            "SELECT COUNT(*) AS cnt FROM maintenance_jobs WHERE property_id = ?", (prop_id,)
        ).fetchone()["cnt"]
        dependencies["maintenance_jobs"] = maintenance_count

        images_count = db.execute(
            "SELECT COUNT(*) AS cnt FROM property_images WHERE property_id = ?", (prop_id,)
        ).fetchone()["cnt"]
        dependencies["images"] = images_count

        access_count = db.execute(
            "SELECT COUNT(*) AS cnt FROM access_records WHERE property_id = ?", (prop_id,)
        ).fetchone()["cnt"]
        dependencies["access_records"] = access_count

        # Check deposits
        deposits_count = 0
        try:
            deposits_count = db.execute(
                "SELECT COUNT(*) AS cnt FROM deposits WHERE property_id = ?", (prop_id,)
            ).fetchone()["cnt"]
        except Exception:
            pass
        dependencies["deposits"] = deposits_count

        # Check transactions
        try:
            transactions_count = db.execute(
                "SELECT COUNT(*) AS cnt FROM transactions WHERE property_id = ?", (prop_id,)
            ).fetchone()["cnt"]
        except Exception:
            transactions_count = 0
        dependencies["transactions"] = transactions_count

        has_history = any(v > 0 for v in dependencies.values())
        if has_history:
            return json_error({
                "message": "Cannot delete property with operational history",
                "code": "HAS_OPERATIONAL_HISTORY",
                "dependencies": {k: v for k, v in dependencies.items() if v > 0},
            }, 409)

        # Delete related records explicitly (CASCADE may not be configured)
        for table in ("access_records", "property_images", "documents"):
            try:
                if table == "documents":
                    db.execute(
                        f"DELETE FROM {table} WHERE related_to = 'property' AND related_id = ?",
                        (str(prop_id),)
                    )
                elif table == "access_records":
                    db.execute(f"DELETE FROM {table} WHERE property_id = ?", (prop_id,))
                else:
                    db.execute(f"DELETE FROM {table} WHERE property_id = ?", (prop_id,))
            except Exception:
                pass  # table may not exist

        # Delete the property
        db.execute("DELETE FROM properties WHERE id = ?", (prop_id,))

        _create_activity_log(db, "property_deleted", prop_id,
                             f"Property '{prop.get('name', '') or prop.get('ref', '')}' permanently deleted by {user.get('username', 'unknown')}")

        db.commit()
        return json_success({
            "id": prop_id,
            "message": "Property permanently deleted",
        })

    except Exception as e:
        db.rollback()
        return json_error(str(e), 500)
    finally:
        db.close()


# ═══════════════════════════════════════════════
# 2g. PROPERTY ACTIVITY LOG — activity history for a specific property
# ═══════════════════════════════════════════════

@banksia_os_bp.route("/properties/<int:prop_id>/activity", methods=["GET"])
def api_property_activity(prop_id):
    """Return paginated activity log entries for a specific property."""
    page = int_param(request.args.get("page"), default=1)
    limit = int_param(request.args.get("per_page", 50), default=50)
    offset = (page - 1) * limit

    db = get_dict_db()
    try:
        # Verify property exists
        prop = db.execute("SELECT id FROM properties WHERE id = ?", (prop_id,)).fetchone()
        if not prop:
            return json_error("Property not found", 404)

        total = db.execute(
            "SELECT COUNT(*) AS cnt FROM activity_log "
            "WHERE entity_type = 'property' AND entity_id = ?",
            (prop_id,)
        ).fetchone()["cnt"]

        rows = db.execute(
            "SELECT * FROM activity_log "
            "WHERE entity_type = 'property' AND entity_id = ? "
            "ORDER BY created DESC LIMIT ? OFFSET ?",
            (prop_id, limit, offset)
        ).fetchall()

        return json_success(rows, total=total, page=page, per_page=limit)
    except Exception as e:
        return json_error(str(e), 500)
    finally:
        db.close()


# ═══════════════════════════════════════════════
# 2h. ACTIVITY LOG — query and create entries
# ═══════════════════════════════════════════════

@banksia_os_bp.route("/activity", methods=["GET"])
def api_get_activity():
    """Query activity log. Supports filtering by entity_type + entity_id and pagination."""
    entity_type = request.args.get("entity_type", "")
    entity_id_str = request.args.get("entity_id", "")
    entity_id = int(entity_id_str) if entity_id_str and entity_id_str.isdigit() else None
    limit = int_param(request.args.get("limit", 50), default=50)
    page = int_param(request.args.get("page", 1), default=1)
    offset = (page - 1) * limit

    db = get_dict_db()
    try:
        if entity_type and entity_id is not None:
            total = db.execute(
                "SELECT COUNT(*) AS cnt FROM activity_log WHERE entity_type = ? AND entity_id = ?",
                (entity_type, entity_id)
            ).fetchone()["cnt"]
            rows = db.execute(
                "SELECT * FROM activity_log WHERE entity_type = ? AND entity_id = ? "
                "ORDER BY created DESC LIMIT ? OFFSET ?",
                (entity_type, entity_id, limit, offset)
            ).fetchall()
        else:
            total = db.execute("SELECT COUNT(*) AS cnt FROM activity_log").fetchone()["cnt"]
            rows = db.execute(
                "SELECT * FROM activity_log ORDER BY created DESC LIMIT ? OFFSET ?",
                (limit, offset)
            ).fetchall()

        return json_success(rows, total=total, page=page, per_page=limit)
    except Exception as e:
        return json_error(str(e), 500)
    finally:
        db.close()


@banksia_os_bp.route("/activity", methods=["POST"])
def api_create_activity():
    """Create an activity log entry programmatically."""
    data = request.get_json(silent=True)
    if not data:
        return json_error("No data provided", 400)

    entity_type = data.get("entity_type")
    entity_id = data.get("entity_id")
    action = data.get("action")

    if not all([entity_type, entity_id, action]):
        return json_error("entity_type, entity_id, and action are required", 400)

    field_changed = data.get("field_changed")
    old_value = data.get("old_value")
    new_value = data.get("new_value")
    notes = data.get("notes")

    _log_activity(
        entity_type=entity_type,
        entity_id=entity_id,
        action=action,
        field_changed=field_changed,
        old_value=old_value,
        new_value=new_value,
        notes=notes,
    )

    return json_success({"message": "Activity logged"})


# ═══════════════════════════════════════════════
# 2h. UNIT CRUD — create, edit, archive, delete, bulk-create
# ═══════════════════════════════════════════════

ALLOWED_UNIT_FIELDS = {
    "unit_ref", "unit_type", "floor", "bedrooms", "capacity",
    "market_rent", "furnished", "status", "notes",
    "unit_status", "max_occupancy", "bathrooms",
}


@banksia_os_bp.route("/properties/<int:prop_id>/units", methods=["POST"])
def api_create_unit_for_property(prop_id):
    """POST /api/banksia-os/properties/{prop_id}/units — create a unit."""
    data = request.get_json(silent=True)
    if not data:
        return json_error("No data provided", 400)

    unit_ref = data.get("unit_ref")
    unit_type = data.get("unit_type")
    if not unit_ref or not unit_type:
        return json_error("'unit_ref' and 'unit_type' are required", 400)

    db = get_dict_db()
    try:
        prop = db.execute("SELECT id FROM properties WHERE id = ?", (prop_id,)).fetchone()
        if not prop:
            return json_error("Property not found", 404)

        now = datetime.now(timezone.utc).isoformat()
        ins_cols = ["property_id", "unit_ref", "unit_type", "created", "modified"]
        ins_vals = [prop_id, unit_ref, unit_type, now, now]

        optional_fields = ["floor", "bedrooms", "capacity", "market_rent", "furnished", "status", "notes",
                           "unit_status", "max_occupancy", "bathrooms"]
        for f in optional_fields:
            if f in data:
                ins_cols.append(f)
                ins_vals.append(data[f])

        placeholders = ",".join(["?"] * len(ins_cols))
        cursor = db.execute(
            f"INSERT INTO units ({','.join(ins_cols)}) VALUES ({placeholders})",
            ins_vals
        )
        new_id = cursor.lastrowid
        db.commit()

        _log_activity("unit", new_id, "created",
                      notes=f"Unit '{unit_ref}' created on property #{prop_id}",
                      db=db)

        created = db.execute("SELECT * FROM units WHERE id = ?", (new_id,)).fetchone()
        return json_success(clean_none(dict(created))), 201
    except Exception as e:
        return json_error(str(e), 500)
    finally:
        db.close()


@banksia_os_bp.route("/units/<int:unit_id>", methods=["PATCH"])
def api_update_unit(unit_id):
    """PATCH /api/banksia-os/units/{unit_id} — edit a unit."""
    data = request.get_json(silent=True)
    if not data:
        return json_error("No data provided", 400)

    db = get_dict_db()
    try:
        unit = db.execute("SELECT * FROM units WHERE id = ?", (unit_id,)).fetchone()
        if not unit:
            return json_error("Unit not found", 404)

        now = datetime.now(timezone.utc).isoformat()
        updates = {}
        for key, val in data.items():
            if key in ALLOWED_UNIT_FIELDS:
                updates[key] = val

        if not updates:
            return json_error("No valid fields to update", 400)

        set_parts = [f"{k} = ?" for k in updates]
        params = list(updates.values())
        set_parts.append("modified = ?")
        params.append(now)
        params.append(unit_id)

        db.execute(f"UPDATE units SET {', '.join(set_parts)} WHERE id = ?", params)
        db.commit()

        _log_activity("unit", unit_id, "update",
                      notes=f"Unit '{unit.get('unit_ref', '')}' updated",
                      db=db)

        updated = db.execute("SELECT * FROM units WHERE id = ?", (unit_id,)).fetchone()
        return json_success(clean_none(dict(updated)))
    except Exception as e:
        return json_error(str(e), 500)
    finally:
        db.close()


@banksia_os_bp.route("/units/<int:unit_id>/archive", methods=["POST"])
def api_archive_unit(unit_id):
    """POST /api/banksia-os/units/{unit_id}/archive — soft-delete a unit."""
    db = get_dict_db()
    try:
        unit = db.execute("SELECT * FROM units WHERE id = ?", (unit_id,)).fetchone()
        if not unit:
            return json_error("Unit not found", 404)

        # Check for active tenancies
        active = db.execute(
            "SELECT COUNT(*) AS cnt FROM tenancies WHERE unit_id=? AND status IN ('Active','active','Periodic','periodic','Current','current')",
            (unit_id,)
        ).fetchone()["cnt"]
        if active > 0:
            return json_error(f"Cannot archive unit with {active} active tenanc{'y' if active == 1 else 'ies'}", 409)

        # Soft-archive by setting status to 'archived'
        now = datetime.now(timezone.utc).isoformat()
        db.execute(
            "UPDATE units SET status='archived', unit_vacant=1, modified=? WHERE id=?",
            (now, unit_id)
        )
        db.commit()

        _log_activity("unit", unit_id, "archived",
                      notes=f"Unit '{unit.get('unit_ref', '')}' archived",
                      db=db)

        return json_success({"id": unit_id, "message": "Unit archived successfully", "status": "archived"})
    except Exception as e:
        return json_error(str(e), 500)
    finally:
        db.close()


@banksia_os_bp.route("/units/<int:unit_id>/delete", methods=["POST"])
def api_delete_unit(unit_id):
    """POST /api/banksia-os/units/{unit_id}/delete — permanently delete a unit."""
    db = get_dict_db()
    try:
        unit = db.execute("SELECT * FROM units WHERE id = ?", (unit_id,)).fetchone()
        if not unit:
            return json_error("Unit not found", 404)

        # Check for active tenancies
        active = db.execute(
            "SELECT COUNT(*) AS cnt FROM tenancies WHERE unit_id=? AND status IN ('Active','active','Periodic','periodic','Current','current')",
            (unit_id,)
        ).fetchone()["cnt"]
        if active > 0:
            return json_error(f"Cannot delete unit with {active} active tenanc{'y' if active == 1 else 'ies'}", 409)

        # Delete related records first
        db.execute("UPDATE tenants SET unit_id=NULL, property_id=NULL WHERE unit_id=?", (unit_id,))
        db.execute("UPDATE tenancies SET unit_id=NULL WHERE unit_id=?", (unit_id,))
        db.execute("DELETE FROM units WHERE id=?", (unit_id,))
        db.commit()

        _log_activity("unit", unit_id, "deleted",
                      notes=f"Unit '{unit.get('unit_ref', '')}' permanently deleted",
                      db=db)

        return json_success({"id": unit_id, "message": "Unit permanently deleted"})
    except Exception as e:
        return json_error(str(e), 500)
    finally:
        db.close()


@banksia_os_bp.route("/properties/<int:prop_id>/units/bulk", methods=["POST"])
def api_bulk_create_units(prop_id):
    """POST /api/banksia-os/properties/{prop_id}/units/bulk — bulk-create units."""
    data = request.get_json(silent=True)
    if not data:
        return json_error("No data provided", 400)

    units_data = data.get("units", [])
    if not units_data or not isinstance(units_data, list):
        return json_error("'units' must be a non-empty array", 400)

    db = get_dict_db()
    try:
        prop = db.execute("SELECT id FROM properties WHERE id = ?", (prop_id,)).fetchone()
        if not prop:
            return json_error("Property not found", 404)

        now = datetime.now(timezone.utc).isoformat()
        created_ids = []
        errors = []

        for idx, unit_data in enumerate(units_data):
            unit_ref = unit_data.get("unit_ref")
            unit_type = unit_data.get("unit_type")
            if not unit_ref or not unit_type:
                errors.append({"index": idx, "error": "'unit_ref' and 'unit_type' are required"})
                continue

            try:
                ins_cols = ["property_id", "unit_ref", "unit_type", "created", "modified"]
                ins_vals = [prop_id, unit_ref, unit_type, now, now]

                optional_fields = ["floor", "bedrooms", "capacity", "market_rent", "furnished", "status", "notes",
                                   "unit_status", "max_occupancy", "bathrooms"]
                for f in optional_fields:
                    if f in unit_data:
                        ins_cols.append(f)
                        ins_vals.append(unit_data[f])

                placeholders = ",".join(["?"] * len(ins_cols))
                cursor = db.execute(
                    f"INSERT INTO units ({','.join(ins_cols)}) VALUES ({placeholders})",
                    ins_vals
                )
                created_ids.append(cursor.lastrowid)
            except Exception as e:
                errors.append({"index": idx, "error": str(e)})

        db.commit()

        return json_success({
            "created_ids": created_ids,
            "count": len(created_ids),
            "errors": errors if errors else None,
        }), 201
    except Exception as e:
        return json_error(str(e), 500)
    finally:
        db.close()


# ═══════════════════════════════════════════════
# 2h. PROPERTY IMAGES — list images for a property
# ═══════════════════════════════════════════════

@banksia_os_bp.route("/properties/<int:prop_id>/images")
def api_property_images(prop_id):
    db = get_dict_db()
    try:
        # Check property exists
        prop = db.execute("SELECT id, image_urls, main_image_url FROM properties WHERE id = ?", (prop_id,)).fetchone()
        if not prop:
            return json_error("Property not found", 404)

        # Try property_images table first
        images = db.execute(
            "SELECT id, category, image_url, caption, sort_order FROM property_images "
            "WHERE property_id = ? ORDER BY sort_order ASC, id ASC",
            (prop_id,)
        ).fetchall()

        # If no images in property_images table, parse image_urls JSON
        if not images and prop.get("image_urls"):
            try:
                urls = json.loads(prop["image_urls"])
                if isinstance(urls, list):
                    images = [{"id": None, "category": None, "image_url": u, "caption": None, "sort_order": i}
                              for i, u in enumerate(urls) if isinstance(u, str)]
                elif isinstance(urls, dict):
                    images = [{"id": None, "category": k, "image_url": v if isinstance(v, str) else (v[0] if isinstance(v, list) else ""),
                               "caption": None, "sort_order": i}
                              for i, (k, v) in enumerate(urls.items())]
            except (json.JSONDecodeError, TypeError):
                pass

        # Also include main_image_url if available
        if prop.get("main_image_url") and not any(
            img.get("image_url") == prop["main_image_url"] for img in images
        ):
            images.insert(0, {
                "id": None, "category": "main", "image_url": prop["main_image_url"],
                "caption": "Main image", "sort_order": -1
            })

        return json_success(images)
    except Exception as e:
        return json_error(str(e), 500)
    finally:
        db.close()


# ═══════════════════════════════════════════════
# 3. UNITS
# ═══════════════════════════════════════════════

@banksia_os_bp.route("/units", methods=["GET", "POST"])
def api_units():
    if request.method == "POST":
        return api_create_unit()
    page = int_param(request.args.get("page"))
    per_page = int_param(request.args.get("per_page"), 20)
    status_filter = request.args.get("status", "").strip()
    property_id = request.args.get("property_id", "").strip()
    search = request.args.get("search", "").strip()

    where_parts = ["1=1"]
    params = []

    if status_filter:
        where_parts.append("unit_status = ?")
        params.append(status_filter)

    if property_id:
        try:
            where_parts.append("property_id = ?")
            params.append(int(property_id))
        except ValueError:
            pass

    if search:
        search_clause, search_params = build_search_clause(
            ["unit_ref", "full_address", "unit_type", "owner_name"], search
        )
        where_parts.append(search_clause)
        params.extend(search_params)

    where = " AND ".join(where_parts)

    rows, total = paginate(
        f"SELECT u.*, "
        f"(SELECT p.name FROM properties p WHERE p.id = u.property_id) AS property_name, "
        f"(SELECT t.main_tenant_name FROM tenancies t WHERE t.unit_id = u.id AND t.status IN ('Current','current','Periodic','periodic','Active','active') ORDER BY t.start_date DESC LIMIT 1) AS tenant_name, "
        f"(SELECT t.start_date FROM tenancies t WHERE t.unit_id = u.id AND t.status IN ('Current','current','Periodic','periodic','Active','active') ORDER BY t.start_date DESC LIMIT 1) AS tenancy_start_date, "
        f"(SELECT t.end_date FROM tenancies t WHERE t.unit_id = u.id AND t.status IN ('Current','current','Periodic','periodic','Active','active') ORDER BY t.start_date DESC LIMIT 1) AS tenancy_end_date "
        f"FROM units u WHERE {where} ORDER BY sort_order ASC, unit_ref ASC",
        f"SELECT COUNT(*) AS cnt FROM units u WHERE {where}",
        params, page, per_page
    )

    # Convert unit_vacant to bool
    for r in rows:
        bool_fields(r, "unit_vacant")

    return json_success(rows, total, page, per_page)


def api_create_unit():
    """POST handler for creating a new unit with room/fixture details."""
    data = request.get_json()
    if not data:
        return json_error("No data provided")
    if not data.get("property_id"):
        return json_error("'property_id' is required")

    db = get_dict_db()
    try:
        cols = ["property_id", "unit_ref", "unit_type", "unit_status", "unit_vacant",
                "full_address", "market_rent", "market_rent_frequency", "deposit_amount",
                "short_description", "furnished", "bedrooms", "bathrooms", "max_occupancy",
                "council_tax_band", "features", "owner_name", "notes"]
        ins_cols = [c for c in cols if c in data]
        ins_vals = [data[c] for c in ins_cols]
        placeholders = ",".join(["?"] * len(ins_cols))
        cursor = db.execute(
            f"INSERT INTO units ({','.join(ins_cols)}) VALUES ({placeholders})",
            ins_vals
        )
        db.commit()
        new_id = cursor.lastrowid
        return json_success({"id": new_id, "message": "Unit created"}), 201
    except Exception as e:
        return json_error(str(e), 500)
    finally:
        db.close()


@banksia_os_bp.route("/units/<int:unit_id>", methods=["GET", "PATCH"])
def api_unit(unit_id):
    if request.method == "PATCH":
        return api_update_resource("units", unit_id)
    db = get_dict_db()
    try:
        unit = db.execute("SELECT * FROM units WHERE id = ?", (unit_id,)).fetchone()
        if not unit:
            return json_error("Unit not found", 404)

        bool_fields(unit, "unit_vacant")

        # Linked tenancy (current active)
        tenancy = db.execute(
            "SELECT * FROM tenancies WHERE unit_id = ? AND status IN ('Active', 'active', 'Periodic', 'periodic') "
            "ORDER BY start_date DESC LIMIT 1",
            (unit_id,)
        ).fetchone()
        unit["current_tenancy"] = tenancy

        # Current tenant(s) for the unit
        if tenancy:
            tenants = db.execute(
                "SELECT * FROM tenants WHERE tenancy_id = ? ORDER BY main_tenant DESC",
                (tenancy["id"],)
            ).fetchall()
            unit["current_tenants"] = tenants
        else:
            unit["current_tenants"] = []

        return json_success(unit)
    except Exception as e:
        return json_error(str(e), 500)
    finally:
        db.close()


# ═══════════════════════════════════════════════
# 4. TENANCIES
# ═══════════════════════════════════════════════

@banksia_os_bp.route("/tenancies")
def api_tenancies():
    page = int_param(request.args.get("page"))
    per_page = int_param(request.args.get("per_page"), 20)
    status_filter = request.args.get("status", "").strip()
    search = request.args.get("search", "").strip()

    where_parts = ["1=1"]
    params = []

    if status_filter:
        if status_filter.lower() == 'all':
            pass  # No status filter — show everything including past
        else:
            where_parts.append("status = ?")
            params.append(status_filter)
    else:
        # Default: only show active/current/periodic tenancies
        where_parts.append("status IN ('Current', 'current', 'Periodic', 'periodic', 'Active', 'active')")

    if search:
        search_clause, search_params = build_search_clause(
            ["ref", "full_address", "main_tenant_name"], search
        )
        where_parts.append(search_clause)
        params.extend(search_params)

    where = " AND ".join(where_parts)

    rows, total = paginate(
        f"SELECT t.*, "
        f"(SELECT COALESCE(NULLIF(p.name, 'multi'), p.address_line_1) FROM properties p WHERE p.id = t.property_id) AS property_name, "
        f"(SELECT p.address_line_1 FROM properties p WHERE p.id = t.property_id) AS property_address, "
        f"(SELECT u.unit_ref FROM units u WHERE u.id = t.unit_id) AS unit_ref, "
        f"(SELECT u.unit_type FROM units u WHERE u.id = t.unit_id) AS unit_type_name, "
        f"t.deposit_registered_amount AS deposit_amount "
        f"FROM tenancies t WHERE {where} ORDER BY start_date DESC",
        f"SELECT COUNT(*) AS cnt FROM tenancies t WHERE {where}",
        params, page, per_page
    )

    for r in rows:
        bool_fields(r, "deposit_registered", "section_21_served", "is_renewed")

    return json_success(rows, total, page, per_page)


@banksia_os_bp.route("/tenancies/<int:ten_id>", methods=["GET", "PATCH"])
def api_tenancy(ten_id):
    if request.method == "PATCH":
        return api_update_resource("tenancies", ten_id)
    db = get_dict_db()
    try:
        ten = db.execute("SELECT * FROM tenancies WHERE id = ?", (ten_id,)).fetchone()
        if not ten:
            return json_error("Tenancy not found", 404)

        bool_fields(ten, "deposit_registered", "section_21_served", "is_renewed")

        # Tenant info — from tenants table (NOT JSON string), with full detail
        tenant_rows = db.execute(
            "SELECT id, first_name, last_name, email, mobile, phone_home, phone_work, "
            "date_of_birth, gender, citizen, ni_number, passport_number, "
            "main_tenant, status, has_guarantor, "
            "guarantor_first_name, guarantor_last_name, guarantor_email, guarantor_mobile, "
            "employment_company, employment_salary, student_status, university, "
            "move_in_date, move_out_date, applicant_note, manager_note, "
            "created, modified "
            "FROM tenants WHERE tenancy_id = ? ORDER BY main_tenant DESC",
            (ten_id,)
        ).fetchall()
        for t in tenant_rows:
            bool_fields(t, "main_tenant", "has_guarantor")
        ten["tenants"] = tenant_rows

        # Transactions
        transactions = db.execute(
            "SELECT * FROM transactions WHERE tenancy_id = ? ORDER BY date DESC",
            (ten_id,)
        ).fetchall()
        for t in transactions:
            bool_fields(t, "is_overdue", "is_outstanding")
        ten["transactions"] = transactions

        # Property info — with address display name
        if ten.get("property_id"):
            prop = db.execute(
                "SELECT id, ref, name, address_line_1, address_line_2, city, postcode, property_type FROM properties WHERE id = ?",
                (ten["property_id"],)
            ).fetchone()
            if prop:
                # Use address_line_1 if name is 'multi'
                display_name = prop["address_line_1"] if prop["name"] == "multi" else prop["name"]
                ten["property"] = {**prop, "display_name": display_name}

        # Unit info
        if ten.get("unit_id"):
            unit = db.execute(
                "SELECT id, unit_ref, unit_type, full_address FROM units WHERE id = ?",
                (ten["unit_id"],)
            ).fetchone()
            ten["unit"] = unit

        # Linked maintenance jobs (by property_id)
        maintenance_jobs = db.execute(
            "SELECT id, reference, title, status, priority, type AS category, created, "
            "contractor AS assigned_to, total_cost, "
            "(SELECT COUNT(*) FROM ll_communications WHERE job_id = maintenance_jobs.id) AS ll_comms_count "
            "FROM maintenance_jobs "
            "WHERE property_id = ? "
            "ORDER BY created DESC LIMIT 20",
            (ten.get("property_id"),)
        ).fetchall()
        ten["maintenance_jobs"] = maintenance_jobs

        return json_success(ten)
    except Exception as e:
        return json_error(str(e), 500)
    finally:
        db.close()


@banksia_os_bp.route("/tenancies/ending-soon")
def api_tenancies_ending_soon():
    """Tenancies ending within 30 days."""
    from datetime import date, timedelta
    today = date.today()
    end_date = today + timedelta(days=30)

    db = get_dict_db()
    try:
        rows = db.execute(
            "SELECT * FROM tenancies WHERE end_date >= ? AND end_date <= ? "
            "AND status IN ('Active', 'active', 'Periodic', 'periodic') "
            "ORDER BY end_date ASC",
            (today.isoformat(), end_date.isoformat())
        ).fetchall()

        for r in rows:
            bool_fields(r, "deposit_registered", "section_21_served", "is_renewed")

        return json_success(rows, total=len(rows), page=1, per_page=len(rows))
    except Exception as e:
        return json_error(str(e), 500)
    finally:
        db.close()


@banksia_os_bp.route("/tenancies/moving-in-this-month")
def api_tenancies_moving_in():
    db = get_dict_db()
    try:
        now = datetime.now(timezone.utc)
        month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0).isoformat()
        if now.month == 12:
            next_month = now.replace(year=now.year + 1, month=1, day=1)
        else:
            next_month = now.replace(month=now.month + 1, day=1)
        month_end = next_month.isoformat()

        rows = db.execute(
            "SELECT * FROM tenancies WHERE move_in_date >= ? AND move_in_date < ? "
            "ORDER BY move_in_date ASC",
            (month_start, month_end)
        ).fetchall()

        for r in rows:
            bool_fields(r, "deposit_registered", "section_21_served", "is_renewed")

        return json_success(rows, total=len(rows), page=1, per_page=len(rows))
    except Exception as e:
        return json_error(str(e), 500)
    finally:
        db.close()


@banksia_os_bp.route("/tenancies/moving-out-this-month")
def api_tenancies_moving_out():
    db = get_dict_db()
    try:
        now = datetime.now(timezone.utc)
        month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0).isoformat()
        if now.month == 12:
            next_month = now.replace(year=now.year + 1, month=1, day=1)
        else:
            next_month = now.replace(month=now.month + 1, day=1)
        month_end = next_month.isoformat()

        rows = db.execute(
            "SELECT * FROM tenancies WHERE move_out_date >= ? AND move_out_date < ? "
            "ORDER BY move_out_date ASC",
            (month_start, month_end)
        ).fetchall()

        for r in rows:
            bool_fields(r, "deposit_registered", "section_21_served", "is_renewed")

        return json_success(rows, total=len(rows), page=1, per_page=len(rows))
    except Exception as e:
        return json_error(str(e), 500)
    finally:
        db.close()


# ═══════════════════════════════════════════════
# 4a. HMO OCCUPANCY / PROPERTY TENANCY OVERVIEW
# ═══════════════════════════════════════════════

@banksia_os_bp.route("/tenancies/property/<int:property_id>")
def api_tenancies_by_property(property_id):
    """All active tenancies + vacant units for a property. HMO room-level overview."""
    db = get_dict_db()
    try:
        active_statuses = ("'Current', 'current', 'Periodic', 'periodic', 'Active', 'active'")

        # Get property
        prop = db.execute(
            "SELECT id, name, address_line_1, address_line_2, city, postcode, property_type, "
            "total_units, rentable_units, max_occupancy, bathrooms, bedrooms "
            "FROM properties WHERE id = ?", (property_id,)
        ).fetchone()
        if not prop:
            return json_error("Property not found", 404)

        display_name = prop["address_line_1"] if prop["name"] == "multi" else prop["name"]
        prop_data = dict(prop)
        prop_data["display_name"] = display_name

        # All units at this property
        units = db.execute(
            "SELECT id, unit_ref, unit_type, unit_status, unit_vacant, max_occupancy, "
            "market_rent, deposit_amount, short_description, features "
            "FROM units WHERE property_id = ? ORDER BY sort_order ASC, unit_ref", (property_id,)
        ).fetchall()

        # Active tenancies with tenant info
        tenancies = db.execute(f"""
            SELECT t.id, t.ref, t.unit_id, t.main_tenant_name, t.rent_amount, t.rent_frequency,
                   t.status, t.start_date, t.end_date, t.move_in_date, t.move_out_date,
                   t.deposit_registered_amount, t.deposit_registered, t.notice_period,
                   t.break_clause_date, t.section_21_served
            FROM tenancies t
            WHERE t.property_id = ? AND t.status IN ({active_statuses})
            ORDER BY t.unit_id, t.start_date DESC
        """, (property_id,)).fetchall()

        for t in tenancies:
            bool_fields(t, "deposit_registered", "section_21_served")
            # Get tenants for this tenancy
            t["tenant_list"] = db.execute(
                "SELECT id, first_name, last_name, email, mobile, main_tenant, status, "
                "date_of_birth, employment_company, student_status "
                "FROM tenants WHERE tenancy_id = ? ORDER BY main_tenant DESC",
                (t["id"],)
            ).fetchall()

        # Enrich units with active tenancy info
        unit_data = []
        for u in units:
            unit_dict = dict(u)
            tenancy = next((t for t in tenancies if t["unit_id"] == u["id"]), None)
            unit_dict["active_tenancy"] = tenancy
            unit_dict["occupied"] = tenancy is not None
            unit_data.append(unit_dict)

        # Vacant unit count
        occupied = sum(1 for u in unit_data if u["occupied"])
        vacant = sum(1 for u in unit_data if not u["occupied"])

        # Summary
        total_rent = sum(t["rent_amount"] or 0 for t in tenancies)

        return json_success({
            "property": prop_data,
            "units": unit_data,
            "tenancies": tenancies,
            "summary": {
                "total_units": len(unit_data),
                "occupied": occupied,
                "vacant": vacant,
                "occupancy_pct": round(occupied / len(unit_data) * 100, 1) if unit_data else 0,
                "active_tenancies": len(tenancies),
                "total_monthly_rent": round(total_rent, 2),
            }
        })
    except Exception as e:
        return json_error(str(e), 500)
    finally:
        db.close()


# ═══════════════════════════════════════════════
# 4b. SHORT-ALIAS ROUTES (flat paths for Next.js frontend)
# ═══════════════════════════════════════════════

@banksia_os_bp.route("/financials")
def api_financials():
    db = get_dict_db()
    try:
        # Active statuses matching dashboard logic
        active_statuses = ("'Current', 'current', 'Periodic', 'periodic', 'Active', 'active'")
        # Total monthly rent
        rent_row = db.execute(
            f"SELECT COALESCE(SUM(rent_amount),0) as total FROM tenancies WHERE status IN ({active_statuses})"
        ).fetchone()
        # Arrears — from transactions outstanding (same as dashboard)
        arrears_row = db.execute(
            "SELECT COALESCE(SUM(amount_outstanding), 0) AS total FROM transactions WHERE is_outstanding = 1"
        ).fetchone()
        # Count tenancies with outstanding transactions
        arrears_count = db.execute(
            "SELECT COUNT(DISTINCT t.id) as cnt FROM tenancies t WHERE EXISTS (SELECT 1 FROM transactions tx WHERE tx.tenancy_id = t.arthur_id AND tx.is_outstanding = 1 AND tx.amount_outstanding > 0)"
        ).fetchone()
        # Deposits
        dep_count = db.execute("SELECT COUNT(*) as c FROM tenancies WHERE deposit_registered = 1").fetchone()
        dep_total = db.execute("SELECT COALESCE(SUM(deposit_registered_amount),0) as t FROM tenancies WHERE deposit_registered = 1").fetchone()
        dep_unreg = db.execute("SELECT COUNT(*) as c FROM tenancies WHERE deposit_registered = 0 AND deposit_registered IS NOT NULL").fetchone()
        
        # Active tenancy count
        active_count = db.execute(
            f"SELECT COUNT(*) as cnt FROM tenancies WHERE status IN ({active_statuses})"
        ).fetchone()
        total_count = db.execute("SELECT COUNT(*) as cnt FROM tenancies").fetchone()
        
        return json_success({
            "monthly_rent_income": rent_row["total"],
            "monthly_rent_roll": rent_row["total"],
            "total_arrears": arrears_row["total"],
            "total_deposits": dep_total["t"],
            "total_deposits_held": dep_total["t"],
            "deposits_registered": dep_count["c"],
            "deposits_total": dep_total["t"],
            "deposits_unregistered": dep_unreg["c"],
            "tenancies_in_arrears_count": arrears_count["cnt"],
            "unit_occupancy_rate": round(active_count["cnt"] / total_count["cnt"] * 100, 1) if total_count["cnt"] else 0,
            "payment_dates": [],
            "rent_collected": 0,
            "rent_outstanding": 0,
            "metrics": {
                "total_tenancies": total_count["cnt"],
                "active_tenancies": active_count["cnt"],
                "in_arrears": arrears_count["cnt"]
            }
        })
    except Exception as e:
        return json_error(str(e), 500)
    finally:
        db.close()


@banksia_os_bp.route("/arrears")
def api_arrears():
    page = int_param(request.args.get("page"))
    per_page = int_param(request.args.get("per_page"), 20)
    db = get_dict_db()
    try:
        # Get tenancies with outstanding transactions (tenancy_id in transactions
        # maps to arthur_id in tenancies, not the local id)
        rows, total = paginate(
            "SELECT t.id, t.ref, t.full_address, t.main_tenant_name, t.rent_amount, t.rent_frequency, "
            "COALESCE((SELECT SUM(amount_outstanding) FROM transactions tx WHERE tx.tenancy_id = t.arthur_id AND tx.is_outstanding = 1), 0) as arrears_amount, "
            "t.status, (SELECT p.name FROM properties p WHERE p.id = t.property_id) AS property_name "
            "FROM tenancies t WHERE EXISTS (SELECT 1 FROM transactions tx WHERE tx.tenancy_id = t.arthur_id AND tx.is_outstanding = 1 AND tx.amount_outstanding > 0) "
            "ORDER BY arrears_amount DESC",
            "SELECT COUNT(DISTINCT t.id) as cnt FROM tenancies t WHERE EXISTS (SELECT 1 FROM transactions tx WHERE tx.tenancy_id = t.arthur_id AND tx.is_outstanding = 1 AND tx.amount_outstanding > 0)",
            [], page, per_page
        )
        return json_success(rows, total, page, per_page)
    except Exception as e:
        return json_error(str(e), 500)
    finally:
        db.close()



@banksia_os_bp.route("/maintenance")
def api_maintenance_list():
    db = get_dict_db()
    try:
        page = int_param(request.args.get("page"))
        per_page = int_param(request.args.get("per_page"), 50)
        search = (request.args.get("search") or "").strip()
        status_filter = request.args.get("status", "")
        type_filter = request.args.get("type", "")
        priority_filter = request.args.get("priority", "")
        contractor_filter = request.args.get("contractor", "")

        where = ["1=1"]
        params = []

        if status_filter:
            where.append("mj.status = ?")
            params.append(status_filter)
        if type_filter:
            where.append("mj.type = ?")
            params.append(type_filter)
        if priority_filter:
            where.append("mj.priority = ?")
            params.append(priority_filter)
        if contractor_filter:
            where.append("mj.contractor = ?")
            params.append(contractor_filter)
        if search:
            where.append("(mj.title LIKE ? OR mj.description LIKE ? OR mj.address LIKE ? OR mj.reference LIKE ? OR mj.contractor LIKE ? OR mj.type LIKE ? OR mj.reporter_name LIKE ? OR mj.team_notes LIKE ?)")
            s = f"%{search}%"
            params.extend([s, s, s, s, s, s, s, s])

        where_clause = " AND ".join(where)

        total = db.execute(
            f"SELECT COUNT(*) AS cnt FROM maintenance_jobs mj WHERE {where_clause}",
            params
        ).fetchone()["cnt"]

        offset = (page - 1) * per_page
        rows = db.execute(
            f"""SELECT mj.*, p.name AS property_name
                FROM maintenance_jobs mj
                LEFT JOIN properties p ON mj.property_id = p.id
                WHERE {where_clause}
                ORDER BY
                    CASE mj.priority
                        WHEN 'Emergency' THEN 0 WHEN 'Critical' THEN 1
                        WHEN 'High' THEN 2 WHEN 'Medium' THEN 3 WHEN 'Low' THEN 4
                    END,
                    mj.created DESC
                LIMIT ? OFFSET ?""",
            params + [per_page, offset]
        ).fetchall()

        for r in rows:
            r["bill_ll"] = bool(r["bill_ll"])
            r["emergency"] = bool(r["emergency"])
            r["ll_informed"] = bool(r["ll_informed"])
            o = db.execute(
                "SELECT COUNT(*) AS cnt FROM maintenance_orders WHERE job_id = ?",
                [r["id"]]
            ).fetchone()
            r["order_count"] = o["cnt"] if o else 0

        counts = {}
        for s in MAINT_STATUSES:
            c = db.execute("SELECT COUNT(*) AS cnt FROM maintenance_jobs WHERE status = ?", [s]).fetchone()
            counts[s] = c["cnt"] if c else 0

        return json_success(rows, total=total, page=page, per_page=per_page)
    except Exception as e:
        return json_error(str(e), 500)
    finally:
        db.close()


@banksia_os_bp.route("/maintenance/<int:job_id>")
def api_maintenance_detail(job_id):
    db = get_dict_db()
    try:
        job = db.execute(
            """SELECT mj.*, p.name AS property_name
               FROM maintenance_jobs mj
               LEFT JOIN properties p ON mj.property_id = p.id
               WHERE mj.id = ?""",
            [job_id]
        ).fetchone()
        if not job:
            return json_error("Job not found", 404)
        orders = db.execute(
            "SELECT * FROM maintenance_orders WHERE job_id = ? ORDER BY created DESC",
            [job_id]
        ).fetchall()
        ll_comms = db.execute(
            "SELECT * FROM ll_communications WHERE job_id = ? ORDER BY sent_at DESC",
            [job_id]
        ).fetchall()
        result = dict(job)
        result["orders"] = [dict(o) for o in orders]
        result["ll_comms"] = [dict(c) for c in ll_comms]
        result["bill_ll"] = bool(result["bill_ll"])
        result["emergency"] = bool(result["emergency"])
        result["ll_informed"] = bool(result["ll_informed"])
        return json_success(result)
    except Exception as e:
        return json_error(str(e), 500)
    finally:
        db.close()


@banksia_os_bp.route("/maintenance/<int:job_id>/emails")
def api_maintenance_job_emails(job_id):
    """Return Missive emails related to a maintenance job by matching property address."""
    import subprocess, json
    db = get_dict_db()
    try:
        job = db.execute(
            """SELECT mj.*, p.name as property_name, p.address_line_1, p.address_line_2,
                      p.city, p.postcode, p.property_owner_name
               FROM maintenance_jobs mj
               LEFT JOIN properties p ON mj.property_id = p.id
               WHERE mj.id = ?""",
            [job_id]
        ).fetchone()
        if not job:
            return json_error("Job not found", 404)

        # Call the fetch_job_emails helper script
        script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scripts", "fetch_job_emails.py")
        if os.path.exists(script_path):
            try:
                result = subprocess.run(
                    [sys.executable, script_path, str(job_id)],
                    capture_output=True, text=True, timeout=30
                )
                if result.returncode == 0 and result.stdout:
                    data = json.loads(result.stdout)
                    if data.get("success"):
                        return json_success(data["data"])
                    else:
                        # Script returned error — degrade to empty
                        return json_success({
                            "emails": [],
                            "property_owner": job.get("property_owner_name"),
                            "property_address": job.get("address_line_1"),
                            "total_matched": 0,
                            "error": data.get("error")
                        })
                else:
                    # Script failed — degrade gracefully
                    return json_success({
                        "emails": [],
                        "property_owner": job.get("property_owner_name"),
                        "property_address": job.get("address_line_1"),
                        "total_matched": 0,
                        "error": result.stderr[:200] if result.stderr else "Script execution failed"
                    })
            except (subprocess.TimeoutExpired, Exception) as e:
                return json_success({
                    "emails": [],
                    "property_owner": job.get("property_owner_name"),
                    "property_address": job.get("address_line_1"),
                    "total_matched": 0,
                    "error": str(e)[:200]
                })
        else:
            return json_success({
                "emails": [],
                "property_owner": job.get("property_owner_name"),
                "property_address": job.get("address_line_1"),
                "total_matched": 0
            })
    except Exception as e:
        return json_error(str(e), 500)
    finally:
        db.close()


# ── Order Emails (Missive Orders inbox) ─────────────────────────
@banksia_os_bp.route("/maintenance/<int:job_id>/order-emails")
def api_maintenance_job_order_emails(job_id):
    """Return Missive Orders inbox emails matched to this job."""
    import subprocess, json
    script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scripts", "fetch_job_orders.py")
    try:
        result = subprocess.run(
            [sys.executable, script_path, str(job_id)],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode != 0:
            return json_success({"orders": [], "total_matched": 0, "error": result.stderr.strip()})
        parsed = json.loads(result.stdout)
        if not parsed.get("success"):
            return json_success({"orders": [], "total_matched": 0, "error": parsed.get("error", "Script failed")})
        return json_success(parsed["data"])
    except subprocess.TimeoutExpired:
        return json_success({"orders": [], "total_matched": 0, "error": "Timed out"})
    except Exception as e:
        return json_success({"orders": [], "total_matched": 0, "error": str(e)})


# ═══════════════════════════════════════════════
#  CONVERSATION TIMELINE — WhatsApp contractor chats per job
# ═══════════════════════════════════════════════

@banksia_os_bp.route("/maintenance/<int:job_id>/conversations")
def api_maintenance_job_conversations(job_id):
    """Return WhatsApp group conversations related to a maintenance job."""
    db = get_dict_db()
    try:
        # Check job exists
        job = db.execute(
            "SELECT id, reference, title, contractor, address FROM maintenance_jobs WHERE id = ?",
            (job_id,)
        ).fetchone()
        if not job:
            return json_error("Job not found", 404)

        # Get conversation timeline entries
        rows = db.execute("""
            SELECT id, sender_name, body, message_timestamp, source_group_name,
                   linked_contractor
            FROM conversation_timeline
            WHERE job_id = ?
            ORDER BY message_timestamp ASC
        """, (job_id,)).fetchall()

        conversations = []
        for r in rows:
            conversations.append({
                "id": r["id"],
                "sender": r["sender_name"],
                "body": r["body"],
                "timestamp": r["message_timestamp"],
                "source_group": r["source_group_name"],
                "contractor": r["linked_contractor"],
            })

        return json_success({
            "job": {
                "id": job["id"],
                "reference": job["reference"],
                "title": job["title"],
                "contractor": job["contractor"],
                "address": job["address"],
            },
            "conversations": conversations,
            "count": len(conversations),
        })
    except Exception as e:
        return json_error(str(e), 500)
    finally:
        db.close()


@banksia_os_bp.route("/maintenance/orders/scan")
def api_scan_orders_inbox():
    """Scan Orders inbox and return all non-marketing order emails."""
    import subprocess, json
    script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scripts", "fetch_job_orders.py")
    try:
        result = subprocess.run(
            [sys.executable, script_path, "0"],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode != 0:
            return json_success({"orders": [], "total_matched": 0, "error": result.stderr.strip()})
        parsed = json.loads(result.stdout)
        if not parsed.get("success"):
            return json_success({"orders": [], "total_matched": 0, "error": parsed.get("error", "Script failed")})
        return json_success(parsed["data"])
    except subprocess.TimeoutExpired:
        return json_success({"orders": [], "total_matched": 0, "error": "Timed out"})
    except Exception as e:
        return json_success({"orders": [], "total_matched": 0, "error": str(e)})


@banksia_os_bp.route("/activity")
def api_activity():
    page = int_param(request.args.get("page"))
    per_page = int_param(request.args.get("per_page"), 30)
    db = get_dict_db()
    try:
        rows = db.execute("""
            SELECT 'tenant' as type, id, first_name || ' ' || last_name as title, modified as timestamp, 'Modified' as action FROM tenants WHERE modified IS NOT NULL
            UNION ALL
            SELECT 'tenancy' as type, id, ref as title, modified as timestamp, 'Modified' as action FROM tenancies WHERE modified IS NOT NULL
            UNION ALL
            SELECT 'applicant' as type, id, first_name || ' ' || last_name as title, modified as timestamp, 'Modified' as action FROM applicants WHERE modified IS NOT NULL
            ORDER BY timestamp DESC LIMIT ? OFFSET ?
        """, [per_page, (page-1)*per_page]).fetchall()
        total = db.execute("SELECT COUNT(*) as cnt FROM (SELECT modified FROM tenants WHERE modified IS NOT NULL UNION ALL SELECT modified FROM tenancies WHERE modified IS NOT NULL UNION ALL SELECT modified FROM applicants WHERE modified IS NOT NULL)").fetchone()["cnt"]
        return json_success(rows, total, page, per_page)
    except Exception as e:
        return json_error(str(e), 500)
    finally:
        db.close()


# ═══════════════════════════════════════════════
# 5. TENANTS
# ═══════════════════════════════════════════════

@banksia_os_bp.route("/tenants")
def api_tenants():
    page = int_param(request.args.get("page"))
    per_page = int_param(request.args.get("per_page"), 20)
    search = request.args.get("search", "").strip()
    property_id = request.args.get("property_id", "").strip()

    where_parts = ["1=1"]
    params = []

    if search:
        search_clause, search_params = build_search_clause(
            ["first_name", "last_name", "email", "mobile", "full_address"], search
        )
        where_parts.append(search_clause)
        params.extend(search_params)

    if property_id:
        try:
            where_parts.append("property_id = ?")
            params.append(int(property_id))
        except ValueError:
            pass

    where = " AND ".join(where_parts)

    rows, total = paginate(
        f"SELECT tn.id, tn.arthur_id, tn.arthur_person_id, tn.tenancy_id, tn.unit_id, tn.property_id, "
        f"tn.full_address, tn.title, tn.first_name, tn.last_name, tn.date_of_birth, tn.gender, tn.citizen, "
        f"tn.email, tn.phone_home, tn.phone_work, tn.mobile AS phone, tn.passport_number, tn.visa_number, tn.visa_type, "
        f"tn.visa_years, tn.country_of_origin, tn.ni_number, tn.main_tenant, tn.status, tn.has_guarantor, "
        f"tn.guarantor_first_name, tn.guarantor_last_name, tn.guarantor_email, "
        f"tn.employment_company, tn.student_status, tn.university, "
        f"tn.bank_name, tn.latest_credit_score, tn.latest_credit_description, "
        f"tn.applicant_note, tn.manager_note, tn.move_in_date, tn.move_out_date, tn.modified, tn.created, "
        f"COALESCE((SELECT COUNT(*) FROM tenancies t2 WHERE t2.id = tn.tenancy_id), 0) AS tenancy_count, "
        f"COALESCE((SELECT COALESCE(NULLIF(p2.name, 'multi'), p2.address_line_1) FROM properties p2 WHERE p2.arthur_id = CAST(tn.property_id AS TEXT)), '') AS property_name, "
        f"COALESCE((SELECT u2.unit_ref FROM units u2 WHERE u2.arthur_id = CAST(tn.unit_id AS TEXT)), '') AS unit_ref "
        f"FROM tenants tn WHERE {where} ORDER BY tn.last_name ASC, tn.first_name ASC",
        f"SELECT COUNT(*) AS cnt FROM tenants WHERE {where}",
        params, page, per_page
    )

    for r in rows:
        bool_fields(r, "main_tenant", "has_guarantor")

    return json_success(rows, total, page, per_page)


@banksia_os_bp.route("/tenants/<int:tenant_id>", methods=["GET", "PATCH"])
def api_tenant(tenant_id):
    if request.method == "PATCH":
        return api_update_resource("tenants", tenant_id)
    db = get_dict_db()
    try:
        tenant = db.execute("SELECT id, arthur_id, arthur_person_id, tenancy_id, unit_id, property_id, "
            "full_address, title, first_name, last_name, date_of_birth, gender, citizen, "
            "email, phone_home, phone_work, mobile AS phone, passport_number, visa_number, visa_type, "
            "visa_years, country_of_origin, ni_number, main_tenant, status, has_guarantor, "
            "guarantor_first_name, guarantor_last_name, guarantor_email, "
            "employment_company, student_status, university, "
            "bank_name, latest_credit_score, latest_credit_description, "
            "applicant_note, manager_note, move_in_date, move_out_date, modified, created "
            "FROM tenants WHERE id = ?", (tenant_id,)).fetchone()
        if not tenant:
            return json_error("Tenant not found", 404)

        bool_fields(tenant, "main_tenant", "has_guarantor", "guarantor_home_owner")

        # Linked tenancy
        if tenant.get("tenancy_id"):
            tenancy = db.execute("SELECT * FROM tenancies WHERE id = ?", (tenant["tenancy_id"],)).fetchone()
            if tenancy:
                bool_fields(tenancy, "deposit_registered", "section_21_served", "is_renewed")
            tenant["tenancy"] = tenancy
        else:
            tenant["tenancy"] = None

        # Linked property — tenants.property_id stores arthur_id, match via properties.arthur_id
        if tenant.get("property_id"):
            prop = db.execute(
                "SELECT id, ref, name, address_line_1, address_line_2, city, postcode, property_type, "
                "COALESCE(NULLIF(name, 'multi'), address_line_1) AS display_name "
                "FROM properties WHERE arthur_id = CAST(? AS TEXT) OR id = ?",
                (tenant["property_id"], tenant["property_id"])
            ).fetchone()
            tenant["property"] = prop

        # Linked unit
        if tenant.get("unit_id"):
            unit = db.execute(
                "SELECT id, unit_ref, unit_type, full_address FROM units WHERE id = ?",
                (tenant["unit_id"],)
            ).fetchone()
            tenant["unit"] = unit

        return json_success(tenant)
    except Exception as e:
        return json_error(str(e), 500)
    finally:
        db.close()


# ═══════════════════════════════════════════════
# 5b. GUARANTORS (from tenants table)
# ═══════════════════════════════════════════════

@banksia_os_bp.route("/guarantors")
def api_guarantors():
    page = int_param(request.args.get("page"))
    per_page = int_param(request.args.get("per_page"), 20)
    search = request.args.get("search", "").strip()

    where_parts = [
        "(t.has_guarantor = 1 OR (t.guarantor_first_name IS NOT NULL AND t.guarantor_first_name != ''))"
    ]
    params = []

    if search:
        search_clause, search_params = build_search_clause(
            ["t.guarantor_first_name", "t.guarantor_last_name",
             "t.guarantor_email", "t.guarantor_mobile"], search
        )
        where_parts.append(search_clause)
        params.extend(search_params)

    where = " AND ".join(where_parts)

    base_cols = (
        "t.id, "
        "t.guarantor_first_name AS first_name, "
        "t.guarantor_last_name AS last_name, "
        "t.guarantor_email AS email, "
        "t.guarantor_mobile AS phone, "
        "t.guarantor_mobile AS mobile, "
        "t.guarantor_relation AS relationship, "
        "t.status, "
        "t.first_name || ' ' || t.last_name AS linked_applicant_name, "
        "t.first_name || ' ' || t.last_name AS linked_tenant_name, "
        "(SELECT p.name FROM properties p WHERE p.arthur_id = CAST(t.property_id AS TEXT)) AS property_name, "
        "t.employment_salary AS annual_income, "
        "t.employment_company AS employer_name"
    )

    rows, total = paginate(
        f"SELECT {base_cols} FROM tenants t WHERE {where} ORDER BY t.guarantor_last_name ASC, t.guarantor_first_name ASC",
        f"SELECT COUNT(*) AS cnt FROM tenants t WHERE {where}",
        params, page, per_page
    )

    return json_success(rows, total, page, per_page)


@banksia_os_bp.route("/guarantors/<int:guarantor_id>")
def api_guarantor(guarantor_id):
    db = get_dict_db()
    try:
        tenant = db.execute(
            "SELECT id, arthur_id, arthur_person_id, tenancy_id, unit_id, property_id, "
            "full_address, title, first_name, last_name, date_of_birth, gender, citizen, "
            "email, phone_home, phone_work, mobile AS phone, passport_number, visa_number, visa_type, "
            "visa_years, country_of_origin, ni_number, main_tenant, status, has_guarantor, "
            "guarantor_first_name, guarantor_last_name, guarantor_date_of_birth, "
            "guarantor_address, guarantor_city, guarantor_postcode, guarantor_country, "
            "guarantor_phone, guarantor_mobile, guarantor_email, guarantor_relation, "
            "guarantor_profession, guarantor_home_owner, "
            "employment_company, employment_salary, employment_length, student_status, university, "
            "bank_name, latest_credit_score, latest_credit_description, "
            "applicant_note, manager_note, move_in_date, move_out_date, modified, created "
            "FROM tenants WHERE id = ?",
            (guarantor_id,)
        ).fetchone()
        if not tenant:
            return json_error("Guarantor not found", 404)

        bool_fields(tenant, "main_tenant", "has_guarantor", "guarantor_home_owner")

        # Add the computed fields from the list endpoint
        tenant["first_name_display"] = tenant.get("guarantor_first_name") or ""
        tenant["last_name_display"] = tenant.get("guarantor_last_name") or ""
        tenant["email_display"] = tenant.get("guarantor_email") or ""
        tenant["phone_display"] = tenant.get("guarantor_mobile") or ""
        tenant["mobile_display"] = tenant.get("guarantor_mobile") or ""
        tenant["relationship"] = tenant.get("guarantor_relation") or ""
        tenant["linked_applicant_name"] = (tenant.get("first_name") or "") + " " + (tenant.get("last_name") or "")
        tenant["linked_tenant_name"] = tenant["linked_applicant_name"]
        tenant["annual_income"] = tenant.get("employment_salary")
        tenant["employer_name"] = tenant.get("employment_company")

        if tenant.get("property_id"):
            prop = db.execute(
                "SELECT p.name FROM properties p WHERE p.arthur_id = CAST(? AS TEXT)",
                (tenant["property_id"],)
            ).fetchone()
            tenant["property_name"] = prop["name"] if prop else None
            prop_full = db.execute(
                "SELECT id, ref, name, address_line_1, city, postcode FROM properties WHERE id = ?",
                (tenant["property_id"],)
            ).fetchone()
            tenant["property"] = prop_full
        else:
            tenant["property_name"] = None
            tenant["property"] = None

        # Linked tenancy
        if tenant.get("tenancy_id"):
            tenancy = db.execute("SELECT * FROM tenancies WHERE id = ?", (tenant["tenancy_id"],)).fetchone()
            if tenancy:
                bool_fields(tenancy, "deposit_registered", "section_21_served", "is_renewed")
            tenant["tenancy"] = tenancy
        else:
            tenant["tenancy"] = None

        # Linked unit
        if tenant.get("unit_id"):
            unit = db.execute(
                "SELECT id, unit_ref, unit_type, full_address FROM units WHERE id = ?",
                (tenant["unit_id"],)
            ).fetchone()
            tenant["unit"] = unit

        return json_success(tenant)
    except Exception as e:
        return json_error(str(e), 500)
    finally:
        db.close()


# ═══════════════════════════════════════════════
# 5c. REFERENCING
# ═══════════════════════════════════════════════

@banksia_os_bp.route("/referencing")
def api_referencing():
    page = int_param(request.args.get("page"))
    per_page = int_param(request.args.get("per_page"), 20)
    search = request.args.get("search", "").strip()

    where_parts = ["1=1"]
    params = []

    if search:
        search_clause, search_params = build_search_clause(
            ["rf.first_name", "rf.last_name", "rf.email"], search
        )
        where_parts.append(search_clause)
        params.extend(search_params)

    where = " AND ".join(where_parts)

    query = (
        "SELECT rf.id, rf.first_name, rf.last_name, rf.email, rf.status, "
        "rf.created, rf.submitted_at, "
        "'' AS assigned_to "
        "FROM referencing_forms rf "
        f"WHERE {where} ORDER BY rf.created DESC"
    )

    count_query = f"SELECT COUNT(*) AS cnt FROM referencing_forms rf WHERE {where}"

    db = get_dict_db()
    try:
        total = db.execute(count_query, params).fetchone()["cnt"]
        offset = (page - 1) * per_page
        rows = db.execute(query + " LIMIT ? OFFSET ?", params + [per_page, offset]).fetchall()

        stats = db.execute("""
            SELECT
                SUM(CASE WHEN status = 'draft' THEN 1 ELSE 0 END) as new,
                SUM(CASE WHEN status = 'submitted' THEN 1 ELSE 0 END) as submitted,
                SUM(CASE WHEN status = 'under_review' THEN 1 ELSE 0 END) as under_review,
                SUM(CASE WHEN status = 'approved' THEN 1 ELSE 0 END) as approved,
                SUM(CASE WHEN status = 'rejected' THEN 1 ELSE 0 END) as rejected
            FROM referencing_forms
        """).fetchone()
        stats["tenancy_created"] = 0
        stats["total"] = stats["new"] + stats["submitted"] + stats["under_review"] + stats["approved"] + stats["rejected"]

        return json_success({"items": rows, "stats": stats}, total=total, page=page, per_page=per_page)
    except Exception as e:
        return json_error(str(e), 500)
    finally:
        db.close()


@banksia_os_bp.route("/referencing/<int:ref_id>")
def api_referencing_detail(ref_id):
    db = get_dict_db()
    try:
        form = db.execute("SELECT * FROM referencing_forms WHERE id = ?", (ref_id,)).fetchone()
        if not form:
            return json_error("Referencing form not found", 404)

        bool_fields(form, "has_guarantor", "guarantor_homeowner", "housing_benefit",
                     "has_pet", "has_ccj", "has_iva", "has_bankruptcy",
                     "has_eviction", "declaration_confirmed")

        # Linked applicant info
        if form.get("applicant_id"):
            applicant = db.execute(
                "SELECT id, first_name, last_name, email, mobile, status, "
                "employment_company, employment_salary, has_guarantor, "
                "guarantor_first_name, guarantor_last_name, "
                "created, modified "
                "FROM applicants WHERE id = ?",
                (form["applicant_id"],)
            ).fetchone()
            if applicant:
                bool_fields(applicant, "has_guarantor")
            form["applicant"] = applicant
        else:
            form["applicant"] = None

        # Check results
        checks = db.execute(
            "SELECT id, form_id, check_type, status, checked_at, details, "
            "confidence, summary, created "
            "FROM referencing_checks WHERE form_id = ? ORDER BY check_type",
            (ref_id,)
        ).fetchall()
        form["checks"] = checks

        # Documents
        docs = db.execute(
            "SELECT id, form_id, category, original_filename, stored_filename, "
            "file_size, mime_type, uploaded_by, uploaded_at, is_verified, "
            "ai_analysis, ai_verified, ai_confidence, ai_flagged, ai_flag_reason "
            "FROM referencing_documents WHERE form_id = ? ORDER BY category",
            (ref_id,)
        ).fetchall()
        for d in docs:
            bool_fields(d, "is_verified", "ai_verified", "ai_flagged")
        form["documents"] = docs

        return json_success(form)
    except Exception as e:
        return json_error(str(e), 500)
    finally:
        db.close()


# ═══════════════════════════════════════════════
# 6. APPLICANTS
# ═══════════════════════════════════════════════

@banksia_os_bp.route("/applicants")
def api_applicants():
    page = int_param(request.args.get("page"))
    per_page = int_param(request.args.get("per_page"), 20)
    status_filter = request.args.get("status", "").strip()
    search = request.args.get("search", "").strip()

    where_parts = ["1=1"]
    params = []

    if status_filter:
        where_parts.append("status = ?")
        params.append(status_filter)

    if search:
        search_clause, search_params = build_search_clause(
            ["first_name", "last_name", "email", "mobile", "full_address"], search
        )
        where_parts.append(search_clause)
        params.extend(search_params)

    where = " AND ".join(where_parts)

    rows, total = paginate(
        f"SELECT * FROM applicants WHERE {where} ORDER BY created DESC",
        f"SELECT COUNT(*) AS cnt FROM applicants WHERE {where}",
        params, page, per_page
    )

    for r in rows:
        bool_fields(r, "has_guarantor")

    return json_success(rows, total, page, per_page)


@banksia_os_bp.route("/applicants/<int:app_id>", methods=["GET", "PATCH"])
def api_applicant(app_id):
    if request.method == "PATCH":
        return api_update_resource("applicants", app_id)
    db = get_dict_db()
    try:
        app = db.execute("SELECT * FROM applicants WHERE id = ?", (app_id,)).fetchone()
        if not app:
            return json_error("Applicant not found", 404)

        bool_fields(app, "has_guarantor")

        # Parse matched_unit_ids if present
        if app.get("matched_unit_ids"):
            try:
                app["matched_units"] = json.loads(app["matched_unit_ids"])
            except (json.JSONDecodeError, TypeError):
                app["matched_units"] = []
        else:
            app["matched_units"] = []

        return json_success(app)
    except Exception as e:
        return json_error(str(e), 500)
    finally:
        db.close()


# ═══════════════════════════════════════════════
# 7. FINANCE
# ═══════════════════════════════════════════════

@banksia_os_bp.route("/finance/overview")
def api_finance_overview():
    db = get_dict_db()
    try:
        # Monthly rent roll
        monthly_rent_roll = db.execute(
            "SELECT COALESCE(SUM(rent_amount), 0) AS total FROM tenancies "
            "WHERE status IN ('Active', 'active', 'Periodic', 'periodic')"
        ).fetchone()["total"]

        # Total arrears
        total_arrears = db.execute(
            "SELECT COALESCE(SUM(amount_outstanding), 0) AS total FROM transactions "
            "WHERE is_outstanding = 1"
        ).fetchone()["total"]

        # Overdue transactions count & total
        overdue = db.execute(
            "SELECT COUNT(*) AS cnt, COALESCE(SUM(amount_outstanding), 0) AS total FROM transactions "
            "WHERE is_overdue = 1"
        ).fetchone()

        # Deposit summary from deposits table
        currently_held = db.execute(
            "SELECT COALESCE(SUM(amount), 0) AS total FROM deposits WHERE current_status = 'held'"
        ).fetchone()["total"]

        protected = db.execute(
            "SELECT COALESCE(SUM(amount), 0) AS total FROM deposits WHERE protection_status = 'protected' AND current_status = 'held'"
        ).fetchone()["total"]

        unprotected = currently_held - protected

        deposit_count = db.execute(
            "SELECT COUNT(*) AS cnt FROM deposits WHERE current_status = 'held'"
        ).fetchone()["cnt"]

        protected_count = db.execute(
            "SELECT COUNT(*) AS cnt FROM deposits WHERE protection_status = 'protected' AND current_status = 'held'"
        ).fetchone()["cnt"]

        # Total transactions
        total_transactions = db.execute(
            "SELECT COUNT(*) AS cnt FROM transactions"
        ).fetchone()["cnt"]

        # Total collected (amount_paid sum)
        total_collected = db.execute(
            "SELECT COALESCE(SUM(amount_paid), 0) AS total FROM transactions"
        ).fetchone()["total"]

        return json_success({
            "monthly_rent_roll": round(monthly_rent_roll, 2),
            "monthly_rent_income": round(monthly_rent_roll, 2),
            "monthly_income": round(monthly_rent_roll, 2),
            "total_expected_monthly": round(monthly_rent_roll, 2),
            "total_collected_monthly": round(total_collected, 2),
            "total_arrears": round(total_arrears, 2),
            "overdue_count": overdue["cnt"],
            "overdue_total": round(overdue["total"], 2),
            "total_collected": round(total_collected, 2),
            "total_transactions": total_transactions,
            "total_deposits_held": round(currently_held, 2),
            "total_deposits": round(currently_held, 2),
            "deposits": {
                "currently_held_count": deposit_count,
                "currently_held_total": round(currently_held, 2),
                "protected_count": protected_count,
                "protected_total": round(protected, 2),
                "unprotected_total": round(unprotected, 2),
            },
        })
    except Exception as e:
        return json_error(str(e), 500)
    finally:
        db.close()


@banksia_os_bp.route("/finance/transactions")
def api_transactions():
    page = int_param(request.args.get("page"))
    per_page = int_param(request.args.get("per_page"), 20)
    is_overdue = request.args.get("is_overdue", "").strip()
    is_outstanding = request.args.get("is_outstanding", "").strip()
    property_id = request.args.get("property_id", "").strip()

    where_parts = ["1=1"]
    params = []

    if is_overdue.lower() in ("1", "true", "yes"):
        where_parts.append("is_overdue = 1")
    elif is_overdue.lower() in ("0", "false", "no"):
        where_parts.append("is_overdue = 0")

    if is_outstanding.lower() in ("1", "true", "yes"):
        where_parts.append("is_outstanding = 1")
    elif is_outstanding.lower() in ("0", "false", "no"):
        where_parts.append("is_outstanding = 0")

    if property_id:
        try:
            where_parts.append("property_id = ?")
            params.append(int(property_id))
        except ValueError:
            pass

    where = " AND ".join(where_parts)

    rows, total = paginate(
        f"SELECT * FROM transactions WHERE {where} ORDER BY date DESC",
        f"SELECT COUNT(*) AS cnt FROM transactions WHERE {where}",
        params, page, per_page
    )

    for r in rows:
        bool_fields(r, "is_overdue", "is_outstanding")

    return json_success(rows, total, page, per_page)


@banksia_os_bp.route("/finance/transactions/<int:txn_id>")
def api_transaction(txn_id):
    db = get_dict_db()
    try:
        txn = db.execute("SELECT * FROM transactions WHERE id = ?", (txn_id,)).fetchone()
        if not txn:
            return json_error("Transaction not found", 404)

        bool_fields(txn, "is_overdue", "is_outstanding")

        # Related entities
        if txn.get("tenancy_id"):
            ten = db.execute(
                "SELECT id, ref, status FROM tenancies WHERE id = ?",
                (txn["tenancy_id"],)
            ).fetchone()
            txn["tenancy"] = ten

        if txn.get("property_id"):
            prop = db.execute(
                "SELECT id, ref, name FROM properties WHERE id = ?",
                (txn["property_id"],)
            ).fetchone()
            txn["property"] = prop

        if txn.get("payee_tenant_id"):
            payee = db.execute(
                "SELECT id, first_name, last_name FROM tenants WHERE id = ?",
                (txn["payee_tenant_id"],)
            ).fetchone()
            if payee:
                txn["payee"] = f"{payee['first_name']} {payee['last_name']}".strip()

        return json_success(txn)
    except Exception as e:
        return json_error(str(e), 500)
    finally:
        db.close()


@banksia_os_bp.route("/finance/deposits")
def api_deposits():
    db = get_dict_db()
    try:
        registered = db.execute(
            "SELECT id, ref, full_address, deposit_held_by, deposit_scheme, "
            "deposit_registered_amount, main_tenant_name "
            "FROM tenancies WHERE deposit_registered = 1 ORDER BY full_address ASC"
        ).fetchall()

        unregistered = db.execute(
            "SELECT tenancies.id, tenancies.ref, tenancies.full_address, "
            "tenancies.deposit_held_by, tenancies.deposit_scheme, "
            "COALESCE(units.deposit_amount, 0) AS deposit_registered_amount, "
            "tenancies.main_tenant_name, tenancies.property_id, tenancies.unit_id "
            "FROM tenancies LEFT JOIN units ON tenancies.unit_id = units.id "
            "WHERE tenancies.deposit_registered = 0 "
            "ORDER BY tenancies.full_address ASC"
        ).fetchall()

        # Merge into flat list for frontend compatibility
        all_deposits = []
        for r in registered:
            all_deposits.append({
                "id": r["id"],
                "tenant_name": r.get("main_tenant_name") or "—",
                "property_name": r.get("full_address") or "—",
                "amount": r.get("deposit_registered_amount") or 0,
                "scheme": r.get("deposit_scheme") or "—",
                "registered": True,
                "ref": r.get("ref") or "",
            })
        for u in unregistered:
            all_deposits.append({
                "id": u["id"],
                "tenant_name": u.get("main_tenant_name") or "—",
                "property_name": u.get("full_address") or "—",
                "amount": u.get("deposit_registered_amount") or 0,
                "scheme": u.get("deposit_scheme") or "—",
                "registered": False,
                "ref": u.get("ref") or "",
            })
        return json_success(all_deposits)
    except Exception as e:
        return json_error(str(e), 500)
    finally:
        db.close()


# ═══════════════════════════════════════════════
# DEPOSITS — Authoritative deposits table endpoints
# ═══════════════════════════════════════════════

@banksia_os_bp.route("/deposits", methods=["GET"])
def api_banksia_deposits():
    """Paginated deposit list with summary stats."""
    page = int_param(request.args.get("page"))
    per_page = int_param(request.args.get("per_page"), 20)
    search = request.args.get("search", "").strip()
    status_filter = request.args.get("status", "").strip()
    protection_filter = request.args.get("protection", "").strip()

    where_parts = ["1=1"]
    params = []

    if status_filter:
        where_parts.append("d.current_status = ?")
        params.append(status_filter)
    if protection_filter:
        where_parts.append("d.protection_status = ?")
        params.append(protection_filter)
    if search:
        where_parts.append("(COALESCE(t.main_tenant_name, '') LIKE ? OR COALESCE(p.ref, '') LIKE ? OR COALESCE(p.address_line_1, '') LIKE ?)")
        like_val = f"%{search}%"
        params.extend([like_val, like_val, like_val])

    where = " AND ".join(where_parts)

    db = get_dict_db()
    try:
        # Stats
        currently_held = db.execute(
            "SELECT COALESCE(SUM(amount), 0) AS total, COUNT(*) AS cnt FROM deposits WHERE current_status = 'held'"
        ).fetchone()
        protected_total = db.execute(
            "SELECT COALESCE(SUM(amount), 0) AS total, COUNT(*) AS cnt FROM deposits WHERE protection_status = 'protected' AND current_status = 'held'"
        ).fetchone()
        awaiting_protection = db.execute(
            "SELECT COALESCE(SUM(amount), 0) AS total, COUNT(*) AS cnt FROM deposits WHERE protection_status = 'unprotected' AND current_status = 'held'"
        ).fetchone()
        historic = db.execute(
            "SELECT COALESCE(SUM(amount), 0) AS total, COUNT(*) AS cnt FROM deposits WHERE current_status IN ('returned', 'deducted')"
        ).fetchone()
        returned_total = db.execute(
            "SELECT COALESCE(SUM(amount_returned), 0) AS total FROM deposits WHERE current_status = 'returned'"
        ).fetchone()
        deduction_total = db.execute(
            "SELECT COALESCE(SUM(deductions), 0) AS total FROM deposits"
        ).fetchone()

        # Paginated list
        total = db.execute(
            f"SELECT COUNT(*) AS cnt FROM deposits d LEFT JOIN tenancies t ON d.tenancy_id = t.id LEFT JOIN properties p ON d.property_id = p.id WHERE {where}",
            params
        ).fetchone()["cnt"]

        offset = (page - 1) * per_page
        rows = db.execute(
            f"SELECT d.*, "
            f"t.main_tenant_name, t.ref AS tenancy_ref, t.status AS tenancy_status, "
            f"tn.first_name AS tenant_first_name, tn.last_name AS tenant_last_name, "
            f"COALESCE(NULLIF(p.ref, ''), NULLIF(p.address_line_1, ''), p.name) AS property_name, "
            f"u.unit_ref "
            f"FROM deposits d "
            f"LEFT JOIN tenancies t ON d.tenancy_id = t.id "
            f"LEFT JOIN tenants tn ON d.tenant_id = tn.id "
            f"LEFT JOIN properties p ON d.property_id = p.id "
            f"LEFT JOIN units u ON d.unit_id = u.id "
            f"WHERE {where} ORDER BY d.created DESC LIMIT ? OFFSET ?",
            params + [per_page, offset]
        ).fetchall()

        return json_success({
            "deposits": rows,
            "stats": {
                "currently_held": round(currently_held["total"], 2),
                "currently_held_count": currently_held["cnt"],
                "protected_total": round(protected_total["total"], 2),
                "protected_count": protected_total["cnt"],
                "awaiting_protection": round(awaiting_protection["total"], 2),
                "awaiting_protection_count": awaiting_protection["cnt"],
                "historic_total": round(historic["total"], 2),
                "historic_count": historic["cnt"],
                "returned_total": round(returned_total["total"], 2),
                "deduction_total": round(deduction_total["total"], 2),
            }
        }, total, page, per_page)
    except Exception as e:
        return json_error(str(e), 500)
    finally:
        db.close()


@banksia_os_bp.route("/deposits/reconciliation", methods=["GET"])
def api_deposits_reconciliation():
    """Returns the reconciliation report for deposits."""
    db = get_dict_db()
    try:
        # Currently held
        currently_held = db.execute(
            "SELECT COUNT(*) AS cnt, COALESCE(SUM(amount), 0) AS total FROM deposits WHERE current_status = 'held'"
        ).fetchone()
        protected = db.execute(
            "SELECT COUNT(*) AS cnt, COALESCE(SUM(amount), 0) AS total FROM deposits WHERE protection_status = 'protected' AND current_status = 'held'"
        ).fetchone()
        unprotected = db.execute(
            "SELECT COUNT(*) AS cnt, COALESCE(SUM(amount), 0) AS total FROM deposits WHERE protection_status = 'unprotected' AND current_status = 'held'"
        ).fetchone()

        # Historic
        historic = db.execute(
            "SELECT COUNT(*) AS cnt, COALESCE(SUM(amount), 0) AS total FROM deposits WHERE current_status IN ('returned', 'deducted')"
        ).fetchone()

        # Orphans — deposits without a linked tenancy
        orphans = db.execute(
            "SELECT d.*, COALESCE(NULLIF(p.ref, ''), NULLIF(p.address_line_1, ''), p.name) AS property_name "
            "FROM deposits d "
            "LEFT JOIN properties p ON d.property_id = p.id "
            "WHERE d.tenancy_id IS NULL OR d.tenancy_id NOT IN (SELECT id FROM tenancies)"
        ).fetchall()

        # Tenancies without a deposit record
        tenancies_without_deposit = db.execute(
            "SELECT t.id, t.ref, t.main_tenant_name, t.status, "
            "COALESCE(NULLIF(p.ref, ''), NULLIF(p.address_line_1, ''), p.name) AS property_name, "
            "t.deposit_registered_amount "
            "FROM tenancies t "
            "LEFT JOIN properties p ON t.property_id = p.id "
            "WHERE t.id NOT IN (SELECT tenancy_id FROM deposits WHERE tenancy_id IS NOT NULL) "
            "AND (t.deposit_registered_amount IS NOT NULL AND t.deposit_registered_amount > 0)"
        ).fetchall()

        # Mismatches — tenancy deposit_registered_amount != deposit record amount
        mismatches = db.execute(
            "SELECT t.id AS tenancy_id, t.ref AS tenancy_ref, t.main_tenant_name, "
            "t.deposit_registered_amount AS tenancy_amount, "
            "d.id AS deposit_id, d.amount AS deposit_amount, "
            "ABS(COALESCE(t.deposit_registered_amount, 0) - COALESCE(d.amount, 0)) AS difference "
            "FROM tenancies t "
            "JOIN deposits d ON d.tenancy_id = t.id "
            "WHERE ABS(COALESCE(t.deposit_registered_amount, 0) - COALESCE(d.amount, 0)) > 0.01"
        ).fetchall()

        # Totals
        total_all_time = db.execute(
            "SELECT COUNT(*) AS cnt, COALESCE(SUM(amount), 0) AS total FROM deposits"
        ).fetchone()

        return json_success({
            "currently_held": {
                "count": currently_held["cnt"],
                "total": round(currently_held["total"], 2),
                "protected": {
                    "count": protected["cnt"],
                    "total": round(protected["total"], 2),
                },
                "unprotected": {
                    "count": unprotected["cnt"],
                    "total": round(unprotected["total"], 2),
                },
            },
            "historic": {
                "count": historic["cnt"],
                "total": round(historic["total"], 2),
            },
            "orphans": orphans,
            "tenancies_without_deposit": tenancies_without_deposit,
            "mismatches": mismatches,
            "total_all_time": total_all_time["cnt"],
            "corrected_total": round(total_all_time["total"], 2),
        })
    except Exception as e:
        return json_error(str(e), 500)
    finally:
        db.close()


@banksia_os_bp.route("/deposits/migrate", methods=["POST"])
def api_deposits_migrate():
    """One-time migration: populate deposits from existing tenancy data.
    Idempotent — skips tenancy_ids that already have a deposit record.

    Requires super_admin role. Guarded by migration_log to prevent re-runs.
    """
    import hashlib
    from datetime import datetime, timezone

    # ── Super admin check ──
    user = session.get("user", {})
    if user.get("role") != "super_admin":
        return json_error("Only super admins can run deposit migration", 403)

    db = get_dict_db()
    log_id = None
    try:
        # ── Migration log guard ──
        existing = db.execute(
            "SELECT id, status, checksum FROM migration_log WHERE name = ?",
            ("deposit_migration_v1",)
        ).fetchone()
        if existing and existing["status"] == "completed":
            return json_error(
                f"Migration already completed (id={existing['id']}, checksum={existing['checksum']})",
                409
            )

        # ── Create or resume migration log entry ──
        now_iso = datetime.now(timezone.utc).isoformat()
        requester = user.get("username", "unknown")
        if existing and existing["status"] == "failed":
            # Reset a previously failed migration
            db.execute(
                "UPDATE migration_log SET status='in_progress', notes=?, start_time=? WHERE id=?",
                ("Retry after failure", now_iso, existing["id"])
            )
            log_id = existing["id"]
        elif not existing:
            cursor = db.execute(
                "INSERT INTO migration_log (name, version, start_time, user_process, status) "
                "VALUES (?, ?, ?, ?, 'in_progress')",
                ("deposit_migration_v1", "1.0", now_iso, requester)
            )
            log_id = cursor.lastrowid
        else:
            # Already 'in_progress' — continue
            log_id = existing["id"]

        # ── Run the migration ──
        active_statuses = ("'Active', 'active', 'Periodic', 'periodic', 'Current', 'current'")
        tenancies_to_migrate = db.execute(
            f"SELECT t.id, t.unit_id, t.property_id, t.deposit_registered_amount, "
            f"t.deposit_scheme, t.deposit_registered, t.main_tenant_name, "
            f"t.ref, t.start_date, t.status "
            f"FROM tenancies t "
            f"WHERE t.id NOT IN (SELECT tenancy_id FROM deposits WHERE tenancy_id IS NOT NULL) "
            f"AND t.deposit_registered_amount IS NOT NULL AND t.deposit_registered_amount > 0 "
            f"AND t.status IN ({active_statuses})"
        ).fetchall()

        total_reviewed = len(tenancies_to_migrate)
        inserted = 0
        skipped = 0
        errors = 0

        for t in tenancies_to_migrate:
            try:
                tenancy_id = t["id"]
                amount = t["deposit_registered_amount"] or 0
                scheme = t["deposit_scheme"]
                protection_status = "protected" if t["deposit_registered"] else "unprotected"
                deposit_type = "cash"

                primary_tenant = db.execute(
                    "SELECT id FROM tenants WHERE tenancy_id = ? AND main_tenant = 1 LIMIT 1",
                    (tenancy_id,)
                ).fetchone()
                tenant_id = primary_tenant["id"] if primary_tenant else None

                db.execute(
                    "INSERT INTO deposits (tenancy_id, tenant_id, unit_id, property_id, "
                    "amount, deposit_type, scheme, protection_status, date_received, "
                    "current_status, source) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'held', 'migration')",
                    (tenancy_id, tenant_id, t["unit_id"], t["property_id"],
                     amount, deposit_type, scheme, protection_status, t["start_date"])
                )
                inserted += 1
            except Exception:
                errors += 1
                continue

        db.commit()

        # ── Update migration log on success ──
        completion_iso = datetime.now(timezone.utc).isoformat()
        # Compute a simple checksum over the deposits table
        checksum_data = db.execute(
            "SELECT COUNT(*) AS cnt, COALESCE(SUM(amount), 0) AS total FROM deposits"
        ).fetchone()
        checksum_input = f"deposit_migration_v1|{checksum_data['cnt']}|{checksum_data['total']}|{completion_iso}"
        checksum = hashlib.sha256(checksum_input.encode()).hexdigest()[:16]

        db.execute(
            "UPDATE migration_log SET "
            "status='completed', completion_time=?, records_reviewed=?, "
            "records_inserted=?, records_skipped=?, errors=?, checksum=? "
            "WHERE id=?",
            (completion_iso, total_reviewed, inserted, skipped, errors, checksum, log_id)
        )
        db.commit()

        return json_success({
            "message": f"Migration complete. Inserted {inserted} deposit records, skipped {skipped} (already present), errors {errors}.",
            "inserted": inserted,
            "skipped": skipped,
            "errors": errors,
            "log_id": log_id,
            "checksum": checksum,
        })

    except Exception as e:
        # ── Update migration log on failure ──
        try:
            if log_id is not None:
                db.execute(
                    "UPDATE migration_log SET status='failed', completion_time=?, notes=? WHERE id=?",
                    (datetime.now(timezone.utc).isoformat(), f"Error: {str(e)}", log_id)
                )
                db.commit()
        except Exception:
            pass
        return json_error(str(e), 500)
    finally:
        db.close()


@banksia_os_bp.route("/deposits/<int:deposit_id>", methods=["GET"])
def api_deposits_detail(deposit_id):
    """Single deposit detail with linked tenancy/tenant/property info."""
    db = get_dict_db()
    try:
        deposit = db.execute(
            "SELECT d.*, "
            "t.main_tenant_name, t.ref AS tenancy_ref, t.status AS tenancy_status, "
            "t.start_date AS tenancy_start_date, t.end_date AS tenancy_end_date, "
            "t.rent_amount, t.rent_frequency, "
            "tn.first_name AS tenant_first_name, tn.last_name AS tenant_last_name, "
            "tn.email AS tenant_email, tn.mobile AS tenant_mobile, "
            "COALESCE(NULLIF(p.ref, ''), NULLIF(p.address_line_1, ''), p.name) AS property_name, "
            "p.address_line_1, p.address_line_2, p.city, p.postcode, "
            "u.unit_ref, u.unit_type "
            "FROM deposits d "
            "LEFT JOIN tenancies t ON d.tenancy_id = t.id "
            "LEFT JOIN tenants tn ON d.tenant_id = tn.id "
            "LEFT JOIN properties p ON d.property_id = p.id "
            "LEFT JOIN units u ON d.unit_id = u.id "
            "WHERE d.id = ?",
            (deposit_id,)
        ).fetchone()

        if not deposit:
            return json_error("Deposit not found", 404)

        return json_success(deposit)
    except Exception as e:
        return json_error(str(e), 500)
    finally:
        db.close()


# ═══════════════════════════════════════════════
# RENT CHARGES — Per-month editable schedule
# ═══════════════════════════════════════════════

@banksia_os_bp.route("/finance/rent-charges/<int:tenancy_id>", methods=["GET"])
def api_get_rent_charges(tenancy_id):
    """Get all monthly rent charges for a tenancy."""
    db = get_dict_db()
    try:
        charges = db.execute(
            "SELECT id, month, rent_amount, paid_amount, status, notes, created, modified "
            "FROM rent_charges WHERE tenancy_id = ? ORDER BY month ASC",
            (tenancy_id,)
        ).fetchall()
        return json_success(charges)
    except Exception as e:
        return json_error(str(e), 500)
    finally:
        db.close()


@banksia_os_bp.route("/finance/rent-charges/generate/<int:tenancy_id>", methods=["POST"])
def api_generate_rent_charges(tenancy_id):
    """Generate monthly rent charges for a tenancy based on its start/end dates and rent_amount.
    Existing charges are preserved; only missing months are added."""
    db = get_dict_db()
    try:
        tenancy = db.execute("SELECT id, start_date, end_date, rent_amount, rent_frequency FROM tenancies WHERE id = ?",
                             (tenancy_id,)).fetchone()
        if not tenancy:
            return json_error("Tenancy not found", 404)

        start = tenancy["start_date"]
        end = tenancy["end_date"] or (datetime.now(timezone.utc).replace(day=1) + timedelta(days=365)).isoformat()[:10]
        rent = float(tenancy["rent_amount"] or 0)
        freq = (tenancy["rent_frequency"] or "pcm").lower()

        # Generate from start to end (or 24 months max)
        try:
            cur = datetime.strptime(start[:7], "%Y-%m") if start else datetime.now(timezone.utc).replace(day=1)
        except:
            cur = datetime.now(timezone.utc).replace(day=1)
        try:
            end_dt = datetime.strptime(end[:7], "%Y-%m")
        except:
            end_dt = cur + timedelta(days=365)

        max_months = 24
        count = 0
        while cur <= end_dt and count < max_months:
            month_str = cur.strftime("%Y-%m")
            existing = db.execute("SELECT id FROM rent_charges WHERE tenancy_id = ? AND month = ?",
                                  (tenancy_id, month_str)).fetchone()
            if not existing:
                db.execute(
                    "INSERT INTO rent_charges (tenancy_id, month, rent_amount, status, created) "
                    "VALUES (?, ?, ?, 'due', ?)",
                    (tenancy_id, month_str, rent, datetime.now(timezone.utc).isoformat())
                )
            count += 1
            # Advance by frequency
            if freq in ("pw", "week", "weekly"):
                cur += timedelta(weeks=4)
            else:
                if cur.month == 12:
                    cur = cur.replace(year=cur.year + 1, month=1)
                else:
                    cur = cur.replace(month=cur.month + 1)

        db.commit()
        total_charges = db.execute("SELECT COUNT(*) AS c FROM rent_charges WHERE tenancy_id = ?",
                                   (tenancy_id,)).fetchone()["c"]
        return json_success({"generated": count, "total_charges": total_charges, "tenancy_id": tenancy_id})
    except Exception as e:
        return json_error(str(e), 500)
    finally:
        db.close()


@banksia_os_bp.route("/finance/rent-charges/<int:charge_id>", methods=["PATCH"])
def api_update_rent_charge(charge_id):
    """Update a specific month's rent charge (amount, paid_amount, status, notes)."""
    data = request.get_json()
    if not data:
        return json_error("No data provided")
    db = get_dict_db()
    try:
        charge = db.execute("SELECT id, tenancy_id FROM rent_charges WHERE id = ?", (charge_id,)).fetchone()
        if not charge:
            return json_error("Charge not found", 404)
        set_parts = ["modified = ?"]
        params = [datetime.now(timezone.utc).isoformat()]
        for key in ("rent_amount", "paid_amount", "status", "notes"):
            if key in data:
                set_parts.append(f"{key} = ?")
                params.append(data[key])
        params.append(charge_id)
        db.execute(f"UPDATE rent_charges SET {', '.join(set_parts)} WHERE id = ?", params)
        db.commit()

        # Recalculate tenancy financial summary
        tenancy_id = charge["tenancy_id"]
        totals = db.execute(
            "SELECT COALESCE(SUM(rent_amount),0) AS total_expected, "
            "COALESCE(SUM(paid_amount),0) AS total_paid "
            "FROM rent_charges WHERE tenancy_id = ?",
            (tenancy_id,)
        ).fetchone()
        return json_success({
            "updated": True,
            "charge_id": charge_id,
            "total_expected": round(totals["total_expected"], 2),
            "total_paid": round(totals["total_paid"], 2),
            "balance": round(totals["total_expected"] - totals["total_paid"], 2)
        })
    except Exception as e:
        return json_error(str(e), 500)
    finally:
        db.close()


@banksia_os_bp.route("/finance/recalculate", methods=["POST"])
def api_recalculate_finances():
    """Recalculate all financial KPI summary data from rent_charges."""
    db = get_dict_db()
    try:
        tenancy_counts = db.execute("SELECT COUNT(DISTINCT tenancy_id) AS c FROM rent_charges").fetchone()["c"]
        total_expected = db.execute("SELECT COALESCE(SUM(rent_amount),0) AS t FROM rent_charges").fetchone()["t"]
        total_paid = db.execute("SELECT COALESCE(SUM(paid_amount),0) AS t FROM rent_charges").fetchone()["t"]
        overdue = db.execute("SELECT COALESCE(SUM(rent_amount - paid_amount),0) AS t FROM rent_charges WHERE status IN ('due','overdue')").fetchone()["t"]
        monthly = db.execute(
            "SELECT COALESCE(SUM(rc.rent_amount),0) AS t FROM rent_charges rc "
            "JOIN tenancies t ON rc.tenancy_id = t.id "
            "WHERE rc.month = strftime('%Y-%m', 'now') AND t.status IN ('Active','Periodic','active','periodic')"
        ).fetchone()["t"]
        return json_success({
            "tenancies_with_charges": tenancy_counts,
            "total_expected": round(total_expected, 2),
            "total_paid": round(total_paid, 2),
            "total_outstanding": round(total_expected - total_paid, 2),
            "current_month_rent": round(monthly, 2),
            "overdue_estimated": round(overdue, 2)
        })
    except Exception as e:
        return json_error(str(e), 500)
    finally:
        db.close()


# ═══════════════════════════════════════════════
# 8. SEARCH
# ═══════════════════════════════════════════════

@banksia_os_bp.route("/search")
def api_search():
    q = request.args.get("q", "").strip()
    if not q:
        return json_error("Query parameter 'q' is required")

    like_val = f"%{q}%"
    db = get_dict_db()
    try:
        # Properties
        properties = db.execute(
            "SELECT id, ref, name, address_line_1, city, postcode, main_image_url, "
            "'property' AS result_type FROM properties "
            "WHERE name LIKE ? OR ref LIKE ? OR address_line_1 LIKE ? OR city LIKE ? OR postcode LIKE ? "
            "LIMIT 10",
            [like_val] * 5
        ).fetchall()

        # Units
        units = db.execute(
            "SELECT id, unit_ref, full_address, unit_type, unit_status, "
            "'unit' AS result_type FROM units "
            "WHERE unit_ref LIKE ? OR full_address LIKE ? OR unit_type LIKE ? OR owner_name LIKE ? "
            "LIMIT 10",
            [like_val] * 4
        ).fetchall()
        for u in units:
            bool_fields(u, "unit_vacant") if "unit_vacant" in u else None

        # Tenancies
        tenancies = db.execute(
            "SELECT id, ref, full_address, status, main_tenant_name, rent_amount, start_date, end_date, "
            "'tenancy' AS result_type FROM tenancies "
            "WHERE ref LIKE ? OR full_address LIKE ? OR main_tenant_name LIKE ? "
            "LIMIT 10",
            [like_val] * 3
        ).fetchall()

        # Tenants
        tenants = db.execute(
            "SELECT id, first_name, last_name, email, mobile, full_address, status, "
            "'tenant' AS result_type FROM tenants "
            "WHERE first_name LIKE ? OR last_name LIKE ? OR email LIKE ? OR mobile LIKE ? OR full_address LIKE ? "
            "LIMIT 10",
            [like_val] * 5
        ).fetchall()

        # Applicants
        applicants = db.execute(
            "SELECT id, first_name, last_name, email, mobile, full_address, status, "
            "'applicant' AS result_type FROM applicants "
            "WHERE first_name LIKE ? OR last_name LIKE ? OR email LIKE ? OR mobile LIKE ? OR full_address LIKE ? "
            "LIMIT 10",
            [like_val] * 5
        ).fetchall()

        results = {
            "properties": properties,
            "units": units,
            "tenancies": tenancies,
            "tenants": tenants,
            "applicants": applicants,
            "total_count": len(properties) + len(units) + len(tenancies) + len(tenants) + len(applicants),
        }

        return json_success(results)
    except Exception as e:
        return json_error(str(e), 500)
    finally:
        db.close()


# ═══════════════════════════════════════════════
# 9. WRITE ENDPOINTS — Tenancies, Applicants, Tenants
# ═══════════════════════════════════════════════

@banksia_os_bp.route("/tenancies", methods=["POST"])
def api_create_tenancy():
    """Create a new tenancy."""
    data = request.get_json(silent=True)
    if not data:
        return json_error("Request body must be JSON")

    property_id = data.get("property_id")
    unit_id = data.get("unit_id")
    start_date = data.get("start_date")
    rent_amount = data.get("rent_amount")
    rent_frequency = data.get("rent_frequency", "pcm")
    deposit_amount = data.get("deposit_amount")
    main_tenant_name = data.get("main_tenant_name")

    if not all([property_id, unit_id, start_date, rent_amount]):
        return json_error("Missing required fields: property_id, unit_id, start_date, rent_amount")

    db = get_dict_db()
    try:
        # Verify unit exists
        unit = db.execute("SELECT id, unit_ref, owner_name FROM units WHERE id = ?", (unit_id,)).fetchone()
        if not unit:
            return json_error("Unit not found", 404)

        # Generate a ref
        now = datetime.now(timezone.utc)
        ref = f"TEN-{now.strftime('%Y%m')}-{db.execute('SELECT COALESCE(MAX(id),0)+1 FROM tenancies').fetchone()['COALESCE(MAX(id),0)+1']}"

        full_address = unit.get("owner_name") or f"Unit {unit.get('unit_ref')}"
        property_id_val = int(property_id)
        rent_amount_val = float(rent_amount)
        deposit_amount_val = float(deposit_amount) if deposit_amount else 0
        now_iso = now.isoformat()

        db.execute(
            """INSERT INTO tenancies
               (property_id, unit_id, ref, full_address, status, start_date,
                rent_amount, rent_frequency, deposit_registered_amount,
                main_tenant_name, modified, created)
               VALUES (?, ?, ?, ?, 'Active', ?, ?, ?, ?, ?, ?, ?)""",
            (property_id_val, int(unit_id), ref, full_address, start_date,
             rent_amount_val, rent_frequency, deposit_amount_val,
             main_tenant_name or "", now_iso, now_iso)
        )
        new_id = db.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]
        db.commit()

        # Mark unit as not vacant
        db.execute("UPDATE units SET unit_vacant = 0, unit_status = 'Let' WHERE id = ?", (int(unit_id),))
        db.commit()

        return json_success({"id": new_id, "ref": ref})
    except Exception as e:
        db.rollback()
        return json_error(str(e), 500)
    finally:
        db.close()


@banksia_os_bp.route("/tenancies/<int:ten_id>/end", methods=["POST"])
def api_end_tenancy(ten_id):
    """End a tenancy — set end_date, move_out_date, and update status."""
    data = request.get_json(silent=True)
    if not data:
        return json_error("Request body must be JSON")

    end_date = data.get("end_date")
    move_out_date = data.get("move_out_date")

    if not end_date:
        return json_error("end_date is required")

    db = get_dict_db()
    try:
        tenancy = db.execute("SELECT * FROM tenancies WHERE id = ?", (ten_id,)).fetchone()
        if not tenancy:
            return json_error("Tenancy not found", 404)

        db.execute(
            "UPDATE tenancies SET status = 'Ended', end_date = ?, move_out_date = ?, modified = ? WHERE id = ?",
            (end_date, move_out_date or end_date, datetime.now(timezone.utc).isoformat(), ten_id)
        )
        db.commit()

        # Mark unit as vacant
        if tenancy.get("unit_id"):
            db.execute("UPDATE units SET unit_vacant = 1, unit_status = 'Available' WHERE id = ?",
                       (tenancy["unit_id"],))
            db.commit()

        return json_success({"id": ten_id, "status": "Ended"})
    except Exception as e:
        db.rollback()
        return json_error(str(e), 500)
    finally:
        db.close()


@banksia_os_bp.route("/applicants", methods=["POST"])
def api_create_applicant():
    """Create a new applicant."""
    data = request.get_json(silent=True)
    if not data:
        return json_error("Request body must be JSON")

    first_name = data.get("first_name", "").strip()
    last_name = data.get("last_name", "").strip()
    email = data.get("email", "").strip()
    mobile = data.get("mobile", "").strip()
    source = data.get("source", "").strip()
    status = data.get("status", "Active").strip()

    if not first_name or not last_name:
        return json_error("first_name and last_name are required")

    db = get_dict_db()
    try:
        now_iso = datetime.now(timezone.utc).isoformat()
        db.execute(
            """INSERT INTO applicants
               (first_name, last_name, email, mobile, source, status, modified, created)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (first_name, last_name, email, mobile, source, status, now_iso, now_iso)
        )
        new_id = db.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]
        db.commit()
        return json_success({"id": new_id})
    except Exception as e:
        db.rollback()
        return json_error(str(e), 500)
    finally:
        db.close()


@banksia_os_bp.route("/applicants/<int:app_id>/status", methods=["POST"])
def api_update_applicant_status(app_id):
    """Update an applicant's status."""
    data = request.get_json(silent=True)
    if not data:
        return json_error("Request body must be JSON")

    status = data.get("status", "").strip()
    if not status:
        return json_error("status is required")

    db = get_dict_db()
    try:
        app = db.execute("SELECT id FROM applicants WHERE id = ?", (app_id,)).fetchone()
        if not app:
            return json_error("Applicant not found", 404)

        now_iso = datetime.now(timezone.utc).isoformat()
        db.execute(
            "UPDATE applicants SET status = ?, modified = ? WHERE id = ?",
            (status, now_iso, app_id)
        )
        db.commit()
        return json_success({"id": app_id, "status": status})
    except Exception as e:
        db.rollback()
        return json_error(str(e), 500)
    finally:
        db.close()


@banksia_os_bp.route("/tenants", methods=["POST"])
def api_create_tenant():
    """Create a new tenant."""
    data = request.get_json(silent=True)
    if not data:
        return json_error("Request body must be JSON")

    first_name = data.get("first_name", "").strip()
    last_name = data.get("last_name", "").strip()
    email = data.get("email", "").strip()
    mobile = data.get("mobile", "").strip()
    tenancy_id = data.get("tenancy_id")

    if not first_name or not last_name:
        return json_error("first_name and last_name are required")

    db = get_dict_db()
    try:
        # Look up tenancy for property/unit info
        tenancy = None
        property_id = None
        unit_id = None
        full_address = ""
        if tenancy_id:
            tenancy = db.execute(
                "SELECT id, property_id, unit_id, full_address FROM tenancies WHERE id = ?",
                (tenancy_id,)
            ).fetchone()
            if tenancy:
                property_id = tenancy["property_id"]
                unit_id = tenancy["unit_id"]
                full_address = tenancy["full_address"] or ""

        now_iso = datetime.now(timezone.utc).isoformat()
        db.execute(
            """INSERT INTO tenants
               (first_name, last_name, email, mobile, tenancy_id, property_id, unit_id,
                full_address, main_tenant, modified, created)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)""",
            (first_name, last_name, email, mobile, tenancy_id,
             property_id, unit_id, full_address, now_iso, now_iso)
        )
        new_id = db.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]
        db.commit()
        return json_success({"id": new_id})
    except Exception as e:
        db.rollback()
        return json_error(str(e), 500)
    finally:
        db.close()


# ═══════════════════════════════════════════════
# 10. DOCUMENT GENERATION
# ═══════════════════════════════════════════════

from document_engine import generate_document, save_template, list_templates, delete_template, list_generated_documents, record_generated_document, get_template_info


@banksia_os_bp.route("/documents/templates", methods=["GET"])
def api_list_templates():
    templates = list_templates()
    return json_success(templates)


@banksia_os_bp.route("/documents/templates", methods=["POST"])
def api_upload_template():
    if "file" not in request.files:
        return json_error("No file uploaded")
    file = request.files["file"]
    name = request.form.get("name", file.filename or "Untitled")
    description = request.form.get("description", "")
    tid, err = save_template(file, name, description)
    if err:
        return json_error(err)
    return json_success({"id": tid, "name": name})


@banksia_os_bp.route("/documents/templates/<template_id>", methods=["DELETE"])
def api_delete_template(template_id):
    if delete_template(template_id):
        return json_success({"deleted": True})
    return json_error("Template not found", 404)


@banksia_os_bp.route("/documents/templates/<template_id>/download")
def api_download_template(template_id):
    info = get_template_info(template_id)
    if not info:
        return json_error("Template not found", 404)
    path = os.path.join(os.path.dirname(__file__), "documents", "templates", info["filename"])
    if not os.path.exists(path):
        return json_error("File not found", 404)
    from flask import send_file
    return send_file(path, as_attachment=True, download_name=info["filename"])


@banksia_os_bp.route("/documents/generate", methods=["POST"])
def api_generate_document():
    data = request.get_json(silent=True) or {}
    template_id = data.get("template_id")
    tenancy_id = data.get("tenancy_id")
    if not template_id or not tenancy_id:
        return json_error("template_id and tenancy_id are required")
    info = get_template_info(template_id)
    if not info:
        return json_error("Template not found", 404)
    template_path = os.path.join(os.path.dirname(__file__), "documents", "templates", info["filename"])
    output_path, err = generate_document(template_path, tenancy_id)
    if err:
        return json_error(err)
    doc_id = record_generated_document(output_path, info["name"], tenancy_id, "Tenant")
    return json_success({"id": doc_id, "filename": os.path.basename(output_path)})


@banksia_os_bp.route("/documents/generated", methods=["GET"])
def api_list_generated():
    docs = list_generated_documents()
    return json_success(docs)


@banksia_os_bp.route("/documents/generated/<doc_id>/download")
def api_download_generated(doc_id):
    docs = list_generated_documents()
    info = next((d for d in docs if d["id"] == doc_id), None)
    if not info:
        return json_error("Document not found", 404)
    path = os.path.join(os.path.dirname(__file__), "documents", "generated", info["filename"])
    if not os.path.exists(path):
        return json_error("File not found", 404)
    from flask import send_file
    return send_file(path, as_attachment=True, download_name=info["filename"])


# ═══════════════════════════════════════════════
# UPLOADED DOCUMENTS STORAGE
# ═══════════════════════════════════════════════

@banksia_os_bp.route("/documents/upload", methods=["POST"])
def api_upload_document():
    """Upload a document file and associate it with a tenancy/property/tenant."""
    if "file" not in request.files:
        return json_error("No file provided")
    file = request.files["file"]
    if file.filename == "":
        return json_error("Empty filename")

    docs_dir = os.path.join(os.path.dirname(__file__), "documents", "uploads")
    os.makedirs(docs_dir, exist_ok=True)

    category = request.form.get("category", "general")
    related_to = request.form.get("related_to", "")
    related_id = request.form.get("related_id", "")
    notes = request.form.get("notes", "")

    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    safe_name = f"{ts}_{file.filename}"
    save_path = os.path.join(docs_dir, safe_name)
    file.save(save_path)

    db = get_dict_db()
    try:
        # ── Auto-match: parse filename to find tenant/tenancy ──
        matched_to = None
        auto_match = request.form.get("auto_match", "false") == "true"
        if auto_match:
            fn = file.filename.lower()
            # Try to extract tenancy ref pattern (TE followed by digits)
            import re
            ref_match = re.search(r'[Tt][Ee]\d+', fn)
            if ref_match:
                ref = ref_match.group().upper()
                tenancy = db.execute(
                    "SELECT id, ref, main_tenant_name, full_address FROM tenancies WHERE ref LIKE ? LIMIT 1",
                    (f"%{ref}%",)
                ).fetchone()
                if tenancy:
                    related_to = "tenancy"
                    related_id = str(tenancy["id"])
                    matched_to = f"Tenancy {ref} ({tenancy.get('main_tenant_name','')[:30]})"
            if not matched_to:
                # Try tenant name match
                name_parts = fn.replace("_", " ").replace("-", " ").split()
                for name in name_parts:
                    if len(name) > 3:
                        tenant = db.execute(
                            "SELECT id, first_name, last_name FROM tenants WHERE first_name LIKE ? OR last_name LIKE ? LIMIT 1",
                            (f"%{name}%", f"%{name}%")
                        ).fetchone()
                        if tenant:
                            related_to = "tenant"
                            related_id = str(tenant["id"])
                            matched_to = f"Tenant {tenant['first_name']} {tenant['last_name']}"
                            break
            if not matched_to:
                # Try tenancy ID in filename
                id_match = re.search(r'\b(\d{3,5})\b', fn)
                if id_match:
                    tid = id_match.group(1)
                    tenancy = db.execute(
                        "SELECT id, ref, main_tenant_name FROM tenancies WHERE id LIKE ? OR ref LIKE ? LIMIT 1",
                        (f"%{tid}%", f"%{tid}%")
                    ).fetchone()
                    if tenancy:
                        related_to = "tenancy"
                        related_id = str(tenancy["id"])
                        matched_to = f"Tenancy {tenancy.get('ref','')}"

        db.execute(
            "INSERT INTO documents (filename, file_path, file_type, category, related_to, related_id, notes, created) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (file.filename, save_path, os.path.splitext(file.filename)[1].lower().lstrip("."),
             category, related_to, related_id, notes, datetime.now(timezone.utc).isoformat())
        )
        db.commit()
        result = {"id": db.lastrowid, "filename": file.filename}
        if matched_to:
            result["matched_to"] = matched_to
        return json_success(result)
    except Exception as e:
        return json_error(str(e), 500)
    finally:
        db.close()


@banksia_os_bp.route("/documents/uploaded", methods=["GET"])
def api_list_uploaded():
    db = get_dict_db()
    try:
        docs = db.execute(
            "SELECT id, filename, file_type, category, related_to, related_id, notes, created "
            "FROM documents ORDER BY created DESC"
        ).fetchall()
        return json_success(docs)
    except Exception as e:
        return json_error(str(e), 500)
    finally:
        db.close()


@banksia_os_bp.route("/documents/uploaded/<int:doc_id>/download")
def api_download_uploaded(doc_id):
    db = get_dict_db()
    try:
        doc = db.execute("SELECT id, filename, file_path FROM documents WHERE id = ?", (doc_id,)).fetchone()
        if not doc:
            return json_error("Document not found", 404)
        if not os.path.exists(doc["file_path"]):
            return json_error("File not found on disk", 404)
        from flask import send_file
        return send_file(doc["file_path"], as_attachment=True, download_name=doc["filename"])
    finally:
        db.close()


@banksia_os_bp.route("/documents/uploaded/<int:doc_id>", methods=["DELETE"])
def api_delete_uploaded(doc_id):
    db = get_dict_db()
    try:
        doc = db.execute("SELECT id, file_path FROM documents WHERE id = ?", (doc_id,)).fetchone()
        if not doc:
            return json_error("Document not found", 404)
        if os.path.exists(doc["file_path"]):
            os.remove(doc["file_path"])
        db.execute("DELETE FROM documents WHERE id = ?", (doc_id,))
        db.commit()
        return json_success({"deleted": True})
    except Exception as e:
        return json_error(str(e), 500)
    finally:
        db.close()


# ═══════════════════════════════════════════════
# COMMENTS & NOTIFICATIONS (Monday.com-style updates)
# ═══════════════════════════════════════════════

@banksia_os_bp.route("/comments/<entity_type>/<int:entity_id>", methods=["GET"])
def api_get_comments(entity_type, entity_id):
    valid = {"tenancy","tenancies","property","properties","tenant","tenants",
             "applicant","applicants","unit","units","transaction","transactions"}
    if entity_type not in valid:
        return json_error("Invalid entity type", 400)
    if entity_type == "tenancy": entity_type = "tenancies"
    elif entity_type == "property": entity_type = "properties"
    elif entity_type == "applicant": entity_type = "applicants"
    elif entity_type == "transaction": entity_type = "transactions"
    db = get_dict_db()
    try:
        comments = db.execute(
            "SELECT id, author, body, mentions, created FROM comments "
            "WHERE entity_type = ? AND entity_id = ? ORDER BY created ASC",
            (entity_type, entity_id)
        ).fetchall()
        return json_success(comments)
    except Exception as e:
        return json_error(str(e), 500)
    finally:
        db.close()


@banksia_os_bp.route("/comments/<entity_type>/<int:entity_id>", methods=["POST"])
def api_add_comment(entity_type, entity_id):
    data = request.get_json()
    if not data or not data.get("body","").strip():
        return json_error("Comment body is required")
    body = data["body"].strip()
    author = data.get("author","Unknown")
    etype = entity_type
    if etype == "tenancy": etype = "tenancies"
    elif etype == "property": etype = "properties"
    elif etype == "applicant": etype = "applicants"
    elif etype == "transaction": etype = "transactions"
    valid = {"tenancies","properties","tenants","applicants","units","transactions"}
    if etype not in valid:
        return json_error("Invalid entity type", 400)
    import re
    mentioned = re.findall(r'@(\w+)', body)
    db = get_dict_db()
    try:
        c = db.execute(
            "INSERT INTO comments (entity_type, entity_id, author, body, mentions, created) VALUES (?,?,?,?,?,?)",
            (etype, entity_id, author, body, json.dumps(mentioned), datetime.now(timezone.utc).isoformat())
        )
        cid = c.lastrowid
        for u in mentioned:
            db.execute(
                "INSERT INTO notifications (username, message, link, read, created) VALUES (?,?,?,0,?)",
                (u, f"{author} @mentioned you on {etype[:-1]} #{entity_id}",
                 f"/banksia-os?entity={etype}&id={entity_id}",
                 datetime.now(timezone.utc).isoformat())
            )
        db.commit()
        return json_success({"id":cid,"author":author,"body":body,"mentions":mentioned,
                            "created":datetime.now(timezone.utc).isoformat()})
    except Exception as e:
        return json_error(str(e), 500)
    finally:
        db.close()


@banksia_os_bp.route("/comments/recent")
def api_recent_comments():
    """Return the most recent N comments across all entities."""
    limit = int_param(request.args.get("limit"), 5)
    db = get_dict_db()
    try:
        comments = db.execute(
            "SELECT id, author, body, entity_type, entity_id, created FROM comments "
            "ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return json_success(comments)
    except Exception as e:
        return json_error(str(e), 500)
    finally:
        db.close()


@banksia_os_bp.route("/properties/compliance")
def api_properties_compliance():
    """Return compliance issues across all properties (missing certificates, etc)."""
    db = get_dict_db()
    try:
        issues = []
        props = db.execute("SELECT id, ref, name FROM properties ORDER BY name").fetchall()
        for p in props:
            # Check for missing council tax band
            if not p.get("council_tax_band"):
                issues.append({"property_id": p["id"], "property_name": p["ref"] or p["name"],
                               "issue": "Council Tax Band not set", "status": "missing"})
            # Check for missing EPC check based on tenancies
            tenancies = db.execute(
                "SELECT COUNT(*) AS cnt FROM tenancies WHERE property_id=? AND status IN ('Current','current','Periodic','periodic')",
                (p["id"],)
            ).fetchone()
            if tenancies and tenancies["cnt"] > 0:
                issues.append({"property_id": p["id"], "property_name": p["ref"] or p["name"],
                               "issue": f"{tenancies['cnt']} active tenancies — compliance review needed",
                               "status": "pending"})
        return json_success(issues)
    except Exception as e:
        return json_error(str(e), 500)
    finally:
        db.close()


@banksia_os_bp.route("/notifications", methods=["GET"])
def api_get_notifications():
    """Enhanced GET /notifications — returns full items + unread_count.
    
    Query params:
        mark_read=true|false  (default true) — mark returned notifications as read
        unread_only=true       — legacy compat, just returns unread_count
    """
    db = get_dict_db()
    try:
        u = getattr(request, 'current_user', None) or session.get("user", {})
        uname = u.get("username", "") if isinstance(u, dict) else getattr(u, "username", "")
        
        # Legacy compat: just return count
        if request.args.get("unread_only", "") == "true":
            cnt = db.execute(
                "SELECT COUNT(*) AS c FROM notifications WHERE username=? AND read=0",
                (uname,)
            ).fetchone()["c"]
            return json_success({"unread_count": cnt})
        
        # Fetch unread notifications (limit 20, ordered by created DESC)
        items = db.execute(
            "SELECT id, message, link, read, created FROM notifications "
            "WHERE username=? AND read=0 ORDER BY created DESC LIMIT 20",
            (uname,)
        ).fetchall()
        
        uc = db.execute(
            "SELECT COUNT(*) AS c FROM notifications WHERE username=? AND read=0",
            (uname,)
        ).fetchone()["c"]
        
        # Mark as read if requested (default true)
        mark_read = request.args.get("mark_read", "true").lower() == "true"
        if mark_read and items:
            ids = [r["id"] for r in items]
            placeholders = ",".join("?" * len(ids))
            db.execute(
                f"UPDATE notifications SET read=1 WHERE id IN ({placeholders})",
                ids
            )
            db.commit()
            uc = 0  # just marked them all as read
        
        return json_success({"items": items, "unread_count": uc})
    except Exception as e:
        return json_error(str(e), 500)
    finally:
        db.close()


@banksia_os_bp.route("/notifications/<int:notification_id>/read", methods=["POST"])
def api_mark_notification_read(notification_id):
    """Mark a single notification as read."""
    db = get_dict_db()
    try:
        u = getattr(request, 'current_user', None) or session.get("user", {})
        uname = u.get("username", "") if isinstance(u, dict) else getattr(u, "username", "")
        db.execute(
            "UPDATE notifications SET read=1 WHERE id=? AND username=?",
            (notification_id, uname)
        )
        db.commit()
        return json_success({"ok": True})
    except Exception as e:
        return json_error(str(e), 500)
    finally:
        db.close()


@banksia_os_bp.route("/notifications/read-all", methods=["POST"])
def api_mark_all_read():
    """Mark all of the current user's notifications as read."""
    db = get_dict_db()
    try:
        u = getattr(request, 'current_user', None) or session.get("user", {})
        uname = u.get("username", "") if isinstance(u, dict) else getattr(u, "username", "")
        db.execute(
            "UPDATE notifications SET read=1 WHERE username=? AND read=0",
            (uname,)
        )
        db.commit()
        return json_success({"ok": True})
    except Exception as e:
        return json_error(str(e), 500)
    finally:
        db.close()


@banksia_os_bp.route("/notifications/mark-read", methods=["POST"])
def api_mark_read():
    """Legacy: mark single notification by id in JSON body, or all if no id given."""
    db = get_dict_db()
    try:
        u = getattr(request, 'current_user', None) or session.get("user", {})
        uname = u.get("username", "") if isinstance(u, dict) else getattr(u, "username", "")
        data = request.get_json() or {}
        nid = data.get("id")
        if nid:
            db.execute("UPDATE notifications SET read=1 WHERE id=? AND username=?", (nid, uname))
        else:
            db.execute("UPDATE notifications SET read=1 WHERE username=? AND read=0", (uname,))
        db.commit()
        return json_success({"ok": True})
    except Exception as e:
        return json_error(str(e), 500)
    finally:
        db.close()


def create_notification(username, message, link=None):
    """Standalone helper: insert a notification for a user.
    
    Args:
        username: str — the recipient's username
        message: str — notification text
        link: str or None — optional link path
    
    Returns:
        int — the new notification id, or None on failure
    """
    try:
        db = get_dict_db()
        try:
            now = datetime.now(timezone.utc).isoformat()
            cur = db.execute(
                "INSERT INTO notifications (username, message, link, read, created) VALUES (?, ?, ?, 0, ?)",
                (username, message, link or "", now)
            )
            db.commit()
            return cur.lastrowid
        finally:
            db.close()
    except Exception:
        return None


@banksia_os_bp.route("/users", methods=["GET"])
def api_users():
    import json as jm
    uf = os.path.join(os.path.dirname(__file__),"users.json")
    users_list = []
    if os.path.exists(uf):
        with open(uf) as f:
            users = jm.load(f)
            for username, info in users.items():
                users_list.append({
                    "username": username,
                    "role": info.get("role", "user"),
                    "email": info.get("email", ""),
                    "biography": info.get("biography", ""),
                })
    return json_success(users_list)


@banksia_os_bp.route("/users", methods=["POST"])
def api_add_user():
    user = session.get("user", {})
    role = user.get("role", "")
    if role not in ("super_admin", "admin"):
        return json_error("Forbidden — admin or super admin only", 403)
    data = request.get_json()
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()
    new_role = data.get("role", "admin").strip()
    if not username or not password:
        return json_error("username and password required", 400)
    if new_role not in ("admin", "super_admin", "projects"):
        new_role = "admin"
    # Only super_admin can create other super_admin accounts
    if new_role == "super_admin" and role != "super_admin":
        return json_error("Only super admins can create super admin accounts", 403)
    users = _load_users()
    users[username] = {"password": password, "role": new_role}
    _save_users(users)
    return json_success({"user": {"username": username, "role": new_role}})


@banksia_os_bp.route("/users/<username>", methods=["PATCH"])
def api_update_user(username):
    data = request.get_json(silent=True)
    if not data:
        return json_error("No data", 400)
    users = _load_users()
    if username not in users:
        return json_error("User not found", 404)
    current_user = session.get("user", {})
    current_role = current_user.get("role", "")
    is_super = current_role == "super_admin"
    is_admin = current_role in ("super_admin", "admin")
    is_self = current_user.get("username") == username
    # Super admin can edit anyone. Admin can edit themselves or non-super_admin users.
    target = users[username] if isinstance(users[username], dict) else {}
    target_role = target.get("role", "admin") if isinstance(target, dict) else "admin"
    if is_super:
        pass  # can edit anyone
    elif is_admin and is_self:
        pass  # can edit self
    elif is_admin and target_role != "super_admin":
        pass  # admin can edit non-super_admin users
    else:
        return json_error("Forbidden", 403)
    allowed_fields = ["email", "phone", "date_of_birth", "biography", "department", "position"]
    for f in allowed_fields:
        if f in data:
            users[username][f] = data[f]
    # Only super admin can change role
    if is_super and "role" in data:
        users[username]["role"] = data["role"]
    # Password update handled separately by change-password endpoint
    if "password" in data and data["password"]:
        users[username]["password"] = data["password"]
    _save_users(users)
    return json_success({"user": {"username": username, "role": users[username].get("role")}})


@banksia_os_bp.route("/users/<username>", methods=["DELETE"])
def api_delete_user(username):
    current = session.get("user", {})
    current_role = current.get("role", "")
    if current_role not in ("super_admin", "admin"):
        return json_error("Forbidden", 403)
    if username == "Sami":
        return json_error("Cannot delete super admin", 400)
    users = _load_users()
    target = users.get(username, {})
    target_role = target.get("role", "admin") if isinstance(target, dict) else "admin"
    # Admins can only delete non-super_admin users
    if current_role == "admin" and target_role == "super_admin":
        return json_error("Admins cannot delete super admins", 403)
    if username in users:
        del users[username]
        _save_users(users)
    return json_success({"deleted": True})


@banksia_os_bp.route("/users/autocomplete", methods=["GET"])
def api_users_autocomplete():
    import json as jm
    uf = os.path.join(os.path.dirname(__file__),"users.json")
    if os.path.exists(uf):
        with open(uf) as f: users = jm.load(f)
        names = list(users.keys())
    else:
        names = []
    return json_success(names)


# ═══════════════════════════════════════════════
# 6. FINANCE — Rent Schedule & Tenancy Summary
# ═══════════════════════════════════════════════

@banksia_os_bp.route("/finance/rent-schedule/<int:tenancy_id>")
def api_rent_schedule(tenancy_id):
    """Return projected rent payment schedule for a tenancy."""
    db = get_dict_db()
    try:
        tenancy = db.execute(
            "SELECT * FROM tenancies WHERE id = ?", (tenancy_id,)
        ).fetchone()
        if not tenancy:
            return json_error("Tenancy not found", 404)

        start_date = tenancy.get("start_date")
        end_date = tenancy.get("end_date")
        rent_amount = tenancy.get("rent_amount")
        rent_frequency = tenancy.get("rent_frequency", "monthly")

        if not start_date or not rent_amount:
            return json_error("Tenancy missing start_date or rent_amount")

        try:
            cur = datetime.strptime(start_date, "%Y-%m-%d")
        except (ValueError, TypeError):
            try:
                cur = datetime.fromisoformat(start_date)
            except (ValueError, TypeError):
                return json_error("Invalid start_date format")

        if end_date:
            try:
                end = datetime.strptime(end_date, "%Y-%m-%d")
            except (ValueError, TypeError):
                try:
                    end = datetime.fromisoformat(end_date)
                except (ValueError, TypeError):
                    end = cur.replace(year=cur.year + 1)
        else:
            end = cur.replace(year=cur.year + 1)

        freq = rent_frequency.lower() if rent_frequency else "monthly"
        schedule = []
        index = 1
        cur_cursor = cur
        while cur_cursor < end:
            payment_date = cur_cursor
            if freq in ("weekly", "week"):
                delta = timedelta(weeks=1)
            elif freq in ("fortnightly", "biweekly", "2-week"):
                delta = timedelta(weeks=2)
            elif freq in ("quarterly", "quarter", "3-month"):
                delta = None
                try:
                    month = cur_cursor.month + 3
                    year = cur_cursor.year + (month - 1) // 12
                    month = ((month - 1) % 12) + 1
                    cur_cursor = cur_cursor.replace(year=year, month=month)
                except ValueError:
                    cur_cursor = cur_cursor.replace(year=cur_cursor.year + 1)
            elif freq in ("annually", "yearly", "annual", "year"):
                delta = timedelta(days=365)
            else:
                delta = timedelta(days=30)

            schedule.append({
                "payment_no": index,
                "due_date": payment_date.strftime("%Y-%m-%d"),
                "amount": float(rent_amount),
            })
            index += 1
            if delta:
                cur_cursor = cur_cursor + delta

        return json_success({
            "tenancy_id": tenancy_id,
            "rent_amount": float(rent_amount),
            "rent_frequency": rent_frequency,
            "start_date": start_date,
            "end_date": end_date,
            "schedule": schedule,
        })
    except Exception as e:
        return json_error(str(e), 500)
    finally:
        db.close()


@banksia_os_bp.route("/finance/tenancy-summary/<int:tenancy_id>")
def api_tenancy_summary(tenancy_id):
    """Return financial summary for a tenancy."""
    db = get_dict_db()
    try:
        tenancy = db.execute(
            "SELECT * FROM tenancies WHERE id = ?", (tenancy_id,)
        ).fetchone()
        if not tenancy:
            return json_error("Tenancy not found", 404)

        start_date = tenancy.get("start_date")
        end_date = tenancy.get("end_date")
        rent_amount = tenancy.get("rent_amount")
        rent_frequency = tenancy.get("rent_frequency", "monthly")

        # Total paid from transactions
        total_paid = db.execute(
            "SELECT COALESCE(SUM(amount), 0) AS total FROM transactions "
            "WHERE tenancy_id = ? AND transaction_type = 'Payment'",
            (tenancy_id,)
        ).fetchone()["total"]

        # Total expected (projected rent up to today or end_date)
        total_expected = 0.0
        if start_date and rent_amount:
            try:
                sd = datetime.strptime(start_date, "%Y-%m-%d") if isinstance(start_date, str) else start_date
            except (ValueError, TypeError):
                try:
                    sd = datetime.fromisoformat(start_date) if isinstance(start_date, str) else start_date
                except (ValueError, TypeError):
                    sd = datetime.now()

            today = datetime.now()
            if end_date:
                try:
                    ed = datetime.strptime(end_date, "%Y-%m-%d") if isinstance(end_date, str) else end_date
                except (ValueError, TypeError):
                    try:
                        ed = datetime.fromisoformat(end_date) if isinstance(end_date, str) else end_date
                    except (ValueError, TypeError):
                        ed = today
            else:
                ed = today

            freq = rent_frequency.lower() if rent_frequency else "monthly"
            cur = sd
            while cur < min(ed, today):
                if freq in ("weekly", "week"):
                    cur += timedelta(weeks=1)
                elif freq in ("fortnightly", "biweekly", "2-week"):
                    cur += timedelta(weeks=2)
                elif freq in ("quarterly", "quarter", "3-month"):
                    try:
                        month = cur.month + 3
                        year = cur.year + (month - 1) // 12
                        month = ((month - 1) % 12) + 1
                        cur = cur.replace(year=year, month=month)
                    except ValueError:
                        cur = cur.replace(year=cur.year + 1)
                elif freq in ("annually", "yearly", "annual", "year"):
                    cur += timedelta(days=365)
                else:
                    cur += timedelta(days=30)
                total_expected += float(rent_amount)

        balance = total_expected - float(total_paid) if total_paid is not None else total_expected

        # Next payment date (first date after today in the projected schedule)
        next_payment_date = None
        if start_date and rent_amount:
            try:
                sd = datetime.strptime(start_date, "%Y-%m-%d") if isinstance(start_date, str) else start_date
            except (ValueError, TypeError):
                try:
                    sd = datetime.fromisoformat(start_date) if isinstance(start_date, str) else start_date
                except (ValueError, TypeError):
                    sd = datetime.now()
            today = datetime.now()
            freq = rent_frequency.lower() if rent_frequency else "monthly"
            cur = sd
            max_iter = 500
            while cur <= today and max_iter > 0:
                if freq in ("weekly", "week"):
                    cur += timedelta(weeks=1)
                elif freq in ("fortnightly", "biweekly", "2-week"):
                    cur += timedelta(weeks=2)
                elif freq in ("quarterly", "quarter", "3-month"):
                    try:
                        month = cur.month + 3
                        year = cur.year + (month - 1) // 12
                        month = ((month - 1) % 12) + 1
                        cur = cur.replace(year=year, month=month)
                    except ValueError:
                        cur = cur.replace(year=cur.year + 1)
                elif freq in ("annually", "yearly", "annual", "year"):
                    cur += timedelta(days=365)
                else:
                    cur += timedelta(days=30)
                max_iter -= 1
            if cur > today:
                next_payment_date = cur.strftime("%Y-%m-%d")

        # Arrears from outstanding transactions
        arrears = db.execute(
            "SELECT COALESCE(SUM(amount_outstanding), 0) AS total FROM transactions "
            "WHERE tenancy_id = ? AND is_outstanding = 1",
            (tenancy_id,)
        ).fetchone()["total"]

        return json_success({
            "tenancy_id": tenancy_id,
            "total_paid": float(total_paid) if total_paid else 0.0,
            "total_expected": total_expected,
            "balance": balance,
            "next_payment_date": next_payment_date,
            "arrears": float(arrears) if arrears else 0.0,
        })
    except Exception as e:
        return json_error(str(e), 500)
    finally:
        db.close()


# ═══════════════════════════════════════════════
# 7. ACCESS MANAGEMENT
# ═══════════════════════════════════════════════

@banksia_os_bp.route("/access", methods=["GET"])
def api_access_list():
    """List access records with pagination + property_id/unit_id filters."""
    page = int_param(request.args.get("page"))
    per_page = int_param(request.args.get("per_page"), 20)
    property_id = request.args.get("property_id")
    unit_id = request.args.get("unit_id")

    where_parts = []
    params = []

    if property_id:
        where_parts.append("property_id = ?")
        params.append(property_id)
    if unit_id:
        where_parts.append("unit_id = ?")
        params.append(unit_id)

    where = " AND ".join(where_parts) if where_parts else "1=1"

    rows, total = paginate(
        f"SELECT * FROM access_records WHERE {where} ORDER BY created_at DESC",
        f"SELECT COUNT(*) AS cnt FROM access_records WHERE {where}",
        params, page, per_page
    )

    return json_success(rows, total, page, per_page)


@banksia_os_bp.route("/access/<int:access_id>", methods=["GET"])
def api_access_get(access_id):
    """Get a single access record."""
    db = get_dict_db()
    try:
        record = db.execute(
            "SELECT * FROM access_records WHERE id = ?", (access_id,)
        ).fetchone()
        if not record:
            return json_error("Access record not found", 404)
        return json_success(record)
    except Exception as e:
        return json_error(str(e), 500)
    finally:
        db.close()


@banksia_os_bp.route("/access", methods=["POST"])
def api_access_create():
    """Create a new access record."""
    data = request.get_json(silent=True) or {}
    property_id = data.get("property_id")
    unit_id = data.get("unit_id")
    rec_type = data.get("type")  # key, fob, code
    label = data.get("label")
    identifier = data.get("identifier") or data.get("value")  # accept both
    notes = data.get("notes")
    assigned_to = data.get("assigned_to")
    issued_date = data.get("issued_date")

    if not property_id:
        return json_error("property_id is required")
    if not rec_type:
        return json_error("type is required (key, fob, code)")
    if rec_type not in ("key", "fob", "code"):
        return json_error("type must be one of: key, fob, code")

    db = get_dict_db()
    try:
        # Check property exists
        prop = db.execute("SELECT id FROM properties WHERE id = ?", (property_id,)).fetchone()
        if not prop:
            return json_error("Property not found", 404)

        db.execute(
            "INSERT INTO access_records (property_id, unit_id, type, label, identifier, notes, assigned_to, issued_date) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (property_id, unit_id, rec_type, label, identifier, notes, assigned_to, issued_date)
        )
        db.commit()
        new_id = db.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]
        record = db.execute("SELECT * FROM access_records WHERE id = ?", (new_id,)).fetchone()
        return json_success(record)
    except Exception as e:
        return json_error(str(e), 500)
    finally:
        db.close()


@banksia_os_bp.route("/access/<int:access_id>", methods=["PUT"])
def api_access_update(access_id):
    """Update an existing access record."""
    data = request.get_json(silent=True) or {}

    db = get_dict_db()
    try:
        record = db.execute(
            "SELECT * FROM access_records WHERE id = ?", (access_id,)
        ).fetchone()
        if not record:
            return json_error("Access record not found", 404)

        # Build SET clause from provided fields
        allowed_fields = [
            "property_id", "unit_id", "type", "label",
            "identifier", "notes", "assigned_to",
            "issued_date", "returned_date",
        ]
        set_parts = []
        params = []
        for field in allowed_fields:
            if field == "identifier":
                val = data.get("identifier") or data.get("value")
            else:
                val = data.get(field)
            if val is not None:
                set_parts.append(f"{field} = ?")
                params.append(val)

        if not set_parts:
            return json_error("No fields to update")

        set_parts.append("updated_at = datetime('now')")
        params.append(access_id)

        db.execute(
            f"UPDATE access_records SET {', '.join(set_parts)} WHERE id = ?",
            params
        )
        db.commit()

        updated = db.execute(
            "SELECT * FROM access_records WHERE id = ?", (access_id,)
        ).fetchone()
        return json_success(updated)
    except Exception as e:
        return json_error(str(e), 500)
    finally:
        db.close()


@banksia_os_bp.route("/access/available", methods=["GET"])
def api_access_available():
    """List available keys/codes for a property (unassigned records)."""
    property_id = request.args.get("property_id")
    if not property_id:
        return json_error("property_id query parameter is required")

    db = get_dict_db()
    try:
        prop = db.execute("SELECT id FROM properties WHERE id = ?", (property_id,)).fetchone()
        if not prop:
            return json_error("Property not found", 404)

        records = db.execute(
            "SELECT * FROM access_records "
            "WHERE property_id = ? AND (assigned_to IS NULL OR assigned_to = '') "
            "ORDER BY type ASC, label ASC",
            (property_id,)
        ).fetchall()
        return json_success(records)
    except Exception as e:
        return json_error(str(e), 500)
    finally:
        db.close()


# ═══════════════════════════════════════════════
# 8. PROPERTY MEDIA UPLOAD
# ═══════════════════════════════════════════════

MEDIA_ROOT = os.path.join(os.path.dirname(__file__), "media")


@banksia_os_bp.route("/properties/<int:prop_id>/images/upload", methods=["POST"])
def api_property_image_upload(prop_id):
    """Upload an image for a property."""
    db = get_dict_db()
    try:
        # Verify property exists
        prop = db.execute("SELECT id FROM properties WHERE id = ?", (prop_id,)).fetchone()
        if not prop:
            return json_error("Property not found", 404)

        if "image" not in request.files:
            return json_error("No image file provided (use field 'image')")

        file = request.files["image"]
        if file.filename == "":
            return json_error("Empty filename")

        category = request.form.get("category", "")

        # Ensure upload directory exists
        prop_dir = os.path.join(MEDIA_ROOT, "properties", str(prop_id))
        os.makedirs(prop_dir, exist_ok=True)

        # Sanitize filename
        safe_name = f"{int(datetime.now().timestamp())}_{file.filename.replace(' ', '_')}"
        filepath = os.path.join(prop_dir, safe_name)
        file.save(filepath)

        # Record in property_images table
        image_url = f"/api/banksia-os/media/properties/{prop_id}/{safe_name}"
        db.execute(
            "INSERT INTO property_images (property_id, category, image_url, caption) "
            "VALUES (?, ?, ?, ?)",
            (prop_id, category, image_url, "Uploaded image")
        )
        db.commit()
        image_id = db.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]

        return json_success({
            "id": image_id,
            "filename": safe_name,
            "url": image_url,
            "category": category,
            "path": filepath,
        })
    except Exception as e:
        return json_error(str(e), 500)
    finally:
        db.close()


@banksia_os_bp.route("/media/properties/<int:prop_id>/<filename>")
def api_serve_property_image(prop_id, filename):
    """Serve an uploaded property image."""
    prop_dir = os.path.join(MEDIA_ROOT, "properties", str(prop_id))
    filepath = os.path.join(prop_dir, filename)

    # Prevent directory traversal
    real_path = os.path.realpath(filepath)
    real_base = os.path.realpath(prop_dir)
    if not real_path.startswith(real_base):
        return json_error("Invalid path", 403)

    if not os.path.exists(filepath):
        return json_error("Image not found", 404)

    from flask import send_file
    return send_file(filepath)


@banksia_os_bp.route("/properties/<int:prop_id>/images/<filename>", methods=["DELETE"])
def api_property_image_delete(prop_id, filename):
    """Delete an uploaded property image."""
    prop_dir = os.path.join(MEDIA_ROOT, "properties", str(prop_id))
    filepath = os.path.join(prop_dir, filename)

    # Prevent directory traversal
    real_path = os.path.realpath(filepath)
    real_base = os.path.realpath(prop_dir)
    if not real_path.startswith(real_base):
        return json_error("Invalid path", 403)

    if not os.path.exists(filepath):
        return json_error("Image not found", 404)

    db = get_dict_db()
    try:
        os.remove(filepath)

        # Remove database record matching this image path
        image_url = f"/api/banksia-os/media/properties/{prop_id}/{filename}"
        db.execute(
            "DELETE FROM property_images WHERE property_id = ? AND image_url = ?",
            (prop_id, image_url)
        )
        db.commit()

        return json_success({"deleted": filename})
    except Exception as e:
        return json_error(str(e), 500)
    finally:
        db.close()


# ═══════════════════════════════════════════════
# 11. TENANCY LIFECYCLE — Renewals, Rent Reviews, Section 21
# ═══════════════════════════════════════════════


@banksia_os_bp.route("/tenancies/<int:ten_id>/renew", methods=["POST"])
def api_renew_tenancy(ten_id):
    """Renew a tenancy — set new end date, optionally new rent."""
    data = request.get_json(silent=True) or {}
    new_end = data.get("end_date")
    new_rent = data.get("rent_amount")
    if not new_end:
        return json_error("new_end_date is required")
    db = get_dict_db()
    try:
        ten = db.execute("SELECT * FROM tenancies WHERE id = ?", (ten_id,)).fetchone()
        if not ten:
            return json_error("Tenancy not found", 404)
        now_iso = datetime.now(timezone.utc).isoformat()
        updates = {
            "renewal_start": ten.get("end_date"),
            "renewal_end": new_end,
            "end_date": new_end,
            "is_renewed": 1,
            "modified": now_iso,
        }
        if new_rent:
            updates["rent_amount"] = new_rent
        set_clause = ", ".join([f"{k} = ?" for k in updates])
        vals = list(updates.values()) + [ten_id]
        db.execute(f"UPDATE tenancies SET {set_clause} WHERE id = ?", vals)
        db.commit()
        return json_success({"renewed": True, "new_end_date": new_end})
    except Exception as e:
        db.rollback()
        return json_error(str(e), 500)
    finally:
        db.close()


@banksia_os_bp.route("/tenancies/<int:ten_id>/rent-review", methods=["POST"])
def api_rent_review(ten_id):
    """Record a rent review for a tenancy."""
    data = request.get_json(silent=True) or {}
    new_rent = data.get("new_rent_amount")
    review_date = data.get("review_date", datetime.now(timezone.utc).strftime("%Y-%m-%d"))
    if not new_rent:
        return json_error("new_rent_amount is required")
    db = get_dict_db()
    try:
        db.execute(
            "UPDATE tenancies SET rent_amount = ?, rent_review_date = ?, modified = ? WHERE id = ?",
            (new_rent, review_date, datetime.now(timezone.utc).isoformat(), ten_id)
        )
        db.commit()
        return json_success({"rent_reviewed": True, "new_rent": new_rent, "review_date": review_date})
    except Exception as e:
        db.rollback()
        return json_error(str(e), 500)
    finally:
        db.close()


@banksia_os_bp.route("/tenancies/<int:ten_id>/section-21", methods=["POST"])
def api_section_21(ten_id):
    """Record that a Section 21 notice has been served."""
    data = request.get_json(silent=True) or {}
    served_date = data.get("served_date", datetime.now(timezone.utc).strftime("%Y-%m-%d"))
    db = get_dict_db()
    try:
        db.execute(
            "UPDATE tenancies SET section_21_served = 1, modified = ? WHERE id = ?",
            (datetime.now(timezone.utc).isoformat(), ten_id)
        )
        db.commit()
        return json_success({"section_21_served": True, "served_date": served_date})
    except Exception as e:
        db.rollback()
        return json_error(str(e), 500)
    finally:
        db.close()


# ═══════════════════════════════════════════════
# 12. TAGS SYSTEM
# ═══════════════════════════════════════════════

@banksia_os_bp.route("/tags")
def api_tags():
    db = get_dict_db()
    try:
        tags = db.execute("SELECT * FROM tags ORDER BY name").fetchall()
        return json_success(tags)
    except Exception as e:
        return json_error(str(e), 500)
    finally:
        db.close()

@banksia_os_bp.route("/tags", methods=["POST"])
def api_create_tag():
    data = request.get_json()
    if not data or not data.get("name"):
        return json_error("Tag name required")
    db = get_dict_db()
    try:
        db.execute("INSERT INTO tags (name, color, category) VALUES (?,?,?)",
                   (data["name"], data.get("color","#80d8ff"), data.get("category","general")))
        db.commit()
        return json_success({"message":"Tag created"}), 201
    except Exception as e:
        return json_error(str(e), 500)
    finally:
        db.close()

@banksia_os_bp.route("/tags/<int:tag_id>", methods=["PATCH","DELETE"])
def api_tag(tag_id):
    if request.method == "DELETE":
        db = get_dict_db()
        try:
            db.execute("DELETE FROM tags WHERE id=?", (tag_id,))
            db.commit()
            return json_success({"deleted":True})
        except Exception as e:
            return json_error(str(e), 500)
        finally:
            db.close()
    return api_update_resource("tags", tag_id)


# ═══════════════════════════════════════════════
# 13. PROPERTY OWNERS
# ═══════════════════════════════════════════════

@banksia_os_bp.route("/property-owners")
def api_property_owners():
    page = int_param(request.args.get("page"))
    per_page = int_param(request.args.get("per_page"), 20)
    search = request.args.get("search","").strip()
    db = get_dict_db()
    try:
        if search:
            where = "WHERE name LIKE ? OR company_name LIKE ? OR main_contact_name LIKE ?"
            like = f"%{search}%"
            total = db.execute(f"SELECT COUNT(*) AS cnt FROM property_owners {where}", (like,like,like)).fetchone()["cnt"]
            rows = db.execute(f"SELECT * FROM property_owners {where} ORDER BY name LIMIT ? OFFSET ?",
                              (like,like,like,per_page,(page-1)*per_page)).fetchall()
        else:
            total = db.execute("SELECT COUNT(*) AS cnt FROM property_owners").fetchone()["cnt"]
            rows = db.execute("SELECT * FROM property_owners ORDER BY name LIMIT ? OFFSET ?",
                              (per_page,(page-1)*per_page)).fetchall()
        return json_success(rows, total, page, per_page)
    except Exception as e:
        return json_error(str(e), 500)
    finally:
        db.close()

@banksia_os_bp.route("/property-owners", methods=["POST"])
def api_create_property_owner():
    data = request.get_json()
    if not data or not data.get("name"):
        return json_error("Owner name required")
    db = get_dict_db()
    try:
        cols = ["name","company_name","office_no","main_contact_name","contact_phone",
                "contact_email","address_line_1","city","postcode","status","tags","notes"]
        ins = {k:data.get(k,"") for k in cols}
        ins["modified"] = datetime.now(timezone.utc).isoformat()
        placeholders = ",".join(["?"]*len(ins))
        cursor = db.execute(f"INSERT INTO property_owners ({','.join(ins.keys())}) VALUES ({placeholders})",
                            list(ins.values()))
        db.commit()
        return json_success({"id": cursor.lastrowid, "message":"Owner created"}), 201
    except Exception as e:
        return json_error(str(e), 500)
    finally:
        db.close()

@banksia_os_bp.route("/property-owners/<int:owner_id>", methods=["GET","PATCH"])
def api_property_owner(owner_id):
    if request.method == "PATCH":
        return api_update_resource("property_owners", owner_id)
    db = get_dict_db()
    try:
        owner = db.execute("SELECT * FROM property_owners WHERE id=?", (owner_id,)).fetchone()
        if not owner: return json_error("Not found", 404)
        # Count linked properties
        count = db.execute("SELECT COUNT(*) AS cnt FROM properties WHERE property_owner_id=? OR property_owner_name=?", 
                           (str(owner_id), owner.get("name",""))).fetchone()["cnt"]
        owner["property_count"] = count
        return json_success(owner)
    except Exception as e:
        return json_error(str(e), 500)
    finally:
        db.close()


# ═══════════════════════════════════════════════
# 14. MESSAGING SYSTEM (Threaded)
# ═══════════════════════════════════════════════

@banksia_os_bp.route("/threads")
def api_threads():
    status = request.args.get("status","").strip()
    db = get_dict_db()
    try:
        where = "1=1"
        params = []
        if status:
            where = "status=?"
            params.append(status)
        threads = db.execute(
            f"SELECT * FROM message_threads WHERE {where} ORDER BY modified DESC LIMIT 50", params
        ).fetchall()
        # Get last message for each thread
        for t in threads:
            last = db.execute("SELECT author, body, created FROM messages WHERE thread_id=? ORDER BY id DESC LIMIT 1",
                              (t["id"],)).fetchone()
            t["last_message"] = last
            msg_count = db.execute("SELECT COUNT(*) AS cnt FROM messages WHERE thread_id=?", (t["id"],)).fetchone()["cnt"]
            t["message_count"] = msg_count
        return json_success(threads)
    except Exception as e:
        return json_error(str(e), 500)
    finally:
        db.close()

@banksia_os_bp.route("/threads", methods=["POST"])
def api_create_thread():
    data = request.get_json()
    if not data:
        return json_error("No data")
    db = get_dict_db()
    try:
        cols = ["title","entity_type","entity_id","tenancy_id","property_id",
                "status","priority","task_type","raised_by","assigned_to","participants"]
        ins = {k:data.get(k,"") for k in cols}
        ins["modified"] = datetime.now(timezone.utc).isoformat()
        pl = ",".join(["?"]*len(ins))
        cursor = db.execute(f"INSERT INTO message_threads ({','.join(ins.keys())}) VALUES ({pl})", list(ins.values()))
        db.commit()
        tid = cursor.lastrowid
        # If there's a body, create first message
        if data.get("body"):
            db.execute("INSERT INTO messages (thread_id, author, body) VALUES (?,?,?)",
                       (tid, data.get("author","System"), data["body"]))
            db.commit()
        return json_success({"id": tid, "message":"Thread created"}), 201
    except Exception as e:
        return json_error(str(e), 500)
    finally:
        db.close()

@banksia_os_bp.route("/threads/<int:thread_id>")
def api_thread(thread_id):
    db = get_dict_db()
    try:
        thread = db.execute("SELECT * FROM message_threads WHERE id=?", (thread_id,)).fetchone()
        if not thread: return json_error("Not found", 404)
        messages = db.execute(
            "SELECT * FROM messages WHERE thread_id=? ORDER BY id ASC", (thread_id,)
        ).fetchall()
        thread["messages"] = messages
        return json_success(thread)
    except Exception as e:
        return json_error(str(e), 500)
    finally:
        db.close()

@banksia_os_bp.route("/threads/<int:thread_id>/status", methods=["PATCH"])
def api_update_thread_status(thread_id):
    data = request.get_json()
    if not data or not data.get("status"):
        return json_error("Status required")
    db = get_dict_db()
    try:
        db.execute("UPDATE message_threads SET status=?, modified=? WHERE id=?",
                   (data["status"], datetime.now(timezone.utc).isoformat(), thread_id))
        db.commit()
        return json_success({"updated":True})
    except Exception as e:
        return json_error(str(e), 500)
    finally:
        db.close()

@banksia_os_bp.route("/threads/<int:thread_id>/attachments", methods=["POST"])
def api_upload_thread_attachment(thread_id):
    """Upload a file attachment to a message thread."""
    if "file" not in request.files:
        return json_error("No file provided")
    file = request.files["file"]
    if file.filename == "":
        return json_error("Empty filename")
    docs_dir = os.path.join(os.path.dirname(__file__), "documents")
    os.makedirs(docs_dir, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    safe_name = f"thread_{thread_id}_{ts}_{file.filename}"
    save_path = os.path.join(docs_dir, safe_name)
    file.save(save_path)
    author = request.form.get("author", session.get("user", {}).get("username", "User"))
    db = get_dict_db()
    try:
        t = db.execute("SELECT id FROM message_threads WHERE id=?", (thread_id,)).fetchone()
        if not t:
            return json_error("Thread not found", 404)
        attachment_url = f"/api/banksia-os/threads/{thread_id}/attachments/{safe_name}"
        body = f"[File attached: {file.filename}]({attachment_url})"
        db.execute("INSERT INTO messages (thread_id, author, author_role, body) VALUES (?,?,?,?)",
                   (thread_id, author, "team", body))
        db.execute("UPDATE message_threads SET modified=? WHERE id=?",
                   (datetime.now(timezone.utc).isoformat(), thread_id))
        db.commit()
        return json_success({"filename": file.filename, "path": save_path, "url": attachment_url, "message_id": db.lastrowid}), 201
    except Exception as e:
        return json_error(str(e), 500)
    finally:
        db.close()

@banksia_os_bp.route("/threads/<int:thread_id>/attachments/<path:filename>")
def api_serve_thread_attachment(thread_id, filename):
    """Serve a file attachment from the documents folder."""
    from flask import send_from_directory
    docs_dir = os.path.join(os.path.dirname(__file__), "documents")
    return send_from_directory(docs_dir, f"thread_{thread_id}_{filename}", as_attachment=True)

@banksia_os_bp.route("/messages", methods=["POST"])
def api_post_message():
    data = request.get_json()
    if not data or not data.get("thread_id") or not data.get("body"):
        return json_error("thread_id and body required")
    db = get_dict_db()
    try:
        db.execute("INSERT INTO messages (thread_id, author, author_role, body) VALUES (?,?,?,?)",
                   (data["thread_id"], data.get("author","User"), data.get("author_role","team"), data["body"]))
        db.execute("UPDATE message_threads SET modified=? WHERE id=?",
                   (datetime.now(timezone.utc).isoformat(), data["thread_id"]))
        db.commit()
        return json_success({"message":"Sent"}), 201
    except Exception as e:
        return json_error(str(e), 500)
    finally:
        db.close()


@banksia_os_bp.route("/messages/<int:msg_id>")
def api_get_message(msg_id):
    db = get_dict_db()
    try:
        msg = db.execute("SELECT * FROM messages WHERE id=? AND (is_deleted IS NULL OR is_deleted=0)", (msg_id,)).fetchone()
        if not msg: return json_error("Not found", 404)
        return json_success(msg)
    except Exception as e:
        return json_error(str(e), 500)
    finally:
        db.close()


@banksia_os_bp.route("/messages/<int:msg_id>", methods=["PATCH"])
def api_edit_message(msg_id):
    data = request.get_json()
    if not data or not data.get("body"):
        return json_error("body required")
    db = get_dict_db()
    try:
        msg = db.execute("SELECT * FROM messages WHERE id=? AND (is_deleted IS NULL OR is_deleted=0)", (msg_id,)).fetchone()
        if not msg: return json_error("Not found", 404)
        db.execute("UPDATE messages SET body=?, edited=1, edited_at=? WHERE id=?",
                   (data["body"], datetime.now(timezone.utc).isoformat(), msg_id))
        db.execute("UPDATE message_threads SET modified=? WHERE id=?",
                   (datetime.now(timezone.utc).isoformat(), msg["thread_id"]))
        db.commit()
        return json_success({"message":"Updated"})
    except Exception as e:
        return json_error(str(e), 500)
    finally:
        db.close()


@banksia_os_bp.route("/messages/<int:msg_id>", methods=["DELETE"])
def api_delete_message(msg_id):
    db = get_dict_db()
    try:
        msg = db.execute("SELECT * FROM messages WHERE id=? AND (is_deleted IS NULL OR is_deleted=0)", (msg_id,)).fetchone()
        if not msg: return json_error("Not found", 404)
        db.execute("UPDATE messages SET body='[deleted]', is_deleted=1, edited=0 WHERE id=?", (msg_id,))
        db.commit()
        return json_success({"message":"Deleted"})
    except Exception as e:
        return json_error(str(e), 500)
    finally:
        db.close()


# ═══════════════════════════════════════════════
# 15. INVOICES
# ═══════════════════════════════════════════════

@banksia_os_bp.route("/invoices")
def api_invoices():
    status = request.args.get("status","").strip()
    db = get_dict_db()
    try:
        where = "1=1"; params=[]
        if status:
            where = "status=?"; params=[status]
        invoices = db.execute(f"SELECT * FROM invoices WHERE {where} ORDER BY due_date DESC", params).fetchall()
        return json_success(invoices)
    except Exception as e:
        return json_error(str(e), 500)
    finally:
        db.close()

@banksia_os_bp.route("/invoices/summary")
def api_invoice_summary():
    db = get_dict_db()
    try:
        unpaid = db.execute("SELECT COALESCE(SUM(amount-amount_paid),0) AS total FROM invoices WHERE status!='paid'").fetchone()
        overdue = db.execute("SELECT COALESCE(SUM(amount-amount_paid),0) AS total FROM invoices WHERE due_date<date('now') AND status!='paid'").fetchone()
        due_today = db.execute("SELECT COALESCE(SUM(amount-amount_paid),0) AS total FROM invoices WHERE due_date=date('now') AND status!='paid'").fetchone()
        return json_success({
            "unpaid_total": round(unpaid["total"], 2),
            "overdue_total": round(overdue["total"], 2),
            "due_today": round(due_today["total"], 2)
        })
    except Exception as e:
        return json_error(str(e), 500)
    finally:
        db.close()

@banksia_os_bp.route("/invoices", methods=["POST"])
def api_create_invoice():
    data = request.get_json()
    if not data:
        return json_error("No data")
    db = get_dict_db()
    try:
        db.execute("INSERT INTO invoices (tenancy_id, tenant_id, invoice_ref, description, amount, due_date, status, type) VALUES (?,?,?,?,?,?,?,?)",
                   (data.get("tenancy_id"), data.get("tenant_id"), data.get("invoice_ref"),
                    data.get("description"), data.get("amount",0), data.get("due_date"),
                    data.get("status","pending"), data.get("type","rent")))
        db.commit()
        return json_success({"message":"Invoice created"}), 201
    except Exception as e:
        return json_error(str(e), 500)
    finally:
        db.close()


# ═══════════════════════════════════════════════
# 16. COMPANY SETTINGS
# ═══════════════════════════════════════════════

@banksia_os_bp.route("/company-settings")
def api_company_settings():
    db = get_dict_db()
    try:
        rows = db.execute("SELECT key, value FROM company_settings").fetchall()
        return json_success({r["key"]: r["value"] for r in rows})
    except Exception as e:
        return json_error(str(e), 500)
    finally:
        db.close()

@banksia_os_bp.route("/company-settings", methods=["POST"])
def api_update_company_settings():
    data = request.get_json()
    if not data:
        return json_error("No data")
    db = get_dict_db()
    try:
        for key, value in data.items():
            db.execute("INSERT INTO company_settings (key, value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                       (key, value))
        db.commit()
        return json_success({"message":"Settings saved"})
    except Exception as e:
        return json_error(str(e), 500)
    finally:
        db.close()


# ═══════════════════════════════════════════════
# 17. ENHANCED PROPERTIES — filtered/tagged
# ═══════════════════════════════════════════════

@banksia_os_bp.route("/properties/enhanced")
def api_properties_enhanced():
    page = int_param(request.args.get("page"))
    per_page = int_param(request.args.get("per_page"), 20)
    search = request.args.get("search","").strip()
    condition = request.args.get("condition","").strip()  # HMO/Residential
    tag_filter = request.args.get("tag","").strip()

    where_parts = ["1=1"]
    params = []
    if search:
        like = f"%{search}%"
        where_parts.append("(ref LIKE ? OR address_line_1 LIKE ? OR city LIKE ? OR postcode LIKE ?)")
        params.extend([like]*4)
    if condition:
        where_parts.append("property_type=?")
        params.append(condition)
    if tag_filter:
        where_parts.append("tags LIKE ?")
        params.append(f"%{tag_filter}%")

    where = " AND ".join(where_parts)
    db = get_dict_db()
    try:
        total = db.execute(f"SELECT COUNT(*) AS cnt FROM properties WHERE {where}", params).fetchone()["cnt"]
        props = db.execute(
            f"SELECT * FROM properties WHERE {where} ORDER BY name ASC LIMIT ? OFFSET ?",
            params + [per_page, (page-1)*per_page]
        ).fetchall()
        # Enrich with unit counts and owner info
        for p in props:
            total_u = db.execute("SELECT COUNT(*) AS cnt FROM units WHERE property_id=?", (p["id"],)).fetchone()["cnt"]
            avail_u = db.execute("SELECT COUNT(*) AS cnt FROM units WHERE property_id=? AND unit_vacant=1", (p["id"],)).fetchone()["cnt"]
            p["total_unit_count"] = total_u
            p["available_units"] = avail_u
            # Parse tags from JSON string
            if p.get("tags"):
                try:
                    import json as jmod
                    parsed = jmod.loads(p["tags"])
                    p["tags_list"] = parsed if isinstance(parsed, list) else [str(parsed)]
                except (json.JSONDecodeError, TypeError):
                    p["tags_list"] = [t.strip() for t in p["tags"].split(",") if t.strip()]
            else:
                p["tags_list"] = []
        return json_success(props, total, page, per_page)
    except Exception as e:
        return json_error(str(e), 500)
    finally:
        db.close()


# ═══════════════════════════════════════════════
# 18. INVOICE DETAIL / PAY / CANCEL
# ═══════════════════════════════════════════════

@banksia_os_bp.route("/invoices/<int:invoice_id>")
def api_invoice_detail(invoice_id):
    db = get_dict_db()
    try:
        inv = db.execute("SELECT * FROM invoices WHERE id=?", (invoice_id,)).fetchone()
        if not inv:
            return json_error("Not found", 404)
        if inv.get("tenancy_id"):
            tn = db.execute("SELECT * FROM tenancies WHERE id=?", (inv["tenancy_id"],)).fetchone()
            if tn:
                inv["tenant_name"] = tn.get("main_tenant_name") or tn.get("tenant_name")
                prop = db.execute("SELECT * FROM properties WHERE id=?", (tn.get("property_id"),)).fetchone()
                if prop:
                    inv["property_name"] = prop.get("name") or prop.get("ref") or prop.get("address_line_1")
        return json_success(inv)
    except Exception as e:
        return json_error(str(e), 500)
    finally:
        db.close()


@banksia_os_bp.route("/invoices/<int:invoice_id>/pay", methods=["POST"])
def api_pay_invoice(invoice_id):
    db = get_dict_db()
    try:
        inv = db.execute("SELECT * FROM invoices WHERE id=?", (invoice_id,)).fetchone()
        if not inv:
            return json_error("Not found", 404)
        from datetime import datetime, timezone
        db.execute("UPDATE invoices SET status='paid', paid_date=? WHERE id=?",
                   (datetime.now(timezone.utc).isoformat(), invoice_id))
        db.commit()
        return json_success({"message": "Invoice marked as paid"})
    except Exception as e:
        return json_error(str(e), 500)
    finally:
        db.close()


@banksia_os_bp.route("/invoices/<int:invoice_id>", methods=["DELETE"])
def api_cancel_invoice(invoice_id):
    db = get_dict_db()
    try:
        inv = db.execute("SELECT * FROM invoices WHERE id=?", (invoice_id,)).fetchone()
        if not inv:
            return json_error("Not found", 404)
        db.execute("UPDATE invoices SET status='cancelled' WHERE id=?", (invoice_id,))
        db.commit()
        return json_success({"message": "Invoice cancelled"})
    except Exception as e:
        return json_error(str(e), 500)
    finally:
        db.close()