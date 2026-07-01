#!/usr/bin/env python3
"""
Banksia OS — HMO Operations API Blueprint.
Provides all HMO operations endpoints for daily team use.
Mounts at /api/banksia-os/
"""
import json, os, sys
from datetime import datetime, timezone, timedelta

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from flask import Blueprint, jsonify, request
from functools import wraps

from verv_os_db import get_db, count, dict_from_row, raw_query

banksia_os_bp = Blueprint("banksia_os", __name__, url_prefix="/api/banksia-os")


# ── Dict row factory for direct dict results ──
def dict_factory(cursor, row):
    d = {}
    for idx, col in enumerate(cursor.description):
        d[col[0]] = row[idx]
    return d


def get_dict_db():
    """Get DB connection with dict row factory."""
    db = get_db()
    db.row_factory = dict_factory
    return db


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

        # Deposits — currently held (active tenancies only) vs all time
        active_deposits = db.execute(
            f"SELECT COALESCE(SUM(deposit_registered_amount), 0) AS total FROM tenancies "
            f"WHERE status IN ({active_statuses}) AND deposit_registered_amount > 0"
        ).fetchone()["total"]

        # Moving in/out this month
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

        # Deposits unregistered
        deposits_unregistered = db.execute(
            "SELECT COUNT(*) AS cnt FROM tenancies WHERE deposit_registered = 0"
        ).fetchone()["cnt"]

        # Total deposits held
        total_deposits_held = db.execute(
            "SELECT COALESCE(SUM(deposit_registered_amount), 0) AS total FROM tenancies WHERE deposit_registered_amount > 0"
        ).fetchone()["total"]

        # Unit occupancy rate
        unit_occupancy_rate = round((occupied_units / total_units * 100) if total_units > 0 else 0, 1)

        # Leading property (highest total rent)
        leading = db.execute(
            "SELECT p.name, SUM(t.rent_amount) AS total_rent FROM tenancies t "
            "JOIN properties p ON t.property_id = p.id "
            "WHERE t.status IN ('Active', 'Periodic', 'active', 'periodic') "
            "GROUP BY p.id ORDER BY total_rent DESC LIMIT 1"
        ).fetchone()

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
            "total_deposits_held": round(active_deposits, 2),
            "total_deposits_all_time": round(total_deposits_held, 2),
            "pending_applicants": pending_applicants,
            "total_pending_applicants": pending_applicants,
            "unit_occupancy_rate": unit_occupancy_rate,
            "recent_arrivals_count": tenants_moving_in_this_month,
            "upcoming_move_outs_count": tenants_moving_out_this_month,
            "tenants_moving_in_this_month": tenants_moving_in_this_month,
            "tenants_moving_out_this_month": tenants_moving_out_this_month,
            "deposits_unregistered": deposits_unregistered,
            "leading_property": ({"name": leading["name"], "total_rent": round(leading["total_rent"], 2)} if leading and leading["name"] else None),
        })
    except Exception as e:
        return json_error(str(e), 500)
    finally:
        db.close()


# ═══════════════════════════════════════════════
# 2. PROPERTIES
# ═══════════════════════════════════════════════

@banksia_os_bp.route("/properties")
def api_properties():
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
        f"SELECT * FROM properties WHERE {base_where} ORDER BY name ASC",
        f"SELECT COUNT(*) AS cnt FROM properties WHERE {base_where}",
        base_params, page, per_page
    )

    return json_success(rows, total, page, per_page)


@banksia_os_bp.route("/properties/<int:prop_id>")
def api_property(prop_id):
    db = get_dict_db()
    try:
        prop = db.execute("SELECT * FROM properties WHERE id = ?", (prop_id,)).fetchone()
        if not prop:
            return json_error("Property not found", 404)

        units = db.execute("SELECT * FROM units WHERE property_id = ? ORDER BY unit_ref ASC", (prop_id,)).fetchall()
        prop["units"] = units
        return json_success(prop)
    except Exception as e:
        return json_error(str(e), 500)
    finally:
        db.close()


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

@banksia_os_bp.route("/units")
def api_units():
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
        f"SELECT * FROM units WHERE {where} ORDER BY unit_ref ASC",
        f"SELECT COUNT(*) AS cnt FROM units WHERE {where}",
        params, page, per_page
    )

    # Convert unit_vacant to bool
    for r in rows:
        bool_fields(r, "unit_vacant")

    return json_success(rows, total, page, per_page)


@banksia_os_bp.route("/units/<int:unit_id>")
def api_unit(unit_id):
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
        f"SELECT * FROM tenancies WHERE {where} ORDER BY start_date DESC",
        f"SELECT COUNT(*) AS cnt FROM tenancies WHERE {where}",
        params, page, per_page
    )

    for r in rows:
        bool_fields(r, "deposit_registered", "section_21_served", "is_renewed")

    return json_success(rows, total, page, per_page)


@banksia_os_bp.route("/tenancies/<int:ten_id>")
def api_tenancy(ten_id):
    db = get_dict_db()
    try:
        ten = db.execute("SELECT * FROM tenancies WHERE id = ?", (ten_id,)).fetchone()
        if not ten:
            return json_error("Tenancy not found", 404)

        bool_fields(ten, "deposit_registered", "section_21_served", "is_renewed")

        # Tenant info
        tenants = db.execute(
            "SELECT * FROM tenants WHERE tenancy_id = ? ORDER BY main_tenant DESC",
            (ten_id,)
        ).fetchall()
        ten["tenants"] = tenants

        # Transactions
        transactions = db.execute(
            "SELECT * FROM transactions WHERE tenancy_id = ? ORDER BY date DESC",
            (ten_id,)
        ).fetchall()
        for t in transactions:
            bool_fields(t, "is_overdue", "is_outstanding")
        ten["transactions"] = transactions

        # Property info
        if ten.get("property_id"):
            prop = db.execute(
                "SELECT id, ref, name, address_line_1, city, postcode FROM properties WHERE id = ?",
                (ten["property_id"],)
            ).fetchone()
            ten["property"] = prop

        # Unit info
        if ten.get("unit_id"):
            unit = db.execute(
                "SELECT id, unit_ref, unit_type, full_address FROM units WHERE id = ?",
                (ten["unit_id"],)
            ).fetchone()
            ten["unit"] = unit

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
        f"SELECT id, arthur_id, arthur_person_id, tenancy_id, unit_id, property_id, "
        f"full_address, title, first_name, last_name, date_of_birth, gender, citizen, "
        f"email, phone_home, phone_work, mobile, passport_number, visa_number, visa_type, "
        f"visa_years, country_of_origin, ni_number, main_tenant, status, has_guarantor, "
        f"guarantor_first_name, guarantor_last_name, guarantor_email, "
        f"employment_company, student_status, university, "
        f"bank_name, latest_credit_score, latest_credit_description, "
        f"applicant_note, manager_note, move_in_date, move_out_date, modified, created, "
        f"(SELECT COUNT(*) FROM tenancies WHERE tenants.tenancy_id = tenancies.arthur_id OR tenants.unit_id = tenancies.unit_id) AS tenancy_count "
        f"FROM tenants WHERE {where} ORDER BY last_name ASC, first_name ASC",
        f"SELECT COUNT(*) AS cnt FROM tenants WHERE {where}",
        params, page, per_page
    )

    for r in rows:
        bool_fields(r, "main_tenant", "has_guarantor")

    return json_success(rows, total, page, per_page)


@banksia_os_bp.route("/tenants/<int:tenant_id>")
def api_tenant(tenant_id):
    db = get_dict_db()
    try:
        tenant = db.execute("SELECT * FROM tenants WHERE id = ?", (tenant_id,)).fetchone()
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

        # Linked property
        if tenant.get("property_id"):
            prop = db.execute(
                "SELECT id, ref, name, address_line_1, city, postcode FROM properties WHERE id = ?",
                (tenant["property_id"],)
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


@banksia_os_bp.route("/applicants/<int:app_id>")
def api_applicant(app_id):
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

        # Deposit summary
        registered_deposits = db.execute(
            "SELECT COUNT(*) AS cnt, COALESCE(SUM(deposit_registered_amount), 0) AS total FROM tenancies "
            "WHERE deposit_registered = 1"
        ).fetchone()

        unregistered_deposits = db.execute(
            "SELECT COUNT(*) AS cnt FROM tenancies WHERE deposit_registered = 0"
        ).fetchone()

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
            "total_arrears": round(total_arrears, 2),
            "overdue_count": overdue["cnt"],
            "overdue_total": round(overdue["total"], 2),
            "total_collected": round(total_collected, 2),
            "total_transactions": total_transactions,
            "deposits": {
                "registered_count": registered_deposits["cnt"],
                "registered_total": round(registered_deposits["total"], 2),
                "unregistered_count": unregistered_deposits["cnt"],
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

        return json_success({
            "registered": registered,
            "registered_count": len(registered),
            "unregistered": unregistered,
            "unregistered_count": len(unregistered),
            "registered_total": round(
                sum(r.get("deposit_registered_amount") or 0 for r in registered), 2
            ),
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