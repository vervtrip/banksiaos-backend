#!/usr/bin/env python3
"""
Banksia OS - Tenant Application API Blueprint.

A SEPARATE client-facing application form, distinct from the Referencing form.
Its fields mirror the "TENANT APPLICATION" template in Documents:
  Applicant Information (1st + 2nd applicant), Property Address, Terms Agreed,
  Holding Deposit confirmation, and the Applicant Declaration.

The team generates a link (pre-tied to a property + unit) from the Tenants page;
the client opens it, fills their details and submits. On submit we create/link an
Applicant record so it appears under the Applicants tab. It does NOT create a
referencing form - this flow is intentionally independent of referencing.
"""
from datetime import datetime, timezone

from flask import Blueprint, request

from banksia_os_db import get_dict_db
from referencing_api import (
    require_team_auth, require_csrf, json_success, json_error,
    generate_form_token, PUBLIC_BASE_URL, safe_error,
)

tenant_app_bp = Blueprint("tenant_application", __name__, url_prefix="/api/tenant-application")


def _ensure_schema():
    db = get_dict_db()
    try:
        db.execute(
            "CREATE TABLE IF NOT EXISTS tenant_applications ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "form_token TEXT UNIQUE NOT NULL,"
            "status TEXT NOT NULL DEFAULT 'draft',"
            "property_id INTEGER,"
            "unit_id INTEGER,"
            "property_address TEXT,"
            "post_code TEXT,"
            "room_number TEXT,"
            "monthly_rent TEXT,"
            "deposit TEXT,"
            "holding_deposit TEXT,"
            "pro_rata TEXT,"
            "check_in_installment TEXT,"
            "check_in_date TEXT,"
            "bills_included INTEGER DEFAULT 0,"
            "holding_deposit_paid TEXT,"
            "holding_deposit_confirmed INTEGER DEFAULT 0,"
            "a1_full_name TEXT, a1_dob TEXT, a1_email TEXT, a1_gender TEXT,"
            "a1_guarantor_email TEXT, a1_guarantor_mobile TEXT,"
            "a2_full_name TEXT, a2_dob TEXT, a2_email TEXT, a2_gender TEXT,"
            "a2_guarantor_email TEXT, a2_guarantor_mobile TEXT,"
            "declaration_confirmed INTEGER DEFAULT 0,"
            "signature_data TEXT,"
            "signature_date TEXT,"
            "applicant_id INTEGER,"
            "created_at TEXT,"
            "submitted_at TEXT"
            ")"
        )
        db.commit()
    finally:
        db.close()


_PUBLIC_KEYS = [
    "status", "property_address", "post_code", "room_number", "monthly_rent", "deposit",
    "holding_deposit", "pro_rata", "check_in_installment", "check_in_date", "bills_included",
    "holding_deposit_paid", "holding_deposit_confirmed",
    "a1_full_name", "a1_dob", "a1_email", "a1_gender", "a1_guarantor_email", "a1_guarantor_mobile",
    "a2_full_name", "a2_dob", "a2_email", "a2_gender", "a2_guarantor_email", "a2_guarantor_mobile",
    "declaration_confirmed", "signature_date",
]


def _row_public(r):
    if not r:
        return None
    return {k: r.get(k) for k in _PUBLIC_KEYS}


@tenant_app_bp.route("/generate", methods=["POST"])
@require_team_auth
@require_csrf
def generate_tenant_application():
    """Create a blank Tenant Application pre-tied to a property + unit and return
    a shareable client link. Property address / postcode / room are locked; rent
    and deposit are pre-filled from the unit where available."""
    _ensure_schema()
    data = request.get_json() or {}
    property_id = data.get("property_id")
    unit_id = data.get("unit_id")
    if not property_id or not unit_id:
        return json_error("property_id and unit_id are required")

    db = get_dict_db()
    try:
        prop = db.execute(
            "SELECT id, name, address_line_1, address_line_2, city, postcode FROM properties WHERE id = ?",
            [property_id]).fetchone()
        if not prop:
            return json_error("Property %s not found" % property_id, 404)
        unit = db.execute(
            "SELECT id, unit_ref, market_rent, deposit_amount FROM units WHERE id = ? AND property_id = ?",
            [unit_id, property_id]).fetchone()
        if not unit:
            return json_error("Unit %s not found under property %s" % (unit_id, property_id), 404)

        addr = ", ".join([b for b in [prop.get("address_line_1"), prop.get("address_line_2"),
                                      prop.get("city")] if b]) or prop.get("name") or ("Property #%s" % property_id)
        token = generate_form_token()
        now = datetime.now(timezone.utc).isoformat()
        rent = unit.get("market_rent")
        dep = unit.get("deposit_amount")
        rent_s = "" if rent in (None, 0, 0.0) else str(rent)
        dep_s = "" if dep in (None, 0, 0.0) else str(dep)
        db.execute(
            "INSERT INTO tenant_applications "
            "(form_token, status, property_id, unit_id, property_address, post_code, room_number, "
            "monthly_rent, deposit, created_at) "
            "VALUES (?, 'draft', ?, ?, ?, ?, ?, ?, ?, ?)",
            [token, property_id, unit_id, addr, prop.get("postcode") or "",
             unit.get("unit_ref") or "", rent_s, dep_s, now])
        db.commit()
        new_id = db.execute("SELECT last_insert_rowid() AS rid").fetchone()["rid"]
        return json_success({
            "id": new_id,
            "form_token": token,
            "link": "%s/tenant-application/%s" % (PUBLIC_BASE_URL, token),
            "property_id": property_id,
            "unit_id": unit_id,
            "property_address": addr,
            "unit_ref": unit.get("unit_ref") or "",
        })
    except Exception as e:
        db.rollback()
        return json_error(safe_error(e), 500)
    finally:
        db.close()


@tenant_app_bp.route("/<token>", methods=["GET"])
def get_tenant_application(token):
    """Public: fetch a tenant application by token (for the form to load + prefill)."""
    _ensure_schema()
    db = get_dict_db()
    try:
        r = db.execute("SELECT * FROM tenant_applications WHERE form_token = ?", [token]).fetchone()
        if not r:
            return json_error("Application not found", 404)
        return json_success(_row_public(r))
    finally:
        db.close()


_APPLICANT_FIELDS = [
    "a1_full_name", "a1_dob", "a1_email", "a1_gender", "a1_guarantor_email", "a1_guarantor_mobile",
    "a2_full_name", "a2_dob", "a2_email", "a2_gender", "a2_guarantor_email", "a2_guarantor_mobile",
    "monthly_rent", "deposit", "holding_deposit", "pro_rata", "check_in_installment",
    "check_in_date", "bills_included", "holding_deposit_paid", "holding_deposit_confirmed",
    "declaration_confirmed", "signature_data", "signature_date",
]
_BOOL_FIELDS = ("bills_included", "holding_deposit_confirmed", "declaration_confirmed")


def _create_or_update_applicant(db, r):
    """Create/link an Applicant from the submitted tenant application so it lands
    under the Applicants tab. Independent of referencing."""
    name = (r.get("a1_full_name") or "").strip()
    parts = name.split(" ", 1)
    first = parts[0] if parts else name
    last = parts[1] if len(parts) > 1 else ""
    now = datetime.now(timezone.utc).isoformat()
    fields = {
        "first_name": first or name or "Applicant",
        "last_name": last,
        "email": r.get("a1_email"),
        "date_of_birth": r.get("a1_dob"),
        "gender": r.get("a1_gender"),
        "guarantor_email": r.get("a1_guarantor_email"),
        "guarantor_mobile": r.get("a1_guarantor_mobile"),
        "has_guarantor": 1 if (r.get("a1_guarantor_email") or r.get("a1_guarantor_mobile")) else 0,
        "full_address": r.get("property_address"),
        "proposed_rent": r.get("monthly_rent"),
        "proposed_deposit": r.get("deposit"),
        "desired_move_in": r.get("check_in_date"),
        "status": "Active",
        "source": "Tenant Application",
        "modified": now,
    }
    if r.get("property_id"):
        fields["property_id"] = r.get("property_id")
    if r.get("unit_id"):
        fields["unit_id"] = r.get("unit_id")

    existing = r.get("applicant_id")
    if existing:
        row = db.execute("SELECT id FROM applicants WHERE id = ?", [existing]).fetchone()
        if row:
            sets, params = [], []
            for col, val in fields.items():
                if val in (None, "") or col == "modified":
                    continue
                sets.append("%s = ?" % col)
                params.append(val)
            sets.append("modified = ?")
            params.append(now)
            params.append(existing)
            db.execute("UPDATE applicants SET %s WHERE id = ?" % ", ".join(sets), params)
            return existing

    fields["created"] = now
    cols = list(fields.keys())
    db.execute(
        "INSERT INTO applicants (%s) VALUES (%s)" % (", ".join(cols), ", ".join(["?"] * len(cols))),
        [fields[c] for c in cols])
    return db.execute("SELECT last_insert_rowid() AS rid").fetchone()["rid"]


@tenant_app_bp.route("/<token>/submit", methods=["POST"])
def submit_tenant_application(token):
    """Public: applicant fills + submits their tenant application."""
    _ensure_schema()
    data = request.get_json() or {}
    db = get_dict_db()
    try:
        r = db.execute("SELECT * FROM tenant_applications WHERE form_token = ?", [token]).fetchone()
        if not r:
            return json_error("Application not found", 404)
        if str(r.get("status")) == "submitted":
            return json_error("This application has already been submitted.", 409)

        if not (data.get("a1_full_name") or "").strip():
            return json_error("First applicant full name is required.")
        if not (data.get("a1_email") or "").strip():
            return json_error("First applicant email is required.")
        if not data.get("declaration_confirmed"):
            return json_error("You must confirm the declaration to submit.")

        sets, params = [], []
        for f in _APPLICANT_FIELDS:
            if f in data:
                val = data.get(f)
                if f in _BOOL_FIELDS:
                    val = 1 if val in (True, 1, "1", "true", "on") else 0
                sets.append("%s = ?" % f)
                params.append(val)
        now = datetime.now(timezone.utc).isoformat()
        sets.append("status = ?")
        params.append("submitted")
        sets.append("submitted_at = ?")
        params.append(now)
        params.append(token)
        db.execute("UPDATE tenant_applications SET %s WHERE form_token = ?" % ", ".join(sets), params)
        db.commit()

        r2 = db.execute("SELECT * FROM tenant_applications WHERE form_token = ?", [token]).fetchone()
        applicant_id = _create_or_update_applicant(db, r2)
        db.execute("UPDATE tenant_applications SET applicant_id = ? WHERE form_token = ?",
                   [applicant_id, token])
        db.commit()
        return json_success({"submitted": True, "applicant_id": applicant_id})
    except Exception as e:
        db.rollback()
        return json_error(safe_error(e), 500)
    finally:
        db.close()
