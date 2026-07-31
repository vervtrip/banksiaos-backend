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
import calendar
import os
from datetime import datetime, timezone

from flask import Blueprint, request

from banksia_os_db import get_dict_db
from referencing_api import (
    require_team_auth, require_csrf, json_success, json_error,
    generate_form_token, PUBLIC_BASE_URL, safe_error,
)

tenant_app_bp = Blueprint("tenant_application", __name__, url_prefix="/api/tenant-application")

# Applicant-facing referencing correspondence goes out from the references inbox.
# If that mailbox is not connected in Missive the send falls back to the default
# Banksia sender rather than failing (see referencing_api.send_email_from).
TA_FROM_EMAIL = "references@banksialondon.com"
TA_FROM_NAME = "Banksia Reference"
TA_REPLY_TO = "references@banksialondon.com"
TA_WEBSITE = "https://www.banksialondon.com"

# Properties where bills are NOT included (everywhere else bills are included).
# Matched loosely against the property address / name (case + spacing insensitive).
_NO_BILLS_PROPERTIES = ["22 carrol close", "10 beach street"]


def _norm(s):
    return " ".join((s or "").lower().split())


def _money(v):
    try:
        f = float(v)
    except (TypeError, ValueError):
        return ""
    if f <= 0:
        return ""
    return "%.2f" % f


def _bills_included_for(prop):
    blob = _norm(prop.get("address_line_1")) + " | " + _norm(prop.get("name"))
    for pat in _NO_BILLS_PROPERTIES:
        if pat in blob:
            return 0
    return 1


def _to_monthly(amount, freq):
    """Normalise a rent amount to a monthly figure based on its frequency."""
    try:
        a = float(amount or 0)
    except (TypeError, ValueError):
        return 0.0
    if a <= 0:
        return 0.0
    f = (freq or "monthly").lower()
    if "biweek" in f or "fortnight" in f:
        return a * 26 / 12
    if "week" in f:
        return a * 52 / 12
    if "dai" in f or "day" in f:
        return a * 365 / 12
    if "annual" in f or "year" in f or "yearly" in f:
        return a / 12
    if "quarter" in f:
        return a / 3
    return a  # monthly (default)


def _unit_monthly_rent(db, unit, unit_id):
    """Monthly rent for a unit: the unit's own market rent, or - when that is
    blank (typical for vacant units) - the most recent tenancy rent for that unit,
    normalised to monthly."""
    try:
        rentf = float(unit.get("market_rent") or 0)
    except (TypeError, ValueError):
        rentf = 0.0
    if rentf > 0:
        return _to_monthly(rentf, unit.get("market_rent_frequency"))
    t = db.execute(
        "SELECT rent_amount, rent_frequency FROM tenancies "
        "WHERE unit_id = ? AND COALESCE(rent_amount,0) > 0 "
        "ORDER BY COALESCE(move_in_date,'') DESC, id DESC LIMIT 1",
        [unit_id]).fetchone()
    if t:
        return _to_monthly(t.get("rent_amount"), t.get("rent_frequency"))
    return 0.0


def _days_until_month_end(d):
    """Number of days from date d until the end of d's month (remaining days
    in the month, i.e. last_day - today). For 24 July -> 31 - 24 = 7."""
    last_day = calendar.monthrange(d.year, d.month)[1]
    return last_day - d.day


def _compute_prorata(holding_f, monthly_rent_f, today):
    """Pro-Rata + Check-In Installment, per Banksia's rule:
      daily_rate       = holding_deposit / 7
      days             = days from today until the end of the month
      pro_rata         = days * daily_rate
                         (+ one month's rent if days < 10)
      check_in_install = pro_rata + deposit - holding_deposit
                         (deposit = one month's rent)
    Returns (pro_rata_str, check_in_installment_str)."""
    if holding_f <= 0 or monthly_rent_f <= 0:
        return "", ""
    daily_rate = holding_f / 7.0
    days = _days_until_month_end(today)
    pro_rata = days * daily_rate
    if days < 10:
        pro_rata += monthly_rent_f
    # deposit == monthly_rent_f (no separate deposit figure)
    check_in = pro_rata + monthly_rent_f - holding_f
    return _money(pro_rata), _money(check_in)


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
            "num_applicants INTEGER DEFAULT 1,"
            "applicant_id INTEGER,"
            "created_at TEXT,"
            "submitted_at TEXT"
            ")"
        )
        have = {r["name"] for r in db.execute("PRAGMA table_info(tenant_applications)")}
        # signature_image holds the drawn signature as a PNG data URL. The older
        # signature_data column stays as the printed name so applications
        # submitted before signing was introduced still render.
        if "signature_image" not in have:
            db.execute("ALTER TABLE tenant_applications ADD COLUMN signature_image TEXT")
        db.commit()
    finally:
        db.close()


_PUBLIC_KEYS = [
    "status", "property_address", "post_code", "room_number", "monthly_rent", "deposit",
    "holding_deposit", "pro_rata", "check_in_installment", "check_in_date", "bills_included",
    "holding_deposit_paid", "holding_deposit_confirmed",
    "a1_full_name", "a1_dob", "a1_email", "a1_gender", "a1_guarantor_email", "a1_guarantor_mobile",
    "a2_full_name", "a2_dob", "a2_email", "a2_gender", "a2_guarantor_email", "a2_guarantor_mobile",
    "declaration_confirmed", "signature_data", "signature_image", "signature_date",
    "num_applicants", "created_at", "first_opened_at",
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
    a shareable client link. Property/postcode/room are locked. Monthly rent and
    deposit are taken from the unit's market rent (there is no separate deposit
    figure, so deposit = one month's rent). Holding deposit is computed as
    (rent x 12 / 52) and mirrored to the amount-transferred field. Bills default
    to Included except for the configured no-bills properties."""
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
            "SELECT id, unit_ref, market_rent, market_rent_frequency, deposit_amount "
            "FROM units WHERE id = ? AND property_id = ?",
            [unit_id, property_id]).fetchone()
        if not unit:
            return json_error("Unit %s not found under property %s" % (unit_id, property_id), 404)

        addr = ", ".join([b for b in [prop.get("address_line_1"), prop.get("address_line_2"),
                                      prop.get("city")] if b]) or prop.get("name") or ("Property #%s" % property_id)

        rentf = _unit_monthly_rent(db, unit, unit_id)
        monthly_rent = _money(rentf)
        deposit = monthly_rent  # no separate deposit figure -> one month's rent
        holding_f = rentf * 12 / 52 if rentf > 0 else 0.0
        holding = _money(holding_f)
        bills = _bills_included_for(prop)

        token = generate_form_token()
        now_dt = datetime.now(timezone.utc)
        now = now_dt.isoformat()
        # Pro-Rata + Check-In Installment, computed against today (the generation
        # date, which is what the form shows top-right as Date of Application).
        pro_rata, check_in_installment = _compute_prorata(holding_f, rentf, now_dt.date())
        db.execute(
            "INSERT INTO tenant_applications "
            "(form_token, status, property_id, unit_id, property_address, post_code, room_number, "
            "monthly_rent, deposit, holding_deposit, holding_deposit_paid, pro_rata, "
            "check_in_installment, bills_included, created_at, check_in_date, num_applicants) "
            "VALUES (?, 'draft', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [token, property_id, unit_id, addr, prop.get("postcode") or "",
             unit.get("unit_ref") or "", monthly_rent, deposit, holding, holding,
             pro_rata, check_in_installment, bills, now, now_dt.date().isoformat(), 1])
        db.commit()
        new_id = db.execute("SELECT last_insert_rowid() AS rid").fetchone()["rid"]
        return json_success({
            "id": new_id,
            "form_token": token,
            "link": "%s/portal?ta=%s" % (PUBLIC_BASE_URL, token),
            "email": data.get("email") or "",
            "property_id": property_id,
            "unit_id": unit_id,
            "property_address": addr,
            "unit_ref": unit.get("unit_ref") or "",
            "monthly_rent": monthly_rent,
            "deposit": deposit,
            "holding_deposit": holding,
            "pro_rata": pro_rata,
            "check_in_installment": check_in_installment,
            "bills_included": bills,
            "num_applicants": 1,
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
        if r["status"] == "draft" and not r.get("first_opened_at"):
            db.execute("UPDATE tenant_applications SET first_opened_at = datetime('now') WHERE id = ?", [r["id"]])
            db.commit()
            r["first_opened_at"] = db.execute("SELECT first_opened_at FROM tenant_applications WHERE id = ?", [r["id"]]).fetchone()["first_opened_at"]
        return json_success(_row_public(r))
    finally:
        db.close()


# Fields the applicant may set on submit. The locked money fields
# (monthly_rent, deposit, holding_deposit, holding_deposit_paid, pro_rata,
# check_in_installment) are server-authoritative from generate and are NOT
# accepted from the client.
_APPLICANT_FIELDS = [
    "a1_full_name", "a1_dob", "a1_email", "a1_gender", "a1_guarantor_email", "a1_guarantor_mobile",
    "a1_phone", "a1_nationality", "a1_employment", "a1_employer_name",
    "a1_annual_income", "a1_residential_status", "a1_current_address",
    "a1_current_landlord", "a1_current_landlord_phone", "a1_current_landlord_email",
    "a1_current_from", "a1_current_to", "a1_reason_for_leaving",
    "a1_previous_address", "a1_previous_landlord", "a1_previous_landlord_phone",
    "a2_full_name", "a2_dob", "a2_email", "a2_gender", "a2_guarantor_email", "a2_guarantor_mobile",
    "check_in_date", "bills_included", "holding_deposit_confirmed",
    "declaration_confirmed", "signature_data", "signature_image", "signature_date",
    "num_applicants",
]
_BOOL_FIELDS = ("bills_included", "holding_deposit_confirmed", "declaration_confirmed")

# Mandatory fields for the primary applicant.
_REQUIRED = [
    ("a1_full_name", "First applicant full name is required."),
    ("a1_dob", "First applicant date of birth is required."),
    ("a1_email", "First applicant email is required."),
    ("a1_guarantor_email", "First applicant guarantor email is required."),
    ("a1_guarantor_mobile", "First applicant guarantor phone number is required."),
]

# A drawn signature arrives as a PNG data URL. Anything larger than this is not a
# signature, and a base64 blob that big has no business going into the row.
_SIGNATURE_MAX_BYTES = 400_000
_SIGNATURE_PREFIX = "data:image/png;base64,"

_REQUIRED_A2 = [
    ("a2_full_name", "Second applicant full name is required."),
    ("a2_dob", "Second applicant date of birth is required."),
    ("a2_email", "Second applicant email is required."),
]

import re as _re

_EMAIL_RE = _re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')
_DATE_RE = _re.compile(r'^\d{4}-\d{2}-\d{2}$')


def _validate_signature(data):
    """The declaration must carry a drawn signature, not a typed name.

    Checked server-side as well as in the browser: the signature is the part of
    the application that makes it a declaration, so it cannot be something a
    caller can skip by posting straight at the endpoint.
    """
    sig = str(data.get("signature_image") or "").strip()
    if not sig:
        return json_error("Please sign in the signature box before submitting.")
    if not sig.startswith(_SIGNATURE_PREFIX):
        return json_error("Signature was not captured correctly. Please clear it and sign again.")
    b64 = sig[len(_SIGNATURE_PREFIX):]
    if len(b64) > _SIGNATURE_MAX_BYTES:
        return json_error("Signature image is too large. Please clear it and sign again.")
    import base64 as _b64
    try:
        raw = _b64.b64decode(b64, validate=True)
    except Exception:
        return json_error("Signature was not captured correctly. Please clear it and sign again.")
    if not raw.startswith(b"\x89PNG\r\n\x1a\n"):
        return json_error("Signature was not captured correctly. Please clear it and sign again.")
    return None


def _validate_application_data(data, r):
    """Run extended validation on tenant application submit data.
    Returns None if OK, or (error_message, status_code) tuple."""

    # Standard required fields
    for key, msg in _REQUIRED:
        if not str(data.get(key) or "").strip():
            return json_error(msg)

    sig_err = _validate_signature(data)
    if sig_err:
        return sig_err

    # Non-standard email/age checks
    a1_email = (data.get("a1_email") or "").strip()
    a1_guar_email = (data.get("a1_guarantor_email") or "").strip()
    if not _EMAIL_RE.match(a1_email):
        return json_error("First applicant email address is not valid.")
    if not _EMAIL_RE.match(a1_guar_email):
        return json_error("First applicant guarantor email address is not valid.")
    if a1_email.lower() == a1_guar_email.lower():
        return json_error("First applicant email and guarantor email must be different.")

    # Age check: must be 18+
    a1_dob_str = str(data.get("a1_dob") or "").strip()
    if _DATE_RE.match(a1_dob_str):
        from datetime import date
        try:
            dob = datetime.strptime(a1_dob_str, "%Y-%m-%d").date()
            today = date.today()
            age = today.year - dob.year - ((today.month, today.day) < (dob.month, dob.day))
            if age < 18:
                return json_error("First applicant must be at least 18 years old.")
        except (ValueError, TypeError):
            pass

    # Conditional a2 fields
    num_apps = int(data.get("num_applicants") or 1)
    if num_apps == 2:
        for key, msg in _REQUIRED_A2:
            if not str(data.get(key) or "").strip():
                return json_error(msg)
        a2_email = (data.get("a2_email") or "").strip()
        if a2_email and not _EMAIL_RE.match(a2_email):
            return json_error("Second applicant email address is not valid.")

    return None  # all good


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


def _draw_signature(pdf, sig_image, printed_name, sig_date):
    """Put the applicant's signature on the page as an image, with the printed
    name and date beneath it the way a signed page reads.

    Applications submitted before signing was introduced carry a typed name and
    no image; those fall back to the printed line so old PDFs still regenerate.
    """
    drawn = False
    sig_image = (sig_image or "").strip()
    if sig_image.startswith("data:image/"):
        try:
            import base64 as _b64
            from io import BytesIO
            raw = _b64.b64decode(sig_image.split(",", 1)[1])
            if pdf.get_y() > 225:          # keep the signature block off a page break
                pdf.add_page()
            pdf.ln(2)
            top = pdf.get_y()
            pdf.image(BytesIO(raw), x=pdf.l_margin, y=top, h=20)
            pdf.set_y(top + 21)
            pdf.set_draw_color(120, 120, 120)
            pdf.line(pdf.l_margin, pdf.get_y(), pdf.l_margin + 70, pdf.get_y())
            pdf.ln(1)
            drawn = True
        except Exception as sig_err:
            print("[tenant_application] could not render signature image:", sig_err)

    pdf.set_font("Helvetica", "", 10)
    if drawn:
        pdf.cell(0, 6, f"Signed by: {printed_name}", new_x="LMARGIN", new_y="NEXT")
    else:
        pdf.cell(0, 6, f"Signature: {printed_name}", new_x="LMARGIN", new_y="NEXT")
    if sig_date:
        pdf.cell(0, 6, f"Date: {sig_date}", new_x="LMARGIN", new_y="NEXT")


def _generate_application_pdf(db, r):
    """Generate a PDF document from a submitted tenant application
    and save it linked to the matching tenancy or applicant."""
    from fpdf import FPDF
    import textwrap

    pdf = FPDF()
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=15)

    # Title
    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 10, "Tenant Application Form", new_x="LMARGIN", new_y="NEXT", align="C")
    pdf.ln(4)

    # Property details
    pdf.set_font("Helvetica", "B", 11)
    pdf.cell(0, 7, "Property Details", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 10)
    addr = r.get("property_address") or ""
    postcode = r.get("post_code") or ""
    room = r.get("room_number") or ""
    pdf.cell(0, 6, f"Address: {addr}", new_x="LMARGIN", new_y="NEXT")
    if postcode:
        pdf.cell(0, 6, f"Postcode: {postcode}", new_x="LMARGIN", new_y="NEXT")
    if room:
        pdf.cell(0, 6, f"Room: {room}", new_x="LMARGIN", new_y="NEXT")

    pdf.ln(3)

    # Financial
    pdf.set_font("Helvetica", "B", 11)
    pdf.cell(0, 7, "Financial Details", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 10)
    monthly = r.get("monthly_rent") or "0"
    deposit_amt = r.get("deposit") or "0"
    holding = r.get("holding_deposit") or "0"
    prorata = r.get("pro_rata") or "0"
    checkin_inst = r.get("check_in_installment") or "0"
    pdf.cell(0, 6, f"Monthly Rent: GBP {monthly}", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 6, f"Deposit: GBP {deposit_amt}", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 6, f"Holding Deposit: GBP {holding}", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 6, f"Pro-Rata: GBP {prorata}", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 6, f"Check-In Installment: GBP {checkin_inst}", new_x="LMARGIN", new_y="NEXT")
    holding_paid = r.get("holding_deposit_paid") or ""
    if holding_paid:
        pdf.cell(0, 6, f"Holding Deposit Paid: GBP {holding_paid}", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 6, "Holding Deposit Transfer Confirmed: %s"
             % ("Yes" if r.get("holding_deposit_confirmed") else "No"),
             new_x="LMARGIN", new_y="NEXT")

    checkin_date = r.get("check_in_date") or ""
    bills = "Yes" if r.get("bills_included") else "No"
    if checkin_date:
        pdf.cell(0, 6, f"Check-In Date: {checkin_date}", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 6, f"Bills Included: {bills}", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 6, "Number of Applicants: %s" % (r.get("num_applicants") or 1),
             new_x="LMARGIN", new_y="NEXT")

    pdf.ln(3)

    # Applicant 1
    pdf.set_font("Helvetica", "B", 11)
    pdf.cell(0, 7, "Primary Applicant", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 10)
    a1_name = r.get("a1_full_name") or ""
    a1_dob = r.get("a1_dob") or ""
    a1_email = r.get("a1_email") or ""
    a1_gender = r.get("a1_gender") or ""
    a1_guar_email = r.get("a1_guarantor_email") or ""
    a1_guar_mob = r.get("a1_guarantor_mobile") or ""
    pdf.cell(0, 6, f"Full Name: {a1_name}", new_x="LMARGIN", new_y="NEXT")
    if a1_dob: pdf.cell(0, 6, f"Date of Birth: {a1_dob}", new_x="LMARGIN", new_y="NEXT")
    if a1_email: pdf.cell(0, 6, f"Email: {a1_email}", new_x="LMARGIN", new_y="NEXT")
    if a1_gender: pdf.cell(0, 6, f"Gender: {a1_gender}", new_x="LMARGIN", new_y="NEXT")
    if a1_guar_email: pdf.cell(0, 6, f"Guarantor Email: {a1_guar_email}", new_x="LMARGIN", new_y="NEXT")
    if a1_guar_mob: pdf.cell(0, 6, f"Guarantor Mobile: {a1_guar_mob}", new_x="LMARGIN", new_y="NEXT")
    a1_phone = r.get("a1_phone") or ""
    a1_nationality = r.get("a1_nationality") or ""
    a1_employment = r.get("a1_employment") or ""
    a1_employer = r.get("a1_employer_name") or ""
    a1_income = r.get("a1_annual_income") or ""
    a1_res_status = r.get("a1_residential_status") or ""
    a1_cur_addr = r.get("a1_current_address") or ""
    a1_cur_ll = r.get("a1_current_landlord") or ""
    a1_cur_ll_phone = r.get("a1_current_landlord_phone") or ""
    a1_cur_ll_email = r.get("a1_current_landlord_email") or ""
    a1_cur_from = r.get("a1_current_from") or ""
    a1_cur_to = r.get("a1_current_to") or ""
    a1_reason = r.get("a1_reason_for_leaving") or ""
    a1_prev_addr = r.get("a1_previous_address") or ""
    a1_prev_ll = r.get("a1_previous_landlord") or ""
    a1_prev_ll_phone = r.get("a1_previous_landlord_phone") or ""
    if a1_phone: pdf.cell(0, 6, f"Phone: {a1_phone}", new_x="LMARGIN", new_y="NEXT")
    if a1_nationality: pdf.cell(0, 6, f"Nationality: {a1_nationality}", new_x="LMARGIN", new_y="NEXT")
    if a1_employment: pdf.cell(0, 6, f"Employment Status: {a1_employment}", new_x="LMARGIN", new_y="NEXT")
    if a1_employer: pdf.cell(0, 6, f"Employer: {a1_employer}", new_x="LMARGIN", new_y="NEXT")
    if a1_income: pdf.cell(0, 6, f"Annual Income: GBP {a1_income}", new_x="LMARGIN", new_y="NEXT")
    if a1_res_status: pdf.cell(0, 6, f"Residential Status: {a1_res_status}", new_x="LMARGIN", new_y="NEXT")
    if a1_cur_addr: pdf.cell(0, 6, f"Current Address: {a1_cur_addr}", new_x="LMARGIN", new_y="NEXT")
    if a1_cur_ll: pdf.cell(0, 6, f"Current Landlord: {a1_cur_ll}", new_x="LMARGIN", new_y="NEXT")
    if a1_cur_ll_phone: pdf.cell(0, 6, f"Landlord Phone: {a1_cur_ll_phone}", new_x="LMARGIN", new_y="NEXT")
    if a1_cur_ll_email: pdf.cell(0, 6, f"Landlord Email: {a1_cur_ll_email}", new_x="LMARGIN", new_y="NEXT")
    if a1_cur_from: pdf.cell(0, 6, f"Current Tenancy From: {a1_cur_from}", new_x="LMARGIN", new_y="NEXT")
    if a1_cur_to: pdf.cell(0, 6, f"Current Tenancy To: {a1_cur_to}", new_x="LMARGIN", new_y="NEXT")
    if a1_reason: pdf.cell(0, 6, f"Reason for Leaving: {a1_reason}", new_x="LMARGIN", new_y="NEXT")
    if a1_prev_addr: pdf.cell(0, 6, f"Previous Address: {a1_prev_addr}", new_x="LMARGIN", new_y="NEXT")
    if a1_prev_ll: pdf.cell(0, 6, f"Previous Landlord: {a1_prev_ll}", new_x="LMARGIN", new_y="NEXT")
    if a1_prev_ll_phone: pdf.cell(0, 6, f"Previous Landlord Phone: {a1_prev_ll_phone}", new_x="LMARGIN", new_y="NEXT")

    pdf.ln(3)

    # Applicant 2 (if present)
    a2_name = r.get("a2_full_name") or ""
    if a2_name.strip():
        pdf.set_font("Helvetica", "B", 11)
        pdf.cell(0, 7, "Secondary Applicant", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 10)
        a2_dob = r.get("a2_dob") or ""
        a2_email = r.get("a2_email") or ""
        a2_gender = r.get("a2_gender") or ""
        a2_guar_email = r.get("a2_guarantor_email") or ""
        a2_guar_mob = r.get("a2_guarantor_mobile") or ""
        pdf.cell(0, 6, f"Full Name: {a2_name}", new_x="LMARGIN", new_y="NEXT")
        if a2_dob: pdf.cell(0, 6, f"Date of Birth: {a2_dob}", new_x="LMARGIN", new_y="NEXT")
        if a2_email: pdf.cell(0, 6, f"Email: {a2_email}", new_x="LMARGIN", new_y="NEXT")
        if a2_gender: pdf.cell(0, 6, f"Gender: {a2_gender}", new_x="LMARGIN", new_y="NEXT")
        if a2_guar_email: pdf.cell(0, 6, f"Guarantor Email: {a2_guar_email}", new_x="LMARGIN", new_y="NEXT")
        if a2_guar_mob: pdf.cell(0, 6, f"Guarantor Mobile: {a2_guar_mob}", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(3)

    # Declaration & Signature
    sig = r.get("signature_data") or ""
    sig_date = r.get("signature_date") or ""
    pdf.set_font("Helvetica", "B", 11)
    pdf.cell(0, 7, "Declaration & Signature", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 10)
    declared = "Confirmed" if r.get("declaration_confirmed") else "Not confirmed"
    pdf.cell(0, 6, f"Declaration: {declared}", new_x="LMARGIN", new_y="NEXT")
    _draw_signature(pdf, r.get("signature_image"), sig or a1_name, sig_date)

    # Terms and Conditions
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 14)
    pdf.cell(0, 10, "Standard Terms and Conditions", new_x="LMARGIN", new_y="NEXT", align="C")
    pdf.ln(4)

    pdf.set_font("Helvetica", "B", 11)
    pdf.cell(0, 7, "Holding Deposit Declaration", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 9)
    terms_lines = [
        "I confirm that I have transferred the above sum as a Holding Deposit to",
        "reserve the specified accommodation unit provided by the Landlord, which will",
        "go toward my deposit.",
        "",
        "Applicant Declaration",
        "",
        "I/We confirm that the information provided in this application is true and",
        "accurate to the best of my/our knowledge.",
        "",
        "I/We confirm that I/we have the legal Right to Rent in the UK for the",
        "duration of the proposed tenancy.",
        "",
        "I/We understand that providing false or misleading information may result in",
        "rejection of this application or termination of any agreement entered into.",
        "",
        "I/We acknowledge that submission of this application does not guarantee",
        "acceptance and that final approval is subject to satisfactory referencing,",
        "affordability assessment, and Landlord approval.",
        "",
        "I/We authorise the Landlord and/or its appointed referencing agency to conduct",
        "credit and identity checks and to obtain relevant information from employers,",
        "previous landlords and other necessary sources for the purpose of assessing",
        "this application.",
        "", ""]
    pdf.set_x(pdf.l_margin)
    for line in terms_lines:
        pdf.set_x(pdf.l_margin)
        pdf.multi_cell(0, 5, line, new_x="LMARGIN", new_y="NEXT")
        if line == "":
            pdf.ln(2)

    pdf.ln(6)
    pdf.set_font("Helvetica", "B", 11)
    pdf.cell(0, 7, "Signature Confirmation", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 10)
    pdf.multi_cell(0, 6, f"I, {a1_name}, confirm that I have read and agree to the Terms and Conditions set out above.")
    _draw_signature(pdf, r.get("signature_image"), sig or a1_name, sig_date)
    pdf.ln(3)

    submitted_at = r.get("submitted_at") or ""
    if submitted_at:
        pdf.ln(3)
        pdf.set_font("Helvetica", "", 9)
        pdf.cell(0, 5, f"Submitted: {submitted_at}", new_x="LMARGIN", new_y="NEXT")

    # Save PDF
    docs_dir = os.path.join(os.path.dirname(__file__), "documents", "uploads")
    os.makedirs(docs_dir, exist_ok=True)

    from datetime import datetime, timezone
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    safe_name = f"tenant_app_{ts}_{a1_name.replace(' ','_')[:30]}.pdf"
    save_path = os.path.join(docs_dir, safe_name)
    pdf.output(save_path)

    # Determine related entity: try tenancy, fall back to applicant
    related_to = "applicant"
    related_id = str(r.get("applicant_id") or "")
    pid = r.get("property_id")
    uid = r.get("unit_id")
    if pid and uid:
        tenancy = db.execute(
            "SELECT id FROM tenancies WHERE property_id = ? AND unit_id = ? "
            "AND status NOT IN ('cancelled','ended') ORDER BY id DESC LIMIT 1",
            [pid, uid]
        ).fetchone()
        if tenancy:
            related_to = "tenancy"
            related_id = str(tenancy["id"])

    # Save to documents table (for tenancy/property linking)
    db.execute(
        "INSERT INTO documents (filename, file_path, file_type, category, related_to, related_id, notes, created) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (safe_name, save_path, "pdf", "Tenant Application",
         related_to, related_id, "Auto-generated from tenant application form submission",
         datetime.now(timezone.utc).isoformat())
    )
    # Also save to entity_documents so it shows under the applicant's Documents tab
    applicant_id = r.get("applicant_id")
    if applicant_id:
        import os as _os
        file_size = _os.path.getsize(save_path) if _os.path.exists(save_path) else 0
        db.execute(
            "INSERT INTO entity_documents "
            "(entity_type, entity_id, original_filename, stored_filename, file_path, file_type, "
            "file_size, mime_type, category, notes, uploaded_by, is_verified, created, updated) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)",
            ("applicant", applicant_id, safe_name, safe_name, save_path, "pdf",
             file_size, "application/pdf", "Tenant Application",
             "Auto-generated from tenant application form submission",
             "system", datetime.now(timezone.utc).isoformat(),
             datetime.now(timezone.utc).isoformat())
        )

    db.commit()
    doc_id = db.execute("SELECT last_insert_rowid() AS rid").fetchone()["rid"]
    print(f"[tenant_application] PDF generated: {safe_name} (doc_id={doc_id}, {related_to}={related_id}, applicant_id={applicant_id})")
    return doc_id


def _application_email_html(salutation, link):
    """The applicant's invitation to fill in their tenant application.

    Written for the inbox as much as for the reader. Spam filters mark down mail
    that is mostly one big button and little else, that hides where a link goes,
    that carries no preview text and no way to identify or reach the sender, so
    this carries real prose, the destination spelled out in full, a preheader,
    and a signed-off footer. The remaining half of deliverability is DNS
    (SPF, DKIM and DMARC on banksialondon.com), which is not set from here.
    """
    return """\
<div style="display:none;max-height:0;overflow:hidden;opacity:0">Your tenant \
application form is ready to complete - it takes about ten minutes.</div>
<div style="font-family:-apple-system,Segoe UI,Inter,Arial,sans-serif;max-width:560px;
     margin:0 auto;color:#1e293b;font-size:15px;line-height:1.6">
  <p style="margin:0 0 16px">Hi %(who)s,</p>
  <p style="margin:0 0 16px">Thank you for your interest in renting with Banksia. Before we can
     move your application forward, we need you to complete your tenant application form.</p>
  <p style="margin:0 0 16px">It takes about ten minutes. You will be asked for your personal
     and contact details, your employment and income, your current and previous addresses,
     and your guarantor's details. You will also be asked to sign the applicant declaration
     at the end, so please have those details to hand before you start.</p>
  <p style="margin:0 0 8px">You will be asked to register an account first. That account is
     also your tenant portal, where you can track the progress of your application and find
     your documents later on.</p>
  <p style="text-align:center;margin:26px 0">
    <a href="%(link)s" style="display:inline-block;padding:13px 26px;background:#f16232;
       color:#ffffff;text-decoration:none;border-radius:8px;font-weight:700">Open my application</a>
  </p>
  <p style="margin:0 0 16px;font-size:13px;color:#475569">If the button does not work, copy
     and paste this address into your browser:<br>
     <span style="word-break:break-all;color:#334155">%(link)s</span></p>
  <p style="margin:0 0 16px;font-size:13px;color:#475569">Please note the link expires 24 hours
     after you first open it. If it expires before you finish, reply to this email and we will
     send you a new one.</p>
  <p style="margin:0 0 4px">If anything is unclear, just reply to this email and a member of
     the team will help.</p>
  <p style="margin:0 0 24px">Kind regards,<br>The Referencing Team<br>Banksia</p>
  <hr style="border:none;border-top:1px solid #e2e8f0;margin:0 0 12px">
  <p style="margin:0;font-size:12px;color:#94a3b8">
    Banksia &middot; <a href="%(site)s" style="color:#94a3b8">banksialondon.com</a>
    &middot; <a href="mailto:%(from)s" style="color:#94a3b8">%(from)s</a><br>
    You have received this because you enquired about a property with us and we are
    processing your application.</p>
</div>""" % {"who": salutation, "link": link, "site": TA_WEBSITE, "from": TA_FROM_EMAIL}


@tenant_app_bp.route("/<token>/send-link", methods=["POST"])
@require_team_auth
@require_csrf
def send_tenant_application_link(token):
    """Send TA link to client email via Missive.

    Team-only. This endpoint sends mail from a Banksia address to a recipient
    and with a link both taken from the request body, so leaving it open let
    anyone who knew the URL send a Banksia-branded email pointing anywhere.
    The matching /generate endpoint is gated the same way.
    """
    from referencing_api import send_email_from
    data = request.get_json() or {}
    email = (data.get("email") or "").strip()
    name = (data.get("name") or "").strip()
    link = data.get("link", "")
    if not email:
        return json_error("email is required")
    if not link:
        return json_error("link is required")
    from html import escape as _esc
    from urllib.parse import quote as _q
    subject = "Your tenant application for %s" % (data.get("property_address") or "your new home")
    salutation = name.split()[0] if name else "there"
    # Append email to the TA link so the page can pre-fill it
    link_with_email = link + "&email=" + _q(email, safe="@")
    html = _application_email_html(_esc(salutation), _esc(link_with_email, quote=True))
    ok, detail, used_from = send_email_from(
        TA_FROM_EMAIL, TA_FROM_NAME, email, name, subject, html,
        reply_to=TA_REPLY_TO)
    if not ok:
        return json_error("Failed to send email: " + str(detail), 502)
    return json_success({
        "sent_to": email,
        "sent_from": used_from,
        "preferred_sender_available": used_from == TA_FROM_EMAIL,
    })

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

        validation_error = _validate_application_data(data, r)
        if validation_error:
            return validation_error
        if not data.get("declaration_confirmed"):
            return json_error("You must confirm the declaration to submit.")
        if not data.get("holding_deposit_confirmed"):
            return json_error("You must confirm the holding deposit transfer to submit.")

        # The signature is now drawn, so the printed name on the declaration is
        # taken from the applicant's own name rather than asked for twice.
        data.setdefault("signature_data", (data.get("a1_full_name") or "").strip())

        sets, params = [], []
        for f in _APPLICANT_FIELDS:
            if f in data:
                val = data.get(f)
                if f in _BOOL_FIELDS:
                    val = 1 if val in (True, 1, "1", "true", "on") else 0
                sets.append("%s = ?" % f)
                params.append(val)
        now = datetime.now(timezone.utc).isoformat()
        # Recalculate pro-rata and check-in installment against the check_in_date
        if data.get("check_in_date"):
            try:
                ci_date = datetime.strptime(str(data["check_in_date"]), "%Y-%m-%d").date()
                holding_f_db = float(r.get("holding_deposit") or 0)
                monthly_rent_f_db = float(r.get("monthly_rent") or 0)
                if holding_f_db > 0 and monthly_rent_f_db > 0:
                    pro_rata_new, check_in_new = _compute_prorata(holding_f_db, monthly_rent_f_db, ci_date)
                    sets.append("pro_rata = ?")
                    params.append(pro_rata_new)
                    sets.append("check_in_installment = ?")
                    params.append(check_in_new)
            except (ValueError, TypeError):
                pass
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
        # Sync applicant_id to portal user (may have been registered before submission)
        a1_email = r2.get("a1_email")
        if a1_email:
            db.execute("UPDATE portal_users SET applicant_id = ? WHERE lower(email) = ?",
                       [applicant_id, a1_email.strip().lower()])
        db.commit()

        # Referencing is the applicant's next step, so open it now rather than
        # leaving the portal pointing at a step with nothing behind it.
        referencing_token = None
        try:
            from referencing_api import ensure_referencing_form_for_applicant
            ref = ensure_referencing_form_for_applicant(db, applicant_id)
            referencing_token = (ref or {}).get("form_token")
        except Exception as ref_err:
            print("[tenant_application] could not open referencing for applicant %s: %s"
                  % (applicant_id, ref_err))

        # Generate PDF of the submitted application (fire-and-forget: don't fail the response)
        try:
            r3 = db.execute("SELECT * FROM tenant_applications WHERE form_token = ?", [token]).fetchone()
            _generate_application_pdf(db, r3)
        except Exception as pdf_err:
            import traceback
            print("[tenant_application] PDF generation failed after successful submit:", pdf_err)
            traceback.print_exc()

        return json_success({
            "submitted": True,
            "applicant_id": applicant_id,
            "next_step": "referencing",
            "referencing_url": ("/apply/" + referencing_token) if referencing_token else None,
        })
    except Exception as e:
        db.rollback()
        return json_error(safe_error(e), 500)
    finally:
        db.close()
