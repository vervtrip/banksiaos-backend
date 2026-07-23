#!/usr/bin/env python3
"""
Banksia OS — Referencing API Blueprint.
Handles applicant referencing forms, document uploads, AI analysis, e-signatures,
tenant portal authentication, and financial tracking.

Mounts at /api/referencing/
"""

import json, os, sys, uuid, hashlib, hmac, secrets, re, time
from datetime import datetime, timezone, timedelta
import fitz  # PyMuPDF — used for PDF signing (module-level so all functions can access it)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from flask import Blueprint, jsonify, request, session as flask_session, send_file
from functools import wraps
from werkzeug.utils import secure_filename
from banksia_os_db import get_db, get_dict_db, dict_from_row

referencing_bp = Blueprint("referencing", __name__, url_prefix="/api/referencing")

# ── Config ──
UPLOAD_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "documents", "referencing")
SIGNED_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "documents", "signed")
TEMPLATE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates", "legal")
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(SIGNED_DIR, exist_ok=True)
os.makedirs(TEMPLATE_DIR, exist_ok=True)

PORTAL_SESSION_TTL = timedelta(hours=24)
FORM_EXPIRY_DAYS = 14
REFERENCING_DEADLINE_HOURS = 48
REFERENCING_REMINDER_HOURS = 24
ONGOING_FORM_STATUSES = ("draft", "submitted", "under_review")


def _find_ongoing_form(db, portal_user_id):
    """Return the applicant's current in-progress application, if any."""
    placeholders = ",".join("?" for _ in ONGOING_FORM_STATUSES)
    return db.execute(
        f"SELECT * FROM referencing_forms WHERE portal_user_id = ? AND status IN ({placeholders}) "
        "ORDER BY id DESC LIMIT 1",
        [portal_user_id, *ONGOING_FORM_STATUSES]
    ).fetchone()

# ── Rate limiter (DB-backed — shared across all workers) ──
_RATE_LIMIT_WINDOW = 60  # seconds

def _check_rate_limit(key: str, max_attempts: int = 10, window: int = _RATE_LIMIT_WINDOW) -> bool:
    """Rate limit by key (IP-based). Uses the shared SQLite DB so it works
    across all gunicorn workers. Cleans old entries on each check."""
    try:
        db = get_dict_db()
        cutoff = (datetime.now(timezone.utc) - timedelta(seconds=window)).isoformat()
        # Clean stale entries
        db.execute("DELETE FROM rate_limits WHERE expires_at < datetime('now')")
        # Count recent attempts
        row = db.execute(
            "SELECT COUNT(*) AS cnt FROM rate_limits WHERE rate_key = ? AND expires_at > datetime('now')",
            [key]
        ).fetchone()
        count = row["cnt"] if row else 0
        if count >= max_attempts:
            return False
        # Record this attempt
        db.execute(
            "INSERT INTO rate_limits (rate_key, expires_at) VALUES (?, datetime('now', ? || ' seconds'))",
            [key, str(window)]
        )
        db.commit()
        return True
    except Exception:
        # If rate_limits table doesn't exist yet, create it and allow through
        try:
            db = get_dict_db()
            db.execute("CREATE TABLE IF NOT EXISTS rate_limits (id INTEGER PRIMARY KEY AUTOINCREMENT, rate_key TEXT, expires_at TEXT)")
            db.commit()
        except Exception:
            pass
        return True
    finally:
        try:
            db.close()
        except Exception:
            pass

# ── Helpers ──

def json_success(data, **extra):
    resp = {"success": True, "data": data}
    resp.update(extra)
    return jsonify(resp)

def json_error(msg, status=400):
    return jsonify({"success": False, "error": msg}), status

def safe_error(exc, context=""):
    """Log the real exception server-side, return a generic message for the client."""
    try:
        from services.logging_service import log_error
        log_error(f"Unhandled exception{f' in {context}' if context else ''}: {exc}")
    except Exception:
        pass
    return "Something went wrong on our end — please try again, or contact support if it persists."

def generate_token(length=48):
    return secrets.token_urlsafe(length)

def _current_username(default="team"):
    """The logged-in team member's username. flask_session['user'] is a dict
    ({username, role, email}) set by the dashboard login — never bind it raw."""
    u = flask_session.get("user")
    if isinstance(u, dict):
        return u.get("username") or u.get("email") or default
    if isinstance(u, str):
        return u
    return default

def generate_form_token():
    """Generates a unique URL-safe token for referencing form access."""
    return secrets.token_urlsafe(32)

def hash_password(password, salt=None):
    """Simple password hashing (for portal auth)."""
    if salt is None:
        salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 600000)
    return f"{salt}${h.hex()}"

def check_password(password, stored):
    salt = stored.split('$')[0]
    return hmac.compare_digest(hash_password(password, salt), stored)


# ── Public URLs & email delivery ──

# ── Portal Audit Log ──

def _audit_log(user_id, email, event_type, detail=None):
    """Write an entry to portal_audit_log. Best-effort (never raises)."""
    try:
        db = get_dict_db()
        try:
            # Ensure table exists
            db.execute(
                "CREATE TABLE IF NOT EXISTS portal_audit_log ("
                "id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, email TEXT, "
                "event_type TEXT, ip_address TEXT, user_agent TEXT, detail TEXT, "
                "created TEXT DEFAULT (datetime('now')))"
            )
            db.execute(
                "INSERT INTO portal_audit_log (user_id, email, event_type, ip_address, user_agent, detail) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                [user_id, email, event_type,
                 request.remote_addr or '',
                 (request.headers.get("User-Agent", "") or "")[:512],
                 (detail or "")[:1024]]
            )
            db.commit()
        finally:
            db.close()
    except Exception:
        pass  # Audit should never block the request


# ── CSRF Protection (Double Submit Cookie) ──

def _generate_csrf_token():
    """Generate a CSRF token and set it as a non-httpOnly cookie.
    The frontend reads it from the cookie and sends it in the X-CSRF-Token header.
    """
    token = secrets.token_urlsafe(32)
    resp = json_success({"csrf_token": token})
    max_age = 86400  # 24 hours
    resp.set_cookie(
        "csrf_token", token,
        max_age=max_age,
        path="/api/referencing",
        secure=os.environ.get("FLASK_ENV") == "production",
        httponly=False,  # Must be readable by JS
        samesite="Strict"
    )
    return resp


def _validate_csrf():
    """Validate CSRF token from X-CSRF-Token header against csrf_token cookie.
    Safe methods (GET, HEAD, OPTIONS) are always allowed.
    Skip validation if no cookie is set (first request — let it through once).
    """
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return True
    cookie_token = request.cookies.get("csrf_token")
    header_token = request.headers.get("X-CSRF-Token")
    if not cookie_token:
        # No cookie set yet — this is acceptable for the first mutation
        # (the cookie is set on the first GET/response). Allow through.
        return True
    if not header_token:
        return False
    return hmac.compare_digest(cookie_token, header_token)


def require_csrf(f):
    """Decorator: validate CSRF token on state-changing requests."""
    @wraps(f)
    def wrap(*args, **kwargs):
        if not _validate_csrf():
            return json_error("CSRF validation failed — missing or invalid X-CSRF-Token header. "
                              "Refresh the page and try again.", 403)
        return f(*args, **kwargs)
    return wrap


# ── Activity timeout ──

ACTIVITY_TIMEOUT_MINUTES = 60  # idle sessions expire after 1 hour

def _touch_session(session_token, db):
    """Update last_activity for the session. Best-effort."""
    try:
        db.execute(
            "UPDATE portal_sessions SET last_activity = datetime('now') WHERE session_token = ?",
            [session_token]
        )
    except Exception:
        pass


PUBLIC_BASE_URL = os.environ.get("BANKSIA_PUBLIC_URL", "https://ops.srv1744186.hstgr.cloud").rstrip("/")

# Banksia referencing correspondence goes out from the Banksia inbox, never the Verv one.
BANKSIA_FROM_EMAIL = "team@banksialondon.com"
BANKSIA_FROM_NAME = "Banksia Lettings"
_MISSIVE_TOKEN_PATH = "/root/.hermes/secrets/missive_token.txt"


def _missive_token():
    try:
        with open(_MISSIVE_TOKEN_PATH) as f:
            return f.read().strip()
    except Exception:
        return None


def send_email(to_email, to_name, subject, html_body, send=True):
    """Deliver an email via Missive from the Banksia inbox.

    Returns (ok: bool, detail: str). When send=False a draft is created but
    not delivered — used for wiring checks so we don't spam real inboxes.
    """
    import urllib.request, urllib.error

    # Hermetic test mode — skip the real API call so the SQA suite doesn't
    # dispatch drafts or generate bounces on every run.
    if os.environ.get("REFERENCING_EMAIL_DRYRUN") == "1":
        return True, "missive 201 (dryrun)"

    token = _missive_token()
    if not token:
        return False, "no missive token"

    payload = {
        "drafts": {
            "subject": subject,
            "body": html_body,
            "to_fields": [{"address": to_email, "name": to_name or to_email}],
            "from_field": {"address": BANKSIA_FROM_EMAIL, "name": BANKSIA_FROM_NAME},
            "send": bool(send),
        }
    }
    req = urllib.request.Request(
        "https://public.missiveapp.com/v1/drafts",
        data=json.dumps(payload).encode(),
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return (200 <= resp.status < 300), f"missive {resp.status}"
    except urllib.error.HTTPError as e:
        return False, f"missive http {e.code}: {e.read().decode('utf-8', 'ignore')[:200]}"
    except Exception as e:
        return False, f"missive error: {e}"


def _email_shell(title, intro, button_label, button_url, footer=""):
    """Consistent Banksia-branded HTML email body."""
    return f"""\
<div style="font-family:-apple-system,Segoe UI,Inter,Arial,sans-serif;max-width:520px;margin:0 auto;color:#1e293b">
  <div style="background:#1e293b;border-radius:14px 14px 0 0;padding:26px 28px">
    <div style="color:#fff;font-size:20px;font-weight:800">Banksia OS</div>
    <div style="color:#c7d2fe;font-size:12px;margin-top:2px">{title}</div>
  </div>
  <div style="border:1px solid #e8edf3;border-top:none;border-radius:0 0 14px 14px;padding:26px 28px">
    <p style="font-size:15px;line-height:1.55;margin:0 0 20px">{intro}</p>
    <a href="{button_url}" style="display:inline-block;background:#6366f1;color:#fff;text-decoration:none;
       font-weight:700;font-size:14px;padding:13px 22px;border-radius:10px">{button_label}</a>
    <p style="font-size:12px;color:#94a3b8;margin:22px 0 0;line-height:1.5">
      If the button doesn't work, copy this link into your browser:<br>
      <span style="color:#6366f1;word-break:break-all">{button_url}</span>
    </p>
    {('<p style="font-size:12px;color:#94a3b8;margin:18px 0 0;line-height:1.5">' + footer + '</p>') if footer else ''}
  </div>
  <div style="text-align:center;color:#cbd5e1;font-size:11px;padding:16px">
    Banksia Lettings · This is an automated message, please do not reply directly.
  </div>
</div>"""


def generate_signed_pdf(out_path, req, signature_data, ip, user_agent, audit_rows=None):
    """Produce a genuine, tamper-evident signed PDF certificate.

    Embeds a drawn signature (base64 data URL) or a typed name, a SHA-256
    integrity hash of the signature + metadata, and the full audit trail.
    Returns the output path.
    """
    import base64, fitz  # PyMuPDF

    signed_ts = datetime.now(timezone.utc).isoformat()
    # Tamper-evident hash binds signature to signer + document + time
    integrity_src = f"{req.get('id')}|{req.get('document_title')}|{req.get('created_for')}|{req.get('created_for_email')}|{signed_ts}|{signature_data}"
    integrity_hash = hashlib.sha256(integrity_src.encode()).hexdigest()

    doc = fitz.open()
    page = doc.new_page(width=595, height=842)  # A4
    NAVY = (0.117, 0.161, 0.231)
    INDIGO = (0.388, 0.400, 0.945)
    GREY = (0.42, 0.45, 0.50)

    # Header band
    page.draw_rect(fitz.Rect(0, 0, 595, 90), color=None, fill=NAVY)
    page.insert_text((40, 45), "Banksia OS", fontname="hebo", fontsize=22, color=(1, 1, 1))
    page.insert_text((40, 68), "Certificate of Electronic Signature", fontname="helv", fontsize=11, color=(0.8, 0.83, 0.9))

    y = 125
    def line(label, value, gap=26):
        nonlocal y
        page.insert_text((40, y), label, fontname="hebo", fontsize=9, color=GREY)
        page.insert_text((200, y), str(value or "—"), fontname="helv", fontsize=11, color=NAVY)
        y += gap

    line("DOCUMENT", req.get("document_title"))
    line("DOCUMENT TYPE", (req.get("document_type") or "").replace("_", " ").title())
    line("SIGNER", req.get("created_for"))
    line("SIGNER EMAIL", req.get("created_for_email"))
    line("SIGNED (UTC)", signed_ts)
    line("IP ADDRESS", ip)
    ua = (user_agent or "")[:60]
    line("DEVICE", ua)
    line("REQUEST ID", req.get("id"))

    # Signature block
    y += 12
    page.insert_text((40, y), "SIGNATURE", fontname="hebo", fontsize=9, color=GREY)
    y += 10
    sig_rect = fitz.Rect(40, y, 300, y + 90)
    page.draw_rect(sig_rect, color=(0.85, 0.87, 0.90), width=1)
    embedded = False
    if isinstance(signature_data, str) and signature_data.startswith("data:image"):
        try:
            b64 = signature_data.split(",", 1)[1]
            img = base64.b64decode(b64)
            page.insert_image(fitz.Rect(48, y + 8, 292, y + 82), stream=img)
            embedded = True
        except Exception:
            embedded = False
    if not embedded:
        # Typed signature — render in a script-like italic
        page.insert_text((55, y + 55), str(signature_data)[:40], fontname="heit", fontsize=26, color=NAVY)
    y += 110

    # Integrity hash
    page.insert_text((40, y), "INTEGRITY HASH (SHA-256)", fontname="hebo", fontsize=9, color=GREY)
    y += 14
    for chunk in [integrity_hash[i:i+64] for i in range(0, len(integrity_hash), 64)]:
        page.insert_text((40, y), chunk, fontname="cour", fontsize=9, color=INDIGO)
        y += 14
    y += 6
    page.insert_text((40, y), "This certificate is tamper-evident. Any change to the signature or", fontname="helv", fontsize=8, color=GREY)
    y += 12
    page.insert_text((40, y), "signer details invalidates the hash above.", fontname="helv", fontsize=8, color=GREY)
    y += 24

    # Audit trail
    if audit_rows:
        page.insert_text((40, y), "AUDIT TRAIL", fontname="hebo", fontsize=9, color=GREY)
        y += 16
        for a in audit_rows:
            ev = (a.get("event_type") or "").upper()
            when = a.get("occurred_at") or ""
            detail = (a.get("event_detail") or "")[:55]
            page.insert_text((40, y), f"• {when}  {ev}", fontname="hebo", fontsize=8, color=NAVY)
            page.insert_text((300, y), detail, fontname="helv", fontsize=8, color=GREY)
            y += 14
            if y > 800:
                page = doc.new_page(width=595, height=842); y = 60

    doc.save(out_path)
    doc.close()
    return out_path


# ── Auth decorators ──

def require_auth(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        # Check portal session token
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
        else:
            token = request.args.get("token", "")
        if not token:
            return json_error("Not authenticated", 401)
        db = get_dict_db()
        try:
            # Check session validity — must not be expired AND must not be idle.
            # expires_at/cutoff must be compared in the same string format SQLite's
            # datetime('now') produces ('YYYY-MM-DD HH:MM:SS'), or lexicographic
            # comparison against ISO-with-'T' timestamps silently breaks.
            row = db.execute(
                "SELECT ps.*, pu.id AS pu_id, pu.email, pu.first_name, pu.last_name, pu.portal_type, "
                "pu.applicant_id, pu.tenancy_id, pu.payee_tenant_id "
                "FROM portal_sessions ps JOIN portal_users pu ON ps.user_id = pu.id "
                "WHERE ps.session_token = ? AND datetime(ps.expires_at) > datetime('now') "
                "AND (ps.last_activity IS NULL OR ps.last_activity > datetime('now', ?))",
                [token, f"-{ACTIVITY_TIMEOUT_MINUTES} minutes"]
            ).fetchone()
            if not row:
                return json_error("Session expired or invalid", 401)
            # Touch session activity
            _touch_session(token, db)
            db.commit()
            request.portal_user = row
            return f(*args, **kwargs)
        finally:
            db.close()
    return wrap

def require_team_auth(f):
    """Requires team dashboard authentication (flask session)."""
    @wraps(f)
    def wrap(*args, **kwargs):
        if "user" not in flask_session:
            return json_error("Not authenticated - please login to the dashboard", 401)
        # Referencing handles applicant/tenant PII — restrict to admin roles.
        role = (flask_session.get("user", {}).get("role") or "").lower()
        if role not in ("super_admin", "admin"):
            return json_error("You do not have permission to access referencing data", 403)
        return f(*args, **kwargs)
    return wrap


# ────────────────────────────────────────────
# SECTION 1: REFERENCING FORMS
# ────────────────────────────────────────────

@referencing_bp.route("/forms", methods=["POST"])
@require_team_auth
@require_csrf
def api_create_form():
    """Create a new referencing form for an applicant."""
    data = request.get_json() or {}
    applicant_id = data.get("applicant_id")
    first_name = data.get("first_name", "").strip()
    last_name = data.get("last_name", "").strip()
    email = data.get("email", "").strip()

    if not first_name or not last_name or not email:
        return json_error("First name, last name and email are required")
    
    # Accept date_of_birth as optional for initial form creation
    date_of_birth = data.get("date_of_birth", "")
    if not date_of_birth:
        date_of_birth = "1900-01-01"  # placeholder until applicant fills it in

    db = get_dict_db()
    try:
        # Generate unique form token
        form_token = generate_form_token()
        expires_at = (datetime.now(timezone.utc) + timedelta(days=FORM_EXPIRY_DAYS)).isoformat()

        db.execute(
            """INSERT INTO referencing_forms (applicant_id, form_token, status, first_name, last_name, email, date_of_birth, submitted_at)
            VALUES (?, ?, 'draft', ?, ?, ?, ?, NULL)""",
            [applicant_id, form_token, first_name, last_name, email, date_of_birth]
        )
        form_id = db.execute("SELECT last_insert_rowid()").fetchone()["last_insert_rowid()"]

        # Create form sections tracking
        sections = [
            'personal', 'contact', 'residential', 'employment', 'self_employed',
            'student', 'guarantor', 'housing_benefit', 'kin', 'bank', 'landlord', 'additional', 'declaration'
        ]
        for section in sections:
            db.execute(
                "INSERT INTO form_sections (form_id, section_key) VALUES (?, ?)",
                [form_id, section]
            )

        delivery = None
        # Optionally email the applicant their referencing link straight away.
        if data.get("send"):
            delivery = _send_form_link(db, form_id, form_token, first_name, last_name, email)

        db.commit()

        form = db.execute("SELECT * FROM referencing_forms WHERE id = ?", [form_id]).fetchone()
        return json_success(form, delivery=delivery)
    except Exception as e:
        db.rollback()
        return json_error(safe_error(e), 500)
    finally:
        db.close()


# ── Referencing Form Progress Calculator ──
# Mirrors the frontend logic in referencing_form.html's updateProgress()
# Weights: fields 60%, documents 20%, declaration 10%, sections 10%
# Required fields worth 2, optional 1. Hidden conditional fields excluded.
def _compute_form_progress(form, valid_docs):
    """Compute progress percentage from form data fields and valid doc count."""
    # Section definitions mirroring the frontend SECTIONS array
    sections = [
        {"fields": [{"key":"title","required":True},{"key":"first_name","required":True},
                    {"key":"last_name","required":True},{"key":"date_of_birth","required":True},
                    {"key":"gender","required":False}]},
        {"fields": [{"key":"email","required":True},{"key":"mobile_phone","required":True},
                    {"key":"current_address_line1","required":True},
                    {"key":"current_address_line2","required":False},
                    {"key":"current_city","required":True},
                    {"key":"current_postcode","required":True},
                    {"key":"current_country","required":True},
                    {"key":"current_address_length","required":True}]},
        {"fields": [{"key":"id_type","required":True},{"key":"id_number","required":True},
                    {"key":"nationality","required":True},{"key":"country_of_origin","required":False},
                    {"key":"ni_number","required":False},{"key":"share_code","required":False},
                    {"key":"visa_number","required":False},{"key":"visa_type","required":False},
                    {"key":"visa_expiry","required":False}]},
        {"fields": [{"key":"employment_status","required":True},
                    {"key":"employer_name","required":False,"showIf":{"key":"employment_status","values":["Employed"]}},
                    {"key":"employer_address","required":False,"showIf":{"key":"employment_status","values":["Employed"]}},
                    {"key":"employer_email","required":False,"showIf":{"key":"employment_status","values":["Employed"]}},
                    {"key":"employer_phone","required":False,"showIf":{"key":"employment_status","values":["Employed"]}},
                    {"key":"job_title","required":False,"showIf":{"key":"employment_status","values":["Employed","Self-Employed"]}},
                    {"key":"annual_salary","required":True,"showIf":{"key":"employment_status","values":["Employed","Self-Employed"]}},
                    {"key":"employment_length","required":False,"showIf":{"key":"employment_status","values":["Employed","Self-Employed"]}},
                    {"key":"employment_contract_type","required":False,"showIf":{"key":"employment_status","values":["Employed"]}}]},
        {"fields": [{"key":"self_employed_company","required":False},
                    {"key":"self_employed_utr","required":False},
                    {"key":"self_employed_address","required":False},
                    {"key":"self_employed_annual_profit","required":False},
                    {"key":"self_employed_length","required":False},
                    {"key":"accountant_name","required":False},
                    {"key":"accountant_email","required":False},
                    {"key":"accountant_phone","required":False}]},
        {"fields": [{"key":"student_university","required":False},
                    {"key":"student_course_id","required":False},
                    {"key":"student_course_name","required":False},
                    {"key":"student_expected_graduation","required":False},
                    {"key":"student_loan_amount","required":False},
                    {"key":"student_maintenance_loan","required":False}]},
        {"fields": [{"key":"has_guarantor","required":False},
                    {"key":"guarantor_title","required":False,"showIf":{"key":"has_guarantor"}},
                    {"key":"guarantor_first_name","required":False,"showIf":{"key":"has_guarantor"}},
                    {"key":"guarantor_last_name","required":False,"showIf":{"key":"has_guarantor"}},
                    {"key":"guarantor_date_of_birth","required":False,"showIf":{"key":"has_guarantor"}},
                    {"key":"guarantor_relation","required":False,"showIf":{"key":"has_guarantor"}},
                    {"key":"guarantor_email","required":False,"showIf":{"key":"has_guarantor"}},
                    {"key":"guarantor_phone","required":False,"showIf":{"key":"has_guarantor"}},
                    {"key":"guarantor_mobile","required":False,"showIf":{"key":"has_guarantor"}},
                    {"key":"guarantor_address_line1","required":False,"showIf":{"key":"has_guarantor"}},
                    {"key":"guarantor_city","required":False,"showIf":{"key":"has_guarantor"}},
                    {"key":"guarantor_postcode","required":False,"showIf":{"key":"has_guarantor"}},
                    {"key":"guarantor_profession","required":False,"showIf":{"key":"has_guarantor"}},
                    {"key":"guarantor_annual_income","required":False,"showIf":{"key":"has_guarantor"}},
                    {"key":"guarantor_homeowner","required":False,"showIf":{"key":"has_guarantor"}}]},
        {"fields": [{"key":"housing_benefit","required":False},
                    {"key":"housing_benefit_council","required":False,"showIf":{"key":"housing_benefit"}},
                    {"key":"housing_benefit_number","required":False,"showIf":{"key":"housing_benefit"}}]},
        {"fields": [{"key":"kin_first_name","required":True},{"key":"kin_last_name","required":True},
                    {"key":"kin_relation","required":True},{"key":"kin_email","required":False},
                    {"key":"kin_phone","required":True},{"key":"kin_mobile","required":False},
                    {"key":"kin_address","required":False}]},
        {"fields": [{"key":"bank_location","required":True},
                    {"key":"bank_name","required":True,"showIf":{"key":"bank_location","values":["UK","International"]}},
                    {"key":"bank_sort_code","required":True,"showIf":{"key":"bank_location","values":["UK"]}},
                    {"key":"bank_account_number","required":True,"showIf":{"key":"bank_location","values":["UK"]}},
                    {"key":"bank_iban","required":True,"showIf":{"key":"bank_location","values":["International"]}},
                    {"key":"bank_swift","required":True,"showIf":{"key":"bank_location","values":["International"]}}]},
        {"fields": [{"key":"previous_landlord_name","required":False},
                    {"key":"previous_landlord_email","required":False},
                    {"key":"previous_landlord_phone","required":False},
                    {"key":"previous_landlord_address","required":False},
                    {"key":"previous_landlord_reason_for_leaving","required":False}]},
        {"fields": [{"key":"has_pet","required":False},{"key":"pet_details","required":False,"showIf":{"key":"has_pet"}},
                    {"key":"has_ccj","required":False},{"key":"ccj_details","required":False,"showIf":{"key":"has_ccj"}},
                    {"key":"has_iva","required":False},{"key":"iva_details","required":False,"showIf":{"key":"has_iva"}},
                    {"key":"has_bankruptcy","required":False},
                    {"key":"bankruptcy_details","required":False,"showIf":{"key":"has_bankruptcy"}},
                    {"key":"has_eviction","required":False},
                    {"key":"eviction_details","required":False,"showIf":{"key":"has_eviction"}},
                    {"key":"smoking_preference","required":False},
                    {"key":"preferred_move_in_date","required":False},
                    {"key":"special_requirements","required":False}]},
    ]

    emp_status = form.get("employment_status", "")
    has_guar = bool(form.get("has_guarantor"))
    decl_ok = bool(form.get("declaration_confirmed")) and bool(form.get("terms_confirmed"))

    # 1. Fields (60%)
    filled_weight = 0
    total_weight = 0
    for section in sections:
        for field in section["fields"]:
            showIf = field.get("showIf")
            if showIf:
                show_val = form.get(showIf["key"])
                if showIf.get("values"):
                    if show_val not in showIf["values"]:
                        continue
                elif not show_val:
                    continue
            total_weight += 2 if field["required"] else 1
            val = form.get(field["key"])
            if val and str(val).strip():
                filled_weight += 2 if field["required"] else 1
    fields_pct = (filled_weight / total_weight * 60) if total_weight > 0 else 0

    # 2. Documents (20%)
    expected = ["passport", "driving_licence"]
    if emp_status in ("Employed", "Self-Employed"):
        expected += ["payslip", "bank_statement", "employment_contract"]
    if emp_status == "Student":
        expected += ["student_letter", "student_id"]
    if has_guar:
        expected.append("guarantor_id")
    docs_pct = min(valid_docs / len(expected), 1) * 20 if expected else 10

    # 3. Declaration (10%)
    decl_pct = 10 if decl_ok else 0

    # 4. Section completion (10%) — count sections where all required visible fields are filled.
    # Sections with no required fields (self-employed, student, guarantor, housing
    # benefit, previous landlord, additional info) must NOT count as complete until
    # the applicant has actually entered something — otherwise a totally blank form
    # shows a non-zero "complete" section count, which is what this fixes.
    sec_ok = 0
    for i, section in enumerate(sections):
        visible_fields = []
        required_fields = []
        for field in section["fields"]:
            showIf = field.get("showIf")
            if showIf:
                show_val = form.get(showIf["key"])
                if showIf.get("values"):
                    if show_val not in showIf["values"]:
                        continue
                elif not show_val:
                    continue
            visible_fields.append(field)
            if field["required"]:
                required_fields.append(field)

        def _filled(f):
            val = form.get(f["key"])
            return bool(val) and bool(str(val).strip())

        if required_fields:
            all_done = all(_filled(f) for f in required_fields)
        else:
            all_done = any(_filled(f) for f in visible_fields)
        if all_done:
            sec_ok += 1
    sec_pct = (sec_ok / len(sections)) * 10

    total_pct = round(fields_pct + docs_pct + decl_pct + sec_pct)
    return max(0, min(total_pct, 100))


def _send_form_link(db, form_id, form_token, first_name, last_name, email, actual_send=True):
    """Email the applicant their referencing form link and log it on the form."""
    form_url = f"{PUBLIC_BASE_URL}/apply/{form_token}"
    body = _email_shell(
        title="Your referencing form",
        intro=(
            f"Hi {first_name},<br><br>"
            "Thanks for applying. To progress your application, please complete our online "
            "referencing form. It covers your details, employment, and a few supporting documents "
            "(ID, payslips, bank statements). You can save and return at any time using the same link."
        ),
        button_label="Start my referencing",
        button_url=form_url,
        footer="This link is unique to you and expires in 14 days.",
    )
    ok, detail = send_email(email, f"{first_name} {last_name}",
                            "Complete your Banksia referencing form", body, send=actual_send)
    if ok:
        db.execute(
            "UPDATE referencing_forms SET status = CASE WHEN status='draft' THEN 'sent' ELSE status END, "
            "link_sent_at = datetime('now') WHERE id = ?",
            [form_id],
        )
    return detail


@referencing_bp.route("/forms/<int:form_id>/send-link", methods=["POST"])
@require_team_auth
@require_csrf
def api_send_form_link(form_id):
    """(Re)send the referencing form link to the applicant by email."""
    db = get_dict_db()
    try:
        form = db.execute("SELECT * FROM referencing_forms WHERE id = ?", [form_id]).fetchone()
        if not form:
            return json_error("Form not found", 404)
        detail = _send_form_link(db, form_id, form["form_token"],
                                 form["first_name"], form["last_name"], form["email"])
        if not str(detail).startswith("missive 2"):
            db.rollback()
            return json_error(f"Could not send form link — {detail}", 502)
        db.commit()
        updated = db.execute("SELECT * FROM referencing_forms WHERE id = ?", [form_id]).fetchone()
        return json_success(updated, delivery=detail)
    finally:
        db.close()


@referencing_bp.route("/forms", methods=["GET"])
@require_team_auth
def api_list_forms():
    """List all referencing forms with optional filters."""
    page = int(request.args.get("page", 1))
    per_page = int(request.args.get("per_page", 20))
    status = request.args.get("status")
    search = request.args.get("search", "").strip()

    db = get_dict_db()
    try:
        where_parts = []
        params = []

        if status:
            where_parts.append("rf.status = ?")
            params.append(status)

        if search:
            where_parts.append("(rf.first_name LIKE ? OR rf.last_name LIKE ? OR rf.email LIKE ?)")
            s = f"%{search}%"
            params.extend([s, s, s])

        where = "WHERE " + " AND ".join(where_parts) if where_parts else ""

        # Get total count
        total = db.execute(
            f"SELECT COUNT(*) as cnt FROM referencing_forms rf {where}", params
        ).fetchone()["cnt"]

        # Get paginated results with document count and review status
        offset = (page - 1) * per_page
        rows = db.execute(
            f"""SELECT rf.*,
                (SELECT COUNT(*) FROM referencing_documents WHERE form_id = rf.id) as doc_count,
                (SELECT COUNT(*) FROM referencing_documents WHERE form_id = rf.id AND ai_flagged = 1) as flagged_count,
                (SELECT COUNT(*) FROM referencing_checks WHERE form_id = rf.id AND status = 'pending') as pending_checks
            FROM referencing_forms rf {where}
            ORDER BY rf.created DESC LIMIT ? OFFSET ?""",
            params + [per_page, offset]
        ).fetchall()

        # Compute progress for each form
        rows_list = [dict(r) for r in rows]
        for r in rows_list:
            doc_count = r.get("doc_count", 0)
            flagged_docs = r.get("flagged_count", 0)
            uploaded_valid = doc_count - flagged_docs
            r["progress_pct"] = _compute_form_progress(r, uploaded_valid)

        return json_success(rows_list, total=total, page=page, per_page=per_page)
    finally:
        db.close()


@referencing_bp.route("/forms/<int:form_id>", methods=["GET"])
def api_get_form(form_id):
    """Get a single referencing form. Token or team auth required."""
    token = request.args.get("token", "") or (request.headers.get("Authorization", "")[7:] if request.headers.get("Authorization", "").startswith("Bearer ") else "")
    is_team = "user" in flask_session

    db = get_dict_db()
    try:
        form = db.execute("SELECT * FROM referencing_forms WHERE id = ?", [form_id]).fetchone()
        if not form:
            return json_error("Form not found", 404)

        # If accessed via token, verify it matches
        if not is_team:
            if form["form_token"] != token:
                return json_error("Not authorised", 401)
            # Don't expose internal_notes to applicant
            form = {k: v for k, v in form.items() if k != 'internal_notes'}

        # Include documents and sections
        documents = db.execute(
            "SELECT * FROM referencing_documents WHERE form_id = ? ORDER BY uploaded_at DESC",
            [form_id]
        ).fetchall()

        sections = db.execute(
            "SELECT * FROM form_sections WHERE form_id = ? ORDER BY section_key",
            [form_id]
        ).fetchall()

        checks = db.execute(
            "SELECT * FROM referencing_checks WHERE form_id = ? ORDER BY created DESC",
            [form_id]
        ).fetchall() if is_team else []

        # Include esignature requests for this form
        esignatures = db.execute(
            "SELECT id, document_type, document_title, status, created_for, created_for_email, "
            "created, sent_at, viewed_at, signed_at, completed_at, "
            "team_signer_name, team_signed_at "
            "FROM esignature_requests WHERE form_id = ? ORDER BY created DESC",
            [form_id]
        ).fetchall() if is_team else []

        # ── Resolve property + unit names from the linked applicant ──
        property_name = None
        unit_ref = None
        property_id = None
        unit_id = None
        applicant_id = form.get("applicant_id")
        if applicant_id:
            app = db.execute(
                "SELECT a.property_id, a.unit_id, "
                "COALESCE(NULLIF(p.ref, ''), NULLIF(p.address_line_1, ''), p.name) AS pname, "
                "u.unit_ref "
                "FROM applicants a "
                "LEFT JOIN properties p ON a.property_id = p.id "
                "LEFT JOIN units u ON a.unit_id = u.id "
                "WHERE a.id = ?",
                [applicant_id]
            ).fetchone()
            if app:
                property_id = app.get("property_id")
                unit_id = app.get("unit_id")
                property_name = app.get("pname")
                unit_ref = app.get("unit_ref")
        # If no applicant-linked property, try the old form-level property fields
        if not property_name:
            property_name = form.get("property_name")
            unit_ref = form.get("unit_ref")
            property_id = form.get("property_id")
            unit_id = form.get("unit_id")

        # Attach resolved property info into the form dict so the frontend
        # renders it without a second API call
        form["property_name"] = property_name
        form["unit_ref"] = unit_ref
        form["property_id"] = property_id
        form["unit_id"] = unit_id

        # Compute progress percentage for display on admin side
        valid_docs = len([d for d in documents if not d.get("ai_flagged")])
        form["progress_pct"] = _compute_form_progress(form, valid_docs)

        return json_success({
            "form": form,
            "documents": documents,
            "sections": sections,
            "checks": checks,
            "esignatures": esignatures,
        })
    finally:
        db.close()


@referencing_bp.route("/forms/<int:form_id>", methods=["PATCH"])
def api_update_form(form_id):
    """Update referencing form fields. Token or team auth required."""
    data = request.get_json() or {}
    is_team = "user" in flask_session
    token = request.args.get("token", "") or ""

    db = get_dict_db()
    try:
        form = db.execute("SELECT * FROM referencing_forms WHERE id = ?", [form_id]).fetchone()
        if not form:
            return json_error("Form not found", 404)

        # Verify access
        if not is_team:
            if form["form_token"] != token:
                return json_error("Not authorised", 401)
            # Applicants can only update draft forms
            if form["status"] != "draft":
                return json_error("Form has already been submitted", 400)
            # Applicants can only update certain fields (not status, notes, etc)
            allowed = {
                'title', 'first_name', 'last_name', 'date_of_birth', 'gender',
                'email', 'mobile_phone', 'current_address_line1', 'current_address_line2',
                'current_city', 'current_postcode', 'current_country', 'current_address_length',
                'id_type', 'id_number', 'nationality', 'country_of_origin', 'ni_number',
                'visa_number', 'visa_type', 'visa_expiry', 'share_code',
                'employment_status', 'employer_name', 'employer_address', 'employer_email',
                'employer_phone', 'job_title', 'annual_salary', 'employment_length',
                'employment_contract_type',
                'self_employed_company', 'self_employed_utr', 'self_employed_address',
                'self_employed_annual_profit', 'self_employed_length',
                'accountant_name', 'accountant_email', 'accountant_phone',
                'student_university', 'student_course_id', 'student_course_name',
                'student_expected_graduation', 'student_loan_amount', 'student_maintenance_loan',
                'has_guarantor', 'guarantor_title', 'guarantor_first_name', 'guarantor_last_name',
                'guarantor_date_of_birth', 'guarantor_relation', 'guarantor_email',
                'guarantor_phone', 'guarantor_mobile', 'guarantor_address_line1',
                'guarantor_address_line2', 'guarantor_city', 'guarantor_postcode',
                'guarantor_country', 'guarantor_profession', 'guarantor_employment_status',
                'guarantor_annual_income', 'guarantor_homeowner',
                'housing_benefit', 'housing_benefit_council', 'housing_benefit_number',
                'kin_first_name', 'kin_last_name', 'kin_relation', 'kin_email', 'kin_phone',
                'kin_mobile', 'kin_address',
                'bank_name', 'bank_account_name', 'bank_sort_code', 'bank_account_number',
                'bank_location', 'bank_iban', 'bank_swift',
                'previous_landlord_name', 'previous_landlord_email', 'previous_landlord_phone',
                'previous_landlord_address', 'previous_landlord_reason_for_leaving',
                'has_pet', 'pet_details', 'has_ccj', 'ccj_details', 'has_iva', 'iva_details',
                'has_bankruptcy', 'bankruptcy_details', 'has_eviction', 'eviction_details',
                'smoking_preference', 'preferred_move_in_date', 'special_requirements',
                'declaration_confirmed', 'declaration_signed_at'
            }
            data = {k: v for k, v in data.items() if k in allowed}

        # Strip control/auth keys that are never DB columns (defensive — the
        # applicant path already whitelists, but the team path does not).
        _control_keys = {"token", "id", "form_id", "form_token", "section",
                         "status", "created", "modified"}
        data = {k: v for k, v in data.items()
                if k not in _control_keys and not isinstance(v, (dict, list))}

        # Drop any key that is not a real column on referencing_forms. The
        # frontend saveSection() always appends terms_confirmed (a checkbox that
        # has no matching column) alongside declaration_confirmed. The applicant
        # path whitelists it away, but the team path does not - an unknown
        # column here 500s the entire save, so the form silently fails to
        # advance and nothing is stored. Filtering to real columns fixes both.
        _valid_cols = {r["name"] for r in
                       db.execute("PRAGMA table_info(referencing_forms)").fetchall()}
        data = {k: v for k, v in data.items() if k in _valid_cols}

        # Update fields
        if not data:
            return json_error("No valid fields to update")

        set_parts = []
        params = []
        for key, value in data.items():
            set_parts.append(f"{key} = ?")
            params.append(value)

        set_parts.append("modified = datetime('now')")
        params.append(form_id)

        db.execute(
            f"UPDATE referencing_forms SET {', '.join(set_parts)} WHERE id = ?",
            params
        )

        # ── Propagate key fields to linked applicant record ──
        form_applicant_id = form.get("applicant_id")
        if form_applicant_id:
            # Map form field names to applicant column names
            field_map = {
                "preferred_move_in_date": "desired_move_in",
                "annual_salary": "employment_salary",
                "employer_name": "employment_company",
                "employer_address": "employment_address",
                "mobile_phone": "mobile",
                "current_address_line1": "full_address",
            }
            # Also handle rent/deposit if stored on referencing_forms
            rent = data.get("agreed_rent") or data.get("proposed_rent")
            deposit = data.get("deposit_amount") or data.get("proposed_deposit")
            move_in = data.get("preferred_move_in_date") or data.get("desired_move_in")

            app_updates = {}
            for form_field, app_column in field_map.items():
                if form_field in data:
                    app_updates[app_column] = data[form_field]

            if "desired_move_in" in data:
                app_updates["desired_move_in"] = data["desired_move_in"]
            if "proposed_rent" in data:
                app_updates["proposed_rent"] = data["proposed_rent"]
            if "proposed_deposit" in data:
                app_updates["proposed_deposit"] = data["proposed_deposit"]

            if app_updates:
                app_set = ", ".join(f"{col} = ?" for col in app_updates)
                app_vals = list(app_updates.values())
                app_vals.append(form_applicant_id)
                db.execute(
                    f"UPDATE applicants SET {app_set} WHERE id = ?",
                    app_vals
                )

        # Track section completion
        section_map = {
            'title': 'personal', 'first_name': 'personal', 'date_of_birth': 'personal',
            'email': 'contact', 'mobile_phone': 'contact', 'current_address_line1': 'contact',
            'id_type': 'residential', 'ni_number': 'residential',
            'employer_name': 'employment', 'self_employed_company': 'self_employed',
            'student_university': 'student', 'has_guarantor': 'guarantor',
            'housing_benefit': 'housing_benefit', 'kin_first_name': 'kin',
            'bank_name': 'bank', 'previous_landlord_name': 'landlord',
            'has_pet': 'additional', 'declaration_confirmed': 'declaration',
        }
        for key in data:
            if key in section_map:
                section = section_map[key]
                db.execute(
                    "UPDATE form_sections SET is_complete = 1, completed_at = datetime('now') "
                    "WHERE form_id = ? AND section_key = ?",
                    [form_id, section]
                )

        db.commit()

        updated = db.execute("SELECT * FROM referencing_forms WHERE id = ?", [form_id]).fetchone()
        return json_success(updated)
    except Exception as e:
        db.rollback()
        return json_error(safe_error(e), 500)
    finally:
        db.close()


@referencing_bp.route("/forms/<int:form_id>/submit", methods=["POST"])
def api_submit_form(form_id):
    """Submit a referencing form (applicant completes and submits)."""
    # Accept token from query string, Authorization header, or JSON body
    body_token = ""
    try:
        body_data = request.get_json(silent=True) or {}
        body_token = body_data.get("token", "")
    except Exception:
        pass
    token = request.args.get("token", "") or body_token or (request.headers.get("Authorization", "")[7:] if request.headers.get("Authorization", "").startswith("Bearer ") else "")

    db = get_dict_db()
    try:
        form = db.execute("SELECT * FROM referencing_forms WHERE id = ?", [form_id]).fetchone()
        if not form:
            return json_error("Form not found", 404)
        if form["form_token"] != token:
            return json_error("Not authorised", 401)
        if form["status"] not in ("draft", "sent"):
            return json_error("Form already submitted", 400)
        if not form["declaration_confirmed"]:
            return json_error("You must confirm the declaration before submitting", 400)

        # Update status
        db.execute(
            """UPDATE referencing_forms SET status = 'submitted', submitted_at = datetime('now'), 
               declaration_ip_address = ?, modified = datetime('now') WHERE id = ?""",
            [request.remote_addr or '', form_id]
        )

        # Create a pending check entry
        db.execute(
            "INSERT INTO referencing_checks (form_id, check_type, status) VALUES (?, 'identity_check', 'pending')",
            [form_id]
        )
        db.execute(
            "INSERT INTO referencing_checks (form_id, check_type, status) VALUES (?, 'income_check', 'pending')",
            [form_id]
        )
        db.execute(
            "INSERT INTO referencing_checks (form_id, check_type, status) VALUES (?, 'right_to_rent', 'pending')",
            [form_id]
        )

        db.commit()

        # ── Auto-trigger AI document review ──
        try:
            documents = db.execute(
                "SELECT * FROM referencing_documents WHERE form_id = ?", [form_id]
            ).fetchall()
            if documents:
                form_row = db.execute("SELECT * FROM referencing_forms WHERE id = ?", [form_id]).fetchone()
                analyses = {}
                for doc in documents:
                    analysis = run_document_analysis(doc, form_row)
                    analyses[doc["id"]] = analysis
                    db.execute(
                        "UPDATE referencing_documents SET ai_analysis = ?, ai_verified = ?, ai_confidence = ?, ai_flagged = ?, ai_flag_reason = ? WHERE id = ?",
                        [json.dumps(analysis), 1 if analysis.get("verified") else 0,
                         analysis.get("confidence", 0), 1 if analysis.get("flagged") else 0,
                         analysis.get("flag_reason", ""), doc["id"]]
                    )
                checks = run_cross_referencing_checks(form_row, documents, analyses)
                for check in checks:
                    # Remove existing pending checks for this type and insert live results
                    db.execute(
                        "DELETE FROM referencing_checks WHERE form_id = ? AND check_type = ?",
                        [form_id, check["type"]]
                    )
                    db.execute(
                        "INSERT INTO referencing_checks (form_id, check_type, status, details, confidence, summary) VALUES (?, ?, ?, ?, ?, ?)",
                        [form_id, check["type"], check["status"], json.dumps(check.get("details", {})),
                         check.get("confidence", 0), check.get("summary", "")]
                    )
                db.commit()
        except Exception:
            pass  # Never block submission on AI review failure

        # Confirmation email + invitation to set up the tracking portal.
        try:
            setup_url = f"{PUBLIC_BASE_URL}/portal?setup={form['form_token']}"
            body = _email_shell(
                title="Application received",
                intro=(
                    f"Hi {form['first_name']},<br><br>"
                    "Thank you — we've received your referencing application and our team will now "
                    "review it. You can set up a secure portal account to track your application "
                    "status and sign any documents."
                ),
                button_label="Set up your account",
                button_url=setup_url,
                footer="If you weren't expecting this, you can safely ignore this email.",
            )
            send_email(form["email"], f"{form['first_name']} {form['last_name']}",
                       "We've received your Banksia referencing application", body, send=True)
        except Exception:
            pass  # never block submission on an email hiccup

        updated = db.execute("SELECT * FROM referencing_forms WHERE id = ?", [form_id]).fetchone()
        return json_success(updated)
    except Exception as e:
        db.rollback()
        return json_error(safe_error(e), 500)
    finally:
        db.close()


@referencing_bp.route("/forms/<int:form_id>/assign-property", methods=["POST"])
@require_team_auth
@require_csrf
def api_assign_form_property(form_id):
    """Delta team assigns a property and unit to this referencing form's applicant.

    Sets property_id + unit_id on the linked applicant record so the
    auto-tenancy-creation flow knows which unit this person is moving into.
    """
    data = request.get_json() or {}
    property_id = data.get("property_id")
    unit_id = data.get("unit_id")

    if not property_id or not unit_id:
        return json_error("property_id and unit_id are required")

    db = get_dict_db()
    try:
        form = db.execute("SELECT * FROM referencing_forms WHERE id = ?", [form_id]).fetchone()
        if not form:
            return json_error("Form not found", 404)

        # Validate property + unit
        prop = db.execute("SELECT id, name, address_line_1 FROM properties WHERE id = ?", [property_id]).fetchone()
        if not prop:
            return json_error(f"Property {property_id} not found", 404)

        unit = db.execute(
            "SELECT id, unit_ref, unit_status FROM units WHERE id = ? AND property_id = ?",
            [unit_id, property_id]
        ).fetchone()
        if not unit:
            return json_error(f"Unit {unit_id} not found under property {property_id}", 404)

        now = datetime.now(timezone.utc).isoformat()
        applicant_id = form.get("applicant_id")
        changes = []

        # Update the applicant record with property_id + unit_id
        if applicant_id:
            app = db.execute("SELECT * FROM applicants WHERE id = ?", [applicant_id]).fetchone()
            if app:
                old_prop = app.get("property_id")
                old_unit = app.get("unit_id")
                db.execute(
                    "UPDATE applicants SET property_id = ?, unit_id = ?, modified = ? WHERE id = ?",
                    [property_id, unit_id, now, applicant_id]
                )
                changes.append(f"applicant #{applicant_id}: property {old_prop}→{property_id}, unit {old_unit}→{unit_id}")

        # Also update referencing form metadata if needed
        db.execute(
            "UPDATE referencing_forms SET modified = ? WHERE id = ?",
            [now, form_id]
        )

        db.commit()

        return json_success({
            "property_id": property_id,
            "unit_id": unit_id,
            "property_name": prop.get("name") or prop.get("address_line_1") or "",
            "unit_ref": unit.get("unit_ref") or "",
            "applicant_id": applicant_id,
            "changes": changes,
        })
    except Exception as e:
        db.rollback()
        return json_error(safe_error(e), 500)
    finally:
        db.close()


@referencing_bp.route("/forms/<int:form_id>/status", methods=["PATCH"])
@require_team_auth
@require_csrf
def api_update_form_status(form_id):
    """Team updates form status (approve/reject)."""
    data = request.get_json() or {}
    status = data.get("status")
    notes = data.get("notes", "")

    if status not in ("under_review", "approved", "rejected"):
        return json_error("Invalid status. Must be: under_review, approved, or rejected")

    db = get_dict_db()
    try:
        db.execute(
            "UPDATE referencing_forms SET status = ?, reviewed_by = ?, reviewed_at = datetime('now'), review_notes = ?, modified = datetime('now') WHERE id = ?",
            [status, _current_username(), notes, form_id]
        )
        db.commit()
        updated = db.execute("SELECT * FROM referencing_forms WHERE id = ?", [form_id]).fetchone()

        # ── Auto-create e-signature on approval ──
        if status == "approved":
            try:
                form = updated
                signer_name = f"{form.get('first_name','')} {form.get('last_name','')}".strip() or "Tenant"
                signer_email = form.get('email', '')
                applicant_id = form.get('applicant_id')

                # Propagate rent/deposit/move-in from form data to applicant for tenancy creation
                if applicant_id:
                    form_rent = form.get("proposed_rent") or form.get("agreed_rent")
                    form_deposit = form.get("proposed_deposit") or form.get("deposit_amount")
                    form_move_in = form.get("preferred_move_in_date") or form.get("desired_move_in")

                    # Always update applicant status to 'approved'
                    app_updates_list = ["status = 'approved'"]
                    app_params_list = []
                    if form_rent:
                        app_updates_list.append("proposed_rent = ?")
                        app_params_list.append(float(form_rent))
                    if form_deposit:
                        app_updates_list.append("proposed_deposit = ?")
                        app_params_list.append(float(form_deposit))
                    if form_move_in:
                        app_updates_list.append("desired_move_in = ?")
                        app_params_list.append(str(form_move_in)[:10])
                    app_params_list.append(applicant_id)
                    db.execute(
                        f"UPDATE applicants SET {', '.join(app_updates_list)} WHERE id = ?",
                        app_params_list
                    )

                if signer_email:
                    # Create the esign request
                    import uuid
                    from datetime import datetime, timezone, timedelta
                    signer_token = uuid.uuid4().hex[:32]
                    team_token = uuid.uuid4().hex[:32]

                    team_name = _current_username() or "Banksia Team"
                    try:
                        # User data is in the JSON file, not a DB table
                        import json as _json
                        with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "users.json")) as _uf:
                            _users = _json.load(_uf)
                        _team_user = _users.get(_current_username(), {})
                        team_email = _team_user.get("email", "team@banksialondon.com")
                    except Exception:
                        team_email = "team@banksialondon.com"

                    db.execute(
                        """INSERT INTO esignature_requests
                           (form_id, document_type, document_title, status,
                            created_for, created_for_email, signer_token, expires_at, created_by,
                            template_id, team_signer_name, team_signer_email, team_token)
                        VALUES (?, 'tenancy_agreement', 'Tenancy Agreement', 'draft',
                                ?, ?, ?, ?, ?,
                                ?, ?, ?, ?)""",
                        [form['id'],
                         signer_name, signer_email, signer_token,
                         (datetime.now(timezone.utc) + timedelta(days=14)).isoformat(),
                         _current_username(),
                         None, team_name, team_email, team_token]
                    )
                    esign_id = db.execute("SELECT last_insert_rowid() AS rid").fetchone()['rid']

                    db.execute(
                        "INSERT INTO esignature_audit_log (request_id, event_type, event_detail) VALUES (?, 'created', ?)",
                        [esign_id, f"Auto-created on referencing form #{form['id']} approval"]
                    )

                    # Send the esign request
                    new_req = db.execute("SELECT * FROM esignature_requests WHERE id = ?", [esign_id]).fetchone()
                    _deliver_esignature(db, new_req, actual_send=True)
            except Exception as e:
                import traceback
                print(f"[AUTO-ESIGN] Failed: {e}", file=sys.stderr)
                traceback.print_exc(file=sys.stderr)
                pass  # Don't fail approval if esign creation errors

            db.commit()  # Commit esign creation + status update

        return json_success(updated)
    finally:
        db.close()


@referencing_bp.route("/forms/<int:form_id>/guarantor-toggle", methods=["POST"])
@require_team_auth
@require_csrf
def api_toggle_guarantor(form_id):
    """Toggle whether a guarantor is required for this applicant."""
    data = request.get_json() or {}
    required = data.get("guarantor_required", True)
    db = get_dict_db()
    try:
        db.execute(
            "UPDATE referencing_forms SET has_guarantor = ?, modified = datetime('now') WHERE id = ?",
            [1 if required else 0, form_id]
        )
        db.commit()
        updated = db.execute("SELECT * FROM referencing_forms WHERE id = ?", [form_id]).fetchone()
        return json_success(updated)
    finally:
        db.close()


# ────────────────────────────────────────────
# SECTION 2: DOCUMENT UPLOAD & AI ANALYSIS
# ────────────────────────────────────────────

@referencing_bp.route("/documents/upload", methods=["POST"])
def api_upload_document():
    """Upload a document for a referencing form. Supports token or team auth."""
    form_id = request.form.get("form_id", type=int)
    category = request.form.get("category", "other")
    token = request.form.get("token", "") or request.args.get("token", "")
    is_team = "user" in flask_session

    if not form_id:
        return json_error("form_id is required")

    MAX_UPLOAD_SIZE = 20 * 1024 * 1024  # 20MB
    ALLOWED_EXTENSIONS = {'.pdf', '.jpg', '.jpeg', '.png', '.doc', '.docx', '.txt', '.rtf', '.csv', '.xls', '.xlsx'}
    if request.content_length and request.content_length > MAX_UPLOAD_SIZE:
        return json_error("File too large. Maximum size is 20MB.", 413)
    if "file" not in request.files:
        return json_error("No file uploaded")

    file = request.files["file"]
    if file.filename == "":
        return json_error("No file selected")
    ext = os.path.splitext(file.filename)[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        return json_error(f"File type '{ext}' is not allowed", 400)

    db = get_dict_db()
    try:
        form = db.execute("SELECT * FROM referencing_forms WHERE id = ?", [form_id]).fetchone()
        if not form:
            return json_error("Form not found", 404)

        if not is_team and form["form_token"] != token:
            return json_error("Not authorised", 401)

        # Save file
        orig_filename = secure_filename(file.filename)
        ext = orig_filename.rsplit(".", 1)[-1] if "." in orig_filename else "bin"
        stored_name = f"{uuid.uuid4().hex}.{ext}"
        file_path = os.path.join(UPLOAD_DIR, stored_name)
        file.save(file_path)

        file_size = os.path.getsize(file_path)
        mime_type = file.content_type or "application/octet-stream"

        # Determine uploaded_by
        uploaded_by = "team" if is_team else "applicant"

        db.execute(
            """INSERT INTO referencing_documents (form_id, category, original_filename, stored_filename, file_path, file_size, mime_type, uploaded_by)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            [form_id, category, orig_filename, stored_name, file_path, file_size, mime_type, uploaded_by]
        )
        doc_id = db.execute("SELECT last_insert_rowid()").fetchone()["last_insert_rowid()"]
        db.commit()

        doc = db.execute("SELECT * FROM referencing_documents WHERE id = ?", [doc_id]).fetchone()

        # Trigger initial AI analysis (async in background)
        # For now we mark for review
        return json_success(doc)
    except Exception as e:
        db.rollback()
        return json_error(safe_error(e), 500)
    finally:
        db.close()


@referencing_bp.route("/documents/<int:doc_id>", methods=["GET"])
def api_get_document(doc_id):
    """Get document metadata or download file.
    Requires team auth (dashboard session) for download. Metadata is public
    enough — just a filename and category — but the actual file content is
    gated behind the team session."""
    db = get_dict_db()
    try:
        doc = db.execute("SELECT * FROM referencing_documents WHERE id = ?", [doc_id]).fetchone()
        if not doc:
            return json_error("Document not found", 404)

        dl = request.args.get("download", "").lower() in ("1", "true", "yes")
        if dl:
            if "user" not in flask_session:
                return json_error("Not authenticated", 401)
            return send_file(doc["file_path"], as_attachment=True, download_name=doc["original_filename"])

        return json_success(doc)
    finally:
        db.close()


@referencing_bp.route("/documents/<int:doc_id>/preview", methods=["GET"])
def api_preview_document(doc_id):
    """View a referencing document inline in the browser.
    Requires team auth. Serves the file without Content-Disposition: attachment
    so the browser displays it natively (PDF, image, etc.)."""
    if "user" not in flask_session:
        return json_error("Not authenticated", 401)
    db = get_dict_db()
    try:
        doc = db.execute("SELECT * FROM referencing_documents WHERE id = ?", [doc_id]).fetchone()
        if not doc:
            return json_error("Document not found", 404)
        from mimetypes import guess_type
        mime = doc.get("mime_type") or guess_type(doc["original_filename"])[0] or "application/octet-stream"
        return send_file(doc["file_path"], mimetype=mime, as_attachment=False, download_name=doc["original_filename"])
    finally:
        db.close()


@referencing_bp.route("/documents/<int:doc_id>/verify", methods=["POST"])
@require_team_auth
@require_csrf
def api_verify_document(doc_id):
    """Team marks a document as verified."""
    data = request.get_json() or {}
    is_verified = data.get("is_verified", True)
    notes = data.get("notes", "")

    db = get_dict_db()
    try:
        db.execute(
            "UPDATE referencing_documents SET is_verified = ?, verified_by = ?, verified_at = datetime('now'), verification_notes = ? WHERE id = ?",
            [1 if is_verified else 0, _current_username(), notes, doc_id]
        )
        db.commit()
        doc = db.execute("SELECT * FROM referencing_documents WHERE id = ?", [doc_id]).fetchone()
        return json_success(doc)
    finally:
        db.close()


@referencing_bp.route("/documents/<int:doc_id>/ai-review", methods=["POST"])
@require_team_auth
@require_csrf
def api_ai_review_document(doc_id):
    """Trigger Neo's AI analysis on a single document."""
    db = get_dict_db()
    try:
        doc = db.execute("SELECT * FROM referencing_documents WHERE id = ?", [doc_id]).fetchone()
        if not doc:
            return json_error("Document not found", 404)

        # Run AI analysis (with form context for name matching)
        form = db.execute("SELECT * FROM referencing_forms WHERE id = ?", [doc["form_id"]]).fetchone()
        analysis = run_document_analysis(doc, form)

        db.execute(
            """UPDATE referencing_documents SET ai_analysis = ?, ai_verified = ?, ai_confidence = ?, 
               ai_flagged = ?, ai_flag_reason = ? WHERE id = ?""",
            [json.dumps(analysis), 1 if analysis.get("verified") else 0,
             analysis.get("confidence", 0), 1 if analysis.get("flagged") else 0,
             analysis.get("flag_reason", ""), doc_id]
        )
        db.commit()

        doc = db.execute("SELECT * FROM referencing_documents WHERE id = ?", [doc_id]).fetchone()
        return json_success(doc)
    except Exception as e:
        db.rollback()
        return json_error(safe_error(e), 500)
    finally:
        db.close()


@referencing_bp.route("/forms/<int:form_id>/ai-review", methods=["POST"])
@require_team_auth
@require_csrf
def api_ai_review_form(form_id):
    """Run full AI review on all documents in a form — Neo checks everything."""
    db = get_dict_db()
    try:
        form = db.execute("SELECT * FROM referencing_forms WHERE id = ?", [form_id]).fetchone()
        if not form:
            return json_error("Form not found", 404)

        documents = db.execute(
            "SELECT * FROM referencing_documents WHERE form_id = ?",
            [form_id]
        ).fetchall()

        results = []
        analyses = {}
        for doc in documents:
            analysis = run_document_analysis(doc, form)
            analyses[doc["id"]] = analysis
            db.execute(
                "UPDATE referencing_documents SET ai_analysis = ?, ai_verified = ?, ai_confidence = ?, ai_flagged = ?, ai_flag_reason = ? WHERE id = ?",
                [json.dumps(analysis), 1 if analysis.get("verified") else 0,
                 analysis.get("confidence", 0), 1 if analysis.get("flagged") else 0,
                 analysis.get("flag_reason", ""), doc["id"]]
            )
            results.append({"doc_id": doc["id"], "filename": doc["original_filename"], "analysis": analysis})

        # Run cross-referencing checks (uses the extracted figures from the analyses above)
        checks = run_cross_referencing_checks(form, documents, analyses)
        for check in checks:
            db.execute(
                "INSERT INTO referencing_checks (form_id, check_type, status, details, confidence, summary) VALUES (?, ?, ?, ?, ?, ?)",
                [form_id, check["type"], check["status"], json.dumps(check.get("details", {})),
                 check.get("confidence", 0), check.get("summary", "")]
            )

        db.commit()

        return json_success({
            "documents_analysed": results,
            "checks": checks
        })
    except Exception as e:
        db.rollback()
        return json_error(safe_error(e), 500)
    finally:
        db.close()


# ── Document content extraction & analysis helpers ──

_MONEY_RE = re.compile(r'£\s?([0-9][0-9,]*(?:\.[0-9]{2})?)')
_SORT_RE = re.compile(r'\b(\d{2}[- ]?\d{2}[- ]?\d{2})\b')
_ACCNO_RE = re.compile(r'\b(\d{8})\b')

# Marker words that identify a document's real type from its text content
_TYPE_MARKERS = {
    "payslip": ["gross pay", "net pay", "paye", "tax period", "ni number", "earnings", "payslip", "deductions"],
    "bank_statement": ["statement period", "balance brought", "balance carried", "sort code", "account number", "opening balance", "closing balance"],
    "passport": ["passport", "p<gbr", "type/type", "surname", "nationality"],
    "driving_licence": ["driving licence", "driver number", "dvla"],
    "contract": ["employment", "salary", "employer", "terms", "hereby agree"],
}


def _money_values(text):
    out = []
    for m in _MONEY_RE.finditer(text or ""):
        try:
            out.append(float(m.group(1).replace(",", "")))
        except Exception:
            pass
    return out


def extract_document_text(doc):
    """Extract text from an uploaded document.
    PDF → embedded text layer (fitz). Scanned PDF / image → vision OCR if available.
    Returns (text, method). Never raises."""
    path = doc.get("file_path")
    if not path or not os.path.exists(path):
        return "", "missing_file"
    ext = os.path.splitext(path)[1].lower()
    try:
        if ext == ".pdf":
            d = fitz.open(path)
            text = "\n".join(p.get_text() for p in d)
            d.close()
            if len(text.strip()) < 20:
                return _vision_ocr(path), "vision_ocr"
            return text, "pdf_text"
        if ext in (".jpg", ".jpeg", ".png", ".webp"):
            return _vision_ocr(path), "vision"
        return "", "unsupported_type"
    except Exception as e:
        return "", f"extract_error:{e}"


def _vision_ocr(path):
    """Best-effort OCR via the shared vision tool (OpenRouter). Returns '' on any failure."""
    try:
        import subprocess
        tool = "/root/.hermes/tools/vision_analyze.py"
        if not os.path.exists(tool):
            return ""
        out = subprocess.run(
            ["python3", tool, path, "Extract all text verbatim from this document."],
            capture_output=True, text=True, timeout=90
        )
        return (out.stdout or "").strip()
    except Exception:
        return ""


def run_document_analysis(doc, form=None):
    """Analyse a single referencing document: extract its text, confirm the applicant's
    name appears, pull key figures, confirm the document type matches its category,
    and flag anything suspicious. Returns a structured analysis dict."""
    cat = (doc.get("category") or "other").lower()
    fname = doc.get("original_filename", "")
    analysis = {
        "verified": False,
        "confidence": 0.5,
        "flagged": False,
        "flag_reason": "",
        "checks_performed": ["file_safety", "text_extraction", "name_match", "type_match", "figures"],
        "findings": {
            "category": cat,
            "filename": fname,
            "size_kb": round((doc.get("file_size", 0) or 0) / 1024, 1),
            "uploaded_by": doc.get("uploaded_by", ""),
        },
        "extracted": {},
        "summary": "",
    }

    # 1. File safety
    suspicious = {'.exe', '.scr', '.bat', '.cmd', '.vbs', '.ps1', '.js', '.jar'}
    ext = os.path.splitext(fname)[1].lower()
    if ext in suspicious:
        analysis.update(flagged=True, verified=False, confidence=0.0,
                        flag_reason=f"Suspicious file type: {ext}")
        analysis["summary"] = "Rejected — unsafe file type."
        return analysis
    if (doc.get("file_size", 0) or 0) == 0:
        analysis.update(flagged=True, verified=False, confidence=0.0, flag_reason="Empty file")
        analysis["summary"] = "Rejected — empty file."
        return analysis
    if (doc.get("file_size", 0) or 0) > 50 * 1024 * 1024:
        analysis.update(flagged=True, verified=False, confidence=0.3, flag_reason="File exceeds 50MB")

    # 2. Extract text
    text, method = extract_document_text(doc)
    analysis["findings"]["extract_method"] = method
    low = (text or "").lower()
    analysis["extracted"]["char_count"] = len(text or "")

    if not text:
        analysis.update(verified=False, confidence=0.3, flagged=True,
                        flag_reason=f"Could not read document content ({method})")
        analysis["summary"] = "Needs manual review — content could not be read automatically."
        return analysis

    # 3. Name match against the form
    name_hit = None
    if form:
        for part in [form.get("first_name"), form.get("last_name")]:
            if part and len(part) > 1 and part.lower() in low:
                name_hit = True if name_hit is None else name_hit
            elif part:
                name_hit = False if name_hit is None else (name_hit and False)
        analysis["extracted"]["applicant_name_found"] = bool(name_hit)
        if name_hit is False:
            analysis["flagged"] = True
            analysis["flag_reason"] = "Applicant name not clearly found in document"

    # 4. Type match — does the content look like what it claims to be?
    markers = _TYPE_MARKERS.get(cat, [])
    hits = [m for m in markers if m in low]
    type_ok = (not markers) or len(hits) >= 1
    analysis["extracted"]["type_markers_found"] = hits
    if markers and not type_ok:
        analysis["flagged"] = True
        analysis["flag_reason"] = f"Content does not look like a {cat.replace('_',' ')}"

    # 5. Figures
    monies = _money_values(text)
    if monies:
        analysis["extracted"]["amounts_gbp"] = sorted(set(monies), reverse=True)[:10]
        analysis["extracted"]["max_amount_gbp"] = max(monies)
    if cat == "bank_statement":
        sc = _SORT_RE.search(text)
        if sc:
            analysis["extracted"]["sort_code"] = sc.group(1)
        # ── Funds analysis: parse opening/closing balances and all transactions ──
        opening = re.search(r'(?:opening balance|balance brought|b/f|brought forward)\s*[:\s]*£?\s*([0-9,.]+)', low)
        closing = re.search(r'(?:closing balance|balance carried|c/f|carried forward)\s*[:\s]*£?\s*([0-9,.]+)', low)
        if opening:
            analysis["extracted"]["opening_balance"] = float(opening.group(1).replace(",",""))
        if closing:
            analysis["extracted"]["closing_balance"] = float(closing.group(1).replace(",",""))
        # Count credits (income) and debits (outgoings) as rough indicators
        credit_lines = re.findall(r'(?:credit|deposit|salary|wages|transfer in|paid in)\s*[:\s]*£?\s*([0-9,.]+)', low)
        debit_lines = re.findall(r'(?:debit|withdrawal|direct debit|standing order|transfer out|payment|card purchase)\s*[:\s]*£?\s*([0-9,.]+)', low)
        if credit_lines:
            analysis["extracted"]["total_credits"] = sum(float(c.replace(",","")) for c in credit_lines if c)
        if debit_lines:
            analysis["extracted"]["total_debits"] = sum(float(d.replace(",","")) for d in debit_lines if d)
        if analysis["extracted"].get("closing_balance") and form:
            monthly_rent = float(form.get("annual_salary") or 0) / 12 if form.get("annual_salary") else 0
            balance = analysis["extracted"]["closing_balance"]
            if monthly_rent > 0 and balance >= monthly_rent:
                analysis["extracted"]["funds_check"] = "sufficient"
            elif monthly_rent > 0:
                analysis["extracted"]["funds_check"] = "low_balance"
                analysis["flagged"] = True
                analysis["flag_reason"] = f"Closing balance (£{balance:,.0f}) is less than one month's rent (~£{monthly_rent:,.0f})"

    # 6. Verdict
    score = 0.5
    if analysis["extracted"].get("applicant_name_found"):
        score += 0.25
    if type_ok and markers:
        score += 0.2
    if monies:
        score += 0.05
    analysis["confidence"] = round(min(score, 0.95), 2)
    analysis["verified"] = (not analysis["flagged"]) and score >= 0.7

    bits = [f"{cat.replace('_',' ').title()} read via {method}."]
    if "applicant_name_found" in analysis["extracted"]:
        bits.append("Applicant name found." if analysis["extracted"]["applicant_name_found"] else "⚠ Applicant name NOT found.")
    if hits:
        bits.append(f"Type confirmed ({', '.join(hits[:3])}).")
    if monies:
        bits.append(f"Amounts detected up to £{max(monies):,.0f}.")
    analysis["summary"] = " ".join(bits)
    return analysis


def run_cross_referencing_checks(form, documents, analyses=None):
    """
    Cross-reference all documents against form data.
    Checks: name consistency, income vs payslips, address matches, right to rent validity.
    `analyses` is an optional {doc_id: analysis_dict} map from run_document_analysis,
    used to compare extracted figures (payslip pay vs bank credits vs declared salary).
    Returns a list of check results.
    """
    analyses = analyses or {}
    checks = []

    # 1. Identity check: do names across documents match the form?
    identity_check = {
        "type": "identity_check",
        "status": "pending",
        "confidence": 0.5,
        "details": {
            "form_name": f"{form.get('first_name', '')} {form.get('last_name', '')}",
            "documents_checked": [d["original_filename"] for d in documents if d["category"] in ("passport", "visa", "driving_licence")],
        },
        "summary": "Identity check pending — documents require manual review"
    }
    checks.append(identity_check)

    # 2. Income check: match declared salary vs figures extracted from payslips/bank statements
    payslips = [d for d in documents if d["category"] == "payslip"]
    statements = [d for d in documents if d["category"] == "bank_statement"]
    try:
        declared_annual = float(str(form.get("annual_salary") or "0").replace(",", "").replace("£", "") or 0)
    except Exception:
        declared_annual = 0.0
    expected_monthly_net = round((declared_annual * 0.75) / 12, 2) if declared_annual else 0  # rough take-home

    # Largest monthly figure seen on payslips (proxy for gross/net monthly pay)
    payslip_amounts = []
    for d in payslips:
        payslip_amounts += (analyses.get(d["id"], {}).get("extracted", {}).get("amounts_gbp") or [])
    top_payslip = max(payslip_amounts) if payslip_amounts else None

    income_status, income_summary, income_conf = "pending", "", 0.5
    if declared_annual and top_payslip:
        implied_annual = top_payslip * 12
        ratio = implied_annual / declared_annual if declared_annual else 0
        if 0.7 <= ratio <= 1.4:
            income_status, income_conf = "passed", 0.85
            income_summary = f"Payslip figures (~£{top_payslip:,.0f}/mo) are consistent with declared £{declared_annual:,.0f}/yr."
        else:
            income_status, income_conf = "flagged", 0.4
            income_summary = f"⚠ Payslip (~£{top_payslip:,.0f}/mo → ~£{implied_annual:,.0f}/yr) does not match declared £{declared_annual:,.0f}/yr."
    elif not payslips:
        income_status = "flagged"
        income_summary = "No payslips uploaded — cannot verify income."
    else:
        income_summary = "Payslips present but figures not auto-read — needs manual review."

    income_check = {
        "type": "income_check",
        "status": income_status,
        "confidence": income_conf,
        "details": {
            "declared_annual_salary": declared_annual,
            "expected_monthly_net_estimate": expected_monthly_net,
            "top_payslip_amount": top_payslip,
            "payslips_count": len(payslips),
            "bank_statements_count": len(statements),
        },
        "summary": income_summary or "Income check pending — review payslips against stated salary"
    }
    checks.append(income_check)

    # ── 2b. Payslip-to-bank-statement matching ──
    if top_payslip and statements:
        # Look for a credit roughly matching the payslip net pay in any bank statement
        bank_amounts = []
        for d in statements:
            bank_amounts += (analyses.get(d["id"], {}).get("extracted", {}).get("amounts_gbp") or [])
        matching_deposits = [a for a in bank_amounts if abs(a - top_payslip) / top_payslip < 0.15] if top_payslip else []
        deposit_match_check = {
            "type": "deposit_match_check",
            "status": "passed" if matching_deposits else ("flagged" if bank_amounts else "pending"),
            "confidence": 0.85 if matching_deposits else (0.3 if bank_amounts else 0.5),
            "details": {
                "payslip_net_amount": top_payslip,
                "matching_deposits_found": len(matching_deposits),
                "matching_deposit_amounts": [round(m, 2) for m in matching_deposits],
            },
            "summary": (
                f"Payslip net pay (~£{top_payslip:,.0f}) matches deposits on bank statements."
                if matching_deposits else
                "⚠ Payslip amount not clearly matched to bank statement deposits — manual review recommended."
            )
        }
        checks.append(deposit_match_check)

    # 3. Right to rent check
    rtr_check = {
        "type": "right_to_rent",
        "status": "pending",
        "confidence": 0.5,
        "details": {
            "has_share_code": bool(form.get("share_code")),
            "has_passport": any(d["category"] == "passport" for d in documents),
            "has_visa": any(d["category"] == "visa" for d in documents),
            "nationality": form.get("nationality", ""),
        },
        "summary": "Right to rent check pending — verify documents and share code"
    }
    checks.append(rtr_check)

    # 4. Guarantor check
    if form.get("has_guarantor"):
        guarantor_check = {
            "type": "guarantor_check",
            "status": "pending",
            "confidence": 0.5,
            "details": {
                "guarantor_name": f"{form.get('guarantor_first_name', '')} {form.get('guarantor_last_name', '')}",
                "guarantor_income": form.get("guarantor_annual_income"),
                "has_guarantor_id": any(d["category"] == "guarantor_id" for d in documents),
            },
            "summary": "Guarantor check pending — review guarantor documents and income"
        }
        checks.append(guarantor_check)

    return checks


# ────────────────────────────────────────────
# SECTION 3: E-SIGNATURE ENGINE
# ────────────────────────────────────────────

@referencing_bp.route("/esignature/create", methods=["POST"])
@require_team_auth
@require_csrf
def api_create_esignature():
    """Create a new e-signature request with two-sided signing support.

    Two-sided flow:
      1. This endpoint creates the request with TWO tokens (signer + team countersign)
      2. Email goes to tenant first with their signing link
      3. After tenant signs, team can countersign via /esignature/team-sign/<token>
      4. Merged PDF includes both signatures with audit trail

    Accepts template_id + layout_data for generating via template editor.
    """
    data = request.get_json() or {}
    form_id = data.get("form_id")
    tenancy_id = data.get("tenancy_id")
    document_type = data.get("document_type", "tenancy_agreement")
    document_title = data.get("document_title", "Tenancy Agreement")
    signer_name = data.get("signer_name", "").strip()
    signer_email = data.get("signer_email", "").strip()
    template_id = data.get("template_id")
    layout_data = data.get("layout_data")

    # Team countersign details
    team_name = data.get("team_name", "").strip()
    team_email = data.get("team_email", "").strip()
    is_two_sided = bool(team_name and team_email)

    if not signer_name or not signer_email:
        return json_error("Signer name and email are required")

    # Generate tokens
    signer_token = generate_token()
    team_token = generate_token() if is_two_sided else None
    expires_at = (datetime.now(timezone.utc) + timedelta(days=14)).isoformat()

    db = get_dict_db()
    try:
        db.execute(
            """INSERT INTO esignature_requests
               (form_id, tenancy_id, document_type, document_title, status,
                created_for, created_for_email, signer_token, expires_at, created_by,
                template_id, layout_data, team_signer_name, team_signer_email, team_token)
            VALUES (?, ?, ?, ?, 'draft', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            [form_id, tenancy_id, document_type, document_title,
             signer_name, signer_email, signer_token, expires_at, _current_username(),
             template_id, json.dumps(layout_data) if layout_data else None,
             team_name if is_two_sided else None,
             team_email if is_two_sided else None,
             team_token]
        )
        req_id = db.execute("SELECT last_insert_rowid() AS rid").fetchone()["rid"]

        # Log audit entry
        created_detail = f"Created by {_current_username()} for {signer_name}"
        if is_two_sided:
            created_detail += f" with team countersign for {team_name}"
        db.execute(
            "INSERT INTO esignature_audit_log (request_id, event_type, event_detail, ip_address, user_agent) VALUES (?, 'created', ?, ?, ?)",
            [req_id, created_detail, request.remote_addr or '', request.headers.get("User-Agent", "")]
        )

        delivery = None
        if data.get("send"):
            req_row = db.execute("SELECT * FROM esignature_requests WHERE id = ?", [req_id]).fetchone()
            ok, delivery = _deliver_esignature(db, req_row, actual_send=True)
            if not ok:
                db.commit()
                request_data = db.execute("SELECT * FROM esignature_requests WHERE id = ?", [req_id]).fetchone()
                return json_success(request_data, delivery=delivery, warning="Request created as draft but email delivery failed")

        db.commit()

        request_data = db.execute("SELECT * FROM esignature_requests WHERE id = ?", [req_id]).fetchone()
        return json_success(request_data, delivery=delivery)
    except Exception as e:
        db.rollback()
        return json_error(safe_error(e), 500)
    finally:
        db.close()


def _deliver_esignature(db, req, actual_send=True):
    """Email the signing link to the signer, mark sent, and log the audit trail.

    Returns (ok, detail). Caller owns the transaction (commit/rollback).
    """
    sign_url = f"{PUBLIC_BASE_URL}/sign/{req['signer_token']}"
    body = _email_shell(
        title="Document ready for signature",
        intro=(
            f"Hi {req['created_for']},<br><br>"
            f"You have a document to review and sign: <strong>{req['document_title']}</strong>. "
            "It only takes a minute — click below to view and sign securely."
        ),
        button_label="Review &amp; Sign",
        button_url=sign_url,
        footer="This link is unique to you and expires in 14 days.",
    )
    ok, detail = send_email(
        req["created_for_email"], req["created_for"],
        f"Please sign: {req['document_title']}", body, send=actual_send,
    )
    if ok:
        db.execute(
            "UPDATE esignature_requests SET status = 'sent', sent_at = datetime('now') WHERE id = ?",
            [req["id"]],
        )
        db.execute(
            "INSERT INTO esignature_audit_log (request_id, event_type, event_detail, ip_address, user_agent) VALUES (?, 'emailed', ?, ?, ?)",
            [req["id"], f"Signing link emailed to {req['created_for_email']} ({detail})", request.remote_addr or '', request.headers.get("User-Agent", "")],
        )
    return ok, detail


@referencing_bp.route("/esignature/<int:req_id>/send", methods=["POST"])
@require_team_auth
@require_csrf
def api_send_esignature(req_id):
    """Email the signing link to the signer and mark the request sent."""
    db = get_dict_db()
    try:
        req = db.execute("SELECT * FROM esignature_requests WHERE id = ?", [req_id]).fetchone()
        if not req:
            return json_error("Request not found", 404)
        if req["status"] in ("completed", "signed"):
            return json_error("This document has already been signed", 400)

        ok, detail = _deliver_esignature(db, req, actual_send=True)
        if not ok:
            db.rollback()
            return json_error(f"Could not send signing email — {detail}", 502)
        db.commit()

        updated = db.execute("SELECT * FROM esignature_requests WHERE id = ?", [req_id]).fetchone()
        return json_success(updated, delivery=detail)
    finally:
        db.close()


@referencing_bp.route("/esignature/sign/<token>", methods=["GET"])
def api_esignature_view(token):
    """View an e-signature request (signer clicks link)."""
    db = get_dict_db()
    try:
        req = db.execute("SELECT * FROM esignature_requests WHERE signer_token = ?", [token]).fetchone()
        if not req:
            return json_error("Invalid or expired signing link", 404)

        if req["status"] not in ("sent", "viewed"):
            return json_error("This signing request has already been completed", 400)

        # Log view event if first time
        if req["status"] == "sent":
            db.execute(
                "UPDATE esignature_requests SET status = 'viewed', viewed_at = datetime('now') WHERE id = ?",
                [req["id"]]
            )
            db.execute(
                "INSERT INTO esignature_audit_log (request_id, event_type, event_detail, ip_address, user_agent) VALUES (?, 'viewed', ?, ?, ?)",
                [req["id"], "Signer viewed the document", request.remote_addr or '', request.headers.get("User-Agent", "")]
            )
            db.commit()
            # Re-fetch so the response reflects the new 'viewed' status
            req = db.execute("SELECT * FROM esignature_requests WHERE signer_token = ?", [token]).fetchone()

        return json_success(req)
    finally:
        db.close()


@referencing_bp.route("/esignature/sign/<token>", methods=["POST"])
def api_esignature_sign(token):
    """Signer completes the signature."""
    ip = request.remote_addr or "unknown"
    if not _check_rate_limit(f"esign_sign:{ip}", max_attempts=10, window=60):
        return json_error("Too many requests. Please try again later.", 429)
    data = request.get_json() or {}
    consent = data.get("consent", False)
    signature_data = data.get("signature", "")  # Could be base64 drawn sig or typed name

    if not consent:
        return json_error("You must consent to electronic signing")

    if not signature_data:
        return json_error("Signature is required")

    db = get_dict_db()
    try:
        req = db.execute("SELECT * FROM esignature_requests WHERE signer_token = ?", [token]).fetchone()
        if not req:
            return json_error("Invalid signing link", 404)

        if req["status"] in ("completed", "signed"):
            return json_error("Already signed", 400)

        # Pull the full audit trail so it can be stamped into the certificate
        audit_rows = db.execute(
            "SELECT * FROM esignature_audit_log WHERE request_id = ? ORDER BY occurred_at ASC",
            [req["id"]]
        ).fetchall()

        # Generate a genuine, tamper-evident signed PDF certificate
        signed_filename = f"signed_{uuid.uuid4().hex}.pdf"
        signed_path = os.path.join(SIGNED_DIR, signed_filename)
        try:
            signed_path = generate_signed_pdf(
                signed_path, req, signature_data,
                request.remote_addr or '', request.headers.get("User-Agent", ""),
                audit_rows
            )
        except Exception as pdf_err:
            # Never lose the signature if PDF generation hiccups — fall back to a text record
            with open(signed_path, 'w') as f:
                f.write("ELECTRONIC SIGNATURE RECORD (fallback)\n")
                f.write(f"Document: {req['document_title']}\nSigner: {req['created_for']}\n")
                f.write(f"Signed At: {datetime.now(timezone.utc).isoformat()}\nError: {pdf_err}\n")

        # Two-sided signing: applicant signs first, then team countersigns
        has_team = bool(req.get("team_token"))
        new_status = "applicant_signed" if has_team else "completed"

        db.execute(
            """UPDATE esignature_requests SET status = ?, signed_at = datetime('now'),
               ip_address = ?, user_agent = ?, pdf_signed_path = ? WHERE id = ?""",
            [new_status, request.remote_addr or '', request.headers.get("User-Agent", ""), signed_path, req["id"]]
        )

        db.execute(
            "INSERT INTO esignature_audit_log (request_id, event_type, event_detail, ip_address, user_agent) VALUES (?, 'signed', ?, ?, ?)",
            [req["id"], f"Signed by {req['created_for']} ({req['created_for_email']})", request.remote_addr or '', request.headers.get("User-Agent", "")]
        )

        if has_team:
            db.execute(
                "INSERT INTO esignature_audit_log (request_id, event_type, event_detail) VALUES (?, 'awaiting_countersign', ?)",
                [req["id"], f"Awaiting countersignature from {req['team_signer_name']}"]
            )
            resp = {"status": "applicant_signed", "message": "Signed successfully. Awaiting team countersignature.", "requires_countersign": True}
        else:
            db.execute(
                "INSERT INTO esignature_audit_log (request_id, event_type, event_detail) VALUES (?, 'completed', ?)",
                [req["id"], "E-signature process completed"]
            )
            resp = {"status": "completed", "message": "Document signed successfully."}

        db.commit()
        return json_success(resp)
    except Exception as e:
        db.rollback()
        return json_error(safe_error(e), 500)
    finally:
        db.close()


@referencing_bp.route("/esignature/team-sign/<token>", methods=["GET"])
def api_esignature_team_view(token):
    """View team countersign request."""
    db = get_dict_db()
    try:
        req = db.execute("SELECT * FROM esignature_requests WHERE team_token = ?", [token]).fetchone()
        if not req:
            return json_error("Invalid or expired countersign link", 404)
        if req["status"] != "applicant_signed":
            return json_error("Applicant has not signed yet or signing is already complete", 400)
        return json_success(req)
    finally:
        db.close()


@referencing_bp.route("/esignature/team-sign/<token>", methods=["POST"])
def api_esignature_team_sign(token):
    """Team member countersigns after applicant has signed."""
    data = request.get_json() or {}
    consent = data.get("consent", False)
    signature_data = data.get("signature", "")

    if not consent:
        return json_error("You must consent to electronic signing")
    if not signature_data:
        return json_error("Signature is required")

    db = get_dict_db()
    try:
        req = db.execute("SELECT * FROM esignature_requests WHERE team_token = ?", [token]).fetchone()
        if not req:
            return json_error("Invalid countersign link", 404)
        if req["status"] != "applicant_signed":
            return json_error("Applicant has not signed yet or countersign already completed", 400)

        signed_ts = datetime.now(timezone.utc).isoformat()

        # Generate merged PDF with both signatures
        if req.get("pdf_signed_path") and os.path.exists(req["pdf_signed_path"]):
            merged_filename = f"merged_{uuid.uuid4().hex}.pdf"
            merged_path = os.path.join(SIGNED_DIR, merged_filename)
            try:
                pdf_doc = fitz.open(req["pdf_signed_path"])
                page = pdf_doc[-1]  # Add to last page
                page_height = page.rect.height

                # Draw team signature overlay on a new page
                pdf_doc.new_page(width=595, height=842)
                new_page = pdf_doc[-1]

                NAVY = (0.117, 0.161, 0.231)
                GREY = (0.42, 0.45, 0.50)

                new_page.insert_text((40, 60), "TEAM COUNTERSIGNATURE", fontname="hebo", fontsize=14, color=NAVY)
                new_page.insert_text((40, 85), f"Countersigned by: {req.get('team_signer_name', 'Authorised Signatory')}", fontname="helv", fontsize=11, color=NAVY)
                new_page.insert_text((40, 105), f"Email: {req.get('team_signer_email', '')}", fontname="helv", fontsize=9, color=GREY)
                new_page.insert_text((40, 125), f"Countersigned at: {signed_ts}", fontname="helv", fontsize=9, color=GREY)
                new_page.insert_text((40, 145), f"IP: {request.remote_addr or ''}", fontname="helv", fontsize=9, color=GREY)

                # Signature block
                sig_rect = fitz.Rect(40, 170, 300, 260)
                new_page.draw_rect(sig_rect, color=(0.85, 0.87, 0.90), width=1)
                new_page.insert_text((48, 190), "Authorised Signatory", fontname="hebo", fontsize=9, color=GREY)

                embedded = False
                if isinstance(signature_data, str) and signature_data.startswith("data:image"):
                    try:
                        import base64 as b64mod
                        b64 = signature_data.split(",", 1)[1]
                        img = b64mod.b64decode(b64)
                        new_page.insert_image(fitz.Rect(48, 198, 292, 252), stream=img)
                        embedded = True
                    except:
                        pass
                if not embedded:
                    new_page.insert_text((55, 235), str(signature_data)[:40], fontname="heit", fontsize=26, color=NAVY)

                # Integrity hash
                integrity_src = f"{req.get('id')}|{req.get('document_title')}|countersign|{req.get('team_signer_name')}|{signed_ts}|{signature_data}"
                integrity_hash = hashlib.sha256(integrity_src.encode()).hexdigest()
                new_page.insert_text((40, 290), "COUNTERSIGN INTEGRITY HASH (SHA-256)", fontname="hebo", fontsize=9, color=GREY)
                for ci, chunk in enumerate([integrity_hash[i:i+64] for i in range(0, len(integrity_hash), 64)]):
                    new_page.insert_text((40, 308 + ci * 14), chunk, fontname="cour", fontsize=9, color=(0.388, 0.400, 0.945))

                pdf_doc.save(merged_path)
                pdf_doc.close()

                # Update DB
                db.execute(
                    """UPDATE esignature_requests SET status = 'completed',
                       team_signed_at = ?, team_ip_address = ?, team_user_agent = ?,
                       team_signature_data = ?, team_pdf_signed_path = ?, completed_at = ?
                       WHERE id = ?""",
                    [signed_ts, request.remote_addr or '', request.headers.get("User-Agent", ""),
                     signature_data, merged_path, signed_ts, req["id"]]
                )
                db.execute(
                    "INSERT INTO esignature_audit_log (request_id, event_type, event_detail, ip_address, user_agent) VALUES (?, 'countersigned', ?, ?, ?)",
                    [req["id"], f"Countersigned by {req.get('team_signer_name','Team')} ({req.get('team_signer_email','')})",
                     request.remote_addr or '', request.headers.get("User-Agent", "")]
                )
                db.execute(
                    "INSERT INTO esignature_audit_log (request_id, event_type, event_detail) VALUES (?, 'completed', ?)",
                    [req["id"], "Two-sided e-signature process completed"]
                )

                # ── Auto-create tenancy on full completion ──
                tenancy_created = False
                try:
                    form_id = req.get("form_id")
                    if form_id:
                        ref_form = db.execute(
                            "SELECT applicant_id, status FROM referencing_forms WHERE id = ?",
                            [form_id]
                        ).fetchone()
                        if ref_form and ref_form.get("applicant_id") and ref_form.get("status") == "approved":
                            app_id = ref_form["applicant_id"]
                            # Check if tenancy already exists
                            existing = db.execute(
                                "SELECT id FROM tenancies WHERE id IN (SELECT tenancy_id FROM tenants WHERE id IN "
                                "(SELECT id FROM applicants WHERE id = ?))",
                                [app_id]
                            ).fetchone()
                            if not existing:
                                # Import and call the tenancy creation from banksia_os blueprint
                                # We'll call the API internally via a direct function call
                                try:
                                    resp = _call_create_tenancy(app_id, db)
                                    if resp.get("success"):
                                        tenancy_created = True
                                except Exception:
                                    pass
                except Exception:
                    pass

                db.commit()
                resp_data = {"status": "completed", "message": "Document countersigned successfully. Both signatures recorded."}
                if tenancy_created:
                    resp_data["message"] += " Tenancy has been created automatically."
                    resp_data["tenancy_created"] = True
                return json_success(resp_data)
            except Exception as merge_err:
                return json_error(f"Failed to generate merged PDF: {str(merge_err)}", 500)

        return json_error("Applicant signed PDF not found", 500)
    except Exception as e:
        db.rollback()
        return json_error(safe_error(e), 500)
    finally:
        db.close()


@referencing_bp.route("/esignature/requests", methods=["GET"])
@require_team_auth
def api_list_esignature_requests():
    """List all e-signature requests."""
    page = int(request.args.get("page", 1))
    per_page = int(request.args.get("per_page", 20))
    status = request.args.get("status")
    search = request.args.get("search", "").strip()

    db = get_dict_db()
    try:
        where = "WHERE 1=1"
        params = []
        if status:
            where += " AND status = ?"
            params.append(status)
        if search:
            where += " AND (created_for LIKE ? OR created_for_email LIKE ? OR document_title LIKE ?)"
            s = f"%{search}%"
            params.extend([s, s, s])

        total = db.execute(f"SELECT COUNT(*) as cnt FROM esignature_requests {where}", params).fetchone()["cnt"]
        offset = (page - 1) * per_page
        rows = db.execute(
            f"SELECT * FROM esignature_requests {where} ORDER BY created DESC LIMIT ? OFFSET ?",
            params + [per_page, offset]
        ).fetchall()

        return json_success(rows, total=total, page=page, per_page=per_page)
    finally:
        db.close()


@referencing_bp.route("/esignature/<int:req_id>/audit", methods=["GET"])
@require_team_auth
def api_esignature_audit(req_id):
    """Get full audit trail for an e-signature request."""
    db = get_dict_db()
    try:
        req = db.execute("SELECT * FROM esignature_requests WHERE id = ?", [req_id]).fetchone()
        if not req:
            return json_error("Request not found", 404)

        audit_log = db.execute(
            "SELECT * FROM esignature_audit_log WHERE request_id = ? ORDER BY occurred_at ASC",
            [req_id]
        ).fetchall()

        return json_success({"request": req, "audit_log": audit_log})
    finally:
        db.close()


@referencing_bp.route("/esignature/<int:req_id>/download-signed", methods=["GET"])
def api_download_signed_pdf(req_id):
    """Download the signed PDF for an e-signature request.
    Can be accessed by team (dashboard session) or applicant (portal Bearer token)."""
    auth_header = request.headers.get("Authorization", "")
    is_portal = auth_header.startswith("Bearer ")
    is_team = "user" in flask_session
    if not is_portal and not is_team:
        return json_error("Not authenticated", 401)

    db = get_dict_db()
    try:
        req = db.execute("SELECT * FROM esignature_requests WHERE id = ?", [req_id]).fetchone()
        if not req:
            return json_error("Request not found", 404)
        # Portal users can only download their own documents
        if is_portal:
            token = auth_header[7:]
            pu = db.execute(
                "SELECT pu.email FROM portal_sessions ps JOIN portal_users pu ON ps.user_id = pu.id WHERE ps.session_token = ? AND datetime(ps.expires_at) > datetime('now')",
                [token]
            ).fetchone()
            if not pu or (pu.get("email") or "").lower() != (req.get("created_for_email") or "").lower():
                return json_error("Not authorised to download this document", 403)
        pdf_path = req.get("team_pdf_signed_path") or req.get("pdf_signed_path")
        if not pdf_path or not os.path.exists(pdf_path):
            return json_error("Signed PDF not found", 404)
        return send_file(pdf_path, as_attachment=True, download_name=f"signed_{req_id}_{req.get('document_title','document').replace(' ','_')}.pdf")
    finally:
        db.close()


@referencing_bp.route("/esignature/<int:req_id>/download-merged", methods=["GET"])
@require_team_auth
def api_download_merged_pdf(req_id):
    """Download the merged (both signatures) PDF for two-sided signing."""
    db = get_dict_db()
    try:
        req = db.execute("SELECT * FROM esignature_requests WHERE id = ?", [req_id]).fetchone()
        if not req:
            return json_error("Request not found", 404)
        pdf_path = req.get("team_pdf_signed_path")
        if not pdf_path or not os.path.exists(pdf_path):
            return json_error("Merged PDF not found. Has the team countersigned yet?", 404)
        return send_file(pdf_path, as_attachment=True, download_name=f"merged_{req_id}_{req.get('document_title','document').replace(' ','_')}.pdf")
    finally:
        db.close()


# ────────────────────────────────────────────
# SECTION 4: TENANT PORTAL AUTH
# ────────────────────────────────────────────

@referencing_bp.route("/portal/applicant-signup", methods=["POST"])
def api_applicant_signup():
    """Create a portal user AND a referencing form in one step."""
    ip = request.remote_addr or "unknown"
    if not _check_rate_limit(f"portal_signup:{ip}", max_attempts=5, window=300):
        return json_error("Too many signup attempts from this IP. Please try again later.", 429)
    data = request.get_json() or {}
    first_name = (data.get("first_name") or "").strip()
    last_name = (data.get("last_name") or "").strip()
    email = (data.get("email") or "").strip().lower()
    password = data.get("password", "")

    if not first_name or not last_name or not email:
        return json_error("First name, last name, and email are required")
    if not password or len(password) < 10:
        return json_error("Password must be at least 10 characters")
    if not re.search(r'[A-Z]', password):
        return json_error("Password must contain an uppercase letter")
    if not re.search(r'[a-z]', password):
        return json_error("Password must contain a lowercase letter")
    if not re.search(r'[0-9]', password):
        return json_error("Password must contain a digit")

    import secrets
    db = get_dict_db()
    try:
        # Check if portal user already exists
        existing = db.execute(
            "SELECT * FROM portal_users WHERE lower(email) = ?", [email]
        ).fetchone()
        if existing and existing["password_hash"]:
            return json_error("An account already exists for this email — please log in", 409)
        if existing and _find_ongoing_form(db, existing["id"]):
            return json_error(
                "An application is already in progress for this email. "
                "Cancel it first before starting a new one.", 409
            )

        now = datetime.now(timezone.utc).isoformat()
        form_token = secrets.token_urlsafe(32)
        deadline_at = (datetime.now(timezone.utc) + timedelta(hours=REFERENCING_DEADLINE_HOURS)).isoformat()

        # Create the referencing form
        cur = db.execute(
            "INSERT INTO referencing_forms (form_token, status, first_name, last_name, "
            "email, created, modified, deadline_at) "
            "VALUES (?, 'draft', ?, ?, ?, ?, ?, ?)",
            [form_token, first_name, last_name, email, now, now, deadline_at]
        )
        form_id = cur.lastrowid

        # Create applicants record (visible in the Applicants module)
        cur = db.execute(
            "INSERT INTO applicants (first_name, last_name, email, status, created, modified) "
            "VALUES (?, ?, ?, 'New', ?, ?)",
            [first_name, last_name, email, now, now]
        )
        applicant_id = cur.lastrowid

        # Link the referencing form to the applicant
        db.execute(
            "UPDATE referencing_forms SET applicant_id = ? WHERE id = ?",
            [applicant_id, form_id]
        )

        # Create or update portal user
        pw_hash = hash_password(password)
        form_ref = db.execute("SELECT * FROM referencing_forms WHERE id = ?", [form_id]).fetchone()

        if existing:
            db.execute(
                "UPDATE portal_users SET password_hash = ?, "
                "portal_type = 'applicant', is_active = 1, modified = datetime('now') WHERE id = ?",
                [pw_hash, existing["id"]],
            )
            user_id = existing["id"]
        else:
            db.execute(
                "INSERT INTO portal_users (email, password_hash, first_name, last_name, "
                "portal_type, is_active, email_verified, created, modified) "
                "VALUES (?, ?, ?, ?, 'applicant', 1, 1, datetime('now'), datetime('now'))",
                [email, pw_hash, first_name, last_name],
            )
            user_id = db.execute("SELECT last_insert_rowid() AS rid").fetchone()["rid"]

        # Link referencing form to the portal user — store user_id on the form
        db.execute(
            "UPDATE referencing_forms SET portal_user_id = ? WHERE id = ?",
            [user_id, form_id]
        )

        # Auto-login
        token = generate_token()
        expires_at = (datetime.now(timezone.utc) + PORTAL_SESSION_TTL).isoformat()
        db.execute(
            "INSERT INTO portal_sessions (user_id, session_token, ip_address, user_agent, expires_at, last_activity) VALUES (?, ?, ?, ?, ?, datetime('now'))",
            [user_id, token, request.remote_addr or '', request.headers.get("User-Agent", ""), expires_at],
        )
        db.execute(
            "UPDATE portal_users SET last_login_at = datetime('now'), last_login_ip = ? WHERE id = ?",
            [request.remote_addr or '', user_id],
        )
        db.commit()

        _audit_log(user_id, email, "signup", f"Portal account created for {first_name} {last_name}")

        return json_success({
            "token": token,
            "user": {
                "id": user_id, "email": email,
                "first_name": first_name, "last_name": last_name,
                "portal_type": "applicant",
            },
            "expires_at": expires_at,
            "form_id": form_id,
            "form_token": form_token,
        }), 201
    except Exception as e:
        db.rollback()
        return json_error(safe_error(e), 500)
    finally:
        db.close()


@referencing_bp.route("/portal/self-create-form", methods=["POST"])
@require_auth
def api_portal_self_create_form():
    """Create a blank referencing form linked to the logged-in portal user.

    One ongoing application per applicant — if they already have one in
    draft/submitted/under_review, they must cancel it before starting another.
    """
    pu = request.portal_user
    db = get_dict_db()
    try:
        existing = _find_ongoing_form(db, pu["pu_id"])
        if existing:
            return json_error(
                "You already have an application in progress. "
                "Cancel it first before starting a new one.", 409
            )

        form_token = generate_form_token()
        deadline_at = (datetime.now(timezone.utc) + timedelta(hours=REFERENCING_DEADLINE_HOURS)).isoformat()

        # Fields start genuinely blank — the applicant fills everything in from
        # scratch, including name/email, so progress/section-complete read 0.
        db.execute(
            """INSERT INTO referencing_forms (applicant_id, form_token, status, first_name, last_name, email, date_of_birth, portal_user_id, deadline_at)
            VALUES (NULL, ?, 'draft', '', '', '', NULL, ?, ?)""",
            [form_token, pu["pu_id"], deadline_at]
        )
        form_id = db.execute("SELECT last_insert_rowid() AS rid").fetchone()["rid"]

        sections = [
            'personal', 'contact', 'residential', 'employment', 'self_employed',
            'student', 'guarantor', 'housing_benefit', 'kin', 'bank', 'landlord', 'additional', 'declaration'
        ]
        for section in sections:
            db.execute(
                "INSERT INTO form_sections (form_id, section_key) VALUES (?, ?)",
                [form_id, section]
            )
        db.commit()
        return json_success({"form_id": form_id, "form_token": form_token})
    except Exception as e:
        db.rollback()
        return json_error(safe_error(e), 500)
    finally:
        db.close()


@referencing_bp.route("/portal/request-cancellation", methods=["POST"])
@require_auth
def api_portal_request_cancellation():
    """Applicant cancels their in-progress application immediately — no management approval needed.

    Cancelling removes the application entirely (form_sections cascade-delete
    with it) rather than leaving a 'cancelled' row behind on the portal.
    """
    pu = request.portal_user
    db = get_dict_db()
    try:
        form = _find_ongoing_form(db, pu["pu_id"])
        if not form:
            return json_error("You don't have an application in progress to cancel.", 404)

        db.execute("DELETE FROM referencing_forms WHERE id = ?", [form["id"]])
        db.commit()
        return json_success({
            "form_id": form["id"],
            "status": "cancelled",
            "message": "Application cancelled. You can start a new one now."
        })
    except Exception as e:
        db.rollback()
        return json_error(safe_error(e), 500)
    finally:
        db.close()


@referencing_bp.route("/portal/self-register", methods=["POST"])
def api_portal_self_register():
    """Register a portal account with just name, email, and password.
    
    No form token required — this is for direct portal sign-ups.
    Sends a confirmation email on success.
    """
    ip = request.remote_addr or "unknown"
    if not _check_rate_limit(f"portal_self_register:{ip}", max_attempts=5, window=300):
        return json_error("Too many registration attempts from this IP. Please try again later.", 429)

    data = request.get_json() or {}
    first_name = (data.get("first_name") or "").strip()
    last_name = (data.get("last_name") or "").strip()
    email = (data.get("email") or "").strip().lower()
    password = data.get("password", "")

    if not first_name or not last_name:
        return json_error("First and last name are required")
    if not email or "@" not in email:
        return json_error("A valid email address is required")
    if not password or len(password) < 10:
        return json_error("Password must be at least 10 characters")
    if not re.search(r'[A-Z]', password):
        return json_error("Password must contain an uppercase letter")
    if not re.search(r'[a-z]', password):
        return json_error("Password must contain a lowercase letter")
    if not re.search(r'[0-9]', password):
        return json_error("Password must contain a digit")

    db = get_dict_db()
    try:
        existing = db.execute(
            "SELECT * FROM portal_users WHERE lower(email) = ?", [email]
        ).fetchone()
        if existing:
            return json_error("An account with this email already exists — please log in", 409)

        pw_hash = hash_password(password)
        db.execute(
            "INSERT INTO portal_users (email, password_hash, first_name, last_name, "
            "portal_type, is_active, email_verified, created, modified) "
            "VALUES (?, ?, ?, ?, 'applicant', 1, 1, datetime('now'), datetime('now'))",
            [email, pw_hash, first_name, last_name],
        )
        user_id = db.execute("SELECT last_insert_rowid() AS rid").fetchone()["rid"]

        # Auto-login
        token = generate_token()
        expires_at = (datetime.now(timezone.utc) + PORTAL_SESSION_TTL).isoformat()
        db.execute(
            "INSERT INTO portal_sessions (user_id, session_token, ip_address, user_agent, expires_at, last_activity) VALUES (?, ?, ?, ?, ?, datetime('now'))",
            [user_id, token, request.remote_addr or '', request.headers.get("User-Agent", ""), expires_at],
        )
        db.execute(
            "UPDATE portal_users SET last_login_at = datetime('now'), last_login_ip = ? WHERE id = ?",
            [request.remote_addr or '', user_id],
        )
        db.commit()

        _audit_log(user_id, email, "self_register", "Portal account registered via self-signup")

        # Send confirmation email
        try:
            confirm_url = f"{PUBLIC_BASE_URL}/portal"
            body = _email_shell(
                title="Welcome to your portal",
                intro=(
                    f"Hi {first_name},<br><br>"
                    "Your portal account has been created successfully. "
                    "From your portal you can track referencing applications, "
                    "sign documents, view your tenancy, report maintenance, "
                    "and message your lettings team."
                ),
                button_label="Go to my portal",
                button_url=confirm_url,
                footer="If you didn't create this account, please contact us immediately.",
            )
            send_email(email, f"{first_name} {last_name}",
                       "Welcome to Banksia — your portal is ready", body, send=True)
        except Exception:
            pass  # Never block registration on an email hiccup

        return json_success({
            "token": token,
            "user": {
                "id": user_id,
                "email": email,
                "first_name": first_name,
                "last_name": last_name,
                "portal_type": "applicant",
            },
            "expires_at": expires_at,
        })
    except Exception as e:
        db.rollback()
        return json_error(safe_error(e), 500)
    finally:
        db.close()


@referencing_bp.route("/portal/register", methods=["POST"])
def api_portal_register():
    """Register (or set the password for) a portal account.

    Gated by a valid referencing form token — only the applicant who owns the
    token can create the account, and the email must match the form on file.
    Auto-logs the applicant in on success.
    """
    ip = request.remote_addr or "unknown"
    if not _check_rate_limit(f"portal_register:{ip}", max_attempts=5, window=300):
        return json_error("Too many registration attempts from this IP. Please try again later.", 429)
    data = request.get_json() or {}
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")
    form_token = data.get("form_token", "").strip()

    if not form_token:
        return json_error("A valid form link is required to register")
    if not password or len(password) < 10:
        return json_error("Password must be at least 10 characters")
    if not re.search(r'[A-Z]', password):
        return json_error("Password must contain an uppercase letter")
    if not re.search(r'[a-z]', password):
        return json_error("Password must contain a lowercase letter")
    if not re.search(r'[0-9]', password):
        return json_error("Password must contain a digit")

    db = get_dict_db()
    try:
        form = db.execute(
            "SELECT * FROM referencing_forms WHERE form_token = ?", [form_token]
        ).fetchone()
        if not form:
            return json_error("Invalid or expired form link", 404)

        form_email = (form["email"] or "").strip().lower()
        # If the applicant supplied an email it must match the one on the form.
        if email and email != form_email:
            return json_error("That email doesn't match the application on file")
        email = form_email
        if not email:
            return json_error("No email on file for this application")

        existing = db.execute(
            "SELECT * FROM portal_users WHERE lower(email) = ?", [email]
        ).fetchone()
        if existing and existing["password_hash"]:
            return json_error("An account already exists for this email — please log in", 409)

        pw_hash = hash_password(password)
        if existing:
            db.execute(
                "UPDATE portal_users SET password_hash = ?, applicant_id = COALESCE(applicant_id, ?), "
                "portal_type = 'applicant', is_active = 1, modified = datetime('now') WHERE id = ?",
                [pw_hash, form["applicant_id"], existing["id"]],
            )
            user_id = existing["id"]
        else:
            db.execute(
                "INSERT INTO portal_users (email, password_hash, first_name, last_name, applicant_id, "
                "portal_type, is_active, email_verified, created, modified) "
                "VALUES (?, ?, ?, ?, ?, 'applicant', 1, 1, datetime('now'), datetime('now'))",
                [email, pw_hash, form["first_name"], form["last_name"], form["applicant_id"]],
            )
            user_id = db.execute("SELECT last_insert_rowid() AS rid").fetchone()["rid"]

        # Auto-login
        token = generate_token()
        expires_at = (datetime.now(timezone.utc) + PORTAL_SESSION_TTL).isoformat()
        db.execute(
            "INSERT INTO portal_sessions (user_id, session_token, ip_address, user_agent, expires_at, last_activity) VALUES (?, ?, ?, ?, ?, datetime('now'))",
            [user_id, token, request.remote_addr or '', request.headers.get("User-Agent", ""), expires_at],
        )
        db.execute(
            "UPDATE portal_users SET last_login_at = datetime('now'), last_login_ip = ? WHERE id = ?",
            [request.remote_addr or '', user_id],
        )
        db.commit()

        _audit_log(user_id, email, "register", "Portal account registered via form link")
        return json_success({
            "token": token,
            "user": {"id": user_id, "email": email,
                     "first_name": form["first_name"], "last_name": form["last_name"],
                     "portal_type": "applicant"},
            "expires_at": expires_at,
        })
    except Exception as e:
        db.rollback()
        return json_error(safe_error(e), 500)
    finally:
        db.close()


@referencing_bp.route("/portal/csrf-token", methods=["GET"])
@require_team_auth
def api_csrf_token():
    """Get a CSRF token. Sets it as a cookie for the Double Submit pattern."""
    return _generate_csrf_token()


@referencing_bp.route("/portal/login", methods=["POST"])
def api_portal_login():
    """Portal user login."""
    ip = request.remote_addr or "unknown"
    if not _check_rate_limit(f"portal_login:{ip}", max_attempts=5, window=60):
        return json_error("Too many login attempts. Please try again later.", 429)
    data = request.get_json() or {}
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")

    if not email or not password:
        return json_error("Email and password required")

    db = get_dict_db()
    try:
        user = db.execute("SELECT * FROM portal_users WHERE email = ? AND is_active = 1", [email]).fetchone()
        if not user or not check_password(password, user["password_hash"]):
            _audit_log(None, email, "login_failure", "Invalid email or password")
            return json_error("Invalid email or password", 401)

        # Generate session
        token = generate_token()
        expires_at = (datetime.now(timezone.utc) + PORTAL_SESSION_TTL).isoformat()
        db.execute(
            "INSERT INTO portal_sessions (user_id, session_token, ip_address, user_agent, expires_at, last_activity) VALUES (?, ?, ?, ?, ?, datetime('now'))",
            [user["id"], token, request.remote_addr or '', request.headers.get("User-Agent", ""), expires_at]
        )
        db.execute(
            "UPDATE portal_users SET last_login_at = datetime('now'), last_login_ip = ? WHERE id = ?",
            [request.remote_addr or '', user["id"]]
        )
        db.commit()

        _audit_log(user["id"], email, "login_success", "Portal login successful")


        return json_success({
            "token": token,
            "user": {
                "id": user["id"],
                "email": user["email"],
                "first_name": user["first_name"],
                "last_name": user["last_name"],
                "portal_type": user["portal_type"],
            },
            "expires_at": expires_at
        })
    finally:
        db.close()


@referencing_bp.route("/portal/logout", methods=["POST"])
@require_auth
def api_portal_logout():
    """Logout — invalidate current session."""
    token = request.headers.get("Authorization", "")[7:]
    pu = request.portal_user
    db = get_dict_db()
    try:
        db.execute("DELETE FROM portal_sessions WHERE session_token = ?", [token])
        db.commit()
        _audit_log(pu["pu_id"], pu["email"], "logout", "Portal user logged out")
        return json_success({"message": "Logged out"})
    finally:
        db.close()


@referencing_bp.route("/portal/me", methods=["GET"])
@require_auth
def api_portal_me():
    """Return the logged-in portal user's profile, application status and documents to sign."""
    pu = request.portal_user
    db = get_dict_db()
    try:
        profile = {
            "email": pu["email"], "first_name": pu["first_name"],
            "last_name": pu["last_name"], "portal_type": pu["portal_type"],
            "applicant_id": pu.get("applicant_id"),
        }

        # Any referencing forms tied to this portal user (by portal_user_id or email)
        forms = db.execute(
            "SELECT id, form_token, status, first_name, last_name, submitted_at, created FROM referencing_forms WHERE portal_user_id = ? AND status NOT IN ('cancelled') ORDER BY created DESC",
            [pu["pu_id"]]
        ).fetchall()

        # Any documents awaiting this person's signature
        to_sign = db.execute(
            "SELECT id, document_title, document_type, status, signer_token, created FROM esignature_requests "
            "WHERE lower(created_for_email) = ? AND status IN ('sent','viewed') ORDER BY created DESC",
            [pu["email"].lower()]
        ).fetchall()

        # Any tenancy linked to this portal user (set when a tenancy is created
        # from an approved form, or linked by the team).
        tenancies = []
        if pu.get("tenancy_id"):
            try:
                tenancies = db.execute(
                    "SELECT id, property_id, full_address, rent_amount, rent_frequency, status, "
                    "start_date, end_date FROM tenancies WHERE id = ?",
                    [pu.get("tenancy_id")]
                ).fetchall()
            except Exception:
                tenancies = []

        return json_success({
            "profile": profile,
            "applications": forms,
            "documents_to_sign": to_sign,
            "tenancies": tenancies,
        })
    finally:
        db.close()


# ── Portal: rent statement ──

@referencing_bp.route("/portal/rent", methods=["GET"])
@require_auth
def api_portal_rent():
    """Rent statement for the logged-in tenant: tenancy, balance, and ledger.

    A charge increases what the tenant owes; a payment reduces it. The running
    balance is (total charged − total paid); a positive balance means arrears.
    """
    pu = request.portal_user
    db = get_dict_db()
    try:
        tenancy_id = pu.get("tenancy_id")
        if not tenancy_id:
            return json_success({"tenancy": None, "ledger": [], "summary": None,
                                 "message": "No active tenancy is linked to your account yet."})

        tenancy = db.execute(
            "SELECT id, arthur_id, ref, full_address, property_id, rent_amount, rent_frequency, status, "
            "start_date, end_date, deposit_registered_amount, deposit_scheme FROM tenancies WHERE id = ?",
            [tenancy_id]
        ).fetchone()
        if not tenancy:
            return json_success({"tenancy": None, "ledger": [], "summary": None,
                                 "message": "No active tenancy is linked to your account yet."})

        # Arthur-synced tenancies store transactions against the Arthur id;
        # Banksia-native tenancies store them against the local id. Match either.
        txn_keys = [str(tenancy_id)]
        if tenancy.get("arthur_id"):
            txn_keys.append(str(tenancy["arthur_id"]))
        placeholders = ",".join("?" * len(txn_keys))
        ledger = db.execute(
            "SELECT id, ref, transaction_type, payment_type, description, amount, amount_charged, "
            "amount_paid, amount_outstanding, date, due_date, is_outstanding, is_overdue "
            f"FROM transactions WHERE CAST(tenancy_id AS TEXT) IN ({placeholders}) "
            "ORDER BY date DESC, id DESC LIMIT 200",
            txn_keys
        ).fetchall()

        charged = paid = outstanding = 0.0
        for t in ledger:
            ptype = (t.get("payment_type") or "").lower()
            amt = float(t.get("amount") or 0)
            if ptype == "charge":
                charged += amt
            elif ptype == "payment":
                paid += amt
            if t.get("is_outstanding"):
                outstanding += float(t.get("amount_outstanding") or 0)

        balance = round(charged - paid, 2)
        summary = {
            "total_charged": round(charged, 2),
            "total_paid": round(paid, 2),
            "balance": balance,
            "in_arrears": balance > 0.01,
            "outstanding_flagged": round(outstanding, 2),
        }
        return json_success({"tenancy": tenancy, "ledger": ledger, "summary": summary})
    finally:
        db.close()


# ── Portal: maintenance requests ──

def _next_maint_ref(db):
    row = db.execute("SELECT reference FROM maintenance_requests WHERE reference LIKE 'MR-%' "
                     "ORDER BY id DESC LIMIT 1").fetchone()
    n = 1
    if row and row.get("reference"):
        try:
            n = int(str(row["reference"]).split("-")[-1]) + 1
        except Exception:
            n = 1
    return f"MR-{n:05d}"


@referencing_bp.route("/portal/maintenance", methods=["GET"])
@require_auth
def api_portal_maintenance_list():
    """List maintenance requests raised by the logged-in tenant."""
    pu = request.portal_user
    db = get_dict_db()
    try:
        rows = db.execute(
            "SELECT id, reference, category, title, description, priority, location, status, "
            "assigned_to, created, resolved_at FROM maintenance_requests "
            "WHERE portal_user_id = ? ORDER BY created DESC",
            [pu.get("pu_id")]
        ).fetchall()
        return json_success({"requests": rows})
    finally:
        db.close()


@referencing_bp.route("/portal/maintenance", methods=["POST"])
@require_auth
def api_portal_maintenance_create():
    """Tenant raises a new maintenance request."""
    pu = request.portal_user
    data = request.get_json() or {}
    title = (data.get("title") or "").strip()
    if not title:
        return json_error("Please describe the issue in the title field")
    category = (data.get("category") or "general").strip()
    description = (data.get("description") or "").strip()
    priority = (data.get("priority") or "normal").strip().lower()
    if priority not in ("low", "normal", "high", "emergency"):
        priority = "normal"
    location = (data.get("location") or "").strip()

    db = get_dict_db()
    try:
        ref = _next_maint_ref(db)
        cur = db.execute(
            "INSERT INTO maintenance_requests (reference, portal_user_id, tenancy_id, property_id, "
            "reporter_name, reporter_email, category, title, description, priority, location, status) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?, 'open')",
            [ref, pu.get("pu_id"), pu.get("tenancy_id"), None,
             f"{pu.get('first_name','')} {pu.get('last_name','')}".strip(),
             pu.get("email"), category, title, description, priority, location]
        )
        db.commit()
        return json_success({"id": cur.lastrowid, "reference": ref, "status": "open"},
                            message="Your maintenance request has been logged. Our team will be in touch.")
    finally:
        db.close()


# ── Portal: documents ──

@referencing_bp.route("/portal/documents", methods=["GET"])
@require_auth
def api_portal_documents():
    """Documents visible to the tenant: their uploaded referencing docs, any
    completed (signed) e-signature PDFs, and pending e-signature requests."""
    pu = request.portal_user
    db = get_dict_db()
    try:
        email = (pu.get("email") or "").lower()

        # Uploaded referencing documents
        uploaded = db.execute(
            "SELECT d.id, d.category, d.original_filename, d.file_size, d.uploaded_at, d.is_verified "
            "FROM referencing_documents d JOIN referencing_forms f ON d.form_id = f.id "
            "WHERE lower(f.email) = ? ORDER BY d.uploaded_at DESC",
            [email]
        ).fetchall()

        # Completed/signed esignature documents
        signed = db.execute(
            "SELECT id, document_title, document_type, status, signed_at, completed_at "
            "FROM esignature_requests WHERE lower(created_for_email) = ? AND status = 'completed' "
            "ORDER BY completed_at DESC",
            [email]
        ).fetchall()

        # Pending esignature requests (awaiting applicant's signature)
        pending = db.execute(
            "SELECT id, document_title, document_type, status, created, expires_at, "
            "signer_token, team_signer_name "
            "FROM esignature_requests WHERE lower(created_for_email) = ? "
            "AND status IN ('draft', 'sent', 'viewed') "
            "ORDER BY created DESC",
            [email]
        ).fetchall()

        return json_success({"uploaded": uploaded, "signed": signed, "pending": pending})
    finally:
        db.close()


# ── Portal: update profile ──

@referencing_bp.route("/portal/profile", methods=["POST"])
@require_auth
def api_portal_profile():
    """Update portal user's profile (phone, notification preferences)."""
    pu = request.portal_user
    data = request.get_json() or {}
    db = get_dict_db()
    try:
        # Ensure preferences column exists
        try:
            db.execute("ALTER TABLE portal_users ADD COLUMN preferences TEXT DEFAULT '{}'")
        except Exception:
            pass  # column already exists

        sets, params = [], []
        if "phone" in data:
            sets.append("phone = ?"); params.append(data["phone"].strip())
        if "preferences" in data:
            sets.append("preferences = ?"); params.append(json.dumps(data["preferences"]))
        if sets:
            params.append(pu["pu_id"])
            db.execute(f"UPDATE portal_users SET {', '.join(sets)}, modified = datetime('now') WHERE id = ?", params)
            db.commit()

        user = db.execute(
            "SELECT id, email, first_name, last_name, phone, portal_type, preferences FROM portal_users WHERE id = ?",
            [pu["pu_id"]]
        ).fetchone()
        return json_success(user)
    finally:
        db.close()


# ── Portal: change password ──

@referencing_bp.route("/portal/change-password", methods=["POST"])
@require_auth
def api_portal_change_password():
    """Verify current password and set a new one."""
    pu = request.portal_user
    data = request.get_json() or {}
    current = data.get("current_password", "")
    new_pw = data.get("new_password", "")
    if not current or not new_pw:
        return json_error("Current password and new password are required")
    if len(new_pw) < 10:
        return json_error("New password must be at least 10 characters")
    if not re.search(r'[A-Z]', new_pw):
        return json_error("New password must contain an uppercase letter")
    if not re.search(r'[a-z]', new_pw):
        return json_error("New password must contain a lowercase letter")
    if not re.search(r'[0-9]', new_pw):
        return json_error("New password must contain a digit")
    db = get_dict_db()
    try:
        user = db.execute("SELECT * FROM portal_users WHERE id = ?", [pu["pu_id"]]).fetchone()
        if not user or not check_password(current, user["password_hash"]):
            _audit_log(pu["pu_id"], pu["email"], "password_change_failure", "Incorrect current password")
            return json_error("Current password is incorrect", 403)
        new_hash = hash_password(new_pw)
        db.execute(
            "UPDATE portal_users SET password_hash = ?, modified = datetime('now') WHERE id = ?",
            [new_hash, pu["pu_id"]]
        )
        db.commit()
        # Invalidate all existing sessions to force re-login
        db.execute("DELETE FROM portal_sessions WHERE user_id = ?", [pu["pu_id"]])
        db.commit()
        _audit_log(pu["pu_id"], pu["email"], "password_change", "Password changed successfully")
        return json_success({"message": "Password updated successfully. Please log in again."})
    finally:
        db.close()


# ── Portal: upload document ──

@referencing_bp.route("/portal/upload-document", methods=["POST"])
@require_auth
def api_portal_upload_document():
    """Upload a supporting document from the tenant portal."""
    pu = request.portal_user
    MAX_UPLOAD_SIZE = 20 * 1024 * 1024  # 20MB
    ALLOWED_EXTENSIONS = {'.pdf', '.jpg', '.jpeg', '.png', '.doc', '.docx', '.txt', '.rtf', '.csv', '.xls', '.xlsx'}
    if request.content_length and request.content_length > MAX_UPLOAD_SIZE:
        return json_error("File too large. Maximum size is 20MB.", 413)
    if "file" not in request.files:
        return json_error("No file provided")
    f = request.files["file"]
    if not f.filename:
        return json_error("Empty filename")
    ext = os.path.splitext(f.filename)[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        return json_error(f"File type '{ext}' is not allowed", 400)
    db = get_dict_db()
    try:
        # Find the referencing form for this user
        applicant_id = pu.get("applicant_id")
        email = pu.get("email", "").lower()
        form = None
        if applicant_id:
            form = db.execute(
                "SELECT id, form_token FROM referencing_forms WHERE applicant_id = ? ORDER BY created DESC LIMIT 1",
                [applicant_id]
            ).fetchone()
        if not form:
            form = db.execute(
                "SELECT id, form_token FROM referencing_forms WHERE lower(email) = ? ORDER BY created DESC LIMIT 1",
                [email]
            ).fetchone()
        if not form:
            return json_error("No referencing form found for your account", 404)
        # Save file
        original_name = secure_filename(f.filename) or "document"
        ext = os.path.splitext(original_name)[1] or ""
        stored_name = f"{uuid.uuid4().hex}{ext}"
        form_token_dir = os.path.join(UPLOAD_DIR, form["form_token"])
        os.makedirs(form_token_dir, exist_ok=True)
        file_path = os.path.join(form_token_dir, stored_name)
        f.save(file_path)
        file_size = os.path.getsize(file_path)
        mime_type = f.content_type or "application/octet-stream"
        db.execute(
            "INSERT INTO referencing_documents (form_id, category, original_filename, stored_filename, file_path, file_size, mime_type, uploaded_by) VALUES (?, ?, ?, ?, ?, ?, ?, 'applicant')",
            [form["id"], "other", original_name, stored_name, file_path, file_size, mime_type]
        )
        db.commit()
        doc_id = db.execute("SELECT last_insert_rowid()").fetchone()["last_insert_rowid()"]
        doc = db.execute(
            "SELECT id, category, original_filename, file_size, uploaded_at, is_verified FROM referencing_documents WHERE id = ?",
            [doc_id]
        ).fetchone()
        return json_success(doc, message="Document uploaded")
    except Exception as e:
        db.rollback()
        return json_error(safe_error(e), 500)
    finally:
        db.close()


# ── Portal: download a referencing document ──

@referencing_bp.route("/portal/download-document/<int:doc_id>", methods=["GET"])
@require_auth
def api_portal_download_document(doc_id):
    """Download a referencing document that belongs to the logged-in portal user."""
    pu = request.portal_user
    email = (pu.get("email") or "").lower()
    db = get_dict_db()
    try:
        doc = db.execute(
            "SELECT d.* FROM referencing_documents d JOIN referencing_forms f ON d.form_id = f.id "
            "WHERE d.id = ? AND lower(f.email) = ?",
            [doc_id, email]
        ).fetchone()
        if not doc:
            return json_error("Document not found or not authorised", 404)
        return send_file(doc["file_path"], as_attachment=True, download_name=doc["original_filename"])
    finally:
        db.close()


# ── Portal: messages ──

@referencing_bp.route("/portal/messages", methods=["GET"])
@require_auth
def api_portal_messages():
    """Return team messages/notifications for the portal user.

    Returns messages from message_threads where entity_type='portal' or
    related to the tenant's property_id.
    """
    pu = request.portal_user
    db = get_dict_db()
    try:
        # Collect property_ids from the user's tenancy / applicant links
        property_ids = []
        tenancy_id = pu.get("tenancy_id")
        if tenancy_id:
            ten = db.execute("SELECT property_id FROM tenancies WHERE id = ?", [tenancy_id]).fetchone()
            if ten and ten.get("property_id"):
                property_ids.append(ten["property_id"])
        applicant_id = pu.get("applicant_id")
        if applicant_id:
            rows = db.execute(
                "SELECT DISTINCT t.property_id FROM tenancies t JOIN referencing_forms f ON f.id = t.id WHERE f.applicant_id = ?",
                [applicant_id]
            ).fetchall()
            for r in rows:
                if r.get("property_id") and r["property_id"] not in property_ids:
                    property_ids.append(r["property_id"])
        # Build where clause: entity_type = 'portal' OR entity matches property_id
        where_parts = ["mt.entity_type = 'portal'"]
        params = []
        if property_ids:
            placeholders = ",".join(["?"] * len(property_ids))
            where_parts.append(f"(mt.entity_type = 'property' AND mt.entity_id IN ({placeholders}))")
            params.extend(property_ids)
        where = "(" + " OR ".join(where_parts) + ")"
        threads = db.execute(
            f"SELECT mt.id, mt.title, mt.entity_type, mt.entity_id, mt.status, mt.created, mt.modified "
            f"FROM message_threads mt WHERE {where} ORDER BY mt.modified DESC LIMIT 50",
            params
        ).fetchall()
        out = []
        for t in threads:
            last_msg = db.execute(
                "SELECT id, body, author, created FROM messages WHERE thread_id = ? ORDER BY id DESC LIMIT 1",
                [t["id"]]
            ).fetchone()
            body_text = last_msg["body"] if last_msg else ""
            preview = (body_text[:120] + "…") if len(body_text) > 120 else body_text
            out.append({
                "id": t["id"],
                "subject": t["title"] or "Message",
                "body": body_text,
                "preview": preview,
                "created": t["created"],
                "modified": t["modified"],
                "status": t["status"],
                "read": True,
            })
        return json_success({"messages": out})
    finally:
        db.close()


# ── Team: maintenance request management ──

@referencing_bp.route("/maintenance/requests", methods=["GET"])
@require_team_auth
def api_team_maintenance_list():
    """Team view of tenant-raised maintenance requests, optionally filtered by status."""
    status = request.args.get("status")
    db = get_dict_db()
    try:
        if status:
            rows = db.execute(
                "SELECT * FROM maintenance_requests WHERE status = ? ORDER BY "
                "CASE priority WHEN 'emergency' THEN 0 WHEN 'high' THEN 1 WHEN 'normal' THEN 2 ELSE 3 END, created DESC",
                [status]
            ).fetchall()
        else:
            rows = db.execute(
                "SELECT * FROM maintenance_requests ORDER BY "
                "CASE status WHEN 'open' THEN 0 WHEN 'in_progress' THEN 1 ELSE 2 END, "
                "CASE priority WHEN 'emergency' THEN 0 WHEN 'high' THEN 1 WHEN 'normal' THEN 2 ELSE 3 END, created DESC"
            ).fetchall()
        counts = {r["status"]: r["n"] for r in db.execute(
            "SELECT status, COUNT(*) n FROM maintenance_requests GROUP BY status").fetchall()}
        return json_success({"requests": rows, "counts": counts})
    finally:
        db.close()


@referencing_bp.route("/maintenance/requests/<int:req_id>", methods=["PATCH"])
@require_team_auth
def api_team_maintenance_update(req_id):
    """Update a maintenance request's status, assignee or team notes."""
    data = request.get_json() or {}
    db = get_dict_db()
    try:
        existing = db.execute("SELECT * FROM maintenance_requests WHERE id = ?", [req_id]).fetchone()
        if not existing:
            return json_error("Request not found", 404)
        sets, params = [], []
        if "status" in data:
            st = (data["status"] or "").strip().lower()
            if st not in ("open", "in_progress", "resolved", "closed", "rejected"):
                return json_error("Invalid status")
            sets.append("status = ?"); params.append(st)
            if st in ("resolved", "closed"):
                sets.append("resolved_at = datetime('now')")
        if "assigned_to" in data:
            sets.append("assigned_to = ?"); params.append((data["assigned_to"] or "").strip())
        if "team_notes" in data:
            sets.append("team_notes = ?"); params.append((data["team_notes"] or "").strip())
        if "priority" in data:
            pr = (data["priority"] or "normal").strip().lower()
            if pr in ("low", "normal", "high", "emergency"):
                sets.append("priority = ?"); params.append(pr)
        if not sets:
            return json_error("Nothing to update")
        sets.append("modified = datetime('now')")
        params.append(req_id)
        db.execute(f"UPDATE maintenance_requests SET {', '.join(sets)} WHERE id = ?", params)
        db.commit()
        row = db.execute("SELECT * FROM maintenance_requests WHERE id = ?", [req_id]).fetchone()
        return json_success(row, message="Request updated")
    finally:
        db.close()


# ────────────────────────────────────────────
# SECTION 5: FINANCIAL TRACKING
# ────────────────────────────────────────────

@referencing_bp.route("/financials/rent-summary", methods=["GET"])
@require_team_auth
def api_rent_summary():
    """Get rent summary across all properties."""
    db = get_dict_db()
    try:
        # Monthly-equivalent so non-monthly frequencies don't distort the rent roll.
        MONTHLY_EQ = """CASE lower(COALESCE(t.rent_frequency,'monthly'))
                WHEN 'biweekly' THEN t.rent_amount*26.0/12
                WHEN 'weekly'   THEN t.rent_amount*52.0/12
                WHEN 'daily'    THEN t.rent_amount*365.0/12
                ELSE t.rent_amount END"""
        LIVE = "('Current', 'Periodic')"
        rents = db.execute(
            f"""SELECT p.name as property_name, p.id as property_id,
                COUNT(t.id) as tenancy_count,
                COALESCE(SUM({MONTHLY_EQ}), 0) as total_rent,
                COALESCE(AVG({MONTHLY_EQ}), 0) as avg_rent
            FROM properties p
            LEFT JOIN tenancies t ON t.property_id = p.id AND t.status IN {LIVE}
            GROUP BY p.id
            ORDER BY p.name"""
        ).fetchall()

        total = db.execute(
            f"SELECT COALESCE(SUM({MONTHLY_EQ}), 0) as total FROM tenancies t WHERE t.status IN {LIVE}"
        ).fetchone()["total"]

        arrears = db.execute(
            """SELECT COALESCE(SUM(amount_outstanding), 0) as total FROM transactions 
               WHERE is_outstanding = 1 AND amount_outstanding > 0"""
        ).fetchone()["total"]

        return json_success({
            "properties": rents,
            "total_monthly_rent": total,
            "total_arrears": arrears,
            "as_at": datetime.now(timezone.utc).isoformat()
        })
    finally:
        db.close()


@referencing_bp.route("/financials/property/<int:property_id>/rent", methods=["GET"])
@require_team_auth
def api_property_rent_detail(property_id):
    """Get detailed rent info for a specific property."""
    db = get_dict_db()
    try:
        tenancies = db.execute(
            """SELECT t.*, u.unit_ref, u.full_address as unit_address
            FROM tenancies t
            JOIN units u ON t.unit_id = u.id
            WHERE t.property_id = ? AND t.status IN ('Active', 'periodic')
            ORDER BY u.sort_order ASC, u.unit_ref""",
            [property_id]
        ).fetchall()

        transactions = db.execute(
            """SELECT * FROM transactions WHERE property_id = ? AND is_outstanding = 1
               ORDER BY date DESC LIMIT 50""",
            [property_id]
        ).fetchall()

        return json_success({"tenancies": tenancies, "outstanding": transactions})
    finally:
        db.close()


# ────────────────────────────────────────────
# SECTION 6: TENANCY CREATION  (Arthur replacement — convert approved applicant → live tenancy)
# ────────────────────────────────────────────

def _next_bks_ref(db):
    """Banksia-native tenancy reference, never collides with synced Arthur 'TE' refs."""
    row = db.execute(
        "SELECT ref FROM tenancies WHERE ref LIKE 'BKS-%' ORDER BY id DESC LIMIT 1"
    ).fetchone()
    n = 1
    if row and row.get("ref"):
        try:
            n = int(str(row["ref"]).split("-")[-1]) + 1
        except Exception:
            n = 1
    return f"BKS-{n:06d}"


def _months_inclusive(start_ym, end_ym):
    (y1, m1), (y2, m2) = start_ym, end_ym
    return (y2 - y1) * 12 + (m2 - m1) + 1


def _month_labels(start_ym, count):
    y, m = start_ym
    out = []
    for _ in range(max(count, 0)):
        out.append(f"{y:04d}-{m:02d}")
        m += 1
        if m > 12:
            m = 1
            y += 1
    return out


def _parse_ym(date_str):
    """'YYYY-MM-DD' or 'YYYY-MM' -> (year, month). Returns None on failure."""
    if not date_str:
        return None
    try:
        parts = str(date_str).strip().split("-")
        return int(parts[0]), int(parts[1])
    except Exception:
        return None


def _generate_rent_schedule(db, tenancy_id, start_date, end_date, rent_amount, frequency):
    """Create rent_charges rows (monthly buckets, 'YYYY-MM', status 'due') matching existing data.

    Fixed-term with an end date → charges for every month start..end inclusive.
    Periodic / rolling (no end date) → 12 months forward from start.
    Non-monthly frequencies are bucketed monthly at their monthly-equivalent for tracking.
    Returns the number of charges written.
    """
    start_ym = _parse_ym(start_date)
    if not start_ym:
        return 0

    end_ym = _parse_ym(end_date)
    if end_ym:
        count = _months_inclusive(start_ym, end_ym)
        if count < 1:
            count = 1
    else:
        count = 12  # periodic — a rolling year forward

    # Monthly-equivalent amount for the bucket
    freq = (frequency or "Monthly").lower()
    if freq == "monthly":
        monthly = float(rent_amount or 0)
    elif freq == "biweekly":
        monthly = round(float(rent_amount or 0) * 26 / 12, 2)
    elif freq == "daily":
        monthly = round(float(rent_amount or 0) * 365 / 12, 2)
    elif freq in ("weekly",):
        monthly = round(float(rent_amount or 0) * 52 / 12, 2)
    else:
        monthly = float(rent_amount or 0)

    # Clear any existing schedule for this tenancy first (idempotent regenerate)
    db.execute("DELETE FROM rent_charges WHERE tenancy_id = ?", [tenancy_id])
    now = datetime.now(timezone.utc).isoformat()
    written = 0
    for label in _month_labels(start_ym, count):
        db.execute(
            "INSERT INTO rent_charges (tenancy_id, month, rent_amount, paid_amount, status, notes, created) "
            "VALUES (?, ?, ?, 0.0, 'due', '', ?)",
            [tenancy_id, label, monthly, now],
        )
        written += 1
    return written


def _tenant_blob_from_form(form):
    """Build the JSON tenant entry stored on tenancies.tenants (mirrors Arthur's shape)."""
    return {
        "first_name": form.get("first_name", ""),
        "last_name": form.get("last_name", ""),
        "date_of_birth": form.get("date_of_birth", ""),
        "mobile": form.get("mobile_phone", ""),
        "email": form.get("email", ""),
        "gender": form.get("gender", ""),
        "main_tenant": True,
        "title": form.get("title", ""),
        "passport_number": form.get("id_number", ""),
        "visa_number": form.get("share_code", "") or form.get("visa_number", ""),
        "visa_type": form.get("visa_type", ""),
        "country_of_origin": form.get("country_of_origin", ""),
        "ni_number": form.get("ni_number", ""),
        "has_guarantor": bool(form.get("has_guarantor")),
        "guarantor_first_name": form.get("guarantor_first_name", ""),
        "guarantor_last_name": form.get("guarantor_last_name", ""),
        "guarantor_relation": form.get("guarantor_relation", ""),
        "guarantor_email": form.get("guarantor_email", ""),
        "guarantor_mobile": form.get("guarantor_mobile", ""),
        "employment_company_name": form.get("employer_name", ""),
        "employment_salary": form.get("annual_salary", ""),
        "bank_name": form.get("bank_name", ""),
        "bank_account_number": form.get("bank_account_number", ""),
        "bank_sort_code": form.get("bank_sort_code", ""),
        "kin_first_name": form.get("kin_first_name", ""),
        "kin_last_name": form.get("kin_last_name", ""),
        "kin_mobile": form.get("kin_mobile", ""),
    }


@referencing_bp.route("/tenancies/create-from-form", methods=["POST"])
@require_team_auth
@require_csrf
def api_create_tenancy_from_form():
    """Convert an APPROVED referencing form into a live tenancy.

    Body: form_id, property_id, unit_id, start_date, [end_date], rent_amount,
    [rent_frequency=Monthly], [deposit_amount], [deposit_scheme], [notice_period],
    [move_in_date], [tenancy_type], [contract_type], [send_agreement=false].
    """
    data = request.get_json() or {}
    form_id = data.get("form_id")
    if not form_id:
        return json_error("form_id is required")

    start_date = (data.get("start_date") or "").strip()
    if not start_date or not _parse_ym(start_date):
        return json_error("A valid start_date (YYYY-MM-DD) is required")

    try:
        rent_amount = float(data.get("rent_amount") or 0)
    except (TypeError, ValueError):
        return json_error("rent_amount must be a number")
    if rent_amount <= 0:
        return json_error("rent_amount must be greater than zero")

    # A tenancy is always attached to a unit (room/property) — mirrors Arthur.
    if not data.get("unit_id"):
        return json_error("Please select a unit before creating the tenancy")

    db = get_dict_db()
    try:
        form = db.execute("SELECT * FROM referencing_forms WHERE id = ?", [form_id]).fetchone()
        if not form:
            return json_error("Referencing form not found", 404)
        if form["status"] != "approved":
            return json_error(
                f"Form must be approved before creating a tenancy (currently '{form['status']}')", 409
            )

        # Guard against duplicate tenancy for the same form
        existing = db.execute(
            "SELECT id, ref FROM tenancies WHERE sync_origin = 'banksia' AND notes LIKE ?",
            [f"%form_id={form_id}%"],
        ).fetchone()
        if existing:
            return json_error(
                f"A tenancy ({existing['ref']}) already exists for this form", 409
            )

        property_id = data.get("property_id")
        unit_id = data.get("unit_id")
        end_date = (data.get("end_date") or "").strip()
        rent_frequency = data.get("rent_frequency") or "Monthly"
        deposit_amount = data.get("deposit_amount") or 0
        deposit_scheme = data.get("deposit_scheme") or ""
        notice_period = data.get("notice_period") or ""
        move_in_date = (data.get("move_in_date") or start_date).strip()
        tenancy_type = data.get("tenancy_type") or "AST"
        contract_type = data.get("contract_type") or ("Fixed Term" if end_date else "Periodic")
        status = "Current"

        # Resolve address from unit → property
        full_address = ""
        if unit_id:
            u = db.execute("SELECT full_address FROM units WHERE id = ?", [unit_id]).fetchone()
            if u:
                full_address = u.get("full_address") or ""
        if not full_address and property_id:
            p = db.execute(
                "SELECT name, address_line_1, address_line_2, city, postcode FROM properties WHERE id = ?",
                [property_id],
            ).fetchone()
            if p:
                full_address = ", ".join(
                    x for x in [p.get("address_line_1"), p.get("address_line_2"),
                                p.get("city"), p.get("postcode")] if x
                ) or (p.get("name") or "")

        main_tenant_name = f"{form['first_name']} {form['last_name']}".strip()
        ref = _next_bks_ref(db)
        tenant_blob = json.dumps([_tenant_blob_from_form(form)])
        now = datetime.now(timezone.utc).isoformat()
        notes = f"Created in Banksia OS from referencing form_id={form_id} by {_current_username()}"

        cur = db.execute(
            """INSERT INTO tenancies
               (ref, property_id, unit_id, status, full_address, tenancy_type, contract_type,
                start_date, end_date, notice_period, move_in_date, rent_amount, rent_frequency,
                deposit_held_by, deposit_scheme, deposit_registered_amount, main_tenant_name,
                tenants, notes, created, modified, sync_origin, sync_dirty, local_modified)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'banksia', 1, ?)""",
            [ref, property_id, unit_id, status, full_address, tenancy_type, contract_type,
             start_date, end_date, notice_period, move_in_date, rent_amount, rent_frequency,
             "Banksia", deposit_scheme, deposit_amount, main_tenant_name,
             tenant_blob, notes, now, now, now],
        )
        tenancy_id = cur.lastrowid

        # Create the tenant record linked to the tenancy
        db.execute(
            """INSERT INTO tenants
               (tenancy_id, unit_id, property_id, full_address, title, first_name, last_name,
                date_of_birth, gender, email, mobile, passport_number, visa_number, visa_type,
                country_of_origin, ni_number, main_tenant, status, has_guarantor,
                guarantor_first_name, guarantor_last_name, guarantor_email, guarantor_mobile,
                guarantor_relation, employment_company, employment_salary, bank_name,
                bank_account_number, bank_sort_code, kin_first_name, kin_last_name, kin_mobile,
                move_in_date, created, modified, sync_origin, sync_dirty)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 'Current', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'banksia', 1)""",
            [tenancy_id, unit_id, property_id, full_address, form.get("title", ""),
             form["first_name"], form["last_name"], form.get("date_of_birth", ""),
             form.get("gender", ""), form.get("email", ""), form.get("mobile_phone", ""),
             form.get("id_number", ""), form.get("share_code", "") or form.get("visa_number", ""),
             form.get("visa_type", ""), form.get("country_of_origin", ""), form.get("ni_number", ""),
             1 if form.get("has_guarantor") else 0,
             form.get("guarantor_first_name", ""), form.get("guarantor_last_name", ""),
             form.get("guarantor_email", ""), form.get("guarantor_mobile", ""),
             form.get("guarantor_relation", ""), form.get("employer_name", ""),
             form.get("annual_salary", ""), form.get("bank_name", ""),
             form.get("bank_account_number", ""), form.get("bank_sort_code", ""),
             form.get("kin_first_name", ""), form.get("kin_last_name", ""),
             form.get("kin_mobile", ""), move_in_date, now, now],
        )

        # Generate the rent schedule
        charges = _generate_rent_schedule(db, tenancy_id, start_date, end_date, rent_amount, rent_frequency)

        # Mark the unit as let
        if unit_id:
            db.execute(
                "UPDATE units SET unit_status = 'Let', unit_vacant = 0, modified = ? WHERE id = ?",
                [now, unit_id],
            )

        # Optionally create + send the tenancy-agreement e-signature in one step
        esign = None
        delivery = None
        if data.get("send_agreement"):
            signer_token = generate_token()
            expires_at = (datetime.now(timezone.utc) + timedelta(days=14)).isoformat()
            ecur = db.execute(
                """INSERT INTO esignature_requests (form_id, tenancy_id, document_type, document_title,
                   status, created_for, created_for_email, signer_token, expires_at, created_by)
                   VALUES (?, ?, 'tenancy_agreement', ?, 'draft', ?, ?, ?, ?, ?)""",
                [form_id, tenancy_id, f"Tenancy Agreement — {ref}", main_tenant_name,
                 form.get("email", ""), signer_token, expires_at, _current_username()],
            )
            eid = ecur.lastrowid
            db.execute(
                "INSERT INTO esignature_audit_log (request_id, event_type, event_detail, ip_address, user_agent) "
                "VALUES (?, 'created', ?, ?, ?)",
                [eid, f"Auto-created with tenancy {ref}", request.remote_addr or "", request.headers.get("User-Agent", "")],
            )
            ereq = db.execute("SELECT * FROM esignature_requests WHERE id = ?", [eid]).fetchone()
            ok, delivery = _deliver_esignature(db, ereq, actual_send=True)
            esign = db.execute("SELECT * FROM esignature_requests WHERE id = ?", [eid]).fetchone()

        # Link the applicant/form onwards
        db.execute(
            "UPDATE referencing_forms SET status = 'tenancy_created', modified = ? WHERE id = ?",
            [now, form_id],
        )

        # Also update the linked applicant's status to 'converted'
        applicant_id = form.get("applicant_id")
        if applicant_id:
            db.execute(
                "UPDATE applicants SET status = 'converted', modified = ? WHERE id = ?",
                [now, applicant_id],
            )

        # Create deposit record if deposit amount was provided
        deposit_amount_val = float(deposit_amount) if deposit_amount else 0
        if deposit_amount_val > 0:
            db.execute(
                "INSERT INTO deposits (tenancy_id, tenant_id, unit_id, property_id, amount, "
                "registered_amount, deposit_type, scheme, protection_status, current_status, "
                "date_received, source, notes, created, modified) "
                "VALUES (?, ?, ?, ?, ?, ?, 'cash', ?, 'unprotected', 'held', ?, 'banksia', ?, ?, ?)",
                [tenancy_id, None, unit_id, property_id, deposit_amount_val, deposit_amount_val,
                 deposit_scheme or "", start_date,
                 f"Auto-created from referencing form #{form_id}", now, now],
            )

        # ── Link the portal user to the tenancy ──
        try:
            form_email = (form.get("email") or "").lower().strip()
            if form_email:
                db.execute(
                    "UPDATE portal_users SET tenancy_id = ?, portal_type = 'tenant', modified = ? WHERE lower(email) = ? AND tenancy_id IS NULL",
                    [tenancy_id, now, form_email]
                )
        except Exception:
            pass  # Non-blocking — portal user may not exist yet

        db.commit()
        tenancy = db.execute("SELECT * FROM tenancies WHERE id = ?", [tenancy_id]).fetchone()
        return json_success(
            {"tenancy": tenancy, "rent_charges_created": charges, "esignature": esign},
            delivery=delivery,
        )
    except Exception as e:
        db.rollback()
        return json_error(safe_error(e), 500)
    finally:
        db.close()


@referencing_bp.route("/tenancies", methods=["GET"])
@require_team_auth
def api_list_tenancies():
    """List tenancies with optional filters: status, property_id, origin (banksia|all), q, limit."""
    status = request.args.get("status")
    property_id = request.args.get("property_id", type=int)
    origin = request.args.get("origin", "all")
    q = (request.args.get("q") or "").strip()
    limit = request.args.get("limit", default=200, type=int)

    where, params = [], []
    if status:
        where.append("status = ?"); params.append(status)
    if property_id:
        where.append("property_id = ?"); params.append(property_id)
    if origin == "banksia":
        where.append("sync_origin = 'banksia'")
    if q:
        where.append("(main_tenant_name LIKE ? OR ref LIKE ? OR full_address LIKE ?)")
        params += [f"%{q}%", f"%{q}%", f"%{q}%"]
    clause = ("WHERE " + " AND ".join(where)) if where else ""

    db = get_dict_db()
    try:
        rows = db.execute(
            f"""SELECT id, ref, status, full_address, main_tenant_name, tenancy_type, contract_type,
                   start_date, end_date, rent_amount, rent_frequency, deposit_scheme,
                   property_id, unit_id, sync_origin, created
                FROM tenancies {clause}
                ORDER BY (sync_origin='banksia') DESC, id DESC LIMIT ?""",
            params + [limit],
        ).fetchall()
        return json_success(rows, count=len(rows))
    finally:
        db.close()


@referencing_bp.route("/tenancies/<int:tid>", methods=["GET"])
@require_team_auth
def api_get_tenancy(tid):
    """Full tenancy detail: record + linked tenants + rent schedule + e-sign requests + arrears."""
    db = get_dict_db()
    try:
        tenancy = db.execute("SELECT * FROM tenancies WHERE id = ?", [tid]).fetchone()
        if not tenancy:
            return json_error("Tenancy not found", 404)
        tenants = db.execute("SELECT * FROM tenants WHERE tenancy_id = ?", [tid]).fetchall()
        charges = db.execute(
            "SELECT * FROM rent_charges WHERE tenancy_id = ? ORDER BY month", [tid]
        ).fetchall()
        esigns = db.execute(
            "SELECT * FROM esignature_requests WHERE tenancy_id = ? ORDER BY id DESC", [tid]
        ).fetchall()
        billed = sum(float(c.get("rent_amount") or 0) for c in charges)
        paid = sum(float(c.get("paid_amount") or 0) for c in charges)
        return json_success({
            "tenancy": tenancy,
            "tenants": tenants,
            "rent_charges": charges,
            "esignatures": esigns,
            "totals": {"billed": round(billed, 2), "paid": round(paid, 2),
                        "arrears": round(billed - paid, 2), "months": len(charges)},
        })
    finally:
        db.close()


@referencing_bp.route("/tenancies/<int:tid>", methods=["PATCH"])
@require_team_auth
def api_update_tenancy(tid):
    """Edit tenancy fields. Regenerates the rent schedule when term/rent fields change."""
    data = request.get_json() or {}
    editable = {
        "status", "full_address", "tenancy_type", "contract_type", "start_date", "end_date",
        "notice_period", "move_in_date", "move_out_date", "rent_amount", "rent_frequency",
        "deposit_scheme", "deposit_registered_amount", "deposit_held_by", "notes",
        "break_clause_date", "rent_review_date", "main_tenant_name",
    }
    sets, params = [], []
    for k, v in data.items():
        if k in editable:
            sets.append(f"{k} = ?"); params.append(v)
    if not sets:
        return json_error("No editable fields supplied")

    db = get_dict_db()
    try:
        tenancy = db.execute("SELECT * FROM tenancies WHERE id = ?", [tid]).fetchone()
        if not tenancy:
            return json_error("Tenancy not found", 404)
        now = datetime.now(timezone.utc).isoformat()
        sets += ["modified = ?", "sync_dirty = 1", "local_modified = ?"]
        params += [now, now, tid]
        db.execute(f"UPDATE tenancies SET {', '.join(sets)} WHERE id = ?", params)

        # If any schedule-affecting field changed, rebuild the rent schedule
        if {"start_date", "end_date", "rent_amount", "rent_frequency"} & set(data.keys()):
            merged = db.execute("SELECT * FROM tenancies WHERE id = ?", [tid]).fetchone()
            _generate_rent_schedule(
                db, tid, merged["start_date"], merged["end_date"],
                merged["rent_amount"], merged["rent_frequency"],
            )
        db.commit()
        updated = db.execute("SELECT * FROM tenancies WHERE id = ?", [tid]).fetchone()
        return json_success(updated)
    except Exception as e:
        db.rollback()
        return json_error(safe_error(e), 500)
    finally:
        db.close()


@referencing_bp.route("/tenancies/<int:tid>/rent/<int:charge_id>", methods=["PATCH"])
@require_team_auth
def api_update_rent_charge(tid, charge_id):
    """Record a payment / edit a single rent charge (paid_amount, status, notes)."""
    data = request.get_json() or {}
    sets, params = [], []
    for k in ("paid_amount", "status", "notes", "rent_amount"):
        if k in data:
            sets.append(f"{k} = ?"); params.append(data[k])
    if not sets:
        return json_error("Nothing to update")
    db = get_dict_db()
    try:
        row = db.execute(
            "SELECT id FROM rent_charges WHERE id = ? AND tenancy_id = ?", [charge_id, tid]
        ).fetchone()
        if not row:
            return json_error("Rent charge not found", 404)
        sets.append("modified = ?"); params.append(datetime.now(timezone.utc).isoformat())
        params.append(charge_id)
        db.execute(f"UPDATE rent_charges SET {', '.join(sets)} WHERE id = ?", params)
        db.commit()
        return json_success(db.execute("SELECT * FROM rent_charges WHERE id = ?", [charge_id]).fetchone())
    finally:
        db.close()


@referencing_bp.route("/units/available", methods=["GET"])
@require_team_auth
def api_available_units():
    """Vacant units for the tenancy-creation picker."""
    property_id = request.args.get("property_id", type=int)
    where = "WHERE (unit_vacant = 1 OR unit_status IN ('Available To Let','Available','Vacant'))"
    params = []
    if property_id:
        where += " AND property_id = ?"; params.append(property_id)
    db = get_dict_db()
    try:
        rows = db.execute(
            f"""SELECT u.id, u.unit_ref, u.unit_status, u.market_rent, u.market_rent_frequency,
                       u.deposit_amount, u.property_id, u.full_address, p.name AS property_name
                FROM units u LEFT JOIN properties p ON u.property_id = p.id
                {where} ORDER BY u.full_address, u.sort_order ASC, u.unit_ref LIMIT 500""",
            params,
        ).fetchall()
        return json_success(rows, count=len(rows))
    finally:
        db.close()


# ────────────────────────────────────────────
# AUTO-CREATE TENANCY HELPER
# ────────────────────────────────────────────

def _call_create_tenancy(app_id, db):
    """Internal helper to create a tenancy from an applicant after esign completes.

    Replicates the core logic from banksia_os.py api_create_tenancy_from_applicant
    but uses an existing DB connection and returns a dict.
    """
    try:
        app = db.execute("SELECT * FROM applicants WHERE id = ?", [app_id]).fetchone()
        if not app:
            return {"success": False, "error": "Applicant not found"}
        app_status = (app.get("status") or "").strip().lower()
        if app_status not in ("approved",):
            return {"success": False, "error": f"Applicant status must be 'approved', got '{app_status}'"}

        property_id = app.get("property_id")
        unit_id = app.get("unit_id")
        if not property_id or not unit_id:
            return {"success": False, "error": "Applicant must have property_id and unit_id"}

        # Fall back to referencing form data if applicant has NULL values
        rent_amount = app.get("proposed_rent")
        deposit_amount = app.get("proposed_deposit")
        start_date = app.get("desired_move_in")

        if not rent_amount or not deposit_amount or not start_date:
            # Try to pull from linked referencing form
            ref = db.execute(
                "SELECT annual_salary, preferred_move_in_date FROM referencing_forms WHERE applicant_id = ? ORDER BY id DESC LIMIT 1",
                [app_id]
            ).fetchone()
            if ref:
                if not rent_amount:
                    rent_amount = ref.get("annual_salary")
                if not start_date:
                    start_date = ref.get("preferred_move_in_date")
            if not deposit_amount:
                deposit_amount = rent_amount * 1.1667 if rent_amount else 0  # ~1 month + 1 week

        now = datetime.now(timezone.utc)
        now_iso = now.isoformat()
        first_name = app.get("first_name", "")
        last_name = app.get("last_name", "")
        email = app.get("email", "")
        phone = app.get("phone", "") or app.get("mobile", "")
        main_tenant_name = f"{first_name} {last_name}".strip()

        if not start_date:
            start_date = now_iso[:10]

        from dateutil.relativedelta import relativedelta
        try:
            start_dt = datetime.fromisoformat(start_date) if "T" in str(start_date) else datetime.strptime(str(start_date), "%Y-%m-%d")
        except (ValueError, TypeError):
            start_dt = now
        end_dt = start_dt + relativedelta(months=6)
        end_date = end_dt.strftime("%Y-%m-%d")

        tenancy_cur = db.execute(
            "INSERT INTO tenancies (property_id, unit_id, main_tenant_name, status, "
            "start_date, end_date, rent_amount, rent_frequency, created, modified) "
            "VALUES (?, ?, ?, 'active', ?, ?, ?, 'pcm', ?, ?)",
            [property_id, unit_id, main_tenant_name, start_date, end_date,
             rent_amount, now_iso, now_iso]
        )
        tenancy_id = tenancy_cur.lastrowid

        tenant_cur = db.execute(
            "INSERT INTO tenants (first_name, last_name, email, phone_home, mobile, "
            "property_id, unit_id, tenancy_id, main_tenant, status, created, modified) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, 'active', ?, ?)",
            [first_name, last_name, email, phone, phone,
             property_id, unit_id, tenancy_id, now_iso, now_iso]
        )
        tenant_id = tenant_cur.lastrowid

        dep_cur = db.execute(
            "INSERT INTO deposits (tenancy_id, tenant_id, unit_id, property_id, "
            "amount, current_status, protection_status, date_received, created, modified) "
            "VALUES (?, ?, ?, ?, ?, 'held', 'unprotected', ?, ?, ?)",
            [tenancy_id, tenant_id, unit_id, property_id,
             deposit_amount or 0, start_date, now_iso, now_iso]
        )

        old_app_status = app.get("status", "")
        db.execute("UPDATE applicants SET status = 'tenancy_created', modified = ? WHERE id = ?",
                   [now_iso, app_id])

        refs = db.execute(
            "SELECT id, status FROM referencing_forms WHERE applicant_id = ? AND status NOT IN ('tenancy_created', 'withdrawn')",
            [app_id]
        ).fetchall()
        for ref in refs:
            db.execute("UPDATE referencing_forms SET status = 'tenancy_created', modified = ? WHERE id = ?",
                       [now_iso, ref["id"]])

        if start_date and str(start_date)[:10] <= now_iso[:10]:
            db.execute(
                "UPDATE units SET unit_status = 'Occupied', unit_vacant = 0, status = 'occupied', modified = ? WHERE id = ?",
                [now_iso, unit_id]
            )

        return {"success": True, "tenancy_id": tenancy_id, "tenant_id": tenant_id}
    except Exception as e:
        return {"success": False, "error": str(e)}


# ────────────────────────────────────────────
# INITIALIZATION
# ────────────────────────────────────────────

# Export the blueprint
__all__ = ["referencing_bp"]
