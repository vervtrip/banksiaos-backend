#!/usr/bin/env python3
"""Verv Ops Dashboard — STR, HMO, Maintenance consolidated view."""
import json, os, subprocess, re, time, sys, urllib.request, uuid
from datetime import datetime, timedelta, date
from functools import wraps
from flask import Flask, render_template, request, jsonify, redirect, session

app = Flask(__name__)
app.secret_key = "verv-ops-dash-2026-secure"
app.config.update(SESSION_COOKIE_SECURE=False, SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Lax')

# ── Multi-user auth system ──
USERS_FILE = os.path.join(os.path.dirname(__file__), "users.json")

def _load_users():
    if not os.path.exists(USERS_FILE):
        return {"Sami": {"password": "Newpassword1323!", "role": "super_admin"}}
    return json.load(open(USERS_FILE))

def _save_users(users):
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=2)

def _authenticate(username, password):
    users = _load_users()
    # Try direct username match first
    u = users.get(username)
    if u and u.get("password") == password:
        return {"username": username, "role": u.get("role", "admin"), "email": u.get("email", "")}
    # Try email match
    for uname, data in users.items():
        if data.get("email", "").lower() == username.lower() and data.get("password") == password:
            return {"username": uname, "role": data.get("role", "admin"), "email": data.get("email", "")}
    # Try case-insensitive username
    for uname, data in users.items():
        if uname.lower() == username.lower() and data.get("password") == password:
            return {"username": uname, "role": data.get("role", "admin"), "email": data.get("email", "")}
    return None

def require_auth(f):
    @wraps(f)
    def wrap(*a, **k):
        user = session.get("user")
        if not user:
            return redirect("/")
        request.current_user = user
        return f(*a, **k)
    return wrap

def require_super_admin(f):
    @wraps(f)
    def wrap(*a, **k):
        user = session.get("user")
        if not user:
            return redirect("/")
        if user.get("role") != "super_admin":
            return jsonify({"error": "Forbidden — super admin only"}), 403
        request.current_user = user
        return f(*a, **k)
    return wrap

# ── Token helpers ──
def get_arthur_token():
    p = "/root/.hermes/state/arthur_token.json"
    if not os.path.exists(p): return None
    d = json.load(open(p))
    if d.get("expires_at", 0) < time.time(): return None
    return d.get("access_token")

def get_hostaway_token():
    # Primary: shared token store
    p = "/root/.hermes/state/hostaway_token.json"
    if os.path.exists(p):
        d = json.load(open(p))
        tok = d.get("access_token")
        if tok: return tok
    # Fallback: hmobanksia profile
    hp = "/root/.hermes/profiles/hmobanksia/.credentials/hostaway.json"
    if os.path.exists(hp):
        d = json.load(open(hp))
        tok = d.get("access_token")
        if tok: return tok
    # Fallback: env file
    env_p = "/root/.hermes/profiles/hmobanksia/.env"
    if os.path.exists(env_p):
        for line in open(env_p):
            if "HOSTAWAY_ACCESS_TOKEN" in line:
                return line.split("=", 1)[1].strip().strip("'\"")
    return None

def get_monday_token():
    tf = "/root/.hermes/secrets/monday_token.txt"
    if os.path.exists(tf): return open(tf).read().strip()
    return None

def get_missive_creds():
    cf = "/root/.hermes/secrets/missive.json"
    if os.path.exists(cf): return json.load(open(cf))
    # Try env
    env_p = "/root/.hermes/.env"
    if os.path.exists(env_p):
        for line in open(env_p):
            if "MISSIVE_API_KEY" in line:
                return {"token": line.split("=",1)[1].strip().strip("'\""), "org_id": ""}
    return None

# ── API Helpers ──
def api_get(url, headers):
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        return {"error": f"HTTP {e.code}", "body": e.read().decode()[:500]}
    except Exception as e:
        return {"error": str(e)}

# ═══════════════════════════════════════════════
# ROUTES
# ═══════════════════════════════════════════════

# ── Login page ──
@app.route("/")
def login_page():
    if session.get("user"):
        return redirect("/dashboard")
    return render_template("login.html")

# ── Auth API ──
@app.route("/api/auth/login", methods=["POST"])
def api_auth_login():
    data = request.get_json()
    username = data.get("username", "").strip()
    password = data.get("password", "")
    user = _authenticate(username, password)
    if not user:
        return jsonify({"error": "Invalid credentials"}), 401
    session["user"] = user
    session.permanent = True
    return jsonify({"success": True, "user": {"username": user["username"], "role": user["role"]}})

@app.route("/api/auth/logout", methods=["POST", "GET"])
def api_auth_logout():
    session.clear()
    return redirect("/")

# ── Password Reset ──
RESET_TOKENS = {}  # {email: {"token": str, "expires": timestamp}}

@app.route("/api/auth/forgot-password", methods=["POST"])
def api_forgot_password():
    data = request.get_json()
    email = data.get("email", "").strip().lower()
    if not email:
        return jsonify({"error": "Email is required"}), 400
    
    # Find user by email
    users = _load_users()
    found = None
    for uname, u in users.items():
        if u.get("email", "").lower() == email:
            found = uname
            break
    
    if not found:
        # Don't reveal whether email exists - always return success
        return jsonify({"success": True, "message": "If this email is registered, a reset link has been sent."})
    
    # Generate reset token
    token = uuid.uuid4().hex[:32]
    RESET_TOKENS[email] = {"token": token, "expires": time.time() + 3600, "username": found}
    reset_url = f"http://187.124.170.214:5050/reset-password?token={token}&email={email}"
    
    # Try sending email via SMTP
    import smtplib
    from email.mime.text import MIMEText
    smtp_sent = False
    smtp_config_path = os.path.join(os.path.dirname(__file__), "smtp_config.json")
    if os.path.exists(smtp_config_path):
        try:
            smtp = json.load(open(smtp_config_path))
            msg = MIMEText(f"Hello {found},\n\nYou requested a password reset for the VERV Operations Dashboard.\n\nClick the link below to reset your password:\n{reset_url}\n\nThis link expires in 1 hour.\n\nIf you didn't request this, please ignore this email.\n\n— VERV Operations")
            msg["Subject"] = "VERV Dashboard — Password Reset"
            msg["From"] = smtp.get("from_email", "noreply@vervrooms.com")
            msg["To"] = email
            with smtplib.SMTP(smtp["host"], smtp["port"], timeout=10) as s:
                if smtp.get("tls", True):
                    s.starttls()
                if smtp.get("username"):
                    s.login(smtp["username"], smtp["password"])
                s.send_message(msg)
            smtp_sent = True
            print(f"[PASSWORD RESET] Email sent to {email}")
        except Exception as e:
            print(f"[PASSWORD RESET] SMTP failed: {e}")
    
    if not smtp_sent:
        print(f"[PASSWORD RESET] Token for {email} ({found}): {token}")
        print(f"[PASSWORD RESET] Reset URL: {reset_url}")
    
    msg = "A password reset link has been sent to your email."
    if not smtp_sent:
        msg = f"Reset link generated. Please contact Neo for your reset link."
    
    return jsonify({"success": True, "message": msg, "debug_token": token if not smtp_sent else None})

@app.route("/api/auth/reset-password", methods=["POST"])
def api_reset_password():
    data = request.get_json()
    email = data.get("email", "").strip().lower()
    token = data.get("token", "").strip()
    new_password = data.get("password", "").strip()
    
    if not email or not token or not new_password:
        return jsonify({"error": "Email, token, and new password are required"}), 400
    if len(new_password) < 6:
        return jsonify({"error": "Password must be at least 6 characters"}), 400
    
    stored = RESET_TOKENS.get(email)
    if not stored or stored["token"] != token or stored["expires"] < time.time():
        return jsonify({"error": "Invalid or expired reset token"}), 400
    
    # Update password
    users = _load_users()
    username = stored["username"]
    if username in users:
        users[username]["password"] = new_password
        _save_users(users)
        del RESET_TOKENS[email]
        return jsonify({"success": True, "message": "Password has been reset successfully."})
    
    return jsonify({"error": "User not found"}), 404

@app.route("/reset-password")
def reset_password_page():
    return render_template("reset-password.html")

@app.route("/dashboard")
@require_auth
def dashboard():
    return render_template("dashboard.html", user=request.current_user)

# ── USER MANAGEMENT (super admin only) ──
@app.route("/api/users", methods=["GET"])
@require_super_admin
def api_list_users():
    users = _load_users()
    safe = {u: {"role": d["role"]} for u, d in users.items()}
    return jsonify(safe)

@app.route("/api/users", methods=["POST"])
@require_super_admin
def api_add_user():
    data = request.get_json()
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()
    role = data.get("role", "admin").strip()
    if not username or not password:
        return jsonify({"error": "username and password required"}), 400
    if role not in ("admin", "super_admin", "projects"):
        role = "admin"
    users = _load_users()
    users[username] = {"password": password, "role": role}
    _save_users(users)
    return jsonify({"success": True, "user": {"username": username, "role": role}})

@app.route("/api/users/<username>", methods=["DELETE"])
@require_super_admin
def api_delete_user(username):
    if username == "Sami":
        return jsonify({"error": "Cannot delete super admin"}), 400
    users = _load_users()
    if username in users:
        del users[username]
        _save_users(users)
    return jsonify({"success": True})

# ── PROPERTIES OVERVIEW ──
@app.route("/api/properties")
@require_auth
def api_properties():
    props = []
    ha = api_get("https://api.hostaway.com/v1/listings?limit=200",
                 {"Authorization": f"Bearer {get_hostaway_token()}"})
    if "result" in ha and isinstance(ha["result"], list):
        for l in ha["result"]:
            name = l.get("name","") or f"STR #{l.get('id')}"
            props.append({
                "id": f"str_{l.get('id')}", "name": name,
                "type": "STR", "brand": "Luna Rooms",
                "source": "hostaway", "status": l.get("status","active"),
                "address": l.get("locationAddress","") or "",
                "bedrooms": l.get("bedrooms",""), "max_guests": l.get("maximumNumberOfGuests","")
            })

    # HMO from Arthur
    tok = get_arthur_token()
    if tok:
        ar = api_get(f"https://api.arthuronline.co.uk/v2/units?limit=200",
                     {"Authorization": f"Bearer {tok}", "X-EntityID": "349912", "User-Agent": "Mozilla/5.0"})
        if "error" not in ar:
            items = ar.get("data", []) if isinstance(ar, dict) else (ar if isinstance(ar, list) else [])
            for u in items:
                props.append({
                    "id": f"hmo_{u.get('id')}", "name": u.get("name","") or f"HMO #{u.get('id')}",
                    "type": "HMO", "brand": "Banksia",
                    "source": "arthur", "status": u.get("status","active"),
                    "address": u.get("address","") or "",
                    "unit_ref": u.get("unit_ref","") or ""
                })

    # Detect Hybrids
    str_names = {p["name"].lower().strip() for p in props if p["type"] == "STR"}
    hmo_names = {p["name"].lower().strip() for p in props if p["type"] == "HMO"}
    hybrids = str_names & hmo_names
    for p in props:
        if p["name"].lower().strip() in hybrids:
            p["type"] = "Hybrid"

    # Brand refinement
    for p in props:
        n = p["name"].lower()
        if "banksia" in n: p["brand"] = "Banksia"
        elif "luna" in n or "lake" in n or "canary" in n or "angel" in n or "studd" in n or "west" in n: p["brand"] = "Luna Rooms"

    return jsonify({"properties": props, "total": len(props)})

# ── STR ──
@app.route("/api/str/arrivals")
@require_auth
def api_str_arrivals():
    today = datetime.now().strftime("%Y-%m-%d")
    r = api_get(f"https://api.hostaway.com/v1/reservations?checkIn={today}&limit=100",
                {"Authorization": f"Bearer {get_hostaway_token()}"})
    if "error" in r: return jsonify(r)
    arrivals = []
    if "result" in r and isinstance(r["result"], list):
        for res in r["result"]:
            arrivals.append({
                "id": res.get("id"), "guest": res.get("guestName",""),
                "listing": res.get("listingTitle","") or res.get("listingName",""), "listing_id": res.get("listingId",""),
                "check_in": res.get("checkIn",""), "check_out": res.get("checkOut",""),
                "status": res.get("status",""), "source": res.get("channelName",""),
                "total_price": res.get("totalPrice","")
            })
    return jsonify({"arrivals": arrivals, "count": len(arrivals)})

@app.route("/api/str/departures")
@require_auth
def api_str_departures():
    today = datetime.now().strftime("%Y-%m-%d")
    r = api_get(f"https://api.hostaway.com/v1/reservations?checkOut={today}&limit=100",
                {"Authorization": f"Bearer {get_hostaway_token()}"})
    if "error" in r: return jsonify(r)
    deps = []
    if "result" in r and isinstance(r["result"], list):
        for res in r["result"]:
            deps.append({
                "id": res.get("id"), "guest": res.get("guestName",""),
                "listing": res.get("listingTitle","") or res.get("listingName",""), "check_out": res.get("checkOut",""),
                "status": res.get("status","")
            })
    return jsonify({"departures": deps, "count": len(deps)})

@app.route("/api/str/reservations")
@require_auth
def api_str_reservations():
    params = {}
    if request.args.get("listingId"): params["listingId"] = request.args["listingId"]
    if request.args.get("status"): params["status"] = request.args["status"]
    params["limit"] = request.args.get("limit","200")
    qs = "&".join(f"{k}={v}" for k,v in params.items())
    r = api_get(f"https://api.hostaway.com/v1/reservations?{qs}",
                {"Authorization": f"Bearer {get_hostaway_token()}"})
    return jsonify(r)

@app.route("/api/str/listings")
@require_auth
def api_str_listings():
    r = api_get("https://api.hostaway.com/v1/listings?limit=200",
                {"Authorization": f"Bearer {get_hostaway_token()}"})
    if "error" in r: return jsonify(r)
    listings = []
    if "result" in r and isinstance(r["result"], list):
        for l in r["result"]:
            listings.append({
                "id": l.get("id"), "name": l.get("name","") or l.get("title",""),
                "status": l.get("status",""), "max_guests": l.get("maximumNumberOfGuests",""),
                "bedrooms": l.get("bedrooms",""), "bathrooms": l.get("bathrooms",""),
                "address": l.get("locationAddress",""), "city": l.get("locationCity","")
            })
    return jsonify({"listings": listings, "count": len(listings)})

# ── HMO ──
@app.route("/api/hmo/tenants")
@require_auth
def api_hmo_tenants():
    tok = get_arthur_token()
    if not tok: return jsonify({"error":"Arthur token unavailable"})
    r = api_get(f"https://api.arthuronline.co.uk/v2/tenancies?status=active,periodic&limit=200",
                {"Authorization": f"Bearer {tok}", "X-EntityID": "349912", "User-Agent": "Mozilla/5.0"})
    if "error" in r: return jsonify(r)
    # Arthur returns {status: 200, data: [...], pagination: {...}}
    items = r.get("data", []) if isinstance(r, dict) else (r if isinstance(r, list) else [])
    tenants = []
    for t in items:
        tn = ""
        if t.get("tenancy_tenants") and len(t["tenancy_tenants"])>0:
            p = t["tenancy_tenants"][0].get("person",{})
            tn = f"{p.get('forename','')} {p.get('surname','')}".strip()
        un = ""
        if t.get("unit"): un = t["unit"].get("name","") or t["unit"].get("address","")
        tenants.append({
            "id": t.get("id"), "tenant_name": tn, "property": un,
            "unit_id": t.get("unit_id",""), "rent_amount": t.get("rent_amount",""),
            "rent_frequency": t.get("rent_frequency",""),
            "start_date": t.get("start_date",""), "end_date": t.get("end_date",""),
            "status": t.get("status","")
        })
    return jsonify({"tenants": tenants, "count": len(tenants)})

@app.route("/api/hmo/properties")
@require_auth
def api_hmo_properties():
    tok = get_arthur_token()
    if not tok: return jsonify({"error":"Arthur token unavailable"})
    r = api_get("https://api.arthuronline.co.uk/v2/units?limit=200",
                {"Authorization": f"Bearer {tok}", "X-EntityID": "349912", "User-Agent": "Mozilla/5.0"})
    if "error" in r: return jsonify(r)
    items = r.get("data", []) if isinstance(r, dict) else (r if isinstance(r, list) else [])
    return jsonify({"properties": items, "count": len(items)})

# ── MAINTENANCE ──
@app.route("/api/maintenance")
@require_auth
def api_maintenance():
    """Get maintenance jobs from Monday.com boards."""
    mtok = get_monday_token()
    maint = []

    if mtok:
        # Maintenance Reports board (ID: 18401159622)
        # Property Operations board (ID: 18414266997)
        for board_id, board_name in [("18401159622","Maintenance Reports"), ("18414266997","Property Operations")]:
            q = """{ boards(ids: [%s]) { id name items_page(limit:100) { items { id name column_values { id text } } } } }""" % board_id
            req = urllib.request.Request("https://api.monday.com/v2",
                data=json.dumps({"query": q}).encode(),
                headers={"Authorization": mtok, "Content-Type": "application/json"})
            try:
                with urllib.request.urlopen(req, timeout=15) as r:
                    data = json.loads(r.read())
                    if "data" in data and data["data"].get("boards"):
                        board = data["data"]["boards"][0]
                        for item in board.get("items_page",{}).get("items",[]):
                            cols = {}
                            for cv in item.get("column_values",[]):
                                cols[cv.get("id","")] = cv.get("text","")
                            maint.append({
                                "id": item.get("id"),
                                "title": item.get("name",""),
                                "board": board_name,
                                "status": cols.get("status","") or cols.get("color_mm0p8qna","") or "",
                                "priority": cols.get("color_mm0p8qna","") or "",
                                "assigned": cols.get("multiple_person_mm1qbn2c","") or cols.get("person","") or "",
                                "date_raised": cols.get("date4","") or "",
                                "type": cols.get("color_mm0vfxmq","") or "",
                                "property": ""
                            })
            except: pass

    return jsonify({"maintenance": maint, "count": len(maint)})

# ── DASHBOARD SUMMARY ──
@app.route("/api/summary")
@require_auth
def api_summary():
    """Return summary counts for dashboard header."""
    s = {"str": {"listings":0,"arrivals":0,"departures":0},
         "hmo": {"properties":0,"tenants":0},
         "maint": {"jobs":0}}
    
    ha = api_get("https://api.hostaway.com/v1/listings?limit=200",
                 {"Authorization": f"Bearer {get_hostaway_token()}"})
    if "result" in ha and isinstance(ha["result"], list):
        s["str"]["listings"] = len(ha["result"])
    
    today = datetime.now().strftime("%Y-%m-%d")
    ar = api_get(f"https://api.hostaway.com/v1/reservations?checkIn={today}&limit=200",
                 {"Authorization": f"Bearer {get_hostaway_token()}"})
    if "result" in ar and isinstance(ar["result"], list):
        s["str"]["arrivals"] = len(ar["result"])
    
    dp = api_get(f"https://api.hostaway.com/v1/reservations?checkOut={today}&limit=200",
                 {"Authorization": f"Bearer {get_hostaway_token()}"})
    if "result" in dp and isinstance(dp["result"], list):
        s["str"]["departures"] = len(dp["result"])
    
    return jsonify(s)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5050, debug=False)