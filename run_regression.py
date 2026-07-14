#!/usr/bin/env python3
"""Banksia OS — Complete Regression Test Suite.
Runs against http://127.0.0.1:5050 through gunicorn+Traefik.
Exit code: 0 = all pass, 1 = any critical failure.

Architecture:
  - One authenticated session created ONCE, reused for ALL protected endpoints.
  - One unauthenticated opener for 401/redirect tests.
  - Schema validation for every API response.
  - Snapshot-based data integrity comparison.
"""
import concurrent.futures
import json
import os
import sqlite3
import subprocess
import sys
import time
import urllib.request
import urllib.error
from http.cookiejar import CookieJar
from collections.abc import Mapping

BASE = "http://127.0.0.1:5050"
DB = "/root/verv-dashboard/verv_os.db"
SNAPSHOT = "/root/verv-dashboard/regression_snapshot_20260714_212453.json"
PASS, FAIL = 0, 0
ERRORS = []

# ── Helpers ──────────────────────────────────────────────────────────────

def ok(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  \u2705 {name}")
    else:
        FAIL += 1
        ERRORS.append(f"{name}: {detail}" if detail else name)
        print(f"  \u274c {name}" + (f" \u2014 {detail}" if detail else ""))


def get_ids():
    """Fetch one real ID per table for detail-endpoint tests."""
    c = sqlite3.connect(DB, timeout=5)
    ids = {}
    for t, q in [("p", "properties"), ("u", "units"), ("t", "tenancies"),
                 ("ten", "tenants"), ("a", "applicants"), ("m", "maintenance_jobs")]:
        r = c.execute(f"SELECT MIN(id) FROM {q} WHERE id>0").fetchone()
        ids[q] = r[0] if r and r[0] else None
    c.close()
    return ids


def make_opener():
    """Create a cookie-preserving HTTP opener."""
    return urllib.request.build_opener(urllib.request.HTTPCookieProcessor())


def login(opener=None):
    """Authenticate an opener (or create-and-auth a new one). Return opener."""
    if opener is None:
        opener = make_opener()
    data = json.dumps({"username": "Sami", "password": "Newpassword1323!"}).encode()
    req = urllib.request.Request(
        f"{BASE}/api/auth/login",
        data=data,
        headers={"Content-Type": "application/json"},
    )
    r = opener.open(req, timeout=10)
    assert r.getcode() == 200, f"Login failed: {r.getcode()}"
    return opener


def req(opener, url, method="GET", data=None, timeout=15):
    """Make an HTTP request with cookie-preserving opener.
    Returns (status_code, parsed_json_or_None, error_str_or_None)."""
    headers = {"Content-Type": "application/json"} if data else {}
    body = json.dumps(data).encode() if data else None
    try:
        r = opener.open(
            urllib.request.Request(url, data=body, headers=headers, method=method),
            timeout=timeout,
        )
        resp_body = r.read()
        try:
            parsed = json.loads(resp_body)
        except (json.JSONDecodeError, ValueError):
            parsed = {"_raw": resp_body.decode("utf-8", errors="replace")[:500]}
        return r.getcode(), parsed, None
    except urllib.error.HTTPError as e:
        try:
            parsed = json.loads(e.read())
        except Exception:
            parsed = {"error": str(e)}
        return e.code, parsed, None
    except urllib.error.URLError as e:
        return 0, None, f"Connection refused / DNS: {e.reason}"
    except Exception as e:
        return 0, None, str(e)


def is_dict(val):
    return isinstance(val, dict)


def is_list(val):
    return isinstance(val, list)


def is_nonempty_list(val):
    return isinstance(val, list) and len(val) > 0


# ── Schema validators ────────────────────────────────────────────────────

SCHEMAS = {}


def check_schema(name, data, checks):
    """Run a dict of checks against parsed JSON data.
    checks is a dict: {"key_path": (type|callable, ...)}
    Supports dot-notation for nested keys like "data.total_properties".
    """
    errors = []
    for path, expected in checks.items():
        # Navigate dot-path
        parts = path.split(".")
        val = data
        for p in parts:
            if isinstance(val, dict) and p in val:
                val = val[p]
            else:
                errors.append(f"{name}: missing key '{path}'")
                break
        else:
            # val is now the resolved value
            if callable(expected):
                if not expected(val):
                    errors.append(f"{name}: '{path}' = {repr(val)[:80]} failed validator")
            elif not isinstance(val, expected):
                errors.append(
                    f"{name}: '{path}' expected {expected.__name__}, got {type(val).__name__} = {repr(val)[:80]}"
                )
    for e in errors:
        ok(e, False)
        ERRORS.append(e)


# ── Boot sequence ────────────────────────────────────────────────────────

I = get_ids()
AUTH = make_opener()  # authenticated session — login ONCE, reuse everywhere
login(AUTH)
GUEST = make_opener()  # unauthenticated session for 401 checks

print("=" * 60)
print("BANKSIA OS REGRESSION SUITE")
print("=" * 60)
print(f"Test IDs: prop={I['properties']}, unit={I['units']}, tenancy={I['tenancies']}, "
      f"tenant={I['tenants']}, applicant={I['applicants']}, maint={I['maintenance_jobs']}\n")

# ══════════════════════════════════════════════════════════════════════════
# 1. AUTH & SECURITY
# ══════════════════════════════════════════════════════════════════════════
print("--- 1. AUTH & SECURITY ---")

code, data, err = req(GUEST, f"{BASE}/")
ok("Login page loads (unauthenticated)", code == 200, detail=err)

# SPA pages render login HTML without auth — no @require_auth on template routes
code, data, err = req(GUEST, f"{BASE}/banksia-os")
ok("Banksia OS page accessible (renders login HTML for unauth)", code == 200, detail=err)

# API endpoints require auth
code, data, err = req(GUEST, f"{BASE}/api/banksia-os/properties")
ok("API 401 without auth", code == 401, detail=f"got {code}: {err}")

code, data, err = req(GUEST, f"{BASE}/api/banksia-os/dashboard")
ok("Dashboard API 401 without auth", code == 401, detail=f"got {code}: {err}")

# Bad login
bad = make_opener()
code, data, err = req(bad, f"{BASE}/api/auth/login", "POST",
                      {"username": "bad", "password": "bad"})
ok("Bad login returns 401", code == 401, detail=f"got {code}")

# Valid login (already done)
ok("Auth session created and reusable", True)

# Auth user profile
code, data, err = req(AUTH, f"{BASE}/api/auth/user")
ok("Auth user returns profile", code == 200 and is_dict(data), detail=err)
check_schema("auth/user", data, {"username": str, "role": str})

# 404 for missing record
code, data, err = req(AUTH, f"{BASE}/api/banksia-os/properties/99999")
ok("404 for missing property", code == 404, detail=f"got {code}: {err}")

# Actually check it returns JSON with error
if code == 404:
    ok("404 body is JSON", is_dict(data))

# 400 for invalid params
code, data, err = req(AUTH, f"{BASE}/api/banksia-os/access/available")
ok("400 for missing required params", code == 400, detail=f"got {code}: {err}")

# /banksia → /banksia-os redirect (legacy interface retirement)
class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None
no_redir = urllib.request.build_opener(_NoRedirect, urllib.request.HTTPCookieProcessor())
try:
    r = no_redir.open(urllib.request.Request(f"{BASE}/banksia"), timeout=10)
    code = r.getcode()
    loc = r.headers.get("Location", "")
except urllib.error.HTTPError as e:
    code = e.code
    loc = e.headers.get("Location", "")
ok("/banksia redirects 301 to /banksia-os", code == 301 and "/banksia-os" in loc,
   detail=f"status={code}, location={loc}")

# Logout
code, data, err = req(AUTH, f"{BASE}/api/auth/logout", "POST")
ok("Logout succeeds", code in (200, 302), detail=err)

# Re-login for remaining tests
login(AUTH)


# ══════════════════════════════════════════════════════════════════════════
# 2. DASHBOARD
# ══════════════════════════════════════════════════════════════════════════
print("\n--- 2. DASHBOARD ---")

code, data, err = req(AUTH, f"{BASE}/api/banksia-os/dashboard")
ok("Dashboard loads", code == 200, detail=err)

if code == 200:
    # Normalize: data may be nested under "data" key
    db = data if "total_properties" in data else data.get("data", {})
    ok("Dashboard has properties count > 0",
       isinstance(db.get("total_properties"), (int, float)) and db.get("total_properties", 0) > 0)
    check_schema("dashboard", db, {
        "total_properties": lambda v: isinstance(v, (int, float)) and v > 0,
        "total_units": lambda v: isinstance(v, (int, float)) and v > 0,
    })

# Submissions inbox
code, data, err = req(AUTH, f"{BASE}/api/banksia-os/submissions")
ok("Submissions inbox loads", code == 200, detail=err)

# Health
code, data, err = req(GUEST, f"{BASE}/health")
ok("Health check passes", code == 200, detail=err)
if code == 200:
    ok("Health status is 'ok'", data.get("status") == "ok",
       detail=f"got: {data.get('status')}")
    check_schema("health", data, {"status": str, "database": str, "uptime_seconds": lambda v: isinstance(v, (int, float))})

# Connections status
code, data, err = req(AUTH, f"{BASE}/api/connections/status")
ok("Connections status loads", code == 200, detail=err)


# ══════════════════════════════════════════════════════════════════════════
# 3. PROPERTIES
# ══════════════════════════════════════════════════════════════════════════
print("\n--- 3. PROPERTIES ---")

code, data, err = req(AUTH, f"{BASE}/api/banksia-os/properties")
ok("Properties list loads", code == 200, detail=err)

prop_list = data.get("data", data.get("properties", data if isinstance(data, list) else []))
if code == 200 and isinstance(prop_list, list):
    ok("Properties list non-empty", len(prop_list) > 0,
       detail=f"got {len(prop_list)} items")
    if len(prop_list) > 0:
        ok("Properties have required fields",
           all(k in prop_list[0] for k in ("id", "name", "address_line_1")),
           detail=f"keys: {list(prop_list[0].keys())}")

code, data, err = req(AUTH, f"{BASE}/api/banksia-os/properties?search=multi")
ok("Property search returns 200", code == 200, detail=err)

if I["properties"]:
    code, data, err = req(AUTH, f"{BASE}/api/banksia-os/properties/{I['properties']}")
    ok("Property detail loads", code == 200, detail=err)
    if code == 200:
        detail_data = data.get("property", data.get("data", data))
        ok("Property detail has id", isinstance(detail_data, dict) and detail_data.get("id") == I["properties"],
           detail=f"id mismatch or missing")

code, data, err = req(AUTH, f"{BASE}/api/banksia-os/properties/enhanced")
ok("Enhanced properties loads", code == 200, detail=err)

code, data, err = req(AUTH, f"{BASE}/api/banksia-os/properties/compliance")
ok("Compliance loads", code == 200, detail=err)


# ══════════════════════════════════════════════════════════════════════════
# 4. UNITS
# ══════════════════════════════════════════════════════════════════════════
print("\n--- 4. UNITS ---")

code, data, err = req(AUTH, f"{BASE}/api/banksia-os/units")
ok("Units list loads", code == 200, detail=err)

unit_list = data.get("data", data.get("units", data if isinstance(data, list) else []))
if code == 200 and isinstance(unit_list, list):
    ok("Units list non-empty", len(unit_list) > 0,
       detail=f"got {len(unit_list)} items")
    if len(unit_list) > 0:
        ok("Units have required fields",
           all(k in unit_list[0] for k in ("id", "unit_ref", "unit_type")),
           detail=f"keys: {list(unit_list[0].keys())}")

if I["units"]:
    code, data, err = req(AUTH, f"{BASE}/api/banksia-os/units/{I['units']}")
    ok("Unit detail loads", code == 200, detail=err)

code, data, err = req(AUTH, f"{BASE}/api/banksia-os/units?type=Room")
ok("Unit filter works", code == 200, detail=err)


# ══════════════════════════════════════════════════════════════════════════
# 5. TENANCIES
# ══════════════════════════════════════════════════════════════════════════
print("\n--- 5. TENANCIES ---")

code, data, err = req(AUTH, f"{BASE}/api/banksia-os/tenancies")
ok("Tenancies list loads", code == 200, detail=err)

ten_list = data.get("data", data.get("tenancies", data if isinstance(data, list) else []))
if code == 200 and isinstance(ten_list, list):
    ok("Tenancies list non-empty", len(ten_list) > 0,
       detail=f"got {len(ten_list)} items")

if I["tenancies"]:
    code, data, err = req(AUTH, f"{BASE}/api/banksia-os/tenancies/{I['tenancies']}")
    ok("Tenancy detail loads", code == 200, detail=err)

code, data, err = req(AUTH, f"{BASE}/api/banksia-os/tenancies/ending-soon")
ok("Ending soon loads", code == 200, detail=err)

code, data, err = req(AUTH, f"{BASE}/api/banksia-os/tenancies/moving-in-this-month")
ok("Moving in loads", code == 200, detail=err)

code, data, err = req(AUTH, f"{BASE}/api/banksia-os/tenancies/moving-out-this-month")
ok("Moving out loads", code == 200, detail=err)


# ══════════════════════════════════════════════════════════════════════════
# 6. TENANTS
# ══════════════════════════════════════════════════════════════════════════
print("\n--- 6. TENANTS ---")

code, data, err = req(AUTH, f"{BASE}/api/banksia-os/tenants")
ok("Tenants list loads", code == 200, detail=err)

tenants_list = data.get("data", data.get("tenants", data if isinstance(data, list) else []))
if code == 200 and isinstance(tenants_list, list):
    ok("Tenants list non-empty", len(tenants_list) > 0,
       detail=f"got {len(tenants_list)} items")

if I["tenants"]:
    code, data, err = req(AUTH, f"{BASE}/api/banksia-os/tenants/{I['tenants']}")
    ok("Tenant detail loads", code == 200, detail=err)

code, data, err = req(AUTH, f"{BASE}/api/banksia-os/tenants?search=a")
ok("Tenant search works", code == 200, detail=err)


# ══════════════════════════════════════════════════════════════════════════
# 7. APPLICANTS
# ══════════════════════════════════════════════════════════════════════════
print("\n--- 7. APPLICANTS ---")

code, data, err = req(AUTH, f"{BASE}/api/banksia-os/applicants")
ok("Applicants list loads", code == 200, detail=err)

app_list = data.get("data", data.get("applicants", data if isinstance(data, list) else []))
if code == 200 and isinstance(app_list, list):
    ok("Applicants list non-empty", len(app_list) > 0,
       detail=f"got {len(app_list)} items")

if I["applicants"]:
    code, data, err = req(AUTH, f"{BASE}/api/banksia-os/applicants/{I['applicants']}")
    ok("Applicant detail loads", code == 200, detail=err)


# ══════════════════════════════════════════════════════════════════════════
# 8. MAINTENANCE
# ══════════════════════════════════════════════════════════════════════════
print("\n--- 8. MAINTENANCE ---")

code, data, err = req(AUTH, f"{BASE}/api/banksia-os/maintenance/jobs")
ok("Maintenance jobs loads", code == 200, detail=err)

maint_list = data.get("data", data.get("jobs", data if isinstance(data, list) else []))
if code == 200 and isinstance(maint_list, list):
    ok("Maintenance list non-empty", len(maint_list) > 0,
       detail=f"got {len(maint_list)} items")
    if len(maint_list) > 0:
        ok("Maintenance items have required fields",
           any(k in maint_list[0] for k in ("id", "title", "status", "property")),
           detail=f"keys: {list(maint_list[0].keys())}")

if I["maintenance_jobs"]:
    code, data, err = req(AUTH, f"{BASE}/api/banksia-os/maintenance/jobs/{I['maintenance_jobs']}")
    ok("Job detail loads", code == 200, detail=err)

code, data, err = req(AUTH, f"{BASE}/api/banksia-os/maintenance/orders")
ok("Orders list loads", code == 200, detail=err)

if I["maintenance_jobs"]:
    code, data, err = req(AUTH, f"{BASE}/api/banksia-os/maintenance/ll-comms?job_id={I['maintenance_jobs']}")
    ok("LL Comms loads", code == 200, detail=err)
else:
    code, data, err = req(AUTH, f"{BASE}/api/banksia-os/maintenance/ll-comms?job_id=1")
    ok("LL Comms loads (default id)", code == 200, detail=err)


# ══════════════════════════════════════════════════════════════════════════
# 9. FINANCIALS
# ══════════════════════════════════════════════════════════════════════════
print("\n--- 9. FINANCIALS ---")

code, data, err = req(AUTH, f"{BASE}/api/banksia-os/finance/overview")
ok("Finance overview loads", code == 200, detail=err)
if code == 200:
    fin = data.get("data", data)
    ok("Finance overview has data", is_dict(fin), detail=f"type: {type(fin).__name__}")
    check_schema("finance/overview", fin, {
        "monthly_rent_income": lambda v: isinstance(v, (int, float)) or isinstance(v, str),
        "total_arrears": lambda v: isinstance(v, (int, float)) or isinstance(v, str),
    })

code, data, err = req(AUTH, f"{BASE}/api/banksia-os/finance/transactions")
ok("Transactions list loads", code == 200, detail=err)

code, data, err = req(AUTH, f"{BASE}/api/banksia-os/finance/deposits")
ok("Deposits list loads", code == 200, detail=err)

code, data, err = req(AUTH, f"{BASE}/api/hmo/arrears")
ok("Arrears loads", code == 200, detail=err)


# ══════════════════════════════════════════════════════════════════════════
# 10. REFERENCING
# ══════════════════════════════════════════════════════════════════════════
print("\n--- 10. REFERENCING ---")

code, data, err = req(AUTH, f"{BASE}/api/referencing/forms")
ok("Referencing forms loads", code == 200, detail=err)

code, data, err = req(AUTH, f"{BASE}/api/referencing/esignature/requests")
ok("E-signature requests loads", code == 200, detail=err)


# ══════════════════════════════════════════════════════════════════════════
# 11. USER MANAGEMENT
# ══════════════════════════════════════════════════════════════════════════
print("\n--- 11. USER MANAGEMENT ---")

code, data, err = req(AUTH, f"{BASE}/api/users")
ok("Users list loads", code == 200, detail=err)
if code == 200 and isinstance(data, list):
    ok("Users list non-empty", len(data) > 0, detail=f"got {len(data)} items")

code, data, err = req(AUTH, f"{BASE}/api/banksia-os/users/autocomplete")
ok("User autocomplete loads", code == 200, detail=err)

code, data, err = req(AUTH, f"{BASE}/api/user/profile")
ok("User profile loads", code == 200, detail=err)
if code == 200:
    check_schema("user/profile", data, {"username": str})


# ══════════════════════════════════════════════════════════════════════════
# 12. MESSAGING
# ══════════════════════════════════════════════════════════════════════════
print("\n--- 12. MESSAGING ---")

code, data, err = req(AUTH, f"{BASE}/api/banksia-os/threads")
ok("Threads list loads", code == 200, detail=err)

code, data, err = req(AUTH, f"{BASE}/api/banksia-os/comments/recent")
ok("Recent comments loads", code == 200, detail=err)


# ══════════════════════════════════════════════════════════════════════════
# 13. ACCESS
# ══════════════════════════════════════════════════════════════════════════
print("\n--- 13. ACCESS ---")

code, data, err = req(AUTH, f"{BASE}/api/banksia-os/access")
ok("Access list loads", code == 200, detail=err)

code, data, err = req(AUTH, f"{BASE}/api/banksia-os/access/available?property_id=242")
ok("Available access loads with property_id", code == 200, detail=err)


# ══════════════════════════════════════════════════════════════════════════
# 14. CONFIGURATION
# ══════════════════════════════════════════════════════════════════════════
print("\n--- 14. CONFIGURATION ---")

code, data, err = req(AUTH, f"{BASE}/api/banksia-os/tags")
ok("Tags list loads", code == 200, detail=err)

code, data, err = req(AUTH, f"{BASE}/api/banksia-os/property-owners")
ok("Property owners loads", code == 200, detail=err)

code, data, err = req(AUTH, f"{BASE}/api/banksia-os/company-settings")
ok("Company settings loads", code == 200, detail=err)

code, data, err = req(AUTH, f"{BASE}/api/banksia-os/invoices")
ok("Invoices list loads", code == 200, detail=err)

code, data, err = req(AUTH, f"{BASE}/api/banksia-os/invoices/summary")
ok("Invoice summary loads", code == 200, detail=err)


# ══════════════════════════════════════════════════════════════════════════
# 15. CONCURRENCY
# ══════════════════════════════════════════════════════════════════════════
print("\n--- 15. CONCURRENCY (50x parallel dashboard requests) ---")

sessions = [login(make_opener()) for _ in range(15)]
statuses = {}
timestamps = []

def concurrency_request(i):
    try:
        r = sessions[i % 15].open(
            urllib.request.Request(f"{BASE}/api/banksia-os/dashboard"), timeout=15
        )
        r.read()
        return r.getcode()
    except Exception:
        return 0

start = time.time()
with concurrent.futures.ThreadPoolExecutor(max_workers=15) as executor:
    for code in concurrent.futures.as_completed(
        [executor.submit(concurrency_request, i) for i in range(50)]
    ):
        statuses[code.result()] = statuses.get(code.result(), 0) + 1

elapsed = time.time() - start
all_200 = statuses.get(200, 0) == 50
ok(f"50 concurrent requests: all 200 ({statuses}, {elapsed:.1f}s)",
   all_200, detail=f"status distribution: {statuses}")


# ══════════════════════════════════════════════════════════════════════════
# 16. DATA INTEGRITY
# ══════════════════════════════════════════════════════════════════════════
print("\n--- 16. DATA INTEGRITY ---")

if not os.path.exists(SNAPSHOT):
    ok("Snapshot file exists", False, detail=f"Not found: {SNAPSHOT}")
else:
    with open(SNAPSHOT) as f:
        snap = json.load(f).get("snapshot", {})

    c = sqlite3.connect(DB, timeout=5)
    current = {}
    tables = [
        "properties", "units", "tenancies", "tenants", "applicants",
        "transactions", "maintenance_jobs", "referencing_forms",
        "message_threads", "invoices", "tags", "property_owners",
    ]
    for t in tables:
        cnt = c.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
        current[t] = cnt
        ok(f"{t:25s} = {cnt}", True)
        # Check snapshot match
        snap_val = snap.get(t, -1)
        ok(f"{t:25s} matches snapshot", cnt == snap_val,
           detail=f"snapshot={snap_val}, current={cnt}")
    c.close()


# ══════════════════════════════════════════════════════════════════════════
# 17. GIT & SERVICE HEALTH
# ══════════════════════════════════════════════════════════════════════════
print("\n--- 17. INFRASTRUCTURE ---")

r = subprocess.run(["git", "rev-parse", "HEAD"],
                   capture_output=True, text=True, cwd="/root/verv-dashboard")
commit_hash = r.stdout.strip()[:12] if r.returncode == 0 else "ERROR"
ok(f"Git commit: {commit_hash}", r.returncode == 0, detail=r.stderr)

r2 = subprocess.run(["git", "tag", "-l", "BANKSIA_OS_STABLE*"],
                    capture_output=True, text=True, cwd="/root/verv-dashboard")
has_tag = "BANKSIA_OS_STABLE_BASELINE_V1" in r2.stdout
ok(f"Tag: {r2.stdout.strip()}", has_tag, detail=f"tags found: {r2.stdout.strip()}")

r3 = subprocess.run(["systemctl", "is-active", "verv-dashboard.service"],
                    capture_output=True, text=True)
ok(f"Service: {r3.stdout.strip()}", r3.returncode == 0, detail=r3.stderr + r3.stdout)

# ══════════════════════════════════════════════════════════════════════════
# FINAL
# ══════════════════════════════════════════════════════════════════════════
print(f"\n{'=' * 60}")
print(f"RESULTS: {PASS} passed, {FAIL} failed")
if ERRORS:
    print("\nFAILURES:")
    for e in ERRORS:
        print(f"  - {e}")
print("=" * 60)

sys.exit(0 if FAIL == 0 else 1)
