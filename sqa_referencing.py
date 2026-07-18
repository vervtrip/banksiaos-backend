#!/usr/bin/env python3
"""
Banksia OS — Referencing end-to-end SQA harness.
Drives the whole applicant → documents → AI review → e-signature → portal → financials
flow through Flask's test client. No network, no approval prompts. Clean pass/fail.
"""
import io, json, sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Keep the suite hermetic — no real emails dispatched during testing.
os.environ["REFERENCING_EMAIL_DRYRUN"] = "1"

import app as appmod
from banksia_os_db import get_db

PASS, FAIL = [], []
def ok(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(f"{'✅' if cond else '❌'} {name}" + (f"  — {detail}" if detail and not cond else ""))
    return cond

client = appmod.app.test_client()   # team (dashboard) — has session
aclient = appmod.app.test_client()  # applicant — NO session, token-only

# Team session (simulates a logged-in dashboard user)
with client.session_transaction() as s:
    s["user"] = "sqa_tester"

# ── 1. Create form (team) ──
r = client.post("/api/referencing/forms", json={
    "first_name": "Test", "last_name": "Applicant", "email": "sqa.applicant@example.com"
})
d = r.get_json() or {}
form = (d.get("data") or {})
form_id = form.get("id"); form_token = form.get("form_token")
ok("create form", r.status_code == 200 and form_id and form_token, f"{r.status_code} {d.get('error')}")

# ── 2. List forms (team) ──
r = client.get("/api/referencing/forms")
d = r.get_json() or {}
ok("list forms", r.status_code == 200 and isinstance(d.get("data"), list), f"{r.status_code} {d.get('error')}")

# ── 3. Get form by token (applicant, no team session) ──
r = aclient.get(f"/api/referencing/forms/{form_id}?token={form_token}")
d = r.get_json() or {}
ok("get form by token", r.status_code == 200 and d.get("data", {}).get("form", {}).get("id") == form_id, f"{r.status_code} {d.get('error')}")

# ── 3b. Reject wrong token ──
r = aclient.get(f"/api/referencing/forms/{form_id}?token=WRONG")
ok("reject bad token (401)", r.status_code == 401, f"got {r.status_code}")

# ── 4. Applicant fills fields via token ──
r = aclient.patch(f"/api/referencing/forms/{form_id}?token={form_token}", json={
    "date_of_birth": "1990-05-01", "gender": "Male", "mobile_phone": "07700900123",
    "current_address_line1": "1 Test Road", "current_city": "London", "current_postcode": "N1 1AA",
    "employment_status": "Employed", "employer_name": "Acme Ltd", "annual_salary": "36000",
    "ni_number": "AB123456C", "nationality": "British",
    "bank_name": "Barclays", "bank_sort_code": "20-00-00", "bank_account_number": "12345678",
})
d = r.get_json() or {}
ok("applicant patch fields", r.status_code == 200 and d.get("data", {}).get("employer_name") == "Acme Ltd", f"{r.status_code} {d.get('error')}")

# ── 4b. Applicant cannot patch protected field (status) ──
r = aclient.patch(f"/api/referencing/forms/{form_id}?token={form_token}", json={"status": "approved", "first_name": "Test"})
d = r.get_json() or {}
# status is not in allowed set → filtered out; first_name still applies
ok("applicant cannot set status", d.get("data", {}).get("status") != "approved", "status leaked")

# ── 5. Submit blocked without declaration ──
r = aclient.post(f"/api/referencing/forms/{form_id}/submit", json={"token": form_token})
ok("submit blocked w/o declaration (400)", r.status_code == 400, f"got {r.status_code}")

# confirm declaration then submit
aclient.patch(f"/api/referencing/forms/{form_id}?token={form_token}", json={"declaration_confirmed": 1})
r = aclient.post(f"/api/referencing/forms/{form_id}/submit", json={"token": form_token})
d = r.get_json() or {}
ok("submit form", r.status_code == 200 and d.get("data", {}).get("status") == "submitted", f"{r.status_code} {d.get('error')}")

# ── 5b. Cannot patch after submit ──
r = aclient.patch(f"/api/referencing/forms/{form_id}?token={form_token}", json={"employer_name": "Changed"})
ok("locked after submit (400)", r.status_code == 400, f"got {r.status_code}")

# ── 6. Upload a document (team) — small valid PDF ──
pdf_bytes = b"%PDF-1.4\n1 0 obj<</Type/Catalog>>endobj\ntrailer<</Root 1 0 R>>\n%%EOF"
r = client.post("/api/referencing/documents/upload", data={
    "form_id": str(form_id), "category": "payslip",
    "file": (io.BytesIO(pdf_bytes), "payslip_march.pdf"),
}, content_type="multipart/form-data")
d = r.get_json() or {}
doc_id = (d.get("data") or {}).get("id")
ok("upload document", r.status_code == 200 and doc_id, f"{r.status_code} {d.get('error')}")

# upload a bank statement too (for cross-ref)
client.post("/api/referencing/documents/upload", data={
    "form_id": str(form_id), "category": "bank_statement",
    "file": (io.BytesIO(pdf_bytes), "bank_march.pdf"),
}, content_type="multipart/form-data")

# ── 6b. Upload a REALISTIC payslip PDF (name + consistent figures) to exercise analysis ──
def make_pdf(lines):
    import fitz
    doc = fitz.open(); pg = doc.new_page(); y = 60
    for ln in lines:
        pg.insert_text((50, y), ln, fontsize=11); y += 18
    buf = doc.tobytes(); doc.close(); return buf

# declared salary was 36000/yr → ~3000/mo gross. Payslip shows consistent figures.
payslip_pdf = make_pdf([
    "ACME LTD — PAYSLIP", "Employee: Test Applicant", "NI Number: AB123456C",
    "Tax Period: 01", "Gross Pay: £3,000.00", "PAYE Tax: £389.00",
    "National Insurance: £250.00", "Net Pay: £2,361.00",
])
r = client.post("/api/referencing/documents/upload", data={
    "form_id": str(form_id), "category": "payslip",
    "file": (io.BytesIO(payslip_pdf), "payslip_real.pdf"),
}, content_type="multipart/form-data")
ok("upload realistic payslip", r.status_code == 200, f"{r.status_code}")

# ── 7. AI review whole form ──
r = client.post(f"/api/referencing/forms/{form_id}/ai-review")
d = r.get_json() or {}
data = d.get("data") or {}
ok("AI review form", r.status_code == 200 and len(data.get("documents_analysed", [])) >= 1 and len(data.get("checks", [])) >= 3, f"{r.status_code} {d.get('error')}")

# The realistic payslip should: find the applicant name, confirm type, extract £ figures
pay_an = next((x["analysis"] for x in data.get("documents_analysed", []) if x["filename"] == "payslip_real.pdf"), {})
ok("payslip: name matched", pay_an.get("extracted", {}).get("applicant_name_found") is True, f"{pay_an.get('summary')}")
ok("payslip: type confirmed", "gross pay" in (pay_an.get("extracted", {}).get("type_markers_found") or []) or "net pay" in (pay_an.get("extracted", {}).get("type_markers_found") or []), f"{pay_an.get('extracted',{}).get('type_markers_found')}")
ok("payslip: figures extracted", pay_an.get("extracted", {}).get("max_amount_gbp", 0) >= 3000, f"{pay_an.get('extracted',{}).get('amounts_gbp')}")

# Income cross-check should PASS (3000/mo consistent with 36000/yr declared)
income = next((c for c in data.get("checks", []) if c["type"] == "income_check"), {})
ok("income cross-check passed", income.get("status") == "passed", f"status={income.get('status')} :: {income.get('summary')}")

# ── 8. Team approve/reject (the placeholder-count bug) ──
r = client.patch(f"/api/referencing/forms/{form_id}/status", json={"status": "under_review", "notes": "looks ok"})
d = r.get_json() or {}
ok("team set status", r.status_code == 200 and d.get("data", {}).get("status") == "under_review", f"{r.status_code} {d.get('error')}")

# ── 9. E-signature create ──
r = client.post("/api/referencing/esignature/create", json={
    "form_id": form_id, "document_type": "tenancy_agreement",
    "document_title": "AST — Test Applicant", "signer_name": "Test Applicant",
    "signer_email": "sqa.applicant@example.com",
})
d = r.get_json() or {}
req = d.get("data") or {}
req_id = req.get("id"); signer_token = req.get("signer_token")
ok("esign create", r.status_code == 200 and req_id and signer_token, f"{r.status_code} {d.get('error')}")

# ── 10. Send ──
r = client.post(f"/api/referencing/esignature/{req_id}/send")
d = r.get_json() or {}
ok("esign send", r.status_code == 200 and d.get("data", {}).get("status") == "sent", f"{r.status_code} {d.get('error')}")

# ── 11. View (signer, GET by token) ──
r = client.get(f"/api/referencing/esignature/sign/{signer_token}")
d = r.get_json() or {}
ok("esign view", r.status_code == 200 and d.get("data", {}).get("status") == "viewed", f"{r.status_code} {d.get('error')}")

# ── 12. Sign (POST) → generates PDF ──
r = client.post(f"/api/referencing/esignature/sign/{signer_token}", json={
    "consent": True, "signature": "Test Applicant",
})
d = r.get_json() or {}
ok("esign sign", r.status_code == 200 and d.get("data", {}).get("status") == "completed", f"{r.status_code} {d.get('error')}")

# verify the signed PDF actually landed on disk
db = get_db()
row = db.execute("SELECT pdf_signed_path FROM esignature_requests WHERE id=?", [req_id]).fetchone()
pdf_path = row[0] if row else None
ok("signed PDF on disk", pdf_path and os.path.exists(pdf_path) and os.path.getsize(pdf_path) > 500, f"path={pdf_path}")

# ── 12b. Cannot sign twice ──
r = client.post(f"/api/referencing/esignature/sign/{signer_token}", json={"consent": True, "signature": "x"})
ok("cannot re-sign (400)", r.status_code == 400, f"got {r.status_code}")

# ── 13. Audit trail ──
r = client.get(f"/api/referencing/esignature/{req_id}/audit")
d = r.get_json() or {}
events = [a.get("event_type") for a in (d.get("data", {}).get("audit_log") or [])]
ok("audit trail complete", r.status_code == 200 and {"created","emailed","viewed","signed","completed"}.issubset(set(events)), f"events={events}")

# ── 13b. Email delivery: (re)send referencing form link (team) ──
r = client.post(f"/api/referencing/forms/{form_id}/send-link")
d = r.get_json() or {}
ok("form link emailed", r.status_code == 200 and str(d.get("delivery","")).startswith("missive 2"), f"{r.status_code} {d.get('error')} delivery={d.get('delivery')}")

# ── 13c. E-sign one-step create & send (team) ──
r = client.post("/api/referencing/esignature/create", json={
    "form_id": form_id, "document_type": "guarantor_agreement",
    "document_title": "Guarantor Agreement", "signer_name": "Test Guarantor",
    "signer_email": "sqa.guarantor@example.com", "send": True,
})
d = r.get_json() or {}
ok("esign create+send", r.status_code == 200 and d.get("data", {}).get("status") == "sent" and str(d.get("delivery","")).startswith("missive 2"), f"{r.status_code} {d.get('error')} delivery={d.get('delivery')}")

# ── 13d. Portal registration (form-token gated + auto-login) ──
# clean any prior account so registration is exercised fresh
db.execute("DELETE FROM portal_users WHERE email=?", ["sqa.applicant@example.com"]); db.commit()
r = aclient.post("/api/referencing/portal/register", json={"form_token": form_token, "password": "short"})
ok("register rejects weak pw (400)", r.status_code == 400)
r = aclient.post("/api/referencing/portal/register", json={"form_token": form_token, "email": "wrong@example.com", "password": "GoodPass123"})
ok("register rejects email mismatch", r.status_code == 400)
r = aclient.post("/api/referencing/portal/register", json={"form_token": "BADTOKEN", "password": "GoodPass123"})
ok("register rejects bad token (404)", r.status_code == 404)
r = aclient.post("/api/referencing/portal/register", json={"form_token": form_token, "password": "GoodPass123"})
d = r.get_json() or {}
reg_token = (d.get("data") or {}).get("token")
ok("register success + auto-login", r.status_code == 200 and bool(reg_token) and d.get("data", {}).get("user", {}).get("email") == "sqa.applicant@example.com", f"{r.status_code} {d.get('error')}")
# session from registration should work against /me
r = aclient.get("/api/referencing/portal/me", headers={"Authorization": "Bearer " + (reg_token or "")})
ok("register session valid on /me", r.status_code == 200 and (r.get_json() or {}).get("data", {}).get("profile", {}).get("email") == "sqa.applicant@example.com", f"{r.status_code}")
r = aclient.post("/api/referencing/portal/register", json={"form_token": form_token, "password": "GoodPass123"})
ok("register rejects duplicate (409)", r.status_code == 409, f"{r.status_code}")

# ── 14. Portal: create a user, login, /me ──
from referencing_api import hash_password
db.execute("DELETE FROM portal_users WHERE email=?", ["sqa.applicant@example.com"])
db.execute(
    "INSERT INTO portal_users (email, password_hash, first_name, last_name, portal_type, is_active) VALUES (?,?,?,?,?,1)",
    ["sqa.applicant@example.com", hash_password("Test1234!"), "Test", "Applicant", "applicant"]
)
db.commit()
r = client.post("/api/referencing/portal/login", json={"email": "sqa.applicant@example.com", "password": "Test1234!"})
d = r.get_json() or {}
ptoken = (d.get("data") or {}).get("token")
ok("portal login", r.status_code == 200 and ptoken, f"{r.status_code} {d.get('error')}")

r = client.post("/api/referencing/portal/login", json={"email": "sqa.applicant@example.com", "password": "WRONG"})
ok("portal reject bad pw (401)", r.status_code == 401, f"got {r.status_code}")

r = client.get("/api/referencing/portal/me", headers={"Authorization": f"Bearer {ptoken}"})
d = r.get_json() or {}
data = d.get("data") or {}
ok("portal /me", r.status_code == 200 and data.get("profile", {}).get("email") == "sqa.applicant@example.com" and len(data.get("applications", [])) >= 1, f"{r.status_code} {d.get('error')}")

# ── 15. Financials ──
r = client.get("/api/referencing/financials/rent-summary")
d = r.get_json() or {}
ok("financials rent-summary", r.status_code == 200 and "total_monthly_rent" in (d.get("data") or {}), f"{r.status_code} {d.get('error')}")

# ── 15b. TENANCY CREATION (Arthur replacement) ──
# Must reject creation while the form is not approved
r = client.post("/api/referencing/tenancies/create-from-form", json={
    "form_id": form_id, "start_date": "2026-08-01", "rent_amount": 950})
ok("tenancy blocked pre-approval (409)", r.status_code == 409, f"got {r.status_code}")

# Approve the form, then create
r = client.patch(f"/api/referencing/forms/{form_id}/status", json={"status": "approved", "notes": "refs ok"})
ok("form approved", r.status_code == 200 and r.get_json().get("data", {}).get("status") == "approved", f"{r.status_code}")

# Available units picker responds
r = client.get("/api/referencing/units/available")
d = r.get_json() or {}
units = d.get("data") or []
ok("available units list", r.status_code == 200 and isinstance(units, list), f"{r.status_code} {d.get('error')}")
unit_id = units[0]["id"] if units else None
property_id = units[0]["property_id"] if units else None

# Create the tenancy (fixed 12-month term) + auto-send agreement (dryrun email)
r = client.post("/api/referencing/tenancies/create-from-form", json={
    "form_id": form_id, "property_id": property_id, "unit_id": unit_id,
    "start_date": "2026-08-01", "end_date": "2027-07-01",
    "rent_amount": 950, "rent_frequency": "Monthly",
    "deposit_amount": 1096, "deposit_scheme": "MyDeposits", "send_agreement": True})
d = r.get_json() or {}
tdata = d.get("data") or {}
tenancy = tdata.get("tenancy") or {}
tenancy_id = tenancy.get("id")
ok("tenancy created", r.status_code == 200 and tenancy_id and str(tenancy.get("ref","")).startswith("BKS-"), f"{r.status_code} {d.get('error')}")
ok("rent schedule generated (12)", tdata.get("rent_charges_created") == 12, f"got {tdata.get('rent_charges_created')}")
ok("agreement auto-sent", str(d.get("delivery","")).startswith("missive 2") and (tdata.get("esignature") or {}).get("status") == "sent", f"delivery={d.get('delivery')}")

# Form advanced to tenancy_created
r = client.get(f"/api/referencing/forms/{form_id}")
ok("form → tenancy_created", (r.get_json().get("data", {}).get("form", {}) or r.get_json().get("data", {})).get("status") == "tenancy_created", "status not advanced")

# Duplicate guard
r = client.post("/api/referencing/tenancies/create-from-form", json={
    "form_id": form_id, "start_date": "2026-08-01", "rent_amount": 950})
ok("duplicate tenancy blocked (409)", r.status_code == 409, f"got {r.status_code}")

# List tenancies (banksia origin) — new one present
r = client.get("/api/referencing/tenancies?origin=banksia")
d = r.get_json() or {}
ok("list banksia tenancies", r.status_code == 200 and any(t["id"] == tenancy_id for t in (d.get("data") or [])), f"{r.status_code} {d.get('error')}")

# Detail: tenants + schedule + totals
r = client.get(f"/api/referencing/tenancies/{tenancy_id}")
d = r.get_json() or {}
det = d.get("data") or {}
ok("tenancy detail: tenant linked", len(det.get("tenants") or []) == 1, f"tenants={len(det.get('tenants') or [])}")
ok("tenancy detail: 12 charges", len(det.get("rent_charges") or []) == 12, f"charges={len(det.get('rent_charges') or [])}")
ok("tenancy detail: billed £11,400", abs((det.get("totals") or {}).get("billed", 0) - 11400) < 0.01, f"billed={(det.get('totals') or {}).get('billed')}")

# Edit rent → schedule rebuilds at new amount
r = client.patch(f"/api/referencing/tenancies/{tenancy_id}", json={"rent_amount": 1000})
ok("tenancy rent edited", r.status_code == 200 and r.get_json().get("data", {}).get("rent_amount") == 1000, f"{r.status_code}")
r = client.get(f"/api/referencing/tenancies/{tenancy_id}")
det = (r.get_json() or {}).get("data") or {}
ok("schedule rebuilt at new rent", abs((det.get("totals") or {}).get("billed", 0) - 12000) < 0.01, f"billed={(det.get('totals') or {}).get('billed')}")

# Record a payment against the first charge
first_charge = (det.get("rent_charges") or [{}])[0]
r = client.patch(f"/api/referencing/tenancies/{tenancy_id}/rent/{first_charge.get('id')}",
                 json={"paid_amount": 1000, "status": "paid"})
ok("rent payment recorded", r.status_code == 200 and r.get_json().get("data", {}).get("status") == "paid", f"{r.status_code}")

# ── 16. Page routes render (200 + HTML) ──
for path, label in [("/apply", "apply page"), (f"/apply/{form_token}", "apply w/ token"),
                    (f"/sign/{signer_token}", "sign page"), ("/portal", "portal page")]:
    r = client.get(path)
    ok(f"route {label}", r.status_code == 200 and b"<" in r.data, f"got {r.status_code}")

# ── Teardown: remove everything this run created so the live DB stays clean ──
try:
    tdb = get_db()
    if 'tenancy_id' in dir() and tenancy_id:
        tdb.execute("DELETE FROM rent_charges WHERE tenancy_id = ?", [tenancy_id])
        tdb.execute("DELETE FROM tenants WHERE tenancy_id = ?", [tenancy_id])
        tdb.execute("DELETE FROM esignature_requests WHERE tenancy_id = ?", [tenancy_id])
        tdb.execute("DELETE FROM tenancies WHERE id = ?", [tenancy_id])
    if form_id:
        tdb.execute("DELETE FROM esignature_audit_log WHERE request_id IN (SELECT id FROM esignature_requests WHERE form_id = ?)", [form_id])
        tdb.execute("DELETE FROM esignature_requests WHERE form_id = ?", [form_id])
        tdb.execute("DELETE FROM referencing_checks WHERE form_id = ?", [form_id])
        tdb.execute("DELETE FROM referencing_documents WHERE form_id = ?", [form_id])
        tdb.execute("DELETE FROM portal_users WHERE applicant_id IS NULL AND email = 'sqa.applicant@example.com'")
        tdb.execute("DELETE FROM referencing_forms WHERE id = ?", [form_id])
    tdb.commit(); tdb.close()
    print("(teardown: test artifacts removed)")
except Exception as e:
    print(f"(teardown warning: {e})")

db.close()

print("\n" + "="*50)
print(f"PASSED: {len(PASS)}   FAILED: {len(FAIL)}")
if FAIL:
    print("FAILURES: " + ", ".join(FAIL))
    sys.exit(1)
print("ALL GREEN")
