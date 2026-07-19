"""End-to-end test of the full referencing → esign → tenancy flow."""
import json, uuid, sys, os, requests, time

BASE = "http://127.0.0.1:5050"
s = requests.Session()

# Log in as team
r = s.post(f"{BASE}/api/auth/login", json={"username": "Sami", "password": "testpass123"})
assert r.status_code == 200, f"Login: {r.text}"
print("✅ Team login OK")

# ── Phase 1: Applicant signup ──
email = f"e2e.{uuid.uuid4().hex[:8]}@test.com"
r = s.post(f"{BASE}/api/referencing/portal/applicant-signup", json={
    "first_name": "E2E", "last_name": "Tenant", "email": email,
    "password": "TestPass123!",
})
assert r.status_code == 201, f"Signup: {r.text}"
data = r.json()["data"]
form_id = data["form_id"]
form_token = data["form_token"]
print(f"✅ Applicant signup — form_id={form_id}")

# ── Phase 2: Fill form ──
r = s.patch(f"{BASE}/api/referencing/forms/{form_id}?token={form_token}", json={
    "title": "Mr", "date_of_birth": "1990-01-15", "gender": "Male",
    "mobile_phone": "+447****0000",
    "current_address_line1": "123 Test Street", "current_city": "London", "current_postcode": "E1 6AN",
    "employment_status": "employed", "employer_name": "Test Corp", "annual_salary": 45000,
    "employer_address": "456 Business Park", "job_title": "Engineer", "employment_length": "3 years",
    "bank_name": "Test Bank", "bank_account_name": "E2E Test",
    "bank_sort_code": "12-34-56", "bank_account_number": "12345678",
    "has_guarantor": 0, "declaration_confirmed": 1,
})
assert r.status_code == 200, f"PATCH: {r.text[:100]}"
print("✅ Form data saved")

# Submit
r = s.post(f"{BASE}/api/referencing/forms/{form_id}/submit?token={form_token}")
assert r.status_code == 200, f"Submit: {r.text[:100]}"
assert r.json()["data"]["status"] == "submitted"
print("✅ Form submitted")

# ── Phase 3: Team review ──
r = s.patch(f"{BASE}/api/referencing/forms/{form_id}/status", json={"status": "under_review"})
assert r.status_code == 200, f"Under review: {r.text[:100]}"
print("✅ Status → under_review")

# Assign property
r = s.post(f"{BASE}/api/referencing/forms/{form_id}/assign-property", json={
    "property_id": 253, "unit_id": 999,
})
assert r.status_code == 200, f"Assign: {r.text[:100]}"
app_id = r.json()["data"]["applicant_id"]
print(f"✅ Property assigned — 4 Studd Street D3 (applicant #{app_id})")

# ── Phase 4: Approve (should auto-create esign) ──
r = s.patch(f"{BASE}/api/referencing/forms/{form_id}/status", json={
    "status": "approved", "notes": "All checks passed.",
})
assert r.status_code == 200, f"Approve: {r.text[:100]}"
print("✅ Approved")

# Check esign was auto-created
r = s.get(f"{BASE}/api/referencing/forms/{form_id}")
esigns = r.json()["data"]["esignatures"]
assert len(esigns) > 0, f"No esign auto-created! Response had {len(esigns)} esigns. Form data: {json.dumps(r.json()['data']['form'], indent=2)}"
esign = esigns[0]
print(f"✅ Esign auto-created — #{esign['id']}, status={esign['status']}")

# Get token from DB
import sqlite3
db = sqlite3.connect("/root/verv-dashboard/banksia_os.db")
cur = db.execute("SELECT signer_token, team_token FROM esignature_requests WHERE id = ?", [esign["id"]])
row = cur.fetchone()
db.close()
assert row, "Token not found in DB"
signer_token, team_token = row[0], row[1]
print(f"✅ Signer token: {signer_token[:16]}...")
print(f"✅ Team token: {team_token[:16]}...")

# ── Phase 5: Applicant signs ──
# View signing page
r = s.get(f"{BASE}/api/referencing/esignature/sign/{signer_token}")
assert r.status_code == 200, f"Sign view: {r.text[:100]}"
assert r.json()["data"]["status"] in ("sent", "viewed"), f"Bad status: {r.json()['data']['status']}"
print("✅ Signing page loaded OK")

# Post signature
r = s.post(f"{BASE}/api/referencing/esignature/sign/{signer_token}", json={
    "consent": True, "signature": "E2E Tenant",
})
assert r.status_code == 200, f"Sign: {r.text[:200]}"
assert r.json()["data"]["status"] == "applicant_signed", f"Bad sign status: {r.json()}"
print(f"✅ Applicant signed — status={r.json()['data']['status']}")

# ── Phase 6: Team countersigns ──
r = s.get(f"{BASE}/api/referencing/esignature/team-sign/{team_token}")
assert r.status_code == 200, f"CS view: {r.text[:100]}"
print("✅ Countersign page loaded OK")

r = s.post(f"{BASE}/api/referencing/esignature/team-sign/{team_token}", json={
    "consent": True, "signature": "Sami Rahman",
})
assert r.status_code == 200, f"CS: {r.text[:200]}"
resp = r.json()["data"]
print(f"✅ Team countersigned — status={resp['status']}")

# Check if tenancy was auto-created
tenancy_created = resp.get("tenancy_created", False)
print(f"✅ Auto-tenancy created: {tenancy_created}")

# ── Phase 7: Verify tenancy is in DB ──
db = sqlite3.connect("/root/verv-dashboard/banksia_os.db")
db.row_factory = sqlite3.Row

# Check tenancy
tenancies = db.execute(
    "SELECT * FROM tenancies WHERE id IN (SELECT tenancy_id FROM tenants WHERE id IN (SELECT id FROM applicants WHERE id = ?))",
    [app_id]
).fetchall()
if tenancies:
    for t in tenancies:
        print(f"\n✅ Tenancy #{t['id']} created:")
        print(f"   Property: #{t['property_id']}, Unit: #{t['unit_id']}")
        print(f"   Tenant: {t['main_tenant_name']}")
        print(f"   Status: {t['status']}")
        print(f"   Rent: £{t['rent_amount']}/pcm")
        print(f"   Start: {t['start_date']}, End: {t['end_date']}")
        print(f"   Move-in: {t['move_in_date']}")
else:
    print("\n⚠️ No tenancy found via applicant link. Checking applicant record...")
    app = db.execute("SELECT * FROM applicants WHERE id = ?", [app_id]).fetchone()
    if app:
        print(f"   Applicant #{app_id}: status={app['status']}, property={app['property_id']}, unit={app['unit_id']}")

# Check tenant
tenants = db.execute("SELECT * FROM tenants WHERE property_id = 253 AND unit_id = 999 AND first_name = 'E2E'").fetchall()
print(f"\n✅ Tenants found in DB: {len(tenants)}")
for t in tenants:
    print(f"   #{t['id']}: {t['first_name']} {t['last_name']} ({t['email']})")
    print(f"   Tenancy #{t['tenancy_id']}, Status: {t['status']}")
    print(f"   Move-in: {t['move_in_date']}")

# Check unit status
unit = db.execute("SELECT id, unit_ref, unit_status, unit_vacant FROM units WHERE id = 999").fetchone()
if unit:
    print(f"\n✅ Unit D3: status={unit['unit_status']}, vacant={unit['unit_vacant']}")

# Check deposit
deposits = db.execute("SELECT id, amount, current_status FROM deposits WHERE unit_id = 999 ORDER BY id DESC LIMIT 1").fetchall()
if deposits:
    for d in deposits:
        print(f"\n✅ Deposit #{d['id']}: £{d['amount']}, status={d['current_status']}")

# Check portal user
portal = db.execute("SELECT id, portal_type, tenancy_id FROM portal_users WHERE email = ?", [email]).fetchone()
if portal:
    print(f"\n✅ Portal user: type={portal['portal_type']}, tenancy_id={portal['tenancy_id']}")

db.close()
print("\n🎉 E2E test complete!")
