#!/usr/bin/env python3
"""Test Arthur API connectivity with stored token."""
import json, os, urllib.request

# Read token from hmobanksia .env (last occurrence)
env_path = "/root/.hermes/profiles/hmobanksia/.env"
with open(env_path) as f:
    lines = f.readlines()

token = ""
entity = "349912"
for line in lines:
    line = line.strip()
    if line.startswith("ARTHUR_ACCESS_TOKEN="):
        token = line.split("=", 1)[1].strip().strip("'\"")
    if line.startswith("ARTHUR_ENTITY_ID="):
        entity = line.split("=", 1)[1].strip().strip("'\"")

headers = {
    "Authorization": f"Bearer {token}",
    "X-EntityID": entity,
    "User-Agent": "Mozilla/5.0"
}

# Test tenancies
req = urllib.request.Request(
    "https://api.arthuronline.co.uk/v2/tenancies?status=active,periodic&limit=5",
    headers=headers
)
try:
    with urllib.request.urlopen(req, timeout=15) as r:
        d = json.loads(r.read())
        print(f"Status: {d.get('status')}")
        data = d.get("data", [])
        print(f"Tenancies found: {len(data)}")
        for t in data:
            tn = ""
            if t.get("tenancy_tenants") and len(t["tenancy_tenants"]) > 0:
                p = t["tenancy_tenants"][0].get("person", {})
                tn = f"{p.get('forename','')} {p.get('surname','')}".strip()
            un = t.get("unit", {}).get("name", "") if t.get("unit") else ""
            print(f"  ID={t['id']} Tenant={tn} Unit={un} Rent={t.get('rent_amount')}/{t.get('rent_frequency')}")
except urllib.error.HTTPError as e:
    print(f"HTTP {e.code}: {e.read().decode()[:300]}")

# Test units
req2 = urllib.request.Request(
    "https://api.arthuronline.co.uk/v2/units?limit=5",
    headers=headers
)
try:
    with urllib.request.urlopen(req2, timeout=15) as r:
        d = json.loads(r.read())
        if d.get("status") == 200:
            data = d.get("data", [])
            print(f"\nUnits found: {len(data)}")
            for u in data:
                print(f"  ID={u.get('id')} Name={u.get('name','')} Ref={u.get('unit_ref','')}")
        else:
            print(f"\nUnits unexpected: {str(d)[:200]}")
except urllib.error.HTTPError as e:
    print(f"\nUnits HTTP {e.code}: {e.read().decode()[:300]}")
except Exception as e:
    print(f"\nUnits error: {e}")