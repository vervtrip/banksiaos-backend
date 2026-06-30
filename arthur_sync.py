#!/usr/bin/env python3
"""
Arthur Live Sync Engine — pulls all data from Arthur API and maps to Verv OS schema.
"""
import json, os, sys, time, urllib.request
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from verv_os_db import *
from verv_os_db import insert, update, get_by_field, count, add_timeline

ARTHUR_TOKEN_FILE = "/root/.hermes/state/arthur_token.json"
ENTITY_ID = "349912"
BASE = "https://api.arthuronline.co.uk/v2"

def get_token():
    if not os.path.exists(ARTHUR_TOKEN_FILE):
        return None
    d = json.load(open(ARTHUR_TOKEN_FILE))
    if d.get("expires_at", 0) < time.time():
        return None
    return d.get("access_token")

def arthur_get(path, params=None):
    tok = get_token()
    if not tok:
        return {"error": "No token"}
    url = f"{BASE}/{path}"
    if params:
        qs = "&".join(f"{k}={v}" for k, v in params.items())
        url = f"{url}?{qs}"
    req = urllib.request.Request(url, headers={
        "Authorization": f"Bearer {tok}",
        "X-EntityID": ENTITY_ID,
        "User-Agent": "Mozilla/5.0"
    })
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        return {"error": f"HTTP {e.code}", "body": e.read().decode()[:500]}
    except Exception as e:
        return {"error": str(e)}

def safe_str(val, default=""):
    if val is None:
        return default
    if isinstance(val, dict):
        return str(val.get("name", val.get("full_name", default)) or default)
    return str(val).strip()

def sync_all():
    print(f"[SYNC] Starting Arthur live sync at {datetime.now(timezone.utc).isoformat()}")
    landlords_map = sync_landlords()
    properties_map = sync_properties()
    units_map = sync_units(properties_map)
    sync_tenancies(units_map, landlords_map)
    print(f"[SYNC] Sync complete. Properties:{count('properties')} Units:{count('units')} Tenancies:{count('tenancies')} Tenants:{count('tenants')} Landlords:{count('landlords')}")

def sync_landlords():
    print("[SYNC] Extracting landlords...")
    r = arthur_get("units", {"limit": 500})
    if "error" in r:
        print(f"[SYNC] Units error: {r['error']}")
        return {}
    items = r.get("data", []) if isinstance(r, dict) else r
    names = set()
    for u in items:
        owner = u.get("owner") or ""
        if isinstance(owner, dict):
            owner = owner.get("name", "") or owner.get("full_name", "") or ""
        owner = str(owner).strip()
        if owner:
            names.add(owner)
    r2 = arthur_get("tenancies", {"status": "active,periodic", "limit": 500})
    if "error" not in r2:
        for t in (r2.get("data", []) if isinstance(r2, dict) else r2):
            uo = t.get("unit_owner") or ""
            if isinstance(uo, dict):
                uo = uo.get("name", "") or uo.get("full_name", "") or ""
            uo = str(uo).strip()
            if uo:
                names.add(uo)
    id_map = {}
    for name in sorted(names):
        existing = get_by_field("landlords", "name", name)
        if existing:
            id_map[name] = existing[0]["id"]
            continue
        lid = insert("landlords", {"name": name, "notes": "Synced from Arthur"})
        id_map[name] = lid
        add_timeline("landlord", lid, "synced", f"Landlord {name} synced", actor="Arthur Sync")
    print(f"[SYNC] Landlords: {len(names)}")
    return id_map

def sync_properties():
    print("[SYNC] Syncing properties...")
    r = arthur_get("units", {"limit": 500})
    if "error" in r:
        print(f"[SYNC] Error: {r['error']}")
        return {}
    items = r.get("data", []) if isinstance(r, dict) else r
    groups = {}
    for u in items:
        pid = u.get("property_id", "")
        if not pid:
            continue
        if pid not in groups:
            groups[pid] = {
                "pid": pid,
                "a1": u.get("address_line_1", "") or "",
                "a2": u.get("address_line_2", "") or "",
                "city": u.get("city", "") or "",
                "full": u.get("full_address", "") or "",
                "owner": u.get("owner", "") or "",
            }
    pid_map = {}
    for pid, g in groups.items():
        full = g["full"] or f"{g['a1']}, {g['city']}"
        name = full.split(",")[0].strip() if full else f"Prop {pid}"
        owner = safe_str(g["owner"])
        existing = get_by_field("properties", "arthur_id", f"prop_{pid}")
        if existing:
            pid_map[pid] = existing[0]["id"]
            update("properties", existing[0]["id"], {"name": name, "address": full, "owner": owner})
            continue
        vid = insert("properties", {
            "arthur_id": f"prop_{pid}", "name": name, "address": full,
            "city": g.get("city", ""), "property_type": "HMO",
            "manager": "Banksia Lettings", "owner": owner,
        })
        pid_map[pid] = vid
        add_timeline("property", vid, "synced", f"Synced {name}", actor="Arthur Sync")
    print(f"[SYNC] Properties: {len(pid_map)}")
    return pid_map

def sync_units(prop_map):
    print("[SYNC] Syncing units...")
    r = arthur_get("units", {"limit": 500})
    if "error" in r:
        print(f"[SYNC] Error: {r['error']}")
        return {}
    items = r.get("data", []) if isinstance(r, dict) else r
    uid_map = {}
    for u in items:
        uid = str(u.get("id", ""))
        pid = u.get("property_id", "")
        if not uid or pid not in prop_map:
            continue
        name = u.get("unit_ref", "") or u.get("unit_type", "") or f"Unit {uid}"
        status = "occupied" if u.get("unit_vacant") is False else "vacant"
        existing = get_by_field("units", "arthur_id", uid)
        if existing:
            vid = existing[0]["id"]
            update("units", vid, {"name": name, "status": status})
            uid_map[uid] = vid
            continue
        vid = insert("units", {
            "arthur_id": uid, "property_id": prop_map[pid],
            "name": name, "unit_ref": u.get("unit_ref", ""), "status": status,
        })
        uid_map[uid] = vid
        add_timeline("unit", vid, "synced", f"Unit {name} synced", actor="Arthur Sync")
    print(f"[SYNC] Units: {len(uid_map)}")
    return uid_map

def sync_tenancies(unit_map, ll_map):
    print("[SYNC] Syncing tenancies...")
    r = arthur_get("tenancies", {"status": "active,periodic", "limit": 500})
    if "error" in r:
        print(f"[SYNC] Error: {r['error']}")
        return
    items = r.get("data", []) if isinstance(r, dict) else r
    synced = 0
    for t in items:
        aid = str(t.get("id", ""))
        u_arthur = str(t.get("unit_id", ""))
        u_vid = unit_map.get(u_arthur)
        if not aid or not u_vid:
            continue
        try:
            rent = float(t["rent_amount"]) if t.get("rent_amount") else None
        except:
            rent = None
        try:
            dep = float(t["deposit_registered_amount"]) if t.get("deposit_registered_amount") else None
        except:
            dep = None
        status = t.get("status", "active").lower()
        if status not in ("active", "periodic", "notice_served"):
            status = "active"
        existing = get_by_field("tenancies", "arthur_id", aid)
        if existing:
            tid = existing[0]["id"]
            update("tenancies", tid, {
                "unit_id": u_vid, "start_date": t.get("start_date"),
                "end_date": t.get("end_date"), "status": status,
                "rent_amount": rent, "rent_frequency": t.get("rent_frequency", "pcm"),
                "deposit_amount": dep,
                "deposit_protected": 1 if t.get("deposit_registered") else 0,
                "deposit_scheme": t.get("deposit_scheme", ""),
                "notice_period": t.get("notice_period", ""),
            })
        else:
            tid = insert("tenancies", {
                "arthur_id": aid, "unit_id": u_vid,
                "start_date": t.get("start_date"), "end_date": t.get("end_date"),
                "status": status, "rent_amount": rent,
                "rent_frequency": t.get("rent_frequency", "pcm"),
                "deposit_amount": dep,
                "deposit_protected": 1 if t.get("deposit_registered") else 0,
                "deposit_scheme": t.get("deposit_scheme", ""),
                "notice_period": t.get("notice_period", ""),
            })
            add_timeline("tenancy", tid, "synced", f"Tenancy {t.get('ref','')} synced", actor="Arthur Sync")
        if rent:
            update("units", u_vid, {"rent_amount": rent, "deposit_amount": dep, "status": "occupied"})
        tenants_data = t.get("tenants", [])
        for tn in tenants_data:
            fn = tn.get("first_name", "") or ""
            ln = tn.get("last_name", "") or ""
            full = f"{fn} {ln}".strip()
            if not full:
                continue
            existing_ts = get_by_field("tenants", "tenancy_id", tid)
            found = False
            for et in existing_ts:
                if et.get("full_name", "").lower() == full.lower():
                    found = True
                    update("tenants", et["id"], {
                        "first_name": fn, "last_name": ln, "full_name": full,
                        "phone": tn.get("mobile", "") or tn.get("phone_home", ""),
                        "email": tn.get("email", ""),
                        "passport_number": tn.get("passport_number", ""),
                        "right_to_rent_verified": 1 if tn.get("passport_number") else 0,
                    })
                    break
            if not found:
                tnid = insert("tenants", {
                    "tenancy_id": tid, "first_name": fn, "last_name": ln, "full_name": full,
                    "phone": tn.get("mobile", "") or tn.get("phone_home", ""),
                    "email": tn.get("email", ""),
                    "passport_number": tn.get("passport_number", ""),
                    "right_to_rent_verified": 1 if tn.get("passport_number") else 0,
                })
                add_timeline("tenant", tnid, "synced", f"Tenant {full} synced", actor="Arthur Sync")
        synced += 1
    print(f"[SYNC] Tenancies synced: {synced}")

if __name__ == "__main__":
    init_db()
    sync_all()