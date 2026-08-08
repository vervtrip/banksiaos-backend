#!/usr/bin/env python3
"""Seed the Arthur sync-protection baseline.

The last successful Arthur pull was 22 July 2026 18:06 UTC; the 23 July backup
is therefore the closest thing we have to "what Arthur last said". Seeding the
shadow from it means every field a member of staff has changed since is
detected as a local edit on the next pull and kept, without anyone having had
to flag it at the time.

Belt and braces: also claim every field the activity log records as a local
edit, which covers rows changed before the baseline.

Run with --apply to write. Without it, reports only.
"""
import gzip, json, os, shutil, sqlite3, sys, tempfile
from datetime import datetime, timezone

LIVE = "/root/banksia-backend/banksia_os.db"
BASELINE_GZ = "/root/banksia-backups/banksia_os_20260723_150224.db.gz"

# Only the fields each sync_* function actually writes are worth a baseline.
SYNC_FIELDS = {
    "properties": ["ref", "name", "address_line_1", "address_line_2", "city", "county",
                   "postcode", "country", "lat", "lng", "property_type", "total_units",
                   "rentable_units", "property_owner_id", "property_owner_name",
                   "max_occupancy", "bathrooms", "bedrooms", "council_tax_band",
                   "council_account_no", "main_image_url", "image_urls", "epc_urls",
                   "floor_plan_urls", "thumbnail_urls", "features", "notes", "tags",
                   "custom_fields"],
    "units": ["property_id", "unit_type", "unit_status", "unit_ref", "unit_vacant",
              "available_from", "market_rent", "market_rent_frequency", "deposit_amount",
              "owner_name", "full_address", "short_description", "description",
              "furnished", "max_occupancy", "bathrooms", "bedrooms", "council_tax_band",
              "main_image_url", "image_urls", "features", "notes", "tags", "days_vacant"],
    "tenancies": ["property_id", "unit_id", "ref", "status", "full_address", "tenancy_type",
                  "contract_type", "start_date", "end_date", "renewal_start", "renewal_end",
                  "is_renewed", "break_clause_date", "rolling_break_date", "notice_period",
                  "move_in_date", "move_out_date", "rent_amount", "rent_frequency",
                  "deposit_held_by", "deposit_scheme", "deposit_registered",
                  "deposit_registered_amount", "rent_review_date", "section_21_served",
                  "rent_payment_bank", "main_tenant_name", "tenants", "notes", "tags"],
    "tenants": ["tenancy_id", "unit_id", "property_id", "full_address", "title",
                "first_name", "last_name", "date_of_birth", "gender", "citizen", "email",
                "phone_home", "phone_work", "mobile", "passport_number", "ni_number",
                "main_tenant", "status", "has_guarantor", "guarantor_first_name",
                "guarantor_last_name", "guarantor_email", "guarantor_mobile",
                "guarantor_relation", "employment_company", "employment_salary",
                "student_status", "university", "applicant_note", "manager_note",
                "move_in_date", "move_out_date"],
    "applicants": ["person_id", "status", "first_name", "last_name", "date_of_birth",
                   "gender", "email", "mobile", "phone", "full_address", "viewing_count",
                   "last_viewing_date", "student_status", "university", "employment_company",
                   "employment_salary", "has_guarantor", "applicant_note", "manager_note",
                   "source", "assigned_to", "matched_unit_ids", "tags", "custom_fields"],
}

# Arthur's wording for the same states, translated exactly as arthur_sync now
# does, so a wording difference is not mistaken for somebody's edit.
UNIT_STATUS_MAP = {"let": "Occupied", "available to let": "Vacant", "available": "Vacant",
                   "unavailable to let": "Inactive", "unavailable": "Inactive"}
UNIT_TYPE_MAP = {"room": "Rooms", "rooms": "Rooms", "house": "House", "flat": "Flat",
                 "studio": "Studio"}
# Arthur recalculates these itself; they are not anybody's edit.
DERIVED = {("units", "days_vacant")}


def translate(table, field, value):
    v = "" if value is None else str(value).strip()
    if table == "units" and v:
        if field == "unit_status":
            return UNIT_STATUS_MAP.get(v.lower(), v)
        if field == "unit_type":
            return UNIT_TYPE_MAP.get(v.lower(), v)
    return "" if value is None else str(value)


ENTITY_TO_TABLE = {
    "property": "properties", "unit": "units", "tenancy": "tenancies",
    "tenant": "tenants", "applicant": "applicants",
}


def txt(v):
    return "" if v is None else str(v)


def main():
    apply = "--apply" in sys.argv
    if not os.path.exists(BASELINE_GZ):
        sys.exit(f"baseline missing: {BASELINE_GZ}")

    tmp = tempfile.mktemp(suffix=".db")
    with gzip.open(BASELINE_GZ, "rb") as fi, open(tmp, "wb") as fo:
        shutil.copyfileobj(fi, fo)

    base = sqlite3.connect(tmp); base.row_factory = sqlite3.Row
    live = sqlite3.connect(LIVE); live.row_factory = sqlite3.Row
    now = datetime.now(timezone.utc).isoformat()

    shadows = 0
    claims = {}      # (table,row_id,field) -> local value
    no_baseline = {}

    for table, fields in SYNC_FIELDS.items():
        base_cols = {r["name"] for r in base.execute(f"PRAGMA table_info({table})")}
        live_cols = {r["name"] for r in live.execute(f"PRAGMA table_info({table})")}
        cols = [f for f in fields if f in base_cols and f in live_cols]

        by_arthur = {}
        for r in base.execute(f"SELECT arthur_id, {', '.join(cols)} FROM {table}"):
            if r["arthur_id"]:
                by_arthur[str(r["arthur_id"])] = {c: translate(table, c, r[c]) for c in cols}

        seen = 0
        for r in live.execute(f"SELECT id, arthur_id, {', '.join(cols)} FROM {table}"):
            aid = str(r["arthur_id"] or "")
            snap = by_arthur.get(aid)
            if not snap:
                no_baseline[table] = no_baseline.get(table, 0) + 1
                continue
            seen += 1
            if apply:
                live.execute(
                    "INSERT INTO arthur_shadow (table_name,row_id,payload,updated_at) VALUES (?,?,?,?) "
                    "ON CONFLICT(table_name,row_id) DO UPDATE SET payload=excluded.payload, "
                    "updated_at=excluded.updated_at",
                    (table, r["id"], json.dumps(snap), now))
            for c in cols:
                if (table, c) in DERIVED:
                    continue
                if txt(r[c]) != snap.get(c, ""):
                    claims[(table, r["id"], c)] = r[c]
        shadows += seen
        print(f"  {table}: baseline for {seen} rows"
              f"{', %d rows have no baseline (created since 23 July)' % no_baseline[table] if table in no_baseline else ''}")

    drifted = len(claims)
    print(f"\nFields changed in Banksia OS since the last Arthur pull: {drifted}")

    # Belt and braces — anything the activity log calls a local edit is claimed too.
    # Excluding bulk runs: one person changing the same field on dozens of records
    # in a day is a migration, not somebody editing records, and claiming those
    # would freeze the field against Arthur for good.
    BULK = 25
    bulk_groups = {
        (r["user_name"], r["d"], r["field_changed"])
        for r in live.execute(
            "SELECT user_name, substr(created,1,10) AS d, field_changed, COUNT(*) AS n "
            "FROM activity_log WHERE action='update' AND field_changed IS NOT NULL "
            "AND field_changed<>'' GROUP BY user_name, d, field_changed HAVING n > ?", (BULK,))
    }
    if bulk_groups:
        print("Ignored as bulk migrations, not edits: " + "; ".join(
            f"{u} {d} {f}" for u, d, f in sorted(bulk_groups)))
    from_log = 0
    for r in live.execute(
        "SELECT DISTINCT entity_type, entity_id, field_changed, user_name, "
        "substr(created,1,10) AS d FROM activity_log "
        "WHERE action='update' AND field_changed IS NOT NULL AND field_changed<>''"):
        if (r["user_name"], r["d"], r["field_changed"]) in bulk_groups:
            continue
        t = ENTITY_TO_TABLE.get(r["entity_type"])
        if not t or t not in SYNC_FIELDS:
            continue
        key = (t, r["entity_id"], r["field_changed"])
        if key not in claims:
            row = live.execute(f"SELECT * FROM {t} WHERE id=?", (r["entity_id"],)).fetchone()
            if not row or r["field_changed"] not in row.keys():
                continue
            claims[key] = row[r["field_changed"]]
            from_log += 1
    print(f"Further fields claimed from the activity log: {from_log}")
    print(f"Total fields Banksia OS will own: {len(claims)}")

    if apply:
        for (t, rid, f), val in claims.items():
            live.execute(
                "INSERT INTO field_overrides (table_name,row_id,field,local_value,set_at,set_by,released_at) "
                "VALUES (?,?,?,?,?,?,NULL) ON CONFLICT(table_name,row_id,field) DO UPDATE SET "
                "local_value=excluded.local_value, released_at=NULL",
                (t, rid, f, None if val is None else str(val), now, "baseline_seed"))
        live.commit()
        print(f"\nAPPLIED. shadow rows: {shadows}, protected fields: {len(claims)}")
    else:
        print("\nDRY RUN — nothing written. Re-run with --apply.")
        by_table = {}
        for (t, _, f) in claims:
            by_table.setdefault(t, {}).setdefault(f, 0)
            by_table[t][f] += 1
        for t, fs in sorted(by_table.items()):
            top = sorted(fs.items(), key=lambda x: -x[1])[:6]
            print(f"  {t}: {sum(fs.values())} fields — " + ", ".join(f"{k}({v})" for k, v in top))

    os.unlink(tmp)


if __name__ == "__main__":
    main()
