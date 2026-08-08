#!/usr/bin/env python3
"""Prove the sync protection on a COPY of the live database.

Simulates exactly what the 3am pull does — hands arthur_sync's writer a payload
straight from Arthur — and checks that a field staff have edited survives while
an untouched field still updates. Nothing here touches the live database.
"""
import os, shutil, sqlite3, sys

LIVE = "/root/banksia-backend/banksia_os.db"
COPY = "/tmp/protection_test.db"

shutil.copy(LIVE, COPY)
os.environ["BANKSIA_DB_PATH"] = COPY
sys.path.insert(0, "/root/banksia-backend")

import banksia_os_db as db
db.DB_PATH = COPY
db._vos_local = type(db._vos_local)()   # drop any cached connection

fails, checks = [], []


def check(name, ok, detail=""):
    checks.append((name, ok, detail))
    if not ok:
        fails.append(name)


con = sqlite3.connect(COPY); con.row_factory = sqlite3.Row

# ── 1. A protected field must survive an inbound overwrite ──────────
row = con.execute(
    "SELECT f.row_id, f.field, f.local_value FROM field_overrides f "
    "WHERE f.table_name='tenancies' AND f.field='end_date' AND f.released_at IS NULL "
    "LIMIT 1").fetchone()
if row:
    tid, fld = row["row_id"], row["field"]
    before = con.execute(f"SELECT {fld}, status FROM tenancies WHERE id=?", (tid,)).fetchone()
    # Arthur sends a blank end date (periodic tenancy) plus a genuine status change
    applied, kept = db.guarded_update("tenancies", tid,
                                      {"end_date": "", "status": "Periodic", "notes": "arthur note"})
    after = con.execute(f"SELECT {fld}, status, notes FROM tenancies WHERE id=?", (tid,)).fetchone()
    check("protected end_date survives an Arthur blank",
          after[fld] == before[fld], f"{before[fld]!r} -> {after[fld]!r}")
    check("end_date reported as kept", fld in kept, str(kept))
    check("unprotected field still syncs", after["notes"] == "arthur note", after["notes"])
else:
    check("found a protected tenancy to test", False)

# ── 2. An untouched row must sync normally, end to end ──────────────
u = con.execute(
    "SELECT u.id FROM units u WHERE NOT EXISTS (SELECT 1 FROM field_overrides f "
    "WHERE f.table_name='units' AND f.row_id=u.id AND f.field='market_rent' "
    "AND f.released_at IS NULL) LIMIT 1").fetchone()
uid = u["id"]
db.guarded_update("units", uid, {"market_rent": 999.0})
got = con.execute("SELECT market_rent FROM units WHERE id=?", (uid,)).fetchone()[0]
check("untouched field accepts Arthur's value", float(got) == 999.0, str(got))

# ── 3. A staff edit after a sync must be detected with no flag set ──
# This is the case the old design missed: raw SQL, no sync_dirty, no override.
db.guarded_update("units", uid, {"market_rent": 500.0})          # Arthur's baseline
con.execute("UPDATE units SET market_rent=750 WHERE id=?", (uid,))  # staff edit, raw SQL
con.commit()
applied, kept = db.guarded_update("units", uid, {"market_rent": 500.0})  # next night's pull
got = con.execute("SELECT market_rent FROM units WHERE id=?", (uid,)).fetchone()[0]
check("raw-SQL staff edit detected with no flag", float(got) == 750.0, str(got))
check("and reported as kept", "market_rent" in kept, str(kept))

# ── 4. Once claimed, it stays claimed on later pulls ────────────────
db.guarded_update("units", uid, {"market_rent": 480.0})
got = con.execute("SELECT market_rent FROM units WHERE id=?", (uid,)).fetchone()[0]
check("stays protected on the following pull", float(got) == 750.0, str(got))

# ── 5. Handing a field back lets Arthur own it again ────────────────
db.release_field_override("units", uid, "market_rent")
db.guarded_update("units", uid, {"market_rent": 460.0})
got = con.execute("SELECT market_rent FROM units WHERE id=?", (uid,)).fetchone()[0]
check("released field syncs again", float(got) == 460.0, str(got))

# ── 6. Vocabulary: Arthur "Let" must not churn a Banksia "Occupied" ─
sys.path.insert(0, "/root/banksia-backend")
import arthur_sync
check("Let maps to Occupied", arthur_sync._map_unit_status("Let") == "Occupied")
check("Available To Let maps to Vacant", arthur_sync._map_unit_status("Available To Let") == "Vacant")
check("Room maps to Rooms", arthur_sync._map_unit_type("Room") == "Rooms")
check("unknown wording passes through", arthur_sync._map_unit_status("Holiday Let") == "Holiday Let")

# ── 7. Conflicts are recorded, not silent ───────────────────────────
n = con.execute("SELECT COUNT(*) FROM sync_conflicts WHERE detail LIKE 'kept local value%'").fetchone()[0]
check("kept values written to sync_conflicts", n > 0, f"{n} rows")

print()
for name, ok, detail in checks:
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f"  ({detail})" if detail else ""))
print(f"\n{len(checks) - len(fails)}/{len(checks)} passed")
os.unlink(COPY)
sys.exit(1 if fails else 0)
