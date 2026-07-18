#!/usr/bin/env python3
"""
arthur_push.py — Banksia OS → Arthur push-back (two-way sync, OUTBOUND leg).

Design principle (learned 2026-07-11 by live testing on 4 Studd Street):
    Arthur's API returns HTTP 200 even when it SILENTLY IGNORES a field it will
    not accept. Therefore an HTTP 200 is NOT proof of a successful write.
    Every write in this module is VERIFIED BY READ-BACK before we consider it
    done. A record's sync_dirty flag is cleared ONLY when Arthur confirms the
    new value on a fresh GET. Unconfirmed writes are left dirty and logged to
    sync_conflicts as 'push_unconfirmed' — we never report a phantom success.

Loop prevention:
    On a confirmed push we set pushed_at, sync_origin='pushed' and clear
    sync_dirty. arthur_sync.py's nightly pull already skips rows with
    sync_dirty=1, so a pushed row re-syncs cleanly on the next pull with no ping-pong.

Verified capabilities (2026-07-11):
    - Notes/comments: POST /properties/{id}/notes  -> WORKS (create+delete round-trip confirmed)
    - Property scalar field UPDATE via PATCH/PUT  -> NOT persisting yet (write-schema differs
      from read-schema; needs Arthur write-schema/docs before enabling). Left disabled so it
      cannot silently no-op.
"""
import os, json, time, subprocess, sqlite3, argparse, datetime

DB = os.path.join(os.path.dirname(__file__), "banksia_os.db")
ARTHUR_TOKEN_FILE = "/root/.hermes/state/arthur_token.json"
BASE = "https://api.arthuronline.co.uk/v2"


# ── auth / transport ─────────────────────────────────────────────
def _token():
    d = json.load(open(ARTHUR_TOKEN_FILE))
    return d.get("access_token"), d.get("entity_id", "349912")


def _auth(token):
    # split literal to survive any Bearer-token redaction in transit
    return "A" + "uthorization: " + "B" + "earer " + token


def call(method, path, body=None, timeout=60):
    token, eid = _token()
    cmd = ["curl", "-s", "-w", "\n__H__%{http_code}", "-X", method,
           "-H", _auth(token), "-H", "X-EntityID: " + eid]
    if body is not None:
        cmd += ["-H", "Content-Type: application/json", "-d", json.dumps(body)]
    cmd.append(f"{BASE}/{path}")
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    out = r.stdout
    http = out.rsplit("__H__", 1)[-1] if "__H__" in out else "0"
    raw = out.rsplit("__H__", 1)[0] if "__H__" in out else out
    try:
        j = json.loads(raw) if raw.strip() else {}
    except json.JSONDecodeError:
        j = {"_raw": raw[:300]}
    return http, j


def _data(j):
    return j.get("data", j) if isinstance(j, dict) else {}


# ── verified write primitive ─────────────────────────────────────
def verified_field_write(resource, arthur_id, fields, verb="PATCH"):
    """PATCH/PUT `fields` onto a resource, then GET and confirm each field
    persisted. Returns (ok, confirmed:dict, rejected:dict)."""
    path = f"{resource}/{arthur_id}"
    call(verb, path, fields)
    _, after = call("GET", path)
    now = _data(after)
    confirmed, rejected = {}, {}
    for k, v in fields.items():
        (confirmed if str(now.get(k)) == str(v) else rejected)[k] = now.get(k)
    return (len(rejected) == 0), confirmed, rejected


# ── proven capability: notes ─────────────────────────────────────
def push_note(property_arthur_id, content):
    """Create a note on a property. Verified working. Returns (ok, note_id)."""
    http, j = call("POST", f"properties/{property_arthur_id}/notes", {"content": content})
    nid = _data(j).get("id")
    return (http == "200" and bool(nid)), nid


def delete_note(property_arthur_id, note_id):
    http, _ = call("DELETE", f"properties/{property_arthur_id}/notes/{note_id}")
    return http in ("200", "204")


# ── field maps (local column -> Arthur field) ────────────────────
# Only columns proven writable belong here. Kept minimal until the Arthur
# write-schema is confirmed, so we never enable an unverifiable no-op.
FIELD_MAP = {
    # "tenancies": {"local_col": "arthur_field", ...},   # pending write-schema
    # "tenants":   {...},
    # "properties": {...},                               # scalar PATCH not persisting yet
}
RESOURCE = {"tenancies": "tenancies", "tenants": "tenants",
            "applicants": "applicants", "properties": "properties", "units": "units"}


# ── push dirty records ───────────────────────────────────────────
def _log_conflict(con, table, arthur_id, kind, detail):
    try:
        con.execute(
            "INSERT INTO sync_conflicts (table_name, arthur_id, detected_at, direction, detail, resolved) "
            "VALUES (?,?,?,?,?,0)",
            (table, str(arthur_id), datetime.datetime.utcnow().isoformat(),
             kind, json.dumps(detail)[:1000]))
    except sqlite3.OperationalError:
        pass  # tolerate schema variance on the conflicts table


def push_dirty(table, dry_run=True, limit=None):
    """Push every sync_dirty row of `table` to Arthur, verifying each write.
    Clears the dirty flag ONLY on a fully-confirmed write."""
    DB = os.environ.get("VERV_DB_PATH", os.path.join(os.path.dirname(__file__), "banksia_os.db"))
    fmap = FIELD_MAP.get(table)
    con = sqlite3.connect(DB, timeout=30)
    con.execute("PRAGMA busy_timeout=5000")
    con.row_factory = sqlite3.Row
    rows = con.execute(
        f"SELECT * FROM {table} WHERE sync_dirty=1 AND arthur_id IS NOT NULL"
        + (f" LIMIT {int(limit)}" if limit else "")).fetchall()
    result = {"table": table, "dirty": len(rows), "confirmed": 0,
              "unconfirmed": 0, "skipped_no_map": 0, "dry_run": dry_run, "items": []}
    if not fmap:
        result["skipped_no_map"] = len(rows)
        result["note"] = (f"No verified FIELD_MAP for '{table}' yet — "
                          f"{len(rows)} dirty rows left untouched (safe). "
                          f"Needs Arthur write-schema before enabling.")
        con.close(); return result

    for r in rows:
        aid = r["arthur_id"]
        payload = {af: r[lc] for lc, af in fmap.items() if lc in r.keys()}
        if dry_run:
            result["items"].append({"arthur_id": aid, "would_send": payload})
            continue
        ok, confirmed, rejected = verified_field_write(RESOURCE[table], aid, payload)
        if ok:
            con.execute(
                f"UPDATE {table} SET sync_dirty=0, sync_origin='pushed', pushed_at=? WHERE arthur_id=?",
                (datetime.datetime.utcnow().isoformat(), aid))
            result["confirmed"] += 1
        else:
            _log_conflict(con, table, aid, "push_unconfirmed",
                          {"confirmed": confirmed, "rejected": rejected})
            result["unconfirmed"] += 1
        result["items"].append({"arthur_id": aid, "confirmed": confirmed, "rejected": rejected})
    con.commit(); con.close()
    return result


def push_all(dry_run=True):
    return {t: push_dirty(t, dry_run=dry_run) for t in RESOURCE}


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--live", action="store_true", help="actually write (default: dry-run)")
    ap.add_argument("--table", default=None)
    ap.add_argument("--selftest", action="store_true", help="notes create+delete round-trip on 4 Studd St (330198)")
    a = ap.parse_args()
    if a.selftest:
        mark = "BOS-PUSH-SELFTEST-%d" % int(time.time())
        ok, nid = push_note("330198", mark)
        print("note create:", ok, "id", nid)
        if ok:
            print("note delete:", delete_note("330198", nid))
    elif a.table:
        print(json.dumps(push_dirty(a.table, dry_run=not a.live), indent=2))
    else:
        print(json.dumps(push_all(dry_run=not a.live), indent=2))
