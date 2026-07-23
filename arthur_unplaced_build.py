#!/usr/bin/env python3
"""
Build the manual-placement queue for Arthur documents that could NOT be
auto-matched to a Banksia entity.

For every non-workorder/task CSV row whose file was NOT imported by
arthur_migrate.py (i.e. no usable id, or an Arthur id that doesn't exist in
Banksia), download the file now (while Arthur is still live) and register it in
the unplaced_documents table so the team can place it by hand from Banksia OS.

Idempotent: a uuid already present with a downloaded file is skipped. Safe to
re-run to resume after interruption.
"""
import csv, os, sqlite3, sys, re, mimetypes
from datetime import datetime
from urllib.parse import urlparse
try:
    import requests
    HAVE_REQUESTS = True
except Exception:
    HAVE_REQUESTS = False
    import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(HERE, "banksia_os.db")
CSV_PATH = os.path.join(HERE, "arthur_docs_export.csv")
UNPLACED_DIR = os.path.join(HERE, "media", "unplaced")
OUT = os.path.join(HERE, "arthur_unplaced_build.out")
os.makedirs(UNPLACED_DIR, exist_ok=True)

DRY = "--dry-run" in sys.argv
LIMIT = None
for a in sys.argv:
    if a.startswith("--limit="):
        LIMIT = int(a.split("=", 1)[1])

CT_EXT = {
    "application/pdf": ".pdf", "image/jpeg": ".jpg", "image/jpg": ".jpg",
    "image/png": ".png", "image/gif": ".gif", "image/webp": ".webp",
    "image/heic": ".heic", "image/heif": ".heif", "image/jfif": ".jpg",
    "application/msword": ".doc",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": ".docx",
    "application/vnd.ms-excel": ".xls",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": ".xlsx",
    "text/plain": ".txt", "video/quicktime": ".mov",
}
KNOWN_EXT = set(CT_EXT.values()) | {".jpeg", ".pdf", ".png", ".doc", ".docx", ".xls",
                                    ".xlsx", ".txt", ".webp", ".gif", ".heic", ".heif",
                                    ".mov", ".jfif"}
SKIP_REL = {"workorder", "task"}


def out(msg):
    line = f"[{datetime.now().strftime('%H:%M:%S')}] {msg}"
    print(line, flush=True)
    with open(OUT, "a") as f:
        f.write(line + "\n")


def asset_uuid(url):
    return urlparse(url).path.rstrip("/").split("/")[-1]


def fetch(url, timeout=60):
    if HAVE_REQUESTS:
        r = requests.get(url, timeout=timeout, stream=True)
        r.raise_for_status()
        return r.content, r.headers.get("Content-Type", "").split(";")[0].strip().lower(), r.headers.get("Content-Disposition", "")
    req = urllib.request.Request(url, headers={"User-Agent": "banksia-migrate"})
    with urllib.request.urlopen(req, timeout=timeout) as f:
        return f.read(), (f.headers.get("Content-Type") or "").split(";")[0].strip().lower(), f.headers.get("Content-Disposition") or ""


def ext_from(cd, ct, doc_name):
    e = os.path.splitext(doc_name or "")[1].lower()
    if e in KNOWN_EXT:
        return ".jpg" if e in (".jpeg", ".jfif") else e
    m = re.search(r'filename="?([^";]+)"?', cd or "")
    if m:
        e = os.path.splitext(m.group(1))[1].lower()
        if e in KNOWN_EXT:
            return ".jpg" if e in (".jpeg", ".jfif") else e
    if ct in CT_EXT:
        return CT_EXT[ct]
    g = mimetypes.guess_extension(ct or "") or ""
    return ".jpg" if g == ".jpeg" else (g or ".bin")


def load_banksia_ids(con):
    m = {}
    for t in ("properties", "units", "tenancies"):
        m[t] = set(str(r[0]) for r in con.execute(
            f"SELECT arthur_id FROM {t} WHERE arthur_id IS NOT NULL AND arthur_id != ''"))
    return m


def imported_uuids(con):
    done = set()
    for row in con.execute("SELECT notes FROM entity_documents WHERE notes LIKE '%arthur-asset:%'"):
        m = re.search(r"arthur-asset:([0-9a-f-]+)", row[0] or "")
        if m:
            done.add(m.group(1))
    return done


def main():
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    ids = load_banksia_ids(con)
    imported = imported_uuids(con)
    existing = set(r[0] for r in con.execute(
        "SELECT arthur_asset_uuid FROM unplaced_documents WHERE file_path IS NOT NULL"))

    rows = list(csv.DictReader(open(CSV_PATH, newline="", encoding="utf-8-sig")))

    # group by URL, choosing the row with the richest metadata / most-specific ids
    by_url = {}
    for r in rows:
        rel = (r["Relationship"] or "").strip().lower()
        if rel in SKIP_REL:
            continue
        u = (r["HTML Download Link"] or "").strip()
        if not u:
            continue
        pid, uid, tid = r["Property ID"].strip(), r["Unit ID"].strip(), r["Tenancy ID"].strip()
        score = (3 if tid else 0) + (2 if uid else 0) + (1 if pid else 0)
        cur = by_url.get(u)
        if cur is None or score > cur[0]:
            by_url[u] = (score, r)

    todo = []
    for u, (score, r) in by_url.items():
        uid = asset_uuid(u)
        if uid in imported:
            continue  # already attached to an entity by the main migration
        pid, uu, tid = r["Property ID"].strip(), r["Unit ID"].strip(), r["Tenancy ID"].strip()
        has_id = bool(pid or uu or tid)
        if not has_id:
            reason = "no_id"
        else:
            in_bk = (tid and tid in ids["tenancies"]) or (uu and uu in ids["units"]) or (pid and pid in ids["properties"])
            if in_bk:
                continue  # would have been imported; skip
            reason = "id_not_in_banksia"
        todo.append((u, uid, reason, r))

    from collections import Counter
    out(f"=== PLAN === parked to queue: {len(todo)} "
        f"({dict(Counter(t[2] for t in todo))}) | already downloaded: {len(existing)}")
    if DRY:
        con.close()
        return

    ok = 0; fail = 0; skip = 0
    n = 0
    for (u, uid, reason, r) in todo:
        if LIMIT and n >= LIMIT:
            break
        n += 1
        if uid in existing:
            skip += 1
            continue
        doc_name = (r["Document Name"] or "document").strip()
        doc_type = (r["Document Type"] or "").strip()
        rel = (r["Relationship"] or "").strip()
        try:
            data, ct, cd = fetch(u)
        except Exception as e:
            fail += 1
            # register the row without a file so it is visible; can retry later
            con.execute(
                "INSERT OR IGNORE INTO unplaced_documents "
                "(arthur_asset_uuid, source_url, doc_name, document_type, relationship, created_date, "
                "raw_property_id, raw_unit_id, raw_tenancy_id, reason, status) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,'pending')",
                (uid, u, doc_name, doc_type, rel, r["Created Date"],
                 r["Property ID"].strip(), r["Unit ID"].strip(), r["Tenancy ID"].strip(), reason))
            con.commit()
            out(f"download_error {uid}: {e}")
            continue
        ext = ext_from(cd, ct, doc_name)
        orig = doc_name if os.path.splitext(doc_name)[1].lower() in KNOWN_EXT else (doc_name.rstrip(". ") + ext)
        orig = orig.replace("/", "-").replace("\\", "-")
        shard = os.path.join(UNPLACED_DIR, uid[:2])
        os.makedirs(shard, exist_ok=True)
        stored = f"{uid}{ext}"
        fpath = os.path.join(shard, stored)
        with open(fpath, "wb") as fh:
            fh.write(data)
        size = os.path.getsize(fpath)
        con.execute(
            "INSERT INTO unplaced_documents "
            "(arthur_asset_uuid, source_url, original_filename, doc_name, document_type, relationship, "
            "created_date, raw_property_id, raw_unit_id, raw_tenancy_id, reason, stored_filename, "
            "file_path, file_type, file_size, mime_type, status) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'pending') "
            "ON CONFLICT(arthur_asset_uuid) DO UPDATE SET "
            "original_filename=excluded.original_filename, stored_filename=excluded.stored_filename, "
            "file_path=excluded.file_path, file_type=excluded.file_type, file_size=excluded.file_size, "
            "mime_type=excluded.mime_type",
            (uid, u, orig, doc_name, doc_type, rel, r["Created Date"],
             r["Property ID"].strip(), r["Unit ID"].strip(), r["Tenancy ID"].strip(), reason,
             stored, fpath, ext.lstrip("."), size, ct or "application/octet-stream"))
        con.commit()
        existing.add(uid)
        ok += 1
        if ok % 200 == 0:
            out(f"...{ok} downloaded")

    out(f"=== DONE === downloaded: {ok} | failed: {fail} | already-had: {skip}")
    con.close()


if __name__ == "__main__":
    main()
