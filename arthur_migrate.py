#!/usr/bin/env python3
"""
Arthur -> Banksia OS document migration.
Downloads each file from the Arthur asset export CSV and attaches it to the
correct Banksia OS entity (property / unit / tenancy) via entity_documents,
mirroring the exact storage convention used by the /entity-documents/upload endpoint.

Rules (per Sami, 2026-07-23):
  - Ignore Workorder rows entirely.
  - Only import a file if it can be confidently matched to a Banksia entity by
    Arthur ID (Property ID / Unit ID / Tenancy ID -> arthur_id). If unsure, SKIP.
  - Most-specific target wins: tenancy > unit > property.
  - Deduplicate by download URL (same URL = same physical file, attach once).
"""
import csv, os, sqlite3, sys, json, hashlib, mimetypes, re, time
from datetime import datetime, timezone
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
UPLOAD_DIR = os.path.join(HERE, "media", "documents")
LOG_PATH = os.path.join(HERE, "arthur_migration_log.jsonl")

DRY = "--dry-run" in sys.argv
LIMIT = None
for a in sys.argv:
    if a.startswith("--limit="):
        LIMIT = int(a.split("=", 1)[1])

CT_EXT = {
    "application/pdf": ".pdf", "image/jpeg": ".jpg", "image/jpg": ".jpg",
    "image/png": ".png", "image/gif": ".gif", "image/webp": ".webp",
    "image/heic": ".heic", "image/heif": ".heif",
    "application/msword": ".doc",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": ".docx",
    "application/vnd.ms-excel": ".xls",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": ".xlsx",
    "text/plain": ".txt", "video/quicktime": ".mov",
}
KNOWN_EXT = set(CT_EXT.values()) | {".jpeg", ".pdf", ".png", ".doc", ".docx", ".xls",
                                    ".xlsx", ".txt", ".webp", ".gif", ".heic", ".heif"}

def asset_uuid(url):
    return urlparse(url).path.rstrip("/").split("/")[-1]

def load_maps(con):
    m = {}
    for t in ("properties", "units", "tenancies"):
        d = {}
        for r in con.execute(f"SELECT id, arthur_id FROM {t} WHERE arthur_id IS NOT NULL AND arthur_id != ''"):
            d[str(r[1])] = r[0]
        m[t] = d
    return m

def target_for_row(r):
    """Return (level, entity_type, arthur_id) most-specific first."""
    if r["Tenancy ID"].strip():
        return (3, "tenancy", r["Tenancy ID"].strip())
    if r["Unit ID"].strip():
        return (2, "unit", r["Unit ID"].strip())
    if r["Property ID"].strip():
        return (1, "property", r["Property ID"].strip())
    return (0, None, None)

def category_for(row):
    rel = (row["Relationship"] or "").strip()
    dt = (row["Document Type"] or "").strip()
    if rel == "Unit":
        return "photo"
    if dt == "Certificate":
        return "certificate"
    if dt == "Contract":
        return "contract"
    if dt == "Reference":
        return "id"
    return "general"

def fetch(url, timeout=60):
    if HAVE_REQUESTS:
        resp = requests.get(url, timeout=timeout, stream=True)
        resp.raise_for_status()
        data = resp.content
        ct = resp.headers.get("Content-Type", "").split(";")[0].strip().lower()
        cd = resp.headers.get("Content-Disposition", "")
        return data, ct, cd
    req = urllib.request.Request(url, headers={"User-Agent": "banksia-migrate"})
    with urllib.request.urlopen(req, timeout=timeout) as f:
        data = f.read()
        ct = (f.headers.get("Content-Type") or "").split(";")[0].strip().lower()
        cd = f.headers.get("Content-Disposition") or ""
    return data, ct, cd

def ext_from(cd, ct, doc_name):
    # 1) extension already on the Arthur document name
    e = os.path.splitext(doc_name)[1].lower()
    if e in KNOWN_EXT:
        return ".jpg" if e == ".jpeg" else e
    # 2) content-disposition filename
    m = re.search(r'filename="?([^";]+)"?', cd or "")
    if m:
        e = os.path.splitext(m.group(1))[1].lower()
        if e in KNOWN_EXT:
            return ".jpg" if e == ".jpeg" else e
    # 3) content-type
    if ct in CT_EXT:
        return CT_EXT[ct]
    g = mimetypes.guess_extension(ct or "") or ""
    return ".jpg" if g == ".jpeg" else (g or ".bin")

def log(rec):
    with open(LOG_PATH, "a") as f:
        f.write(json.dumps(rec) + "\n")

def main():
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    maps = load_maps(con)
    tbl = {"tenancy": "tenancies", "unit": "units", "property": "properties"}

    rows = list(csv.DictReader(open(CSV_PATH, newline="", encoding="utf-8-sig")))

    # group by URL, choose most specific target row
    by_url = {}
    for r in rows:
        if (r["Relationship"] or "").strip() == "Workorder":
            continue
        u = (r["HTML Download Link"] or "").strip()
        if not u:
            continue
        lvl, et, aid = target_for_row(r)
        cur = by_url.get(u)
        if cur is None or lvl > cur[0][0]:
            by_url[u] = ((lvl, et, aid), r)

    plan = {"tenancy": 0, "unit": 0, "property": 0}
    skip_noid = []
    skip_missing = []
    todo = []
    for u, ((lvl, et, aid), r) in by_url.items():
        if lvl == 0:
            skip_noid.append((u, r["Document Name"]))
            continue
        internal = maps[tbl[et]].get(aid)
        if not internal:
            skip_missing.append((u, et, aid, r["Document Name"]))
            continue
        plan[et] += 1
        todo.append((u, et, internal, aid, r))

    print("=== PLAN ===")
    print("unique non-workorder URLs:", len(by_url))
    print("to import ->", plan, "= total", sum(plan.values()))
    print("SKIP no-id-in-row:", len(skip_noid))
    print("SKIP arthur-id-not-in-banksia:", len(skip_missing))
    if DRY:
        # show a breakdown of skip_missing by entity type for visibility
        from collections import Counter
        print("skip_missing by type:", dict(Counter(x[1] for x in skip_missing)))
        # sample of no-id doc names
        from collections import Counter as C2
        print("skip_noid top doc names:", C2(n for _, n in skip_noid).most_common(10))
        con.close()
        return

    # idempotency: already-imported asset uuids per entity
    done = set()
    for row in con.execute("SELECT entity_type, entity_id, notes FROM entity_documents WHERE notes LIKE '%arthur-asset:%'"):
        m = re.search(r"arthur-asset:([0-9a-f-]+)", row["notes"] or "")
        if m:
            done.add((row["entity_type"], row["entity_id"], m.group(1)))

    ok = 0; failed = 0; skipped_dupe = 0
    n = 0
    for (u, et, internal, aid, r) in todo:
        if LIMIT and n >= LIMIT:
            break
        n += 1
        uuid = asset_uuid(u)
        if (et, internal, uuid) in done:
            skipped_dupe += 1
            continue
        try:
            data, ct, cd = fetch(u)
        except Exception as e:
            failed += 1
            log({"status": "download_error", "url": u, "err": str(e), "doc": r["Document Name"]})
            continue
        doc_name = (r["Document Name"] or "document").strip()
        doc_name = doc_name.replace("/", "-").replace("\\", "-").lstrip(".") or "document"
        ext = ext_from(cd, ct, doc_name)
        orig = doc_name if os.path.splitext(doc_name)[1].lower() in KNOWN_EXT else (doc_name + ext)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        hash_part = hashlib.md5((orig + uuid).encode()).hexdigest()[:8]
        stored = f"{et}_{internal}_{ts}_{hash_part}{ext}"
        edir = os.path.join(UPLOAD_DIR, et, str(internal))
        os.makedirs(edir, exist_ok=True)
        fpath = os.path.join(edir, stored)
        with open(fpath, "wb") as fh:
            fh.write(data)
        size = os.path.getsize(fpath)
        mime = ct or "application/octet-stream"
        cat = category_for(r)
        notes = (f"Migrated from Arthur {r['Created Date']} | arthur-asset:{uuid} | "
                 f"type:{r['Document Type'] or '-'} rel:{r['Relationship'] or '-'} | "
                 f"tenancy:{r['Tenancy ID'] or '-'} unit:{r['Unit ID'] or '-'} property:{r['Property ID'] or '-'}")
        con.execute(
            "INSERT INTO entity_documents "
            "(entity_type, entity_id, original_filename, stored_filename, file_path, "
            "file_type, file_size, mime_type, category, notes, uploaded_by, is_verified) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,0)",
            (et, internal, orig, stored, fpath, ext.lstrip("."), size, mime, cat, notes, "arthur-migration"))
        con.commit()
        ok += 1
        log({"status": "ok", "url": u, "entity_type": et, "entity_id": internal,
             "arthur_id": aid, "orig": orig, "size": size, "category": cat})
        if ok % 250 == 0:
            print(f"...{ok} imported")

    print("=== DONE ===")
    print("imported:", ok, "| failed:", failed, "| skipped_dupe:", skipped_dupe)
    con.close()

if __name__ == "__main__":
    main()
