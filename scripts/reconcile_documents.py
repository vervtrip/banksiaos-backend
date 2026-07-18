#!/usr/bin/env python3
"""
Document Reconciliation Script.
For each document in the documents table:
  - Resolve related_id (which may be an Arthur ID or internal ID) to actual internal DB IDs
  - Classify as: linked (already resolved), resolved (now linked), ambiguous, unmatched
  - Log the results and save a report

The documents table uses related_to / related_id to link to entities.
related_id can be an Arthur ID (e.g., '1145870') or an internal DB ID (e.g., '2290'),
so we need to try both.

Idempotent: skips documents already properly resolved.
"""

import os, sys, json
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from banksia_os_db import get_dict_db

REPORT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "docs")
os.makedirs(REPORT_DIR, exist_ok=True)

def resolve_entity(db, related_to, related_id_str):
    """
    Resolve a related_to/related_id pair to internal DB IDs.
    Returns dict with keys: entity_type, entity_id, property_id, unit_id, tenancy_id, tenant_id, applicant_id
    Or None if no match.
    """
    if not related_id_str or not related_id_str.strip():
        return None

    related_id = related_id_str.strip()
    result = {
        "entity_type": related_to,
        "entity_id": None,
        "property_id": None,
        "unit_id": None,
        "tenancy_id": None,
        "tenant_id": None,
        "applicant_id": None,
    }

    if related_to == "property":
        # Try internal ID first
        if related_id.isdigit():
            row = db.execute("SELECT id, arthur_id FROM properties WHERE id = ?", (int(related_id),)).fetchone()
            if row:
                result["entity_id"] = row["id"]
                result["property_id"] = row["id"]
                return result
        # Try arthur_id
        row = db.execute("SELECT id FROM properties WHERE arthur_id = ?", (related_id,)).fetchone()
        if row:
            result["entity_id"] = row["id"]
            result["property_id"] = row["id"]
            return result

    elif related_to == "tenancy":
        # Try internal ID first
        if related_id.isdigit():
            row = db.execute("SELECT id, property_id, unit_id FROM tenancies WHERE id = ?", (int(related_id),)).fetchone()
            if row:
                result["entity_id"] = row["id"]
                result["tenancy_id"] = row["id"]
                result["property_id"] = row["property_id"]
                result["unit_id"] = row["unit_id"]
                return result
        # Try arthur_id
        row = db.execute("SELECT id, property_id, unit_id FROM tenancies WHERE arthur_id = ?", (related_id,)).fetchone()
        if row:
            result["entity_id"] = row["id"]
            result["tenancy_id"] = row["id"]
            result["property_id"] = row["property_id"]
            result["unit_id"] = row["unit_id"]
            return result

    elif related_to == "tenant":
        # Try internal ID first
        if related_id.isdigit():
            row = db.execute("SELECT id, tenancy_id, property_id, unit_id FROM tenants WHERE id = ?", (int(related_id),)).fetchone()
            if row:
                result["entity_id"] = row["id"]
                result["tenant_id"] = row["id"]
                result["tenancy_id"] = row["tenancy_id"]
                result["property_id"] = row["property_id"]
                result["unit_id"] = row["unit_id"]
                return result
        # Try arthur_id
        row = db.execute("SELECT id, tenancy_id, property_id, unit_id FROM tenants WHERE arthur_id = ?", (related_id,)).fetchone()
        if row:
            result["entity_id"] = row["id"]
            result["tenant_id"] = row["id"]
            result["tenancy_id"] = row["tenancy_id"]
            result["property_id"] = row["property_id"]
            result["unit_id"] = row["unit_id"]
            return result

    elif related_to == "applicant":
        # Try internal ID first
        if related_id.isdigit():
            row = db.execute("SELECT id FROM applicants WHERE id = ?", (int(related_id),)).fetchone()
            if row:
                result["entity_id"] = row["id"]
                result["applicant_id"] = row["id"]
                return result
        # Try arthur_id
        row = db.execute("SELECT id FROM applicants WHERE arthur_id = ?", (related_id,)).fetchone()
        if row:
            result["entity_id"] = row["id"]
            result["applicant_id"] = row["id"]
            return result

    return None


def main():
    db = get_dict_db()

    # Fetch all documents
    docs = db.execute("SELECT * FROM documents ORDER BY id").fetchall()
    total = len(docs)
    print(f"\n{'='*70}")
    print(f"  DOCUMENT RECONCILIATION REPORT")
    print(f"  Generated: {datetime.now(timezone.utc).isoformat()}")
    print(f"{'='*70}")
    print(f"\nTotal documents in DB: {total}")

    if total == 0:
        print("No documents to reconcile.")
        return

    categories = {
        "linked": [],       # Already had related_id that resolved immediately / entity_id already populated
        "resolved": [],     # Successfully resolved related_id → internal ID via arthur_id or direct match
        "ambiguous": [],    # related_id matched multiple records
        "unmatched": [],    # Could not resolve related_id to any internal ID
        "no_ref": [],       # No related_to / related_id set at all
    }

    resolutions = []

    # We'll also store new notes with resolution details
    for doc in docs:
        doc_id = doc["id"]
        related_to = doc.get("related_to") or ""
        related_id = doc.get("related_id") or ""
        filename = doc.get("filename") or "?"
        notes = doc.get("notes") or ""

        entry = {
            "id": doc_id,
            "filename": filename,
            "related_to": related_to,
            "related_id": related_id,
        }

        if not related_to or not related_id:
            entry["reason"] = "No related_to or related_id set"
            categories["no_ref"].append(entry)
            resolutions.append(entry)
            continue

        # Check if already resolved (notes contain '[RESOLVED]' marker)
        if "[RESOLVED]" in notes:
            entry["reason"] = "Already resolved in previous run"
            categories["linked"].append(entry)
            resolutions.append(entry)
            continue

        entity = resolve_entity(db, related_to, related_id)

        if entity is None:
            # Could not resolve
            entry["reason"] = f"No match found for {related_to} ID '{related_id}'"
            categories["unmatched"].append(entry)
            resolutions.append(entry)
            continue

        # Successfully resolved
        entry["entity_id"] = entity["entity_id"]
        entry["property_id"] = entity["property_id"]
        entry["unit_id"] = entity["unit_id"]
        entry["tenancy_id"] = entity["tenancy_id"]
        entry["tenant_id"] = entity["tenant_id"]
        entry["applicant_id"] = entity["applicant_id"]

        # Actually update the documents table with a resolution note
        # (The current schema doesn't have FK columns, so we add a note)
        detail_parts = []
        if entity["tenancy_id"]:
            detail_parts.append(f"tenancy_id={entity['tenancy_id']}")
        if entity["property_id"]:
            detail_parts.append(f"property_id={entity['property_id']}")
        if entity["unit_id"]:
            detail_parts.append(f"unit_id={entity['unit_id']}")
        if entity["tenant_id"]:
            detail_parts.append(f"tenant_id={entity['tenant_id']}")
        if entity["applicant_id"]:
            detail_parts.append(f"applicant_id={entity['applicant_id']}")

        new_note = f"[RESOLVED] {related_to}#{entity['entity_id']} ({', '.join(detail_parts)})"
        if notes:
            if "[RESOLVED]" not in notes:
                new_note = notes + f" | {new_note}"
        else:
            new_note = new_note

        db.execute(
            "UPDATE documents SET notes = ? WHERE id = ?",
            (new_note, doc_id)
        )

        entry["reason"] = f"Resolved to internal {related_to}#{entity['entity_id']}"
        categories["resolved"].append(entry)
        resolutions.append(entry)

    db.commit()

    # ── Print Report ────────────────────────────────────
    print(f"\n─── CLASSIFICATION ──────────────────────────────────────")
    print(f"  LINKED    (already resolved):  {len(categories['linked'])}")
    print(f"  RESOLVED  (newly resolved):    {len(categories['resolved'])}")
    print(f"  AMBIGUOUS (multiple matches):  {len(categories['ambiguous'])}")
    print(f"  UNMATCHED (no match found):    {len(categories['unmatched'])}")
    print(f"  NO_REF    (no entity ref):     {len(categories['no_ref'])}")
    print(f"  ───────────────────────────────────────────")
    print(f"  TOTAL     (all documents):     {total}")
    print(f"{'='*70}")

    if categories["resolved"]:
        print(f"\n─── NEWLY RESOLVED DOCUMENTS ──────────────────────────")
        for entry in categories["resolved"]:
            print(f"  [{entry['id']}] {entry['filename'][:50]:50s} → {entry['reason']}")

    if categories["unmatched"]:
        print(f"\n─── UNMATCHED DOCUMENTS ───────────────────────────────")
        for entry in categories["unmatched"]:
            print(f"  [{entry['id']}] {entry['filename'][:50]:50s} → {entry['reason']}")

    if categories["no_ref"]:
        print(f"\n─── DOCUMENTS WITHOUT ENTITY REFERENCE ────────────────")
        for entry in categories["no_ref"]:
            print(f"  [{entry['id']}] {entry['filename'][:50]:50s} → {entry['reason']}")

    if categories["ambiguous"]:
        print(f"\n─── AMBIGUOUS (NEEDS MANUAL REVIEW) ───────────────────")
        for entry in categories["ambiguous"]:
            print(f"  [{entry['id']}] {entry['filename'][:50]:50s} → {entry['reason']}")

    # ── Save detailed report ────────────────────────────
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    report_path = os.path.join(REPORT_DIR, f"document_reconciliation_{timestamp}.txt")
    with open(report_path, "w") as f:
        f.write(f"Document Reconciliation Report\n")
        f.write(f"Generated: {datetime.now(timezone.utc).isoformat()}\n")
        f.write(f"{'='*80}\n\n")
        f.write(f"Total documents in DB: {total}\n\n")
        f.write(f"─── CLASSIFICATION ───\n")
        f.write(f"  LINKED:    {len(categories['linked'])}\n")
        f.write(f"  RESOLVED:  {len(categories['resolved'])}\n")
        f.write(f"  AMBIGUOUS: {len(categories['ambiguous'])}\n")
        f.write(f"  UNMATCHED: {len(categories['unmatched'])}\n")
        f.write(f"  NO_REF:    {len(categories['no_ref'])}\n")
        f.write(f"  TOTAL:     {total}\n\n")
        f.write(f"{'='*80}\n\n")

        for cat_name in ["linked", "resolved", "unmatched", "ambiguous", "no_ref"]:
            items = categories[cat_name]
            if not items:
                continue
            f.write(f"\n{'='*80}\n")
            f.write(f"Category: {cat_name.upper()} ({len(items)} items)\n")
            f.write(f"{'='*80}\n")
            for entry in items:
                f.write(f"  ID={entry['id']} | filename={entry['filename']} | related_to={entry.get('related_to','?')} | related_id={entry.get('related_id','?')} | reason={entry.get('reason','')}\n")

    # Also save JSON version
    json_path = os.path.join(REPORT_DIR, f"document_reconciliation_{timestamp}.json")
    with open(json_path, "w") as f:
        json.dump({
            "generated": datetime.now(timezone.utc).isoformat(),
            "summary": {
                "total": total,
                "linked": len(categories["linked"]),
                "resolved": len(categories["resolved"]),
                "ambiguous": len(categories["ambiguous"]),
                "unmatched": len(categories["unmatched"]),
                "no_ref": len(categories["no_ref"]),
            },
            "categories": {k: v for k, v in categories.items()},
        }, f, indent=2, default=str)

    print(f"\nDetailed report saved to: {report_path}")
    print(f"JSON report saved to:    {json_path}")


if __name__ == "__main__":
    main()
