#!/usr/bin/env python3
"""
Maintenance Job Reconciliation Script.
For each maintenance_job:
  - If property_id is already set → keep (linked)
  - Try to match by address substring in the title field or address field
  - Try to match by property reference or name patterns
  - Only auto-link confident exact matches
  - Mark ambiguous matches for manual review
  - Update property_id where confident

Idempotent: skips jobs that already have property_id set.
"""

import os, sys, json, re
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from banksia_os_db import get_dict_db

REPORT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "docs")
os.makedirs(REPORT_DIR, exist_ok=True)


def extract_address_patterns(title, address):
    """
    Extract identifiable address/place patterns from a maintenance job title and address.
    Returns a list of candidate strings to search against property addresses/names.
    """
    candidates = []
    text = f"{title or ''} {address or ''}"

    # Extract postcodes (UK postcodes)
    postcodes = re.findall(r'\b[A-Z]{1,2}\d[A-Z\d]?\s*\d[A-Z]{2}\b', text, re.IGNORECASE)
    for pc in postcodes:
        candidates.append(pc.strip().upper())

    # Extract property-name-looking patterns: "Xxx — ..." or "Xxx - ..."
    # e.g. "32 Clinton Road - ...", "13 Jacobson House — ..."
    # This is the most reliable pattern from the data
    named = re.findall(r'^(.*?)\s*[—–\-–]\s', text.strip(), re.MULTILINE)
    for n in named:
        n = n.strip()
        if n and len(n) > 3:
            candidates.append(n)

    # Also look for "Flat X, ..." or "Room X, ..." patterns
    flat_matches = re.findall(r'(Flat\s+\w+[^,]*,\s*[^,]+)', text, re.IGNORECASE)
    for fm in flat_matches:
        candidates.append(fm.strip())

    # Extract numbered addresses like "32 Clinton Road", "95 Wheat Sheaf Close"
    addr_matches = re.findall(r'\b(\d+\s+[A-Z][a-zA-Z\s]+?)(?:[,\(]|$|\s+–|\s+—|\s+-)', text)
    for am in addr_matches:
        am = am.strip().rstrip(",")
        if am and len(am) > 5:
            candidates.append(am)

    return candidates


def find_matching_property(db, title, address):
    """
    Try to find a matching property for a maintenance job.
    Returns (property_id, match_type, confidence) or (None, reason, 0).
    
    match_type: 'exact_address', 'unique_postcode', 'title_prefix', 'partial', 'ambiguous', 'none'
    """
    if not title and not address:
        return (None, "No title or address provided", 0.0)

    text = (f"{title or ''} {address or ''}").strip()
    if not text:
        return (None, "Empty text", 0.0)

    candidates = extract_address_patterns(title, address)

    # Strategy 1: Check for postcode match
    postcodes = re.findall(r'\b([A-Z]{1,2}\d[A-Z\d]?\s*\d[A-Z]{2})\b', text, re.IGNORECASE)
    if postcodes:
        # Standardise the postcode
        pc = postcodes[0].strip().upper()
        pc_stripped = pc.replace(" ", "")
        props = db.execute(
            "SELECT id, name, address_line_1, postcode FROM properties WHERE postcode IS NOT NULL AND postcode != ''"
        ).fetchall()
        exact_matches = []
        for p in props:
            db_pc = (p["postcode"] or "").strip().upper().replace(" ", "")
            if pc_stripped == db_pc or pc == (p["postcode"] or "").strip().upper():
                exact_matches.append(p)
            elif pc_stripped in db_pc or db_pc in pc_stripped:
                exact_matches.append(p)

        if len(exact_matches) == 1:
            return (exact_matches[0]["id"], "unique_postcode", 0.9)
        elif len(exact_matches) > 1:
            # Multiple properties with same postcode – try address line match to disambiguate
            addr_line = re.sub(r'\b' + re.escape(postcodes[0]) + r'\b', '', text, flags=re.IGNORECASE).strip()
            for p in exact_matches:
                p_addr = (p["address_line_1"] or "").lower()
                if p_addr and (p_addr in addr_line.lower() or addr_line.lower() in p_addr):
                    return (p["id"], "exact_address", 0.95)
            # Still ambiguous
            return (None, f"ambiguous_postcode_{pc}_{len(exact_matches)}_matches", 0.0)

    # Strategy 2: Check title prefix patterns like "32 Clinton Road - ..." or "13 Jacobson House — ..."
    # These are the most common patterns in the data
    for prefix_match in [
        re.match(r'^([\d]+\s+[A-Za-z].*?)\s*[—–\-–]\s', text),
        re.match(r'^([A-Za-z].*?)\s*[—–\-–]\s', text),
    ]:
        if prefix_match:
            prefix = prefix_match.group(1).strip().rstrip(",")
            if len(prefix) < 5:
                continue
            props = db.execute(
                "SELECT id, address_line_1, name FROM properties WHERE address_line_1 IS NOT NULL"
            ).fetchall()
            matches = []
            for p in props:
                p_addr = (p["address_line_1"] or "").lower()
                p_name = (p["name"] or "").lower()
                prefix_lower = prefix.lower()
                # Check if prefix is contained in address or vice versa
                if prefix_lower in p_addr or p_addr in prefix_lower:
                    matches.append(p)
                # Also check flat number patterns
                elif prefix_lower in p_name:
                    matches.append(p)

            if len(matches) == 1:
                return (matches[0]["id"], "title_prefix", 0.9)
            elif len(matches) > 1:
                return (None, f"ambiguous_prefix_{prefix}_{len(matches)}_matches", 0.0)

    # Strategy 3: Check if any address pattern matches a unique property address
    props = db.execute(
        "SELECT id, address_line_1, name FROM properties WHERE address_line_1 IS NOT NULL"
    ).fetchall()

    exact_matches = []
    for p in props:
        p_addr = (p["address_line_1"] or "").lower()
        text_lower = text.lower()
        # Check if the exact property address appears in the job text
        if p_addr and len(p_addr) > 5 and (p_addr in text_lower or text_lower in p_addr):
            exact_matches.append(p)
        # Also check intersection of significant keywords
        elif p_addr and len(p_addr) > 5:
            # Try matching address number + street name
            addr_parts = p_addr.split(",")
            first_part = addr_parts[0].strip()
            if first_part and len(first_part) > 5 and first_part in text_lower:
                exact_matches.append(p)

    if len(exact_matches) == 1:
        return (exact_matches[0]["id"], "exact_address", 0.9)
    elif len(exact_matches) > 1:
        return (None, f"ambiguous_address_{len(exact_matches)}_matches", 0.0)

    # Strategy 4: Try to match specific known property addresses from the text
    # For jobs with addresses like "30 Bettons Park, E15 3JN, Room 3"
    if address:
        addr_lower = address.lower().strip()
        for p in props:
            p_addr = (p["address_line_1"] or "").lower().strip()
            if p_addr and (p_addr in addr_lower or addr_lower in p_addr):
                return (p["id"], "address_field_match", 0.85)
            # Check if the address starts with the property address
            if p_addr and addr_lower.startswith(p_addr):
                return (p["id"], "address_prefix_match", 0.85)

    # Strategy 5: Check for "Unknown Property" titles
    if "unknown property" in text.lower():
        return (None, "marked_as_unknown_property", 0.0)

    # Strategy 6: For job titles that mention a property by unique substrings
    # e.g. "Bricklane" → Brick Lane properties, "Claremont" → Claremont Square
    special_mappings = [
        (r'\bbricklane\b', "Brick Lane"),
        (r'\bbrick\s*lane\b', "Brick Lane"),
        (r'\bclaremont\b', "Claremont Square"),
        (r'\bhonor\s*oak\b', "Honor Oak"),
        (r'\bhighbury\b', "Highbury Corner"),
        (r'\blubbock\b', "Lubbock House"),
        (r'\bjacobson\b', "Jacobson House"),
        (r'\bradford\b', "Radford House"),
        (r'\bfakruddin\b', "Fakruddin Street"),
        (r'\bagamemnon\b', "Agamemnon Road"),
        (r'\bgreen\s*street\b', "Green street"),
        (r'\bcarrol\s*close\b', "Carrol Close"),
        (r'\bclaylands\b', "Claylands Road"),
        (r'\bepstein\b', "Epstein Square"),
        (r'\bfishguard\b', "Fishguard Way"),
        (r'\bcarolina\s*close\b', "Carolina Close"),
        (r'\bgrundy\b', "Grundy Street"),
        (r'\bmile\s*end\b', "Mile End Road"),
        (r'\bclinton\b', "Clinton Road"),
        (r'\bwheat\s*sheaf\b', "Wheat Sheaf Close"),
        (r'\bloren\b', "Loren Apartments"),
        (r'\bbunning\b', "Bunning Way"),
        (r'\bettrick\b', "Ettrick Street"),
        (r'\bdavey\s*close\b', "Davey Close"),
        (r'\bwraysbury\b', "Wraysbury Drive"),
        (r'\brabazon\b', "Brabazon Street"),
        (r'\bboxley\b', "Bexley"),
        (r'\bstudd\b', "Studd Street"),
        (r'\beleanor\b', "Eleanor Road"),
        (r'\brectory\b', "Rectory Square"),
        (r'\bbettons\b', "Bettons Park"),
        (r'\bzion\b.*\bjubilee\b', "Zion House"),
        (r'\blowfield\b', "Lowfield Road"),
        (r'\bchingford\b', "Chingford"),
        (r'\bradford\b', "Radford House"),
    ]

    for pattern, keyword in special_mappings:
        if re.search(pattern, text, re.IGNORECASE):
            matching_props = []
            for p in props:
                p_addr = (p["address_line_1"] or "").lower()
                if keyword.lower() in p_addr:
                    matching_props.append(p)
            if len(matching_props) == 1:
                return (matching_props[0]["id"], "keyword_match", 0.7)
            elif len(matching_props) > 1:
                return (None, f"ambiguous_keyword_{keyword}_{len(matching_props)}_matches", 0.0)

    # Strategy 7: Check for numbered address pattern at start of title
    # Like "40 Brabazon Street (Room 2) — ..."
    addr_num_match = re.match(r'^(\d+\s+[A-Za-z].*?)\s*(?:\(|\[|\s*[—–\-–]\s)', text)
    if addr_num_match:
        addr_str = addr_num_match.group(1).strip().rstrip(",")
        for p in props:
            p_addr = (p["address_line_1"] or "").lower()
            if addr_str.lower() in p_addr or p_addr in addr_str.lower():
                return (p["id"], "numbered_address", 0.8)

    return (None, "no_match", 0.0)


def main():
    db = get_dict_db()

    # Fetch all maintenance jobs
    jobs = db.execute("SELECT * FROM maintenance_jobs ORDER BY id").fetchall()
    total = len(jobs)
    print(f"\n{'='*70}")
    print(f"  MAINTENANCE JOB RECONCILIATION REPORT")
    print(f"  Generated: {datetime.now(timezone.utc).isoformat()}")
    print(f"{'='*70}")
    print(f"\nTotal maintenance jobs in DB: {total}")

    categories = {
        "linked": [],       # property_id already set
        "resolved": [],     # property_id now matched and set
        "ambiguous": [],    # Multiple possible property matches
        "unmatched": [],    # No match found
    }

    updated_count = 0

    for job in jobs:
        job_id = job["id"]
        title = job.get("title") or ""
        address = job.get("address") or ""
        monday_id = job.get("monday_id") or ""
        ref = job.get("reference") or ""
        existing_pid = job.get("property_id")

        entry = {
            "id": job_id,
            "monday_id": monday_id,
            "title": title[:60],
            "address": address or "(none)",
            "existing_property_id": existing_pid,
        }

        # If already linked, keep
        if existing_pid is not None:
            # Verify the property still exists
            prop = db.execute("SELECT id FROM properties WHERE id = ?", (existing_pid,)).fetchone()
            if prop:
                entry["matched_property_id"] = existing_pid
                entry["reason"] = "Already linked"
                categories["linked"].append(entry)
                continue
            else:
                # property_id points to non-existent property — treat as unmatched
                entry["reason"] = f"property_id={existing_pid} references non-existent property"
                categories["unmatched"].append(entry)
                continue

        # Try to match
        property_id, match_type, confidence = find_matching_property(db, title, address)

        if property_id is not None:
            # Confident match — update the property_id
            db.execute(
                "UPDATE maintenance_jobs SET property_id = ? WHERE id = ?",
                (property_id, job_id)
            )
            updated_count += 1
            entry["matched_property_id"] = property_id
            entry["match_type"] = match_type
            entry["confidence"] = confidence
            entry["reason"] = f"Matched via {match_type} (conf={confidence})"
            categories["resolved"].append(entry)
        elif "ambiguous" in match_type:
            entry["match_type"] = match_type
            entry["reason"] = match_type
            categories["ambiguous"].append(entry)
        else:
            entry["reason"] = match_type
            categories["unmatched"].append(entry)

    db.commit()

    # ── Print Report ────────────────────────────────────
    resolved = len(categories["resolved"])
    linked = len(categories["linked"])
    ambiguous = len(categories["ambiguous"])
    unmatched = len(categories["unmatched"])

    print(f"\n─── CLASSIFICATION ──────────────────────────────────────")
    print(f"  LINKED    (already set):      {linked}")
    print(f"  RESOLVED  (newly matched):     {resolved}")
    print(f"  AMBIGUOUS (multiple matches):  {ambiguous}")
    print(f"  UNMATCHED (no match found):    {unmatched}")
    print(f"  ───────────────────────────────────────────")
    print(f"  TOTAL     (all jobs):          {total}")
    print(f"  Updated in DB:                {updated_count}")
    print(f"{'='*70}")

    if categories["resolved"]:
        print(f"\n─── NEWLY RESOLVED MAINTENANCE JOBS ───────────────────")
        for entry in categories["resolved"][:30]:
            print(f"  [{entry['id']}] {entry['title'][:55]:55s} → prop_id={entry['matched_property_id']} ({entry['reason']})")
        if len(categories["resolved"]) > 30:
            print(f"  ... and {len(categories['resolved']) - 30} more")

    if categories["ambiguous"]:
        print(f"\n─── AMBIGUOUS (NEEDS MANUAL REVIEW) ───────────────────")
        for entry in categories["ambiguous"][:20]:
            print(f"  [{entry['id']}] {entry['title'][:55]:55s} → {entry['reason']}")
        if len(categories["ambiguous"]) > 20:
            print(f"  ... and {len(categories['ambiguous']) - 20} more")

    if categories["unmatched"]:
        print(f"\n─── UNMATCHED MAINTENANCE JOBS ─────────────────────────")
        for entry in categories["unmatched"][:30]:
            print(f"  [{entry['id']}] {entry['title'][:55]:55s} → {entry['reason']}")
        if len(categories["unmatched"]) > 30:
            print(f"  ... and {len(categories['unmatched']) - 30} more")

    # ── Save detailed report ────────────────────────────
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    report_path = os.path.join(REPORT_DIR, f"maintenance_reconciliation_{timestamp}.txt")
    with open(report_path, "w") as f:
        f.write(f"Maintenance Job Reconciliation Report\n")
        f.write(f"Generated: {datetime.now(timezone.utc).isoformat()}\n")
        f.write(f"{'='*80}\n\n")
        f.write(f"Total maintenance jobs in DB: {total}\n")
        f.write(f"Records updated in DB:        {updated_count}\n\n")
        f.write(f"─── CLASSIFICATION ───\n")
        f.write(f"  LINKED:    {linked}\n")
        f.write(f"  RESOLVED:  {resolved}\n")
        f.write(f"  AMBIGUOUS: {ambiguous}\n")
        f.write(f"  UNMATCHED: {unmatched}\n")
        f.write(f"  TOTAL:     {total}\n\n")

        for cat_name in ["linked", "resolved", "unmatched", "ambiguous"]:
            items = categories[cat_name]
            if not items:
                continue
            f.write(f"\n{'='*80}\n")
            f.write(f"Category: {cat_name.upper()} ({len(items)} items)\n")
            f.write(f"{'='*80}\n")
            for entry in items:
                f.write(f"  ID={entry['id']} | monday={entry.get('monday_id','?')} | title={entry.get('title','?')} | address={entry.get('address','?')} | reason={entry.get('reason','?')}")
                if entry.get("matched_property_id"):
                    f.write(f" | matched_property_id={entry['matched_property_id']}")
                f.write("\n")

    # JSON version
    json_path = os.path.join(REPORT_DIR, f"maintenance_reconciliation_{timestamp}.json")
    with open(json_path, "w") as f:
        json.dump({
            "generated": datetime.now(timezone.utc).isoformat(),
            "summary": {
                "total": total,
                "linked": linked,
                "resolved": resolved,
                "ambiguous": ambiguous,
                "unmatched": unmatched,
                "updated": updated_count,
            },
            "categories": {k: v for k, v in categories.items()},
        }, f, indent=2, default=str)

    print(f"\nDetailed report saved to: {report_path}")
    print(f"JSON report saved to:    {json_path}")


if __name__ == "__main__":
    main()
