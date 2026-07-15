"""
Conversation Timeline Backfill & Sync
======================================
Scans the observation DB for messages about specific maintenance jobs and
logs them into the conversation_timeline table.

Also provides a bridge log parser for real-time message capture.

Usage:
    python3 conversation_timeline.py backfill           # One-time backfill from observations
    python3 conversation_timeline.py sync <job_id>      # Scan for a specific job
"""

import sqlite3
import json
import sys
import re
from datetime import datetime, timezone

DB_PATH = "/root/verv-dashboard/verv_os.db"
OBS_DB_PATH = "/opt/data/.neo/observation/observation.db"

GROUP_NAMES = {
    "120363025808656845@g.us": "Zolt & Alex (Maintenance)",
    "120363402767920961@g.us": "Zolt & Fernando (Maintenance)",
    "120363412447325160@g.us": "Zolt & Arslan (Maintenance)",
    "120363423115520243@g.us": "HMO/STR Maintenance",
    "120363400323093606@g.us": "STR Chat",
    "120363426036377353@g.us": "HMO Management",
    "120363197465376628@g.us": "Luna (STR) Chat",
    "120363287524126919@g.us": "Verv Management",
    "120363025642209897@g.us": "Central Hub",
    "120363028224237544@g.us": "Verv & Millwall",
    "120363406319097872@g.us": "Banksia & Fernanda",
    "120363291996726949@g.us": "Luna & StarLite Laundry",
}

# Contractor keywords to match in messages
CONTRACTOR_MAP = {
    "fernando": "Fernando",
    "calazans": "Fernando",
    "alex": "Alex",
    "mirpolat": "Mirpolat",
    "mirpo": "Mirpolat",
    "jermaine": "Jermaine",
    "javeed": "Javeed",
    "devup": "DevUp",
    "fernanda": "Fernanda",
    "nisar": "Nisar",
    "shahid": "Shahid",
    "arslan": "Arslan",
}

def get_db():
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    return db

def make_hash(job_id, sender_id, body, ts):
    """Make a deterministic hash to prevent duplicates."""
    raw = f"{job_id}|{sender_id}|{body}|{ts}"
    return str(hash(raw))

def index_message(job_id, source_group, sender_id, sender_name, body, ts, contractor=None):
    """Insert a message into the conversation_timeline table."""
    db = get_db()
    try:
        group_name = GROUP_NAMES.get(source_group, source_group)
        h = make_hash(job_id, sender_id, body, ts)
        
        db.execute("""
            INSERT OR IGNORE INTO conversation_timeline
                (job_id, source_group, source_group_name, sender_id, sender_name,
                 body, message_timestamp, hash, linked_contractor)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (job_id, source_group, group_name, sender_id, sender_name, body, ts, h, contractor))
        db.commit()
    except Exception as e:
        print(f"  Error indexing message: {e}")
    finally:
        db.close()

def find_matching_jobs(text):
    """Find which maintenance jobs might be referenced in a message.
    Matches by address fragments or reference numbers only — strict matching."""
    db = get_db()
    matches = []
    try:
        text_lower = text.lower() if text else ""
        
        # Get all jobs with addresses
        rows = db.execute("""
            SELECT mj.id, mj.reference, mj.title, mj.contractor, 
                   mj.address
            FROM maintenance_jobs mj
            WHERE mj.address IS NOT NULL AND mj.address != ''
               OR mj.reference IS NOT NULL AND mj.reference != ''
            ORDER BY mj.id
        """).fetchall()
        
        for r in rows:
            addr = (r["address"] or "").strip().lower()
            ref = (r["reference"] or "").strip().lower()
            
            # Match by full address (exact match on individual lines)
            if addr and len(addr) > 5:
                # Break address into significant parts
                addr_parts = [p.strip() for p in addr.replace(',', ' ').split() if len(p.strip()) > 3]
                significant_parts = [p for p in addr_parts if not p.startswith('flat') and not p.startswith('room')]
                if significant_parts and all(p in text_lower for p in significant_parts[:2]):
                    matches.append((r["id"], r["reference"], r["contractor"]))
                    continue
            
            # Match by ref number
            if ref and ref in text_lower:
                matches.append((r["id"], r["reference"], r["contractor"]))
                continue
                        
    except Exception as e:
        print(f"  Error matching jobs: {e}")
    finally:
        db.close()
    
    return matches

def backfill_from_observations():
    """Scan all observations for contractor-related messages and index them."""
    if not OBS_DB_PATH:
        print("Observation DB not found")
        return
    
    obs_db = sqlite3.connect(OBS_DB_PATH)
    obs_db.row_factory = sqlite3.Row
    
    # Get all observations
    rows = obs_db.execute("""
        SELECT timestamp, group_id, group_name, sender_id, sender_name, raw_preview
        FROM observations
        WHERE raw_preview IS NOT NULL AND raw_preview != ''
        ORDER BY timestamp ASC
    """).fetchall()
    
    print(f"Scanning {len(rows)} observations for contractor conversations...")
    
    indexed = 0
    for r in rows:
        text = r["raw_preview"]
        sender = r["sender_name"] or "?"
        group = r["group_id"] or r["group_name"] or ""
        ts = r["timestamp"]
        sender_id = r["sender_id"] or ""
        
        # Find which contractor this relates to
        contractor = None
        text_lower = text.lower()
        for keyword, name in CONTRACTOR_MAP.items():
            if keyword in text_lower:
                contractor = name
                break
        
        # Find which jobs this matches
        job_matches = find_matching_jobs(text)
        
        if job_matches:
            for job_id, ref, job_contractor in job_matches:
                # Use the job's contractor if we didn't find one from text
                c = contractor or job_contractor
                index_message(job_id, group, sender_id, sender, text[:500], ts, c)
                indexed += 1
                if indexed <= 5:
                    print(f"  Indexed: Job #{job_id} ({ref}) — {sender}: {text[:80]}...")
    
    print(f"\nTotal indexed: {indexed} messages")
    obs_db.close()

def scan_for_job(job_id):
    """Scan and find all conversation entries for a specific job."""
    db = get_db()
    try:
        rows = db.execute("""
            SELECT ct.*, mj.reference AS job_ref, mj.title AS job_title,
                   mj.contractor AS job_contractor, mj.address AS job_address
            FROM conversation_timeline ct
            JOIN maintenance_jobs mj ON mj.id = ct.job_id
            WHERE ct.job_id = ?
            ORDER BY ct.message_timestamp ASC
        """, (job_id,)).fetchall()
        
        result = []
        for r in rows:
            result.append({
                "id": r["id"],
                "sender_name": r["sender_name"],
                "body": r["body"],
                "timestamp": r["message_timestamp"],
                "source_group": r["source_group_name"] or r["source_group"],
                "linked_contractor": r["linked_contractor"],
            })
        
        contractor = rows[0]["job_contractor"] if rows else None
        ref = rows[0]["job_ref"] if rows else None
        title = rows[0]["job_title"] if rows else None
        addr = rows[0]["job_address"] if rows else None
        
        return {
            "job_id": job_id,
            "job_ref": ref,
            "job_title": title,
            "job_contractor": contractor,
            "job_address": addr,
            "conversations": result,
            "count": len(result),
        }
    finally:
        db.close()

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "backfill":
        backfill_from_observations()
    elif len(sys.argv) > 2 and sys.argv[1] == "sync":
        scan_for_job(int(sys.argv[2]))
    else:
        print("Usage: python3 conversation_timeline.py backfill")
        print("       python3 conversation_timeline.py sync <job_id>")
