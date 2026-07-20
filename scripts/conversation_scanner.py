"""
Forward conversation scanner for maintenance jobs.
Runs via cron every 15 minutes to index new WhatsApp messages about jobs.
Uses the Hermes session DB to find recent messages from Zolt contractor groups.
"""

import sqlite3
import os
import sys
import json
from datetime import datetime

# Add parent for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

DB_PATH = "/root/banksia-backend/banksia_os.db"

# Contractor keywords mapped to names
CONTRACTOR_KEYWORDS = {
    "fernando": "Fernando", "calazans": "Fernando",
    "alex": "Alex",
    "mirpolat": "Mirpolat", "mirpo": "Mirpolat",
    "jermaine": "Jermaine",
    "javeed": "Javeed",
    "devup": "DevUp",
    "fernanda": "Fernanda",
    "nisar": "Nisar", "shahid": "Shahid",
    "arslan": "Arslan",
}

# Priority groups to scan (Zolt contractor groups)
PRIORITY_GROUPS = [
    "120363025808656845@g.us",   # Zolt & Alex
    "120363402767920961@g.us",   # Zolt & Fernando
    "120363412447325160@g.us",   # Zolt & Arslan
    "120363423115520243@g.us",   # HMO/STR Maintenance
    "120363426036377353@g.us",   # HMO Management
    "120363400323093606@g.us",   # STR Chat
    "120363197465376628@g.us",   # Luna STR Chat
    "120363406319097872@g.us",   # Banksia & Fernanda
    "120363287524126919@g.us",   # Verv Management
]

GROUP_NAMES = {
    "120363025808656845@g.us": "Zolt & Alex (Maintenance)",
    "120363402767920961@g.us": "Zolt & Fernando (Maintenance)",
    "120363412447325160@g.us": "Zolt & Arslan (Maintenance)",
    "120363423115520243@g.us": "HMO/STR Maintenance",
    "120363426036377353@g.us": "HMO Management",
    "120363400323093606@g.us": "STR Chat",
    "120363197465376628@g.us": "Luna (STR) Chat",
    "120363287524126919@g.us": "Verv Management",
    "120363406319097872@g.us": "Banksia & Fernanda",
    "120363291996726949@g.us": "Luna & StarLite Laundry",
}

def get_db():
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    return db

def find_matching_jobs(text_lower):
    """Find maintenance jobs whose address appears in the text."""
    db = get_db()
    matches = []
    try:
        rows = db.execute("""
            SELECT id, reference, contractor, address
            FROM maintenance_jobs
            WHERE address IS NOT NULL AND address != ''
        """).fetchall()
        
        for r in rows:
            addr = (r["address"] or "").strip().lower()
            if addr and len(addr) > 5:
                # Match significant address parts
                parts = [p.strip() for p in addr.replace(',', ' ').split() if len(p.strip()) > 3]
                sig_parts = [p for p in parts 
                             if not p.startswith('flat') and not p.startswith('room')
                             and not p.startswith('door')]
                if sig_parts and all(p in text_lower for p in sig_parts[:2]):
                    matches.append((r["id"], r["reference"], r["contractor"]))
    except Exception as e:
        print(f"  Error: {e}")
    finally:
        db.close()
    return matches

def detect_contractor(text_lower):
    for kw, name in CONTRACTOR_KEYWORDS.items():
        if kw in text_lower:
            return name
    return None

def index_message(job_id, source_group, sender_name, body, ts, contractor=None):
    db = get_db()
    try:
        group_name = GROUP_NAMES.get(source_group, source_group)
        raw = f"{job_id}|{source_group}|{sender_name}|{body[:200]}|{ts}"
        h = str(hash(raw))
        
        db.execute("""
            INSERT OR IGNORE INTO conversation_timeline
                (job_id, source_group, source_group_name, sender_name,
                 body, message_timestamp, hash, linked_contractor)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (job_id, source_group, group_name, sender_name, body[:500], ts, h, contractor))
        db.commit()
    except Exception as e:
        print(f"  Index error: {e}")
    finally:
        db.close()

def scan():
    """
    Main scan function. Reads observation DB for recent messages
    and indexes them against maintenance jobs.
    """
    obs_path = "/opt/data/.neo/observation/observation.db"
    if not os.path.isfile(obs_path):
        print("No observation DB found")
        return
    
    obs_db = sqlite3.connect(obs_path)
    obs_db.row_factory = sqlite3.Row
    
    # Get recent observations from priority groups
    # Last indexed observation ID from state file
    state_file = "/root/banksia-backend/.ct_state.json"
    last_id = 0
    if os.path.isfile(state_file):
        with open(state_file) as f:
            state = json.load(f)
            last_id = state.get("last_observation_id", 0)
    
    # Fetch new observations from priority groups
    group_placeholders = ",".join("?" for _ in PRIORITY_GROUPS)
    rows = obs_db.execute(f"""
        SELECT id, timestamp, group_id, group_name, sender_id, sender_name, raw_preview
        FROM observations
        WHERE id > ?
          AND group_id IN ({group_placeholders})
          AND raw_preview IS NOT NULL AND raw_preview != ''
        ORDER BY id ASC
    """, [last_id] + PRIORITY_GROUPS).fetchall()
    
    indexed = 0
    for r in rows:
        text = r["raw_preview"]
        text_lower = text.lower()
        group = r["group_id"] or r["group_name"] or ""
        ts = r["timestamp"]
        sender = r["sender_name"] or "?"
        
        # Detect contractor
        contractor = detect_contractor(text_lower)
        
        # Find matching jobs
        job_matches = find_matching_jobs(text_lower)
        
        if job_matches:
            for job_id, ref, job_contractor in job_matches:
                c = contractor or job_contractor
                index_message(job_id, group, sender, text[:500], ts, c)
                indexed += 1
        
        last_id = r["id"]
    
    # Save state
    with open(state_file, "w") as f:
        json.dump({"last_observation_id": last_id, "last_scanned": datetime.now().isoformat()}, f)
    
    obs_db.close()
    
    # Stats
    db = get_db()
    total = db.execute("SELECT COUNT(*) AS c FROM conversation_timeline").fetchone()["c"]
    jobs = db.execute("SELECT COUNT(DISTINCT job_id) AS c FROM conversation_timeline").fetchone()["c"]
    db.close()
    
    print(f"Scanned {len(rows)} new messages, indexed {indexed}, total: {total} entries across {jobs} jobs")
    
    if indexed > 0:
        return f"✅ Indexed {indexed} new messages. Total: {total} entries across {jobs} jobs."
    else:
        # Silent — nothing new
        return None

if __name__ == "__main__":
    result = scan()
    if result:
        print(result)
