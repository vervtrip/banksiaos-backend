#!/usr/bin/env python3
"""
Fetch Missive emails related to a maintenance job by matching property address.
Called by the Flask API endpoint via subprocess.
Usage: python3 fetch_job_emails.py <job_id>
Outputs JSON with matched emails to stdout.
"""
import json, os, sys, re

# Add Missive client to path
sys.path.insert(0, '/opt/data/.neo/integrations/missive')
from missive_client import MissiveClient

VERV_ADMIN_INBOX_KEY = 'verv_admin'
TEAM_ID = 'def63c0e-5de1-4751-96dd-01974a030d91'

# Common words to strip when matching addresses
STOP_WORDS = {'the', 'a', 'an', 'and', 'or', 'of', 'to', 'in', 'for', 'on', 'at', 'road', 'street', 
              'close', 'lane', 'drive', 'avenue', 'gardens', 'way', 'court', 'place', 'terrace',
              'crescent', 'grove', 'rise', 'view', 'park', 'house', 'flat', 'london', 'nw', 'nw1',
              'nw2', 'nw3', 'nw4', 'nw5', 'nw6', 'nw7', 'nw8', 'n9', 'n10', 'n11',
              'sw1', 'sw2', 'sw3', 'sw4', 'sw5', 'sw6', 'sw7', 'sw8', 'sw9', 'sw10',
              'se1', 'se2', 'se3', 'se4', 'se5', 'se6', 'se7', 'se8', 'se9', 'se10',
              'e1', 'e2', 'e3', 'e4', 'e5', 'e6', 'e7', 'e8', 'e9', 'e10', 'e11',
              'w1', 'w2', 'w3', 'w4', 'w5', 'w6', 'w7', 'w8', 'w9', 'w10', 'w11',
              'n1', 'n2', 'n3', 'n4', 'n5', 'n6', 'n7', 'n8', 'n9', 'n10', 'n11',
              '1tf', '2tf', '3tf', '4tf', '5tf'}


def get_db():
    """Connect to the verv dashboard database to get job info."""
    db_path = '/root/verv-dashboard/verv_os.db'
    import sqlite3
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def extract_address_keywords(address_line_1, city):
    """Extract meaningful keywords from an address for matching."""
    parts = []
    if address_line_1:
        # Extract house number + street name
        parts.append(address_line_1.lower().strip())
        # Also add individual meaningful words
        words = re.findall(r'[a-zA-Z]+', address_line_1)
        for w in words:
            if len(w) > 2 and w.lower() not in STOP_WORDS:
                parts.append(w.lower())
    if city:
        parts.append(city.lower().strip())
    return parts


def match_subject(subject, address_keywords):
    """Check if the email subject contains address keywords."""
    if not subject or not address_keywords:
        return False
    subject_lower = subject.lower()
    # Check full address line 1 first (strongest match)
    if address_keywords and address_keywords[0] in subject_lower:
        return True
    # Check city
    if len(address_keywords) > 1 and address_keywords[1] in subject_lower:
        # Must also match at least one other keyword
        for kw in address_keywords[2:]:
            if kw in subject_lower:
                return True
    return False


def main():
    if len(sys.argv) < 2:
        print(json.dumps({"success": False, "error": "Usage: fetch_job_emails.py <job_id>"}))
        sys.exit(1)
    
    job_id = int(sys.argv[1])
    
    # Get job info from local database
    db = get_db()
    try:
        job = db.execute(
            """SELECT mj.*, p.name as property_name, p.address_line_1, p.address_line_2, 
                      p.city, p.postcode, p.property_owner_name 
               FROM maintenance_jobs mj 
               LEFT JOIN properties p ON mj.property_id = p.id 
               WHERE mj.id = ?""",
            [job_id]
        ).fetchone()
        
        if not job:
            print(json.dumps({"success": False, "error": "Job not found"}))
            sys.exit(1)
        
        # Convert Row to dict for easier access
        job = dict(job)
        
        address_line_1 = job.get("address_line_1") or job.get("address") or ""
        city = job.get("city") or ""
        property_owner = job.get("property_owner_name") or ""
        
        # Build search keywords from address
        address_keywords = [address_line_1.lower().strip(), city.lower().strip()]
        # Add individual words for fuzzy matching
        for part in [address_line_1, job.get("property_name", ""), job.get("address_line_2", "")]:
            if part:
                for w in re.findall(r'[a-zA-Z]+', part):
                    if len(w) > 2 and w.lower() not in STOP_WORDS:
                        address_keywords.append(w.lower())
        # Deduplicate
        address_keywords = list(dict.fromkeys(address_keywords))
        
        # Fetch conversations from Missive
        client = MissiveClient()
        conv_resp = client.list_conversations(inbox_key=VERV_ADMIN_INBOX_KEY, limit=100)
        
        matched_emails = []
        
        if conv_resp["success"]:
            conversations = conv_resp["data"].get("conversations", [])
            for conv in conversations:
                subject = conv.get("latest_message_subject") or conv.get("subject") or ""
                authors = conv.get("authors", []) or []
                users = conv.get("users", []) or []
                
                # Try to match subject against address keywords
                if not match_subject(subject, address_keywords):
                    continue
                
                # Get sender info from authors
                from_name = ""
                from_address = ""
                if authors:
                    first = authors[0] if isinstance(authors[0], dict) else {}
                    from_name = first.get("name", "")
                    from_address = first.get("address", "")
                
                # Get date from last_message_at or created_at
                created_at = conv.get("last_activity_at") or conv.get("created_at") or ""
                
                matched_emails.append({
                    "missive_id": conv.get("id"),
                    "subject": subject[:200],
                    "from_name": from_name[:100],
                    "from_address": from_address[:100],
                    "date": created_at,
                    "snippet": (conv.get("preview") or "")[:300],
                })
        else:
            # Missive fetch failed — return empty list gracefully
            pass
        
        result = {
            "success": True,
            "data": {
                "emails": matched_emails,
                "property_owner": property_owner,
                "property_address": address_line_1,
                "property_city": city,
                "total_matched": len(matched_emails),
            }
        }
        
        print(json.dumps(result))
        
    except Exception as e:
        print(json.dumps({"success": False, "error": str(e)}))
        sys.exit(1)
    finally:
        db.close()


if __name__ == "__main__":
    main()
