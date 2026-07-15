#!/usr/bin/env python3
"""
Fetch Missive Orders inbox emails and match to maintenance jobs by property address.
Called by the Flask API endpoint via subprocess.
Usage: python3 fetch_job_orders.py <job_id>
  job_id=0: Return ALL non-marketing orders from the Orders inbox
  job_id>0: Return orders matched to that specific job
Outputs JSON with matched orders to stdout.
"""
import json, os, sys, re

# Add Missive client to path
sys.path.insert(0, '/opt/data/.neo/integrations/missive')
from missive_client import MissiveClient

ORDERS_INBOX_KEY = 'orders'

# Marketing filters - skip obvious promos
MARKETING_KEYWORDS = ['sale', 'deal', 'review', 'feedback', 'shopping spree',
                      'members.wayfair', 'em.screwfix', 'reply.ebay', 'emails.argos',
                      'newsletter', 'unsubscribe', 'worth a closer look',
                      'less than 48h', 'don\'t forget', 'massive discount',
                      'before it\'s gone', 't.ao.com', 'verification code']

# Email domains that indicate marketing/bulk senders
MARKETING_DOMAIN_PARTS = ['members.wayfair', 'em.screwfix', 'reply.ebay', 't.ao.com']


def get_db():
    """Connect to the verv dashboard database."""
    import sqlite3
    conn = sqlite3.connect('/root/verv-dashboard/verv_os.db')
    conn.row_factory = sqlite3.Row
    return conn


def is_marketing(subject, from_address=''):
    """Check if an email subject looks like marketing/promotional."""
    if not subject:
        return False
    subject_lower = subject.lower()
    if any(k in subject_lower for k in MARKETING_KEYWORDS):
        return True
    # Check sender domain
    if from_address:
        from_lower = from_address.lower()
        if any(d in from_lower for d in MARKETING_DOMAIN_PARTS):
            return True
    return False


def extract_order_ref(subject):
    """Try to extract an order reference from the subject line."""
    if not subject:
        return ''
    ref_match = re.search(r'(?:order|ref|#)\s*[#: ]?([A-Z0-9]{5,20})', subject, re.IGNORECASE)
    if ref_match:
        return ref_match.group(1)
    return ''


def fetch_all_orders():
    """Return ALL non-marketing orders from the Orders inbox."""
    try:
        client = MissiveClient()
        convs = client.list_conversations(inbox_key=ORDERS_INBOX_KEY, limit=50)
        if not convs.get('success'):
            return {"orders": [], "error": "Missive API error"}

        conversations = convs['data'].get('conversations', [])
        orders = []

        for conv in conversations:
            if conv is None:
                continue

            subject = str(conv.get('latest_message_subject', '') or '').lower()
            authors = conv.get('authors', []) or []

            # Get sender info first
            from_name = ''
            from_addr = ''
            if authors and len(authors) > 0 and authors[0]:
                from_name = str(authors[0].get('name', '') or '')
                from_addr = str(authors[0].get('address', '') or '')

            # Skip marketing emails
            if is_marketing(subject, from_addr):
                continue

            orders.append({
                "missive_id": conv.get('id', ''),
                "subject": conv.get('latest_message_subject', '') or '',
                "from_name": from_name,
                "from_address": from_addr,
                "created_at": conv.get('created_at', 0),
                "order_ref": extract_order_ref(subject),
            })

        return {"orders": orders, "total_matched": len(orders)}
    except Exception as e:
        return {"orders": [], "error": str(e)}


def fetch_orders_for_job(job_id):
    """Return order emails from Missive that might relate to this job."""
    import sqlite3
    db = get_db()

    try:
        # Get job and property info
        job = db.execute("""
            SELECT mj.*, p.name as property_name, p.address_line_1, p.address_line_2,
                   p.city, p.postcode
            FROM maintenance_jobs mj
            LEFT JOIN properties p ON mj.property_id = p.id
            WHERE mj.id = ?
        """, [job_id]).fetchone()

        if not job:
            return {"orders": [], "error": "Job not found"}

        # Convert Row to dict
        job = dict(job)

        # Build search terms from property address
        address_parts = []
        for field in ['address_line_1', 'address_line_2', 'city', 'postcode', 'property_name', 'address']:
            val = job.get(field, '')
            if val and len(str(val)) > 3:
                address_parts.append(str(val).lower())

        # Also get the title/description for keyword matching
        job_title = str(job.get('title') or '').lower()
        job_desc = str(job.get('description') or '').lower()

        try:
            c = MissiveClient()
            convs = c.list_conversations(inbox_key=ORDERS_INBOX_KEY, limit=50)
            if not convs.get('success'):
                return {"orders": [], "error": "Missive API error"}

            conversations = convs['data'].get('conversations', [])
            matched = []

            for conv in conversations:
                if conv is None:
                    continue

                subject = str(conv.get('latest_message_subject', '') or '').lower()

                # Skip marketing emails
                if is_marketing(subject):
                    continue

                # Get sender info
                from_name = ''
                from_addr = ''
                authors = conv.get('authors', []) or []
                if authors and len(authors) > 0 and authors[0]:
                    from_name = str(authors[0].get('name', '') or '')
                    from_addr = str(authors[0].get('address', '') or '')

                # Match: check if property address keywords appear in subject
                address_match = any(part in subject for part in address_parts if len(part) > 5)

                # Also try matching job title keywords
                title_keywords = [w for w in job_title.split() if len(w) > 4]
                desc_keywords = [w for w in job_desc.split() if len(w) > 4]
                keyword_match = any(kw in subject for kw in title_keywords + desc_keywords)

                if address_match or keyword_match:
                    # Extract potential order ref from subject
                    order_ref = extract_order_ref(subject)

                    matched.append({
                        "missive_id": conv.get('id', ''),
                        "subject": conv.get('latest_message_subject', '') or '',
                        "from_name": from_name,
                        "from_address": from_addr,
                        "created_at": conv.get('created_at', 0),
                        "order_ref": order_ref,
                        "match_type": "address" if address_match else "keyword",
                        "match_term": next((p for p in address_parts if p in subject),
                                           next((k for k in title_keywords + desc_keywords if k in subject), ''))
                    })

            return {"orders": matched, "total_matched": len(matched)}
        except Exception as e:
            return {"orders": [], "error": str(e)}
    except Exception as e:
        return {"orders": [], "error": str(e)}
    finally:
        db.close()


def main():
    if len(sys.argv) < 2:
        print(json.dumps({"success": False, "error": "Usage: fetch_job_orders.py <job_id>"}))
        sys.exit(1)

    job_id = int(sys.argv[1])

    if job_id == 0:
        # Return ALL non-marketing orders
        result = fetch_all_orders()
        print(json.dumps({"success": True, "data": result}))
    else:
        # Return orders matched to this specific job
        result = fetch_orders_for_job(job_id)
        print(json.dumps({"success": True, "data": result}))


if __name__ == '__main__':
    main()
