"""
Arthur Landlord Email Syncer
━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Syncs landlord/owner emails from Arthur API into Banksia OS property_owners table.

Usage:
    python3 /root/verv-dashboard/scripts/sync_arthur_owner_emails.py

Requires:
    - Valid Arthur OAuth credentials in hmobanksia profile
    - Arthur API access to /v2/landlords endpoint

This script must be run AFTER a fresh Arthur OAuth token has been obtained.
To re-authorise Arthur: run the OAuth PKCE flow through the hmobanksia profile.
"""

import json
import subprocess
import sys
import os

# Add the dashboard dir for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# ─── Arthur auth ────────────────────────────────────────────────────────

def read_env_value(key):
    """Read the LAST occurrence of a key from the hmobanksia .env file."""
    env_path = '/root/.hermes/profiles/hmobanksia/.env'
    if not os.path.exists(env_path):
        print(f"ERROR: {env_path} not found")
        sys.exit(1)
    
    with open(env_path) as f:
        lines = f.readlines()
    
    value = ''
    for line in lines:
        line = line.strip()
        if line.startswith(key + '='):
            value = line.split('=', 1)[1]
    return value


def get_arthur_token():
    """Refresh the Arthur OAuth token."""
    client_id = read_env_value('ARTHUR_CLIENT_ID')
    client_secret = read_env_value('ARTHUR_CLIENT_SECRET')
    refresh_token = read_env_value('ARTHUR_REFRESH_TOKEN')
    
    if not all([client_id, client_secret, refresh_token]):
        print("ERROR: Missing Arthur OAuth credentials in hmobanksia/.env")
        print("Run: hermes auth add arthur --profile hmobanksia")
        sys.exit(1)
    
    result = subprocess.run([
        'curl', '-s', '--max-time', '10', '-X', 'POST',
        'https://auth.arthuronline.co.uk/oauth/token',
        '-H', 'Content-Type: application/x-www-form-urlencoded',
        '-d', f'grant_type=refresh_token&refresh_token={refresh_token}&client_id={client_id}&client_secret={client_secret}',
    ], capture_output=True, text=True, timeout=15)
    
    d = json.loads(result.stdout)
    
    if 'access_token' in d:
        # Save the refreshed token
        state_path = '/root/.hermes/state/arthur_token.json'
        with open(state_path, 'w') as f:
            json.dump(d, f)
        print(f"Token refreshed, expires in {d.get('expires_in', '?')}s")
        return d['access_token']
    else:
        print(f"Token refresh failed: {d.get('name')} - {d.get('message')}")
        print("\nTo authorise Arthur fresh:")
        print("  hermes auth add arthur --profile hmobanksia")
        return None


def fetch_landlords(token):
    """Fetch all landlords from Arthur."""
    all_landlords = []
    page = 1
    per_page = 200
    
    while True:
        result = subprocess.run([
            'curl', '-s', '--max-time', '15',
            f'https://api.arthuronline.co.uk/v2/landlords?page={page}&per_page={per_page}',
            '-H', f'Authorization: Bearer {token}',
            '-H', 'Accept: application/json',
        ], capture_output=True, text=True, timeout=20)
        
        d = json.loads(result.stdout)
        landlords = d.get('landlords', [])
        
        if not landlords:
            if 'error' in d:
                print(f"API error: {d['error']} - {d.get('message', '')}")
            break
        
        all_landlords.extend(landlords)
        total = d.get('total', 0)
        print(f"  Page {page}: got {len(landlords)} landlords (total: {total})")
        
        if len(all_landlords) >= total:
            break
        page += 1
    
    return all_landlords


def sync_owner_emails(landlords):
    """Update the property_owners table with landlord emails."""
    from banksia_os_db import get_dict_db
    
    db = get_dict_db()
    updated = 0
    skipped = 0
    
    # Get existing owners as a map keyed by name (case-insensitive)
    existing = db.execute(
        "SELECT id, name, contact_email FROM property_owners"
    ).fetchall()
    
    name_map = {}
    for row in existing:
        name_map[row['name'].strip().lower()] = {
            'id': row['id'],
            'name': row['name'],
            'current_email': row['contact_email'] or '',
        }
    
    print(f"\nExisting owners in DB: {len(name_map)}")
    
    for landlord in landlords:
        arthur_id = landlord.get('id', '')
        name = (landlord.get('name') or '').strip()
        email = (landlord.get('email') or '').strip()
        email2 = (landlord.get('email2') or '').strip()
        
        if not name:
            continue
        
        key = name.lower()
        match = name_map.get(key)
        
        if not match:
            print(f"  SKIP (no match): {name} (Arthur ID: {arthur_id})")
            skipped += 1
            continue
        
        # Combine emails
        emails = [e for e in [email, email2] if e]
        combined = ', '.join(emails) if emails else ''
        
        if not combined:
            skipped += 1
            continue
        
        if match['current_email'] == combined:
            skipped += 1
            continue
        
        # Update the owner
        db.execute(
            "UPDATE property_owners SET contact_email = ? WHERE id = ?",
            [combined, match['id']]
        )
        print(f"  UPDATE: {name:35s} → {combined}")
        updated += 1
    
    db.commit()
    db.close()
    
    print(f"\nDone! Updated: {updated}, Skipped: {skipped}")


# ─── Main ──────────────────────────────────────────────────────────────

if __name__ == '__main__':
    print("=== Arthur Landlord Email Syncer ===")
    
    token = get_arthur_token()
    if not token:
        sys.exit(1)
    
    print(f"\nFetching landlords from Arthur...")
    landlords = fetch_landlords(token)
    print(f"Total: {len(landlords)}")
    
    with_email = [l for l in landlords if l.get('email') or l.get('email2')]
    print(f"With email: {len(with_email)}")
    
    for l in with_email[:20]:
        print(f"  {l['id']:10s} | {l.get('name',''):35s} | {l.get('email',''):30s} | {l.get('email2',''):30s}")
    
    sync_owner_emails(landlords)
