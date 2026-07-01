#!/usr/bin/env python3
"""Test Arthur API endpoints."""
import json, subprocess

tok = json.load(open('/root/.hermes/state/arthur_token.json'))
TOKEN = tok['access_token']
EID = tok.get('entity_id', '349912')
BASE = 'https://api.arthuronline.co.uk/v2'

def ag(path):
    hdr = 'Authorization: Bearer *** + TOKEN
    cmd = ['curl', '-s', '-H', hdr, '-H', 'X-EntityID: ' + EID, BASE + '/' + path]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    return json.loads(r.stdout)

for name, path in [
    ('tenancies_all', 'tenancies?per_page=5'),
    ('tenancies_active', 'tenancies?status=active&per_page=5'),
    ('tenancies_periodic', 'tenancies?status=periodic&per_page=5'),
]:
    d = ag(path)
    items = d.get('data', [])
    pag = d.get('pagination', {})
    print(f'{name}: items={len(items)}, total={pag.get("count")}')
    if items:
        print(f'  statuses: {[x.get("status") for x in items]}')
        print(f'  keys: {list(items[0].keys())[:25]}')
    print()