#!/usr/bin/env python3
"""Full transaction sync — imports ALL transactions from Arthur without limits."""
import sys, json, subprocess, os, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from arthur_sync import arthur_get_all_pages, get_db, raw_execute

print('[SYNC] Syncing ALL transactions...')
raw_execute('DELETE FROM transactions')
print('  Cleared existing transactions')

items = arthur_get_all_pages(
    'transactions',
    params={'status': 'overdue,outstanding,paid,cancelled,refunded,void'},
    max_pages=None
)
print(f'  Arthur returned: {len(items) if items else 0} items')

if not items:
    print('  No transactions returned')
    sys.exit(0)

synced = 0
updated = 0
inserted = 0
now = time.time()
CHECKPOINT = 200

for item in items:
    synced += 1
    arthur_id = str(item.get('id', ''))
    db = get_db()
    try:
        existing = db.execute('SELECT id FROM transactions WHERE arthur_id = ?', (arthur_id,)).fetchone()
        if existing:
            fields, vals = [], []
            for key, val in item.items():
                if isinstance(val, (dict, list)) or key == 'id':
                    continue
                safe_key = key.replace(' ', '_').replace('-', '_')
                fields.append(f'{safe_key} = ?')
                vals.append(val)
            vals.append(existing['id'])
            db.execute(f'UPDATE transactions SET {", ".join(fields)} WHERE id = ?', vals)
            updated += 1
        else:
            keys, placeholders, vals = [], [], []
            for key, val in item.items():
                if isinstance(val, (dict, list)) or key == 'id':
                    continue
                safe_key = key.replace(' ', '_').replace('-', '_')
                keys.append(safe_key)
                placeholders.append('?')
                vals.append(val)
            db.execute(f'INSERT INTO transactions (arthur_id, {", ".join(keys)}) VALUES (?, {", ".join(placeholders)})', [arthur_id] + vals)
            inserted += 1
        db.commit()
        if synced % CHECKPOINT == 0:
            elapsed = time.time() - now
            print(f'  {synced}/{len(items)} synced ({elapsed:.0f}s)')
    except Exception as e:
        print(f'  Error item {arthur_id}: {e}')
    finally:
        db.close()

print(f'  Complete: {synced} total ({inserted} inserted, {updated} updated)')
print(f'  Time: {time.time() - now:.0f}s')