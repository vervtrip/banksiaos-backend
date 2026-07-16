#!/usr/bin/env python3
"""Run maintenance push-sync — push pending items to Monday.com."""
import sys
sys.path.insert(0, '/root/verv-dashboard')

from monday_push import push_all_pending
from verv_os_db import get_db

db = get_db()
result = push_all_pending(db)
print(f"Pushed: {result['pushed']}, Failed: {result['failed']}")
if result.get('errors'):
    for e in result['errors']:
        print(f"  Error: {e}")
print(f"Message: {result['message']}")
