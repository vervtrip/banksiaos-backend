#!/usr/bin/env python3
"""Script entry point — call push_all_pending from the module."""
import sys
sys.path.insert(0, '/root/verv-dashboard')

from verv_os_db import get_db
from monday_push import push_all_pending

db = get_db()
result = push_all_pending(db)
print(f"Pushed: {result['pushed']}, Failed: {result['failed']}")
if result.get('errors'):
    for e in result['errors']:
        print(f"  Error: {e}")
print(f"Message: {result['message']}")
