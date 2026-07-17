#!/usr/bin/env python3
"""Cron entry point: push pending maintenance jobs to Monday.com."""
import sys
sys.path.insert(0, "/root/verv-dashboard")

from verv_os_db import get_dict_db
from monday_push import push_all_pending

db = get_dict_db()
result = push_all_pending(db)
print(f"PUSHED: {result['pushed']}")
print(f"FAILED: {result['failed']}")
errors = result.get('errors', [])
if errors:
    for e in errors:
        print(f"  ERROR: {e}")
print(f"MESSAGE: {result['message']}")
