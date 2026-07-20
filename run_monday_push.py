#!/usr/bin/env python3
"""Cron entry point: push pending maintenance changes to Monday.com."""
import sys
sys.path.insert(0, '/root/banksia-backend')

import banksia_os_db as verv_os_db
from monday_push import push_all_pending

db = verv_os_db.get_db()
result = push_all_pending(db)
pushed = result.get("pushed", 0)
failed = result.get("failed", 0)
msg = result.get("message", "Unknown")
print(f"Monday push sync: {msg}")
if failed:
    print(f"Errors: {result.get('errors', [])}")
