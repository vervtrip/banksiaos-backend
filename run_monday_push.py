#!/usr/bin/env python3
"""Cron entry point: push pending maintenance changes to Monday.com."""
import sys
sys.path.insert(0, '/root/verv-dashboard')

from verv_os_db import get_db
from monday_push import push_all_pending

db = get_db()
count = push_all_pending(db)
print(f"Pushed {count} pending maintenance item(s) to Monday.com board 18401159622.")
