#!/usr/bin/env python3
"""Cron entry point: push pending local dashboard changes to Monday.com."""
import sys
sys.path.insert(0, '/root/banksia-dashboard')
from monday_push import push_all_pending
from banksia_os_db import get_db

db = get_db()
result = push_all_pending(db)
print(result["message"])
sys.exit(0 if result["failed"] == 0 else 1)
