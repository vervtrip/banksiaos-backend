#!/usr/bin/env python3
"""Run the Monday push sync — called by cron."""
import sqlite3
import sys
sys.path.insert(0, "/root/verv-dashboard")

from monday_push import push_all_pending

db = sqlite3.connect("/root/verv-dashboard/banksia_os.db")
db.row_factory = sqlite3.Row

result = push_all_pending(db)
db.close()

print(f"Pushed: {result['pushed']}, Failed: {result['failed']}")
if result.get("errors"):
    for e in result["errors"]:
        print(f"  ERROR: {e}")
print(result["message"])
