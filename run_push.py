#!/usr/bin/env python3
"""CLI entry point: push all pending local changes to Monday.com Maintenance Reports."""
import sys
import sqlite3
sys.path.insert(0, "/root/verv-dashboard")

from monday_push import push_all_pending

db = sqlite3.connect("/root/verv-dashboard/verv_os.db")
db.row_factory = sqlite3.Row

result = push_all_pending(db)
print(result["message"])
if result["pushed"] > 0:
    print(f"  Pushed: {result['pushed']}")
if result["failed"] > 0:
    print(f"  Failed: {result['failed']}")
    for e in result.get("errors", []):
        print(f"     - {e}")
db.close()
