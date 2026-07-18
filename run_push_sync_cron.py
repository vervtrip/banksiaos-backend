"""Cron entry point: push pending local maintenance changes to Monday.com."""
import sys, os
sys.path.insert(0, os.path.dirname(__file__))

from banksia_os_db import get_db
from monday_push import push_all_pending

db = get_db()
result = push_all_pending(db)

print(f"Pushed: {result['pushed']}, Failed: {result['failed']}")
if result.get("errors"):
    for e in result["errors"][:3]:
        print(f"  Error: {e}")
print(result.get("message", ""))
