#!/usr/bin/env python3
"""Run push_all_pending from monday_push module."""
import sys
sys.path.insert(0, '/root/banksia-backend')

from banksia_os_db import get_dict_db
from monday_push import push_all_pending

db = get_dict_db()
result = push_all_pending(db)
db.close()

print(f"Pushed: {result['pushed']}")
print(f"Failed: {result['failed']}")
if result.get('errors'):
    print(f"Errors: {result['errors']}")
print(f"Message: {result['message']}")
