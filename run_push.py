#!/usr/bin/env python3
"""Push pending maintenance changes to Monday.com and report results."""
import sys
sys.path.insert(0, "/root/verv-dashboard")

from verv_os_db import get_dict_db
from monday_push import push_all_pending

db = get_dict_db()
result = push_all_pending(db)
print(
    f"push_all_pending returned: "
    f"pushed={result['pushed']}, "
    f"failed={result['failed']}, "
    f'message="{result["message"]}"'
)
if result.get("errors"):
    for e in result["errors"]:
        print(f"  Error: {e}")
db.close()
