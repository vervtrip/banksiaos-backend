#!/usr/bin/env python3
import sys
sys.path.insert(0, '/root/verv-dashboard')

from verv_os_db import get_db
from monday_push import push_all_pending

db = get_db()
result = push_all_pending(db)
print(result)
