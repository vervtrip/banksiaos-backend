#!/usr/bin/env python3
"""Runner: call push_all_pending with the verv_os_db connection."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from verv_os_db import get_db
from monday_push import push_all_pending
db = get_db()
result = push_all_pending(db)
print(result)
