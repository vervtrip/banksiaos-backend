#!/usr/bin/env python3
"""Run the maintenance push sync and report results."""
import json
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))

from verv_os_db import get_db
from monday_push import push_all_pending

db = get_db()
result = push_all_pending(db)
print(json.dumps(result))
