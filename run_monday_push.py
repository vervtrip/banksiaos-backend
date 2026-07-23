#!/usr/bin/env python3
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import monday_push
monday_push.TOKEN_PATH = '/root/.hermes/secrets/monday_token.txt'
from banksia_os_db import get_db
db = get_db()
try:
    result = monday_push.push_all_pending(db)
    print(f"PUSH RESULT: {result["message"]}")
    print(f"  Pushed: {result["pushed"]}")
    print(f"  Failed: {result["failed"]}")
    if result.get("errors"):
        for e in result["errors"]:
            print(f"  Error: {e}")
finally:
    db.close()
