def _fetch_first_id(conn, table, col="id"):
    """Get the first real ID from a table for testing."""
    return conn.execute(f"SELECT MIN({col}) FROM {table} WHERE {col} > 0").fetchone()[0]

import sqlite3
_TEST_IDS = sqlite3.connect("/root/banksia-dashboard/banksia_os.db", timeout=5)
PID, UID, TID, TENID, AID, MID
_TEST_IDS.close()