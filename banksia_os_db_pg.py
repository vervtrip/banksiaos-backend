#!/usr/bin/env python3
"""
Banksia OS — PostgreSQL Database Layer.
Drop-in replacement for banksia_os_db.py using PgBouncer connection pooling.
Connection string: postgresql://banksia:banksia_os_pass@127.0.0.1:6432/banksia_os
"""
import json, os, threading, uuid, time
from datetime import datetime, timezone

import psycopg2
import psycopg2.extras
import psycopg2.pool

PG_DSN = "host=127.0.0.1 port=6432 dbname=banksia_os user=banksia password=banksia_os_pass"
MIN_CONN = 5
MAX_CONN = 20

_pool = None
_pool_lock = threading.Lock()


def _get_pool():
    global _pool
    if _pool is None:
        with _pool_lock:
            if _pool is None:
                _pool = psycopg2.pool.ThreadedConnectionPool(MIN_CONN, MAX_CONN, PG_DSN)
    return _pool


_vos_local = threading.local()


def _get_conn():
    """Get a connection from the pool (thread-local cached)."""
    if not hasattr(_vos_local, 'conn') or _vos_local.conn is None:
        pool = _get_pool()
        _vos_local.conn = pool.getconn()
        _vos_local.dict_conn = None
    return _vos_local.conn


def _get_dict_conn():
    """Get a dict-row connection from the pool."""
    if not hasattr(_vos_local, 'dict_conn') or _vos_local.dict_conn is None:
        pool = _get_pool()
        conn = pool.getconn()
        conn.autocommit = False
        _vos_local.dict_conn = conn
    return _vos_local.dict_conn


def _put_conns():
    """Return thread-local connections to the pool. Call at end of request."""
    pool = _get_pool()
    for attr in ('conn', 'dict_conn'):
        c = getattr(_vos_local, attr, None)
        if c is not None:
            try:
                pool.putconn(c)
            except Exception:
                pass
            setattr(_vos_local, attr, None)


# ═══════════════════════════════════════════════
# Public API — mirrors banksia_os_db.py
# ═══════════════════════════════════════════════

def get_db():
    """Return a psycopg2 connection with standard row factory."""
    conn = _get_conn()
    return conn


def get_dict_db():
    """Return a psycopg2 connection with RealDictCursor (like sqlite3.Row)."""
    conn = _get_dict_conn()
    return conn


def init_db():
    """No-op for PG — schema already created by migration script."""
    pass


def dict_from_row(row, cursor=None):
    """
    Convert a psycopg2 RealDictRow (or any dict-like) to a plain dict.
    Works like the sqlite3 version: dict(row).
    """
    if row is None:
        return None
    return dict(row)


def insert(table, data):
    """
    Insert a row and return the new ID.
    Data is a dict of {column: value}.
    """
    conn = _get_dict_conn()
    cols = list(data.keys())
    vals = [data[c] for c in cols]
    col_str = ', '.join(f'"{c}"' for c in cols)
    placeholders = ', '.join(['%s'] * len(cols))

    cur = conn.cursor()
    try:
        cur.execute(
            f'INSERT INTO "{table}" ({col_str}) VALUES ({placeholders}) RETURNING id',
            vals
        )
        conn.commit()
        row = cur.fetchone()
        return row[0] if row else None
    except Exception:
        conn.rollback()
        raise
    finally:
        cur.close()


def update(table, row_id, data, mark_dirty=False):
    """
    Update a row by id. Data is a dict of {column: value}.
    If mark_dirty=True, also sets sync_dirty=1.
    """
    conn = _get_dict_conn()
    updates = dict(data)
    if mark_dirty and 'sync_dirty' not in updates:
        updates['sync_dirty'] = 1

    set_clause = ', '.join(f'"{c}" = %s' for c in updates)
    vals = list(updates.values()) + [row_id]

    cur = conn.cursor()
    try:
        cur.execute(
            f'UPDATE "{table}" SET {set_clause} WHERE id = %s',
            vals
        )
        conn.commit()
        return cur.rowcount
    except Exception:
        conn.rollback()
        raise
    finally:
        cur.close()


def get(table, row_id):
    """Get a single row by id. Returns dict or None."""
    conn = _get_dict_conn()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        cur.execute(f'SELECT * FROM "{table}" WHERE id = %s', (row_id,))
        row = cur.fetchone()
        return dict(row) if row else None
    finally:
        cur.close()


def get_by_field(table, field, value):
    """Get rows where field = value. Returns list of dicts."""
    conn = _get_dict_conn()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        cur.execute(f'SELECT * FROM "{table}" WHERE "{field}" = %s', (value,))
        return [dict(r) for r in cur.fetchall()]
    finally:
        cur.close()


def list_all(table, order="id DESC", limit=500, off=0):
    """List rows with ordering and pagination."""
    conn = _get_dict_conn()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        # Sanitise order clause — only allow column + ASC/DESC
        safe_order = _sanitise_order(order)
        cur.execute(
            f'SELECT * FROM "{table}" ORDER BY {safe_order} LIMIT %s OFFSET %s',
            (limit, off)
        )
        return [dict(r) for r in cur.fetchall()]
    finally:
        cur.close()


def count(table, where="1=1", params=None):
    """Count rows matching a WHERE clause."""
    conn = _get_dict_conn()
    cur = conn.cursor()
    try:
        cur.execute(f'SELECT COUNT(*) AS cnt FROM "{table}" WHERE {where}', params or [])
        return cur.fetchone()[0]
    finally:
        cur.close()


def raw_query(sql, params=None):
    """
    Execute a SELECT query and return all rows as list of dicts.
    WARNING: table/column names in sql must be safe — no user interpolation!
    For parameterised WHERE clauses, use %s placeholders and pass params.
    """
    conn = _get_dict_conn()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        cur.execute(sql, params or [])
        return [dict(r) for r in cur.fetchall()]
    finally:
        cur.close()


def raw_execute(sql, params=None):
    """
    Execute a write query (INSERT/UPDATE/DELETE) and commit.
    Returns rowcount.
    WARNING: table/column names in sql must be safe — no user interpolation!
    """
    conn = _get_dict_conn()
    cur = conn.cursor()
    try:
        cur.execute(sql, params or [])
        conn.commit()
        return cur.rowcount
    except Exception:
        conn.rollback()
        raise
    finally:
        cur.close()


def _sanitise_order(order):
    """Allow only safe ORDER BY expressions: column ASC/DESC, optionally multiple separated by comma."""
    parts = []
    for part in order.split(','):
        part = part.strip()
        tokens = part.split()
        if len(tokens) == 1:
            col = tokens[0].strip('"')
            if col.isidentifier():
                parts.append(f'"{col}"')
        elif len(tokens) == 2:
            col, direction = tokens
            col = col.strip('"')
            direction = direction.upper()
            if col.isidentifier() and direction in ('ASC', 'DESC'):
                parts.append(f'"{col}" {direction}')
        # If nothing matched, skip this part (safe fallback)
    return ', '.join(parts) if parts else 'id DESC'


# ── Connection cleanup for Flask teardown ──

def close_request():
    """Call this at end of request to return connections to pool."""
    _put_conns()


def cleanup_pool():
    """Close all connections in the pool. Call on app shutdown."""
    global _pool
    if _pool is not None:
        _pool.closeall()
        _pool = None
