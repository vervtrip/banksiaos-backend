"""
Banksia OS — Database service layer.
Common DB helpers, pagination, response formatting, and change log.
"""
from banksia_os_db import get_dict_db
from flask import jsonify, request


def bool_fields(row, *fields):
    """Convert 0/1 int fields to bool in-place."""
    for f in fields:
        if f in row:
            row[f] = bool(row[f])
    return row


def paginate(query, count_query, params, page, per_page):
    """Run a paginated query returning (rows, total)."""
    db = get_dict_db()
    try:
        total = db.execute(count_query, params).fetchone()["cnt"]
        offset = (page - 1) * per_page
        rows = db.execute(query + " LIMIT ? OFFSET ?", params + [per_page, offset]).fetchall()
        return rows, total
    finally:
        db.close()


def json_success(data, total=None, page=None, per_page=None):
    """Standard success response envelope."""
    resp = {"success": True, "data": data}
    if total is not None:
        resp["total"] = total
        resp["page"] = page or 1
        resp["per_page"] = per_page or 20
    return jsonify(resp)


def json_error(msg, status=400):
    """Standard error response."""
    return jsonify({"success": False, "error": msg}), status


def clean_none(row):
    """Replace all None values with empty string, recursing into nested dicts/lists."""
    if row is None:
        return ""
    if isinstance(row, dict):
        return {k: clean_none(v) for k, v in row.items()}
    if isinstance(row, list):
        return [clean_none(v) for v in row]
    return row


def int_param(val, default=1, max_val=None):
    """Safely parse an int query parameter."""
    try:
        v = int(val)
        return min(v, max_val) if max_val is not None else v
    except (TypeError, ValueError):
        return default


def float_param(val):
    """Safely parse a float query parameter. Returns None if not provided."""
    try:
        return float(val)
    except (TypeError, ValueError):
        return None


def build_search_clause(fields, search_term):
    """Build a bare SQL clause (no leading AND/WHERE) for searching across multiple
    fields. Callers either wrap it in their own parens or join it into a where_parts
    list with " AND ".join() — it must not carry its own leading boolean operator."""
    if not search_term:
        return "", []
    clauses = [f"{f} LIKE ?" for f in fields]
    return "(" + " OR ".join(clauses) + ")", [f"%{search_term}%"] * len(fields)


def build_order_by(sortable_map, default_clause):
    """Build ORDER BY clause from sortable field map and default."""
    sort_by = request.args.get("sort_by")
    sort_dir = request.args.get("sort_dir", "asc")
    if sort_by and sort_by in sortable_map:
        col = sortable_map[sort_by]
        d = "DESC" if sort_dir.lower() == "desc" else "ASC"
        return f"{col} {d}"
    return default_clause


def record_change(user_name, action, entity_type, entity_id=None, summary=None, details=None):
    """Record an activity/change log entry."""
    try:
        db = get_dict_db()
        db.execute(
            "INSERT INTO change_log (user_name, action, entity_type, entity_id, summary, details) VALUES (?, ?, ?, ?, ?, ?)",
            [user_name, action, entity_type, entity_id, summary, details]
        )
        db.commit()
        db.close()
    except Exception:
        pass
