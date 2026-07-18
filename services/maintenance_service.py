"""
Banksia OS — Maintenance service layer.
Maintenance jobs, orders, LL comms, Monday sync, portal promotion.
"""
import json, os, re
from datetime import datetime
from banksia_os_db import get_dict_db
from services.db_service import json_success, json_error, paginate, int_param, record_change
from services.property_service import get_monday_token, _monday_graphql


def safe_status(val):
    """Safely parse a status column value."""
    if val is None:
        return ""
    if isinstance(val, dict):
        return val.get("label") or val.get("text") or ""
    s = str(val).strip()
    if s.startswith("{") and s.endswith("}"):
        try:
            d = json.loads(s)
            return d.get("label") or d.get("text") or ""
        except (json.JSONDecodeError, TypeError):
            pass
    return s


def safe_priority(val):
    """Safely parse a priority column value, returning 0-3."""
    if val is None:
        return 0
    if isinstance(val, (int, float)):
        return int(val)
    label = safe_status(val)
    mapping = {"urgent": 3, "high": 2, "medium": 1, "low": 0}
    return mapping.get(label.lower(), 0)


def parse_monday_cols(column_values):
    """Parse Monday.com column values JSON into a dict."""
    parsed = {}
    for col in column_values:
        col_id = col.get("id", "")
        col_type = col.get("type", "")
        val = col.get("value")
        if val:
            try:
                val = json.loads(val) if isinstance(val, str) else val
            except (json.JSONDecodeError, TypeError):
                pass
        parsed[col_id] = {
            "type": col_type,
            "value": val,
            "text": col.get("text", ""),
        }
    return parsed


def parse_photo_paths(cols):
    """Extract photo file paths from Monday column values."""
    paths = []
    for col_id, col_data in cols.items():
        if col_id.startswith("text") or "photo" in col_id.lower() or "image" in col_id.lower():
            val = col_data.get("value")
            if isinstance(val, dict) and val.get("url"):
                paths.append(val["url"])
            elif isinstance(val, str) and val.startswith("http"):
                paths.append(val)
    return paths


def parse_invoice_paths(cols):
    """Extract invoice file paths from Monday column values."""
    paths = []
    for col_id, col_data in cols.items():
        if "invoice" in col_id.lower() or "receipt" in col_id.lower():
            val = col_data.get("value")
            if isinstance(val, dict) and val.get("url"):
                paths.append(val["url"])
            elif isinstance(val, str) and val.startswith("http"):
                paths.append(val)
    return paths
