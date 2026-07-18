"""
Banksia OS — Activity & timeline service layer.
Change logging, activity tracking, timeline generation.
"""
from banksia_os_db import get_dict_db
from services.db_service import json_success


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


def create_activity_log(db, action, resource_id, description, user=None):
    """Create an activity log entry. Returns the new row id."""
    try:
        db.execute(
            "INSERT INTO activity_log (action, resource_id, description, user_name, created_at) VALUES (?, ?, ?, ?, datetime('now'))",
            [action, resource_id, description, user or "system"]
        )
        db.commit()
        return db.lastrowid
    except Exception:
        return None


def log_activity(entity_type, entity_id, action, field_changed=None,
                 old_value=None, new_value=None, user=None):
    """
    Log a granular field-level activity with old/new values.
    Used by the universal timeline and my-updates feed.
    """
    try:
        db = get_dict_db()
        db.execute("""
            INSERT INTO activity_log
                (entity_type, entity_id, action, field_changed, old_value, new_value, user_name, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))
        """, [entity_type, entity_id, action, field_changed, old_value, new_value, user or "system"])
        db.commit()
        db.close()
        return True
    except Exception:
        return False


def _format_value(val):
    """Format a value for display in activity logs."""
    if val is None:
        return ""
    s = str(val)
    if len(s) > 200:
        return s[:197] + "..."
    return s


def _redact_if_sensitive(val):
    """Redact potentially sensitive PII values from activity display."""
    if val and isinstance(val, str) and len(val) > 4:
        # Redact email-like and phone-like values
        if "@" in val:
            local, domain = val.split("@", 1)
            return local[:2] + "***@" + domain
        if val.replace(" ", "").replace("-", "").replace("+", "").isdigit() and len(val) >= 7:
            return val[:3] + "***" + val[-2:]
    return val


def _get_entity_label(db, entity_type, entity_id):
    """Resolve a human-readable label for an entity reference."""
    if entity_id is None:
        return "Unknown"
    try:
        eid = int(entity_id)
    except (TypeError, ValueError):
        return str(entity_id)

    table_map = {
        "property": "properties", "unit": "units", "tenancy": "tenancies",
        "tenant": "tenants", "applicant": "applicants", "maintenance_job": "maintenance_jobs",
        "contractor": "contractors", "invoice": "invoices",
    }
    table = table_map.get(entity_type)
    if not table:
        return f"{entity_type}#{entity_id}"

    name_cols = {"properties": "name", "units": "ref", "tenancies": "id",
                 "tenants": "name", "applicants": "name", "maintenance_jobs": "description",
                 "contractors": "name", "invoices": "id"}
    col = name_cols.get(table, "id")
    row = db.execute(f"SELECT {col} FROM {table} WHERE id = ?", [eid]).fetchone()
    if row:
        val = row[col] if isinstance(row, dict) else row[0]
        return val or f"{entity_type}#{entity_id}"
    return f"{entity_type}#{entity_id}"


def _derive_timeline_type(action, entity_type, field_changed):
    """Derive a display category for timeline items."""
    if action in ("created", "create"):
        return "created"
    if action in ("deleted", "delete", "archived", "restored"):
        return "archived" if action == "archived" else action
    if action in ("payment", "charge", "rent_charge"):
        return "financial"
    if action in ("status_change",) or field_changed == "status":
        return "status_change"
    if action in ("note", "comment"):
        return "note"
    return "update"


def _redact_sensitive_fields(item_dict):
    """Remove sensitive PII from timeline items before returning to non-admin roles."""
    sensitive_keys = {"email", "phone", "mobile", "date_of_birth", "dob", "passport", "national_insurance", "ni_number"}
    redacted = {}
    for k, v in item_dict.items():
        if k.lower() in sensitive_keys:
            redacted[k] = "[REDACTED]"
        else:
            redacted[k] = v
    return redacted


def _enhance_timeline_item(item):
    """Add display-friendly fields to a timeline item."""
    item["display_type"] = _derive_timeline_type(
        item.get("action", ""), item.get("entity_type"), item.get("field_changed")
    )
    if item.get("old_value") is not None or item.get("new_value") is not None:
        item["old_value_fmt"] = _format_value(item.get("old_value"))
        item["new_value_fmt"] = _format_value(item.get("new_value"))
    return item
