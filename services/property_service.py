"""
Banksia OS — Property & unit service layer.
Properties CRUD, units management, vacancy syncing, Monday property list sync.
"""
import os, json, re
from datetime import datetime
from banksia_os_db import get_dict_db
from services.db_service import json_success, json_error, paginate, int_param, record_change
from services.activity_service import create_activity_log


def get_monday_token():
    """Load Monday API token from environment or file."""
    token = os.environ.get("MONDAY_API_TOKEN")
    if token:
        return token
    token_paths = [
        os.path.join(os.path.dirname(os.path.dirname(__file__)), ".secrets", "monday_token.txt"),
        os.path.expanduser("~/.hermes/secrets/monday_token.txt"),
    ]
    for p in token_paths:
        if os.path.exists(p):
            with open(p) as f:
                return f.read().strip()
    return None


def _monday_graphql(mtok, query):
    """Execute a GraphQL query against Monday.com."""
    import urllib.request
    req = urllib.request.Request(
        "https://api.monday.com/v2",
        data=json.dumps({"query": query}).encode(),
        headers={
            "Authorization": mtok,
            "Content-Type": "application/json",
            "API-Version": "2024-10",
        }
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode())


def sync_unit_vacancy(db=None):
    """
    Sync unit vacancy status based on active tenancies.
    Returns count of units changed.
    """
    close_db = db is None
    if close_db:
        db = get_dict_db()
    try:
        changed = 0
        units = db.execute("SELECT id FROM units WHERE is_active = 1").fetchall()
        for u in units:
            uid = u["id"]
            active = db.execute(
                "SELECT COUNT(*) AS cnt FROM tenancies WHERE unit_id = ? AND status IN ('active', 'periodic') AND is_active = 1",
                [uid]
            ).fetchone()["cnt"]
            current_status = db.execute("SELECT is_vacant FROM units WHERE id = ?", [uid]).fetchone()["is_vacant"]
            should_be_vacant = active == 0
            if bool(current_status) != should_be_vacant:
                db.execute("UPDATE units SET is_vacant = ? WHERE id = ?", [1 if should_be_vacant else 0, uid])
                changed += 1
        if changed:
            db.commit()
        return {"total_checked": len(units), "total_changed": changed}
    finally:
        if close_db:
            db.close()


def ensure_landlord_link(db, data):
    """Resolve or create a property_owner link from form data."""
    owner_id = data.get("property_owner_id")
    owner_name = data.get("property_owner_name")
    if owner_id:
        try:
            owner_id = int(owner_id)
        except (TypeError, ValueError):
            owner_id = None
    if not owner_id and owner_name:
        existing = db.execute(
            "SELECT id FROM property_owners WHERE name = ?", [owner_name]
        ).fetchone()
        if existing:
            owner_id = existing["id"]
        else:
            db.execute(
                "INSERT INTO property_owners (name, created_at) VALUES (?, datetime('now'))",
                [owner_name]
            )
            db.commit()
            owner_id = db.lastrowid
    return owner_id
