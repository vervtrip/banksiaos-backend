#!/usr/bin/env python3
"""Banksia OS Monday sync module — push local changes to Monday.com."""

import json
import os
import urllib.request

# ── LABEL→INDEX mappings for Monday status columns ──
STATUS_INDEX = {"ON HOLD":0,"COMPLETED":1,"CANCELLED":2,"IN PROGRESS":3,"LIVE":4,"PENDING":5,"ACKNOWLEDGED":6,"WAITING INVOICE":7,"No Invoice Found":8,"Invoice Uploaded":9}
PRIORITY_INDEX = {"Emergency":0,"Low":7,"Critical":10,"Medium":109,"High":110}
TYPE_INDEX = {"Heating":0,"Plumbing":1,"Electrical":2,"Utilities":3,"Furniture":4,"NA":5,"Cleaning":6,"Structural":7,"Appliances":8,"Refurbishment":9,"Certificate":10,"Orders":11,"Wall Repairs":12,"Painting":13,"Removal":14,"Appliance":15,"Locksmith":16,"Pest Control":17,"Small Repair":18,"Licenses":19,"Inspection":101,"Gardening":102}
CONTRACTOR_INDEX = {"Raj":0,"Mirpolat":1,"Jermaine":2,"Osman":3,"Shahid":4,"Javeed":6,"Nisar":7,"Calvin":8,"John":9,"Ben":10,"Nick":11,"David Removal":12,"Fernando":13,"Team Member":14,"Fernanda":15,"LL":16,"Council":17,"David":18,"Alex":19,"Ali":101,"Shah":102,"DevUp":103,"Ali contractor":104,"Ali Plumber":105,"Flash Removal":106,"Noor Elec":107,"HB Appliance":108,"Arslan":109,"Marcel":110,"Yusuf Locksmith":151}
MAINTENANCE_BOARD_ID = "18401159622"
TOKEN_PATH = "/root/.hermes/secrets/monday_token.txt"


def get_token():
    with open(TOKEN_PATH) as f:
        return f.read().strip()


def monday_graphql(query):
    tok = get_token()
    req = urllib.request.Request(
        "https://api.monday.com/v2",
        data=json.dumps({"query": query}).encode(),
        headers={"Authorization": tok, "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read())


def push_job_status(job):
    """Push a single maintenance job's changes to Monday."""
    monday_id = job.get("monday_id")
    if not monday_id:
        return False, "no monday_id"

    column_values = {}

    # Status
    label = job.get("status") or "PENDING"
    col_id = STATUS_INDEX.get(label)
    if col_id is not None:
        column_values["status"] = {"index": col_id}

    # Priority
    pri_label = job.get("priority") or "Medium"
    pri_idx = PRIORITY_INDEX.get(pri_label)
    if pri_idx is not None:
        column_values["color_mm0p8qna"] = {"index": pri_idx}

    # Type
    type_label = job.get("type") or ""
    if type_label and type_label in TYPE_INDEX:
        column_values["color_mm0vfxmq"] = {"index": TYPE_INDEX[type_label]}

    # Address
    addr = job.get("address") or ""
    if addr:
        column_values["short_text041ydfbp"] = addr

    # Contractor
    con_label = job.get("contractor") or ""
    if con_label and con_label in CONTRACTOR_INDEX:
        column_values["color_mm0p4947"] = {"index": CONTRACTOR_INDEX[con_label]}

    # Labour cost
    lc = job.get("labour_cost")
    if lc:
        column_values["numeric_mm0pndmj"] = str(lc)

    # Materials cost
    mc = job.get("materials_cost")
    if mc:
        column_values["numeric_mm0p7jdn"] = str(mc)

    # Bill LL
    bl = job.get("bill_ll")
    if bl is not None:
        column_values["boolean_mm0phkaq"] = {"checked": bool(bl)}

    # Emergency
    em = job.get("emergency")
    if em is not None:
        column_values["boolean2hbqq7ey"] = {"checked": bool(em)}

    # Reporter name
    rn = job.get("reporter_name") or ""
    if rn:
        column_values["short_textcvckh2h3"] = rn

    if not column_values:
        return False, "no changes"

    mutation = (
        'mutation { change_multiple_column_values('
        f'board_id: {MAINTENANCE_BOARD_ID}, item_id: "{monday_id}", '
        f'column_values: {json.dumps(json.dumps(column_values))})'
        " { id } }"
    )

    try:
        resp = monday_graphql(mutation)
        if resp.get("data") and resp["data"].get("change_multiple_column_values"):
            return True, "pushed"
        errors = resp.get("errors", [])
        return False, str(errors)
    except Exception as e:
        return False, str(e)


def push_all_pending(db):
    """Push all maintenance_jobs with sync_pending=1 to Monday."""
    pending = db.execute(
        "SELECT * FROM maintenance_jobs WHERE sync_pending = 1 AND monday_id IS NOT NULL"
    ).fetchall()

    if not pending:
        return {"pushed": 0, "failed": 0, "message": "Nothing pending"}

    pushed = 0
    failed = 0
    errors = []

    for job in pending:
        success, msg = push_job_status(dict(job))
        if success:
            db.execute(
                "UPDATE maintenance_jobs SET sync_pending = 0, modified = datetime('now') WHERE id = ?",
                [job["id"]],
            )
            pushed += 1
        else:
            failed += 1
            errors.append(f"job {job['id']}: {msg}")

    db.commit()
    return {"pushed": pushed, "failed": failed, "errors": errors[:5], "message": f"Pushed {pushed} to Monday" if not failed else f"Pushed {pushed}, {failed} failed"}
