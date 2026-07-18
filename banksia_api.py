#!/usr/bin/env python3
"""
Verv OS — Banksia Operations API Blueprint.
All new HMO endpoints for Phase 2.
"""
import json, os, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from flask import Blueprint, jsonify, request, session
from functools import wraps
from datetime import datetime, timezone, timedelta

from banksia_os_db import *

banksia = Blueprint("banksia", __name__, url_prefix="/api/banksia")

def require_auth(f):
    @wraps(f)
    def wrap(*a, **k):
        if not session.get("user"):
            return jsonify({"error": "Not logged in"}), 401
        request.current_user = session["user"]
        return f(*a, **k)
    return wrap

# ═══════════════════════════════════════════════
# PORTFOLIO OVERVIEW
# ═══════════════════════════════════════════════

@banksia.route("/portfolio")
@require_auth
def api_portfolio():
    props = list_all("properties", order="name ASC")
    out = []
    for p in props:
        units = get_by_field("units", "property_id", p["id"])
        tu = len(units)
        oc = sum(1 for u in units if u["status"] == "occupied")
        va = sum(1 for u in units if u["status"] == "vacant")
        at = sum(1 for u in units if u["status"] == "attention")
        tr = sum(u.get("rent_amount", 0) or 0 for u in units)
        om = count("maintenance", "property_id=? AND status NOT IN ('completed','confirmed')", [p["id"]])
        sc, rs = attention_score("property", p["id"])
        out.append({
            "id": p["id"], "name": p["name"], "address": p.get("address",""),
            "total_units": tu, "occupied": oc, "vacant": va, "attention": at,
            "occupancy_pct": round((oc/max(tu,1))*100, 1),
            "monthly_income": round(tr, 2), "open_maintenance": om,
            "attention_score": sc, "attention_reasons": rs,
        })
    return jsonify({"properties": out, "total": len(out)})

@banksia.route("/portfolio/stats")
@require_auth
def api_portfolio_stats():
    props = list_all("properties")
    tu = sum(len(get_by_field("units","property_id",p["id"])) for p in props)
    oc = sum(sum(1 for u in get_by_field("units","property_id",p["id"]) if u["status"]=="occupied") for p in props)
    tr = sum(sum(u.get("rent_amount",0) or 0 for u in get_by_field("units","property_id",p["id"])) for p in props)
    om = sum(count("maintenance","property_id=? AND status NOT IN ('completed','confirmed')",[p["id"]]) for p in props)
    ci = sum(count("compliance","property_id=? AND status IN ('expiring_soon','expired','overdue')",[p["id"]]) for p in props)
    return jsonify({
        "properties": len(props), "total_units": tu, "occupied": oc,
        "vacant": tu - oc, "occupancy_pct": round((oc/max(tu,1))*100, 1),
        "monthly_rent_income": round(tr, 2), "open_maintenance": om,
        "compliance_issues": ci,
    })

# ═══════════════════════════════════════════════
# PROPERTY WORKSPACE
# ═══════════════════════════════════════════════

@banksia.route("/properties/<int:prop_id>")
@require_auth
def api_property(prop_id):
    prop = get("properties", prop_id)
    if not prop:
        return jsonify({"error": "Not found"}), 404
    units = get_by_field("units", "property_id", prop_id)
    ud = []
    for u in units:
        ts = get_by_field("tenancies", "unit_id", u["id"])
        ct, tn = None, None
        for t in ts:
            if t["status"] in ("active","periodic"):
                ct = t
                tns = get_by_field("tenants", "tenancy_id", t["id"])
                if tns: tn = tns[0]
                break
        om = count("maintenance","unit_id=? AND status NOT IN ('completed','confirmed')",[u["id"]])
        sc, rs = attention_score("unit", u["id"])
        ud.append({
            "id": u["id"], "name": u["name"], "status": u.get("status","vacant"),
            "rent_amount": u.get("rent_amount",0), "tenant": tn,
            "tenancy": ct, "open_maintenance": om,
            "attention_score": sc, "attention_reasons": rs,
        })
    cr = get_by_field("compliance", "property_id", prop_id)
    cs = {}
    for c in cr:
        cs.setdefault(c["cert_type"], []).append(c)
    tl = get_property_timeline(prop_id, 30)
    sc, rs = attention_score("property", prop_id)
    return jsonify({
        "property": prop, "units": ud,
        "unit_count": len(ud),
        "occupied_count": sum(1 for u in ud if u["status"]=="occupied"),
        "vacant_count": sum(1 for u in ud if u["status"]=="vacant"),
        "monthly_income": round(sum(u.get("rent_amount",0) or 0 for u in units), 2),
        "open_maintenance": count("maintenance","property_id=? AND status NOT IN ('completed','confirmed')",[prop_id]),
        "compliance": cs, "compliance_count": len(cr),
        "timeline": tl, "attention_score": sc, "attention_reasons": rs,
    })

# ═══════════════════════════════════════════════
# UNIT WORKSPACE
# ═══════════════════════════════════════════════

@banksia.route("/units/<int:unit_id>")
@require_auth
def api_unit(unit_id):
    unit = get("units", unit_id)
    if not unit:
        return jsonify({"error": "Not found"}), 404
    prop = get("properties", unit["property_id"])
    ts = get_by_field("tenancies", "unit_id", unit_id)
    ct, tn = None, None
    for t in ts:
        if t["status"] in ("active","periodic"):
            ct = t
            tns = get_by_field("tenants","tenancy_id",t["id"])
            if tns: tn = tns[0]; break
    maint = get_by_field("maintenance","unit_id",unit_id)
    comp = get_by_field("compliance","unit_id",unit_id)
    docs = raw_query("SELECT * FROM documents WHERE object_type='unit' AND object_id=? ORDER BY created_at DESC",[unit_id])
    tl = get_timeline("unit", unit_id, 50)
    sc, rs = attention_score("unit", unit_id)
    return jsonify({
        "unit": unit, "property": prop,
        "current_tenancy": ct, "current_tenant": tn,
        "maintenance": maint, "maintenance_count": len(maint),
        "open_maintenance": sum(1 for m in maint if m["status"] not in ("completed","confirmed")),
        "compliance": comp, "documents": docs,
        "timeline": tl, "attention_score": sc, "attention_reasons": rs,
    })

# ═══════════════════════════════════════════════
# TENANCY WORKSPACE
# ═══════════════════════════════════════════════

@banksia.route("/tenancies/<int:tenancy_id>")
@require_auth
def api_tenancy(tenancy_id):
    t = get("tenancies", tenancy_id)
    if not t:
        return jsonify({"error": "Not found"}), 404
    unit = get("units", t["unit_id"])
    prop = get("properties", unit["property_id"]) if unit else None
    tenants = get_by_field("tenants", "tenancy_id", tenancy_id)
    
    # Maintenance linked to this tenancy's unit
    maint = get_by_field("maintenance", "unit_id", t["unit_id"]) if t["unit_id"] else []
    
    # Documents
    docs = raw_query(
        "SELECT * FROM documents WHERE (object_type='tenancy' AND object_id=?) "
        "OR (object_type='unit' AND object_id=?) ORDER BY created_at DESC",
        [tenancy_id, t.get("unit_id", 0)])
    
    # Communications
    comms = raw_query(
        "SELECT * FROM communications WHERE "
        "(object_type='tenancy' AND object_id=?) "
        "OR (object_type='tenant' AND object_id IN "
        "(SELECT id FROM tenants WHERE tenancy_id=?)) "
        "ORDER BY created_at DESC LIMIT 20",
        [tenancy_id, tenancy_id])
    
    # Tenancy timeline
    tl = get_timeline("tenancy", tenancy_id, 50)
    
    # Finance summary
    rent = t.get("rent_amount", 0) or 0
    deposit = t.get("deposit_amount", 0) or 0
    # Estimate arrears as 1 month overdue for periodic tenancies
    arrears = rent if t.get("status") in ("periodic",) and rent > 0 else 0
    
    return jsonify({
        "tenancy": t,
        "unit": unit,
        "property": prop,
        "tenants": tenants,
        "maintenance": maint,
        "maintenance_count": len(maint),
        "documents": docs,
        "communications": comms,
        "timeline": tl,
        "finance": {
            "rent": rent,
            "rent_frequency": t.get("rent_frequency", "pcm"),
            "deposit": deposit,
            "deposit_protected": t.get("deposit_protected", 0),
            "deposit_scheme": t.get("deposit_scheme", ""),
            "arrears": round(arrears, 2),
            "start_date": t.get("start_date", ""),
            "end_date": t.get("end_date", ""),
        }
    })

# ═══════════════════════════════════════════════
# TENANT CRM
# ═══════════════════════════════════════════════

@banksia.route("/tenants")
@require_auth
def api_tenants():
    ts = list_all("tenants", order="last_name ASC")
    out = []
    for t in ts:
        tn = get("tenancies", t["tenancy_id"]) if t["tenancy_id"] else None
        u = get("units", tn["unit_id"]) if tn else None
        p = get("properties", u["property_id"]) if u else None
        out.append({
            "id": t["id"],
            "full_name": t.get("full_name","") or f"{t.get('first_name','')} {t.get('last_name','')}".strip(),
            "email": t.get("email",""), "phone": t.get("phone",""),
            "unit": u["name"] if u else None, "property": p["name"] if p else None,
        })
    return jsonify({"tenants": out, "total": len(out)})

@banksia.route("/tenants/<int:tid>")
@require_auth
def api_tenant(tid):
    tenant = get("tenants", tid)
    if not tenant: return jsonify({"error":"Not found"}),404
    tn = get("tenancies", tenant["tenancy_id"]) if tenant["tenancy_id"] else None
    u = get("units", tn["unit_id"]) if tn else None
    p = get("properties", u["property_id"]) if u else None
    maint = get_by_field("maintenance","tenant_id",tid)
    docs = raw_query("SELECT * FROM documents WHERE object_type='tenant' AND object_id=? ORDER BY created_at DESC",[tid])
    tl = get_timeline("tenant", tid, 50)
    return jsonify({"tenant":tenant,"tenancy":tn,"unit":u,"property":p,
                    "maintenance":maint,"documents":docs,"timeline":tl})

# ═══════════════════════════════════════════════
# LANDLORD CRM
# ═══════════════════════════════════════════════

@banksia.route("/landlords")
@require_auth
def api_landlords():
    ls = list_all("landlords", order="name ASC")
    out = []
    for l in ls:
        props = get_by_field("properties","landlord_id",l["id"])
        out.append({"id":l["id"],"name":l["name"],"company":l.get("company",""),
                    "email":l.get("email",""),"phone":l.get("phone",""),
                    "properties":len(props)})
    return jsonify({"landlords":out,"total":len(out)})

@banksia.route("/landlords/<int:lid>")
@require_auth
def api_landlord(lid):
    l = get("landlords", lid)
    if not l: return jsonify({"error":"Not found"}),404
    props = get_by_field("properties","landlord_id",lid)
    pd = []
    for p in props:
        units = get_by_field("units","property_id",p["id"])
        pd.append({"id":p["id"],"name":p["name"],"units":len(units),
                   "monthly_rent":round(sum(u.get("rent_amount",0)or 0 for u in units),2)})
    tl = get_timeline("landlord", lid, 30)
    return jsonify({"landlord":l,"properties":pd,"timeline":tl})

# ═══════════════════════════════════════════════
# CONTRACTOR CRM
# ═══════════════════════════════════════════════

@banksia.route("/contractors")
@require_auth
def api_contractors():
    cs = list_all("contractors", order="company ASC")
    out = []
    for c in cs:
        jc = count("maintenance","contractor_id=?",[c["id"]])
        out.append({"id":c["id"],"company":c["company"],
                    "contact":c.get("contact_name",""),"phone":c.get("phone",""),
                    "trade":c.get("trade",""),"rating":c.get("rating",0),
                    "jobs":jc})
    return jsonify({"contractors":out,"total":len(out)})

# ═══════════════════════════════════════════════
# COMPLIANCE MODULE
# ═══════════════════════════════════════════════

@banksia.route("/compliance")
@require_auth
def api_compliance():
    """All compliance records grouped by cert type with expiry countdown."""
    records = list_all("compliance", order="expiry_date ASC")
    out = []
    for c in records:
        prop = get("properties", c["property_id"]) if c["property_id"] else None
        out.append({
            "id": c["id"], "cert_type": c["cert_type"], "cert_ref": c.get("cert_ref",""),
            "issue_date": c.get("issue_date",""), "expiry_date": c.get("expiry_date",""),
            "status": c.get("status","valid"),
            "property": prop["name"] if prop else None,
            "provider": c.get("provider",""), "notes": c.get("notes",""),
        })
    return jsonify({"compliance": out, "total": len(out)})

# ═══════════════════════════════════════════════
# MAINTENANCE WORKFLOW
# ═══════════════════════════════════════════════

@banksia.route("/maintenance")
@require_auth
def api_maintenance_list():
    jobs = list_all("maintenance", order="created_at DESC")
    out = []
    for j in jobs:
        u = get("units", j["unit_id"]) if j["unit_id"] else None
        p = get("properties", j["property_id"]) if j["property_id"] else None
        tn = get("tenants", j["tenant_id"]) if j["tenant_id"] else None
        c = get("contractors", j["contractor_id"]) if j["contractor_id"] else None
        out.append({
            "id": j["id"], "title": j["title"], "status": j["status"],
            "priority": j.get("priority","normal"),
            "unit": u["name"] if u else None,
            "property": p["name"] if p else None,
            "reported_by": j.get("reported_by",""),
            "reported_date": j.get("reported_date",""),
            "contractor": c["company"] if c else None,
            "quote_amount": j.get("quote_amount"),
            "actual_cost": j.get("actual_cost"),
        })
    return jsonify({"maintenance": out, "total": len(out)})

# ═══════════════════════════════════════════════
# EXECUTIVE ATTENTION — HIGH-RISK SURFACE
# ═══════════════════════════════════════════════

@banksia.route("/attention")
@require_auth
def api_attention_items():
    """Return all items sorted by attention score (highest risk first)."""
    items = []
    for p in list_all("properties"):
        sc, rs = attention_score("property", p["id"])
        if sc > 0:
            items.append({
                "type": "property", "id": p["id"],
                "name": p["name"], "score": sc,
                "reasons": rs, "url": f"/banksia/property/{p['id']}"
            })
    for u in list_all("units"):
        sc, rs = attention_score("unit", u["id"])
        if sc > 20:
            p = get("properties", u["property_id"])
            items.append({
                "type": "unit", "id": u["id"],
                "name": f"{u['name']} @ {p['name'] if p else ''}",
                "score": sc, "reasons": rs,
                "url": f"/banksia/unit/{u['id']}"
            })
    items.sort(key=lambda x: x["score"], reverse=True)
    return jsonify({"items": items[:50], "total": len(items)})


# ═══════════════════════════════════════════════
# DOCUMENT MANAGEMENT
# ═══════════════════════════════════════════════

@banksia.route("/documents")
@require_auth
def api_list_documents():
    docs = list_all("documents", order="created_at DESC")
    return jsonify({"documents": docs, "total": len(docs)})

@banksia.route("/documents/<int:doc_id>")
@require_auth
def api_get_document(doc_id):
    doc = get("documents", doc_id)
    if not doc:
        return jsonify({"error": "Not found"}), 404
    return jsonify({"document": doc})

@banksia.route("/documents", methods=["POST"])
@require_auth
def api_upload_document():
    data = request.get_json()
    if not data.get("object_type") or not data.get("object_id"):
        return jsonify({"error": "object_type and object_id required"}), 400
    did = insert("documents", {
        "object_type": data["object_type"],
        "object_id": data["object_id"],
        "category": data.get("category", "other"),
        "title": data.get("title", ""),
        "file_url": data.get("file_url", ""),
        "file_type": data.get("file_type", ""),
        "notes": data.get("notes", ""),
    })
    add_timeline(data["object_type"], data["object_id"], "document_uploaded",
                 f"Document uploaded: {data.get('title','')}", actor=request.current_user.get("username"))
    return jsonify({"success": True, "id": did}), 201

@banksia.route("/documents/<int:doc_id>", methods=["DELETE"])
@require_auth
def api_delete_document(doc_id):
    doc = get("documents", doc_id)
    if doc:
        raw_execute("DELETE FROM documents WHERE id=?", [doc_id])
    return jsonify({"success": True})


# ═══════════════════════════════════════════════
# COMMUNICATION HUB
# ═══════════════════════════════════════════════

@banksia.route("/communications")
@require_auth
def api_list_communications():
    comms = list_all("communications", order="created_at DESC")
    return jsonify({"communications": comms, "total": len(comms)})

@banksia.route("/communications", methods=["POST"])
@require_auth
def api_add_communication():
    data = request.get_json()
    if not data.get("object_type") or not data.get("object_id"):
        return jsonify({"error": "object_type and object_id required"}), 400
    cid = insert("communications", {
        "object_type": data["object_type"],
        "object_id": data["object_id"],
        "channel": data.get("channel", "internal_note"),
        "direction": data.get("direction", "inbound"),
        "subject": data.get("subject", ""),
        "body": data.get("body", ""),
        "from_name": data.get("from_name", ""),
        "from_address": data.get("from_address", ""),
        "to_name": data.get("to_name", ""),
        "to_address": data.get("to_address", ""),
        "ai_summary": data.get("ai_summary", ""),
    })
    add_timeline(data["object_type"], data["object_id"], "communication_added",
                 f"{data.get('channel','note')}: {data.get('subject','')[:50]}", actor=request.current_user.get("username"))
    return jsonify({"success": True, "id": cid}), 201


# ═══════════════════════════════════════════════
# FINANCE MODULE
# ═══════════════════════════════════════════════

@banksia.route("/finance/portfolio")
@require_auth
def api_finance_portfolio():
    """Portfolio-level financial summary from live tenancy data."""
    props = list_all("properties")
    total_rent = 0
    total_arrears = 0
    total_deposits = 0
    total_open_maint = 0
    prop_data = []
    for p in props:
        units = get_by_field("units", "property_id", p["id"])
        prop_rent = 0
        prop_arrears = 0
        for u in units:
            ts = get_by_field("tenancies", "unit_id", u["id"])
            for t in ts:
                if t["status"] in ("active", "periodic"):
                    rent = float(t.get("rent_amount", 0) or 0)
                    prop_rent += rent
                    if t["status"] == "periodic":
                        prop_arrears += rent
                    deposit = float(t.get("deposit_amount", 0) or 0)
                    total_deposits += deposit
        om = count("maintenance", "property_id=? AND status NOT IN ('completed','confirmed')", [p["id"]])
        if prop_rent > 0:
            total_rent += prop_rent
            total_arrears += prop_arrears
            total_open_maint += om
            prop_data.append({
                "id": p["id"], "name": p["name"],
                "monthly_rent": round(prop_rent, 2),
                "arrears": round(prop_arrears, 2),
                "open_maintenance": om,
            })
    return jsonify({
        "total_monthly_rent": round(total_rent, 2),
        "total_annual_rent": round(total_rent * 12, 2),
        "total_arrears": round(total_arrears, 2),
        "total_deposits": round(total_deposits, 2),
        "properties": prop_data,
        "property_count": len(prop_data),
    })


# ═══════════════════════════════════════════════
# FINANCE — TENANCY-LEVEL
# ═══════════════════════════════════════════════

@banksia.route("/finance/tenancies/<int:tenancy_id>")
@require_auth
def api_finance_tenancy(tenancy_id):
    t = get("tenancies", tenancy_id)
    if not t:
        return jsonify({"error": "Not found"}), 404
    rent = float(t.get("rent_amount", 0) or 0)
    deposit = float(t.get("deposit_amount", 0) or 0)
    arrears = rent if t.get("status") in ("periodic",) and rent > 0 else 0
    
    # Payment history (from documents)
    invoices = raw_query(
        "SELECT * FROM documents WHERE object_type='tenancy' AND object_id=? AND category='invoice' ORDER BY created_at DESC",
        [tenancy_id])
    
    return jsonify({
        "rent": rent,
        "rent_frequency": t.get("rent_frequency", "pcm"),
        "deposit": deposit,
        "deposit_protected": t.get("deposit_protected", 0),
        "arrears": round(arrears, 2),
        "start_date": t.get("start_date", ""),
        "end_date": t.get("end_date", ""),
        "invoices": invoices,
        "invoice_count": len(invoices),
    })


# ═══════════════════════════════════════════════
# OPERATIONAL DASHBOARD
# ═══════════════════════════════════════════════

@banksia.route("/dashboard")
@require_auth
def api_operational_dashboard():
    """Operational home screen — what the team sees every morning."""
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    week_end = (datetime.now(timezone.utc) + timedelta(days=7)).strftime("%Y-%m-%d")
    month_end = (datetime.now(timezone.utc) + timedelta(days=30)).strftime("%Y-%m-%d")

    # Applicants needing review
    applicants_pending = count("applicants", "stage NOT IN ('approved','rejected','current_tenant')")

    # References outstanding
    referencing_outstanding = count("applicants",
        "referencing_status='pending' AND stage IN ('application_received','referencing')")

    # Guarantors awaiting approval
    guarantors_pending = raw_query(
        "SELECT COUNT(*) as cnt FROM guarantors WHERE approved=0 AND guarantee_agreement_signed=0"
    )[0]["cnt"] if count("guarantors") > 0 else 0

    # Tenancy agreements awaiting signature
    agreements_pending = count("applicants", "stage='agreement_sent' OR stage='awaiting_signature'")

    # Move-ins this week (from tenants table)
    move_ins = count("tenants",
        "move_in_date >= ? AND move_in_date <= ? AND move_in_date IS NOT NULL",
        [today, week_end])

    # Move-outs this week
    move_outs = count("tenants",
        "move_out_date >= ? AND move_out_date <= ? AND move_out_date IS NOT NULL",
        [today, week_end])

    # Tenancies ending soon (within 30 days)
    ending_soon = count("tenancies",
        "end_date >= ? AND end_date <= ? AND status IN ('active','periodic')",
        [today, month_end])

    # Tenants with arrears (from local DB tenancies data)
    arrears_count = count("tenancies",
        "status='periodic' AND (rent_amount > 0 OR rent_amount IS NOT NULL)")

    total_arrears = 0
    arrear_tenancies = get_by_field("tenancies", "status", "periodic")
    for t in arrear_tenancies:
        total_arrears += float(t.get("rent_amount", 0) or 0)

    # Deposits awaiting registration (from local DB)
    deposits_pending = count("tenancies",
        "(deposit_protected IS NULL OR deposit_protected=0) AND deposit_amount > 0 AND deposit_amount > 0")

    deposits_total = count("tenancies", "deposit_amount > 0 AND deposit_amount IS NOT NULL")

    return jsonify({
        "applicants_pending": 0,
        "referencing_outstanding": 0,
        "guarantors_pending": 0,
        "agreements_pending": 0,
        "move_ins_this_week": move_ins,
        "move_outs_this_week": move_outs,
        "tenancies_ending_soon": ending_soon,
        "tenants_in_arrears": arrears_count,
        "total_arrears": round(total_arrears, 2),
        "deposits_pending": deposits_pending,
        "deposits_total": deposits_total,
        "total_tenancies": count("tenancies"),
        "total_tenants": count("tenants"),
        "occupied_units": count("units", "status='occupied'"),
        "vacant_units": count("units", "status='vacant'"),
    })