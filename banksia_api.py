#!/usr/bin/env python3
"""
Verv OS — Banksia Operations API Blueprint.
All new HMO endpoints for Phase 2.
"""
import json, os, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from flask import Blueprint, jsonify, request, session
from functools import wraps

from verv_os_db import *

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
    tenants = get_by_field("tenants","tenancy_id",tenancy_id)
    docs = raw_query("SELECT * FROM documents WHERE object_type='tenancy' AND object_id=? ORDER BY created_at DESC",[tenancy_id])
    tl = get_timeline("tenancy", tenancy_id, 50)
    return jsonify({"tenancy": t, "unit": unit, "property": prop,
                    "tenants": tenants, "documents": docs, "timeline": tl})

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