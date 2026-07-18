#!/usr/bin/env python3
"""
Comprehensive Integrity Audit for Banksia OS Database.

Checks every table for:
1. Orphan records (FKs referencing missing parents)
2. Duplicate records (same data appearing twice)
3. Missing relationships (records that should be linked but aren't)
4. Data integrity issues (conflicting states, overlapping tenancies, etc.)
5. Schema issues (missing PKs, timestamps, indexes)

Outputs a detailed Markdown report to docs/integrity_audit.md
"""

import os
import sys
import sqlite3
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "banksia_os.db")
REPORT_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "docs", "integrity_audit.md")
os.makedirs(os.path.dirname(REPORT_PATH), exist_ok=True)

conn = sqlite3.connect(DB_PATH)
conn.row_factory = sqlite3.Row
cur = conn.cursor()


def q(sql, params=None):
    """Run a query and return all rows."""
    if params is None:
        params = []
    return cur.execute(sql, params).fetchall()


def q1(sql, params=None):
    """Run a query and return first row or None."""
    if params is None:
        params = []
    row = cur.execute(sql, params).fetchone()
    return dict(row) if row else None


def count_rows(sql, params=None):
    """Run a count query."""
    if params is None:
        params = []
    return cur.execute(sql, params).fetchone()[0]


# ── Collect table metadata ──
tables_info = {}
for row in q("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"):
    tname = row["name"]
    col_rows = q(f"PRAGMA table_info(\"{tname}\")")
    columns = [(c["name"], c["type"], c["pk"], c["notnull"]) for c in col_rows]
    pk_cols = [c[0] for c in columns if c[2] == 1]
    has_created = any(c[0] == "created" for c in columns)
    has_modified = any(c[0] == "modified" for c in columns)
    total = count_rows(f"SELECT COUNT(*) FROM \"{tname}\"")
    tables_info[tname] = {
        "columns": columns,
        "pk_cols": pk_cols,
        "has_created": has_created,
        "has_modified": has_modified,
        "total": total,
    }

# ── Collect FK info ──
fk_info = {}
for tname in tables_info:
    fk_rows = q(f"PRAGMA foreign_key_list(\"{tname}\")")
    fks = []
    for fk in fk_rows:
        fks.append({
            "from_col": fk["from"],
            "to_table": fk["table"],
            "to_col": fk["to"],
        })
    fk_info[tname] = fks

# ── Collect index info ──
index_info = {}
for tname in tables_info:
    idx_rows = q(f"PRAGMA index_list(\"{tname}\")")
    index_info[tname] = [r["name"] for r in idx_rows]

# ── Report accumulator ──
report_lines = []
total_orphans = 0
total_duplicates = 0
total_missing_relations = 0
total_data_issues = 0
total_schema_issues = 0

def h1(text):
    report_lines.append(f"\n# {text}\n")

def h2(text):
    report_lines.append(f"\n## {text}\n")

def h3(text):
    report_lines.append(f"\n### {text}\n")

def p(text):
    report_lines.append(f"{text}\n")

def code_block(text):
    report_lines.append(f"```\n{text}\n```\n")

def bullet(text):
    report_lines.append(f"- {text}\n")

def table(headers, rows):
    """Format a simple markdown table."""
    sep = "| " + " | ".join("---" for _ in headers) + " |"
    header_line = "| " + " | ".join(headers) + " |"
    report_lines.append(header_line + "\n")
    report_lines.append(sep + "\n")
    for r in rows:
        report_lines.append("| " + " | ".join(str(c) for c in r) + " |\n")

def analyze_orphan(desc, sql, params=None):
    """Check for orphans and report."""
    global total_orphans
    rows = q(sql, params)
    count = len(rows)
    total_orphans += count
    h3(desc)
    p(f"- **Count:** {count}")
    code_block(sql)
    if count > 0:
        sample_ids = [dict(r) for r in rows[:10]]
        p(f"- **Sample records (up to 10):**")
        for s in sample_ids:
            p(f"  - {s}")
    p("---")
    return count

def analyze_duplicate(desc, sql, params=None):
    """Check for duplicates and report."""
    global total_duplicates
    rows = q(sql, params)
    count = len(rows)
    total_duplicates += count
    h3(desc)
    p(f"- **Count:** {count}")
    code_block(sql)
    if count > 0:
        sample_ids = [dict(r) for r in rows[:10]]
        p(f"- **Sample duplicates (up to 10):**")
        for s in sample_ids:
            p(f"  - {s}")
    p("---")
    return count

def analyze_missing(desc, sql, params=None):
    """Check for missing relationships and report."""
    global total_missing_relations
    rows = q(sql, params)
    count = len(rows)
    total_missing_relations += count
    h3(desc)
    p(f"- **Count:** {count}")
    code_block(sql)
    if count > 0:
        sample_ids = [dict(r) for r in rows[:10]]
        p(f"- **Sample records (up to 10):**")
        for s in sample_ids:
            p(f"  - {s}")
    p("---")
    return count

def analyze_data(desc, sql, params=None):
    """Check for data integrity issues and report."""
    global total_data_issues
    rows = q(sql, params)
    count = len(rows)
    total_data_issues += count
    h3(desc)
    p(f"- **Count:** {count}")
    code_block(sql)
    if count > 0:
        sample_ids = [dict(r) for r in rows[:10]]
        p(f"- **Sample records (up to 10):**")
        for s in sample_ids:
            p(f"  - {s}")
    p("---")
    return count

def analyze_schema(desc, check_result):
    """Check for schema issues."""
    global total_schema_issues
    h3(desc)
    if check_result:
        p(f"- **ISSUE:** {check_result}")
        total_schema_issues += 1
    else:
        p("- ✅ OK")
    p("---")


# ─────────────────────────────────────────────
# START REPORT
# ─────────────────────────────────────────────
h1("Banksia OS — Database Integrity Audit")
p(f"**Generated:** {datetime.now().isoformat()}")
p(f"**Database:** {DB_PATH}")

# ── Table Overview ──
h2("1. Table Overview")
table(["Table", "Records", "PK Columns", "Has created", "Has modified", "FK Count", "Index Count"],
      [(t, info["total"], ", ".join(info["pk_cols"]) or "NONE", "✅" if info["has_created"] else "❌",
        "✅" if info["has_modified"] else "❌", len(fk_info.get(t, [])), len(index_info.get(t, [])))
       for t, info in tables_info.items()])

# ─────────────────────────────────────────────
# SECTION 1: ORPHAN RECORDS
# ─────────────────────────────────────────────
h1("2. Orphan Records (FK references to non-existent parents)")

# -- tenants --
analyze_orphan(
    "Tenants with tenancy_id that doesn't exist in tenancies",
    """SELECT t.id, t.first_name, t.last_name, t.tenancy_id
      FROM tenants t LEFT JOIN tenancies tn ON t.tenancy_id = tn.id
      WHERE t.tenancy_id IS NOT NULL AND tn.id IS NULL"""
)
analyze_orphan(
    "Tenants with property_id that doesn't exist in properties",
    """SELECT t.id, t.first_name, t.last_name, t.property_id
      FROM tenants t LEFT JOIN properties p ON t.property_id = p.id
      WHERE t.property_id IS NOT NULL AND p.id IS NULL"""
)

# -- tenancies --
analyze_orphan(
    "Tenancies with property_id not in properties",
    """SELECT tn.id, tn.ref, tn.property_id
      FROM tenancies tn LEFT JOIN properties p ON tn.property_id = p.id
      WHERE tn.property_id IS NOT NULL AND p.id IS NULL"""
)
analyze_orphan(
    "Tenancies with unit_id not in units",
    """SELECT tn.id, tn.ref, tn.unit_id
      FROM tenancies tn LEFT JOIN units u ON tn.unit_id = u.id
      WHERE tn.unit_id IS NOT NULL AND u.id IS NULL"""
)

# -- units --
analyze_orphan(
    "Units with property_id not in properties",
    """SELECT u.id, u.unit_ref, u.property_id
      FROM units u LEFT JOIN properties p ON u.property_id = p.id
      WHERE u.property_id IS NOT NULL AND p.id IS NULL"""
)

# -- deposits --
analyze_orphan(
    "Deposits with tenancy_id not in tenancies",
    """SELECT d.id, d.tenancy_id FROM deposits d
      LEFT JOIN tenancies tn ON d.tenancy_id = tn.id
      WHERE d.tenancy_id IS NOT NULL AND tn.id IS NULL"""
)
analyze_orphan(
    "Deposits with tenant_id not in tenants",
    """SELECT d.id, d.tenant_id FROM deposits d
      LEFT JOIN tenants t ON d.tenant_id = t.id
      WHERE d.tenant_id IS NOT NULL AND t.id IS NULL"""
)

# -- maintenance_jobs --
analyze_orphan(
    "Maintenance jobs with property_id not in properties",
    """SELECT mj.id, mj.reference, mj.property_id FROM maintenance_jobs mj
      LEFT JOIN properties p ON mj.property_id = p.id
      WHERE mj.property_id IS NOT NULL AND p.id IS NULL"""
)

# -- documents --
analyze_orphan(
    "Documents with property_id not in properties",
    """SELECT d.id, d.filename, d.related_id FROM documents d
      WHERE d.related_to = 'property' AND d.related_id IS NOT NULL
      AND d.related_id NOT IN (SELECT id FROM properties)"""
)
analyze_orphan(
    "Documents with tenancy_id not in tenancies",
    """SELECT d.id, d.filename, d.related_id FROM documents d
      WHERE d.related_to = 'tenancy' AND d.related_id IS NOT NULL
      AND d.related_id NOT IN (SELECT id FROM tenancies)"""
)
analyze_orphan(
    "Documents with tenant_id not in tenants",
    """SELECT d.id, d.filename, d.related_id FROM documents d
      WHERE d.related_to = 'tenant' AND d.related_id IS NOT NULL
      AND d.related_id NOT IN (SELECT id FROM tenants)"""
)

# -- applicants --
analyze_orphan(
    "Applicants with property_id not in properties",
    """SELECT a.id, a.first_name, a.last_name, a.property_id FROM applicants a
      LEFT JOIN properties p ON a.property_id = p.id
      WHERE a.property_id IS NOT NULL AND p.id IS NULL"""
)
analyze_orphan(
    "Applicants with unit_id not in units",
    """SELECT a.id, a.first_name, a.last_name, a.unit_id FROM applicants a
      LEFT JOIN units u ON a.unit_id = u.id
      WHERE a.unit_id IS NOT NULL AND u.id IS NULL"""
)

# -- referencing_forms --
analyze_orphan(
    "Referencing forms with applicant_id not in applicants",
    """SELECT rf.id, rf.first_name, rf.last_name, rf.applicant_id FROM referencing_forms rf
      LEFT JOIN applicants a ON rf.applicant_id = a.id
      WHERE rf.applicant_id IS NOT NULL AND a.id IS NULL"""
)

# -- invoices --
analyze_orphan(
    "Invoices with tenancy_id not in tenancies",
    """SELECT i.id, i.invoice_ref, i.tenancy_id FROM invoices i
      LEFT JOIN tenancies tn ON i.tenancy_id = tn.id
      WHERE i.tenancy_id IS NOT NULL AND tn.id IS NULL"""
)

# -- guarantors --
analyze_orphan(
    "Guarantors with applicant_id not in applicants",
    """SELECT g.id, g.first_name, g.last_name, g.applicant_id FROM guarantors g
      LEFT JOIN applicants a ON g.applicant_id = a.id
      WHERE g.applicant_id IS NOT NULL AND a.id IS NULL"""
)

# -- maintenance_requests --
analyze_orphan(
    "Maintenance requests with property_id not in properties",
    """SELECT mr.id, mr.reference, mr.property_id FROM maintenance_requests mr
      LEFT JOIN properties p ON mr.property_id = p.id
      WHERE mr.property_id IS NOT NULL AND p.id IS NULL"""
)
analyze_orphan(
    "Maintenance requests with tenancy_id not in tenancies",
    """SELECT mr.id, mr.reference, mr.tenancy_id FROM maintenance_requests mr
      LEFT JOIN tenancies tn ON mr.tenancy_id = tn.id
      WHERE mr.tenancy_id IS NOT NULL AND tn.id IS NULL"""
)

# -- maintenance_jobs with tenant_id --
analyze_orphan(
    "Maintenance jobs with tenant_id not in tenants",
    """SELECT mj.id, mj.reference, mj.tenant_id FROM maintenance_jobs mj
      LEFT JOIN tenants t ON mj.tenant_id = t.id
      WHERE mj.tenant_id IS NOT NULL AND t.id IS NULL"""
)

# ─────────────────────────────────────────────
# SECTION 2: DUPLICATE RECORDS
# ─────────────────────────────────────────────
h1("3. Duplicate Records")

analyze_duplicate(
    "Duplicate unit_ref within same property_id",
    """SELECT u.property_id, u.unit_ref, COUNT(*) AS cnt, GROUP_CONCAT(u.id) AS ids
      FROM units u WHERE u.unit_ref IS NOT NULL AND u.unit_ref != ''
      GROUP BY u.property_id, u.unit_ref HAVING COUNT(*) > 1"""
)

analyze_duplicate(
    "Duplicate property_ref",
    """SELECT p.property_ref, COUNT(*) AS cnt, GROUP_CONCAT(p.id) AS ids
      FROM properties p WHERE p.property_ref IS NOT NULL AND p.property_ref != ''
      GROUP BY p.property_ref HAVING COUNT(*) > 1"""
)

analyze_duplicate(
    "Duplicate email within tenants",
    """SELECT t.email, COUNT(*) AS cnt, GROUP_CONCAT(t.id) AS ids,
             GROUP_CONCAT(t.first_name || ' ' || t.last_name) AS names
      FROM tenants t WHERE t.email IS NOT NULL AND t.email != ''
      GROUP BY t.email HAVING COUNT(*) > 1"""
)

analyze_duplicate(
    "Duplicate applicant emails",
    """SELECT a.email, COUNT(*) AS cnt, GROUP_CONCAT(a.id) AS ids,
             GROUP_CONCAT(a.first_name || ' ' || a.last_name) AS names
      FROM applicants a WHERE a.email IS NOT NULL AND a.email != ''
      GROUP BY a.email HAVING COUNT(*) > 1"""
)

# ─────────────────────────────────────────────
# SECTION 3: MISSING RELATIONSHIPS
# ─────────────────────────────────────────────
h1("4. Missing Relationships")

analyze_missing(
    "Tenants with no tenancy_id",
    """SELECT id, first_name, last_name, property_id FROM tenants
      WHERE tenancy_id IS NULL"""
)

analyze_missing(
    "Tenancies with no unit_id",
    """SELECT id, ref, property_id FROM tenancies WHERE unit_id IS NULL"""
)

analyze_missing(
    "Tenancies with no property_id",
    """SELECT id, ref, unit_id FROM tenancies WHERE property_id IS NULL"""
)

analyze_missing(
    "Units with no tenancies at all (vacant with no tenancy history)",
    """SELECT u.id, u.unit_ref, u.property_id FROM units u
      WHERE u.id NOT IN (SELECT DISTINCT unit_id FROM tenancies WHERE unit_id IS NOT NULL)"""
)

analyze_missing(
    "Deposits with no protection reference",
    """SELECT d.id, d.amount, d.tenancy_id, d.protection_status FROM deposits d
      WHERE (d.protection_reference IS NULL OR d.protection_reference = '')
      AND d.protection_status != 'unprotected'"""
)

analyze_missing(
    "Maintenance records with NULL property_id",
    """SELECT mj.id, mj.reference, mj.title FROM maintenance_jobs mj
      WHERE mj.property_id IS NULL"""
)

# ─────────────────────────────────────────────
# SECTION 4: DATA INTEGRITY ISSUES
# ─────────────────────────────────────────────
h1("5. Data Integrity Issues")

analyze_data(
    "Tenants linked to inactive properties",
    """SELECT t.id, t.first_name, t.last_name, t.property_id, p.name AS property_name, p.is_active
      FROM tenants t JOIN properties p ON t.property_id = p.id
      WHERE p.is_active = 0 OR p.is_active IS NULL"""
)

analyze_data(
    "Tenancies on archived/inactive properties",
    """SELECT tn.id, tn.ref, tn.property_id, p.name AS property_name, p.is_active
      FROM tenancies tn JOIN properties p ON tn.property_id = p.id
      WHERE p.is_active = 0 OR p.is_active IS NULL"""
)

analyze_data(
    "Overlapping active tenancies on same unit",
    """SELECT a.unit_id, a.id AS tenancy_a, a.start_date AS a_start, a.end_date AS a_end,
             b.id AS tenancy_b, b.start_date AS b_start, b.end_date AS b_end
      FROM tenancies a
      JOIN tenancies b ON a.unit_id = b.unit_id AND a.id < b.id
      WHERE a.status IN ('Active', 'active', 'Periodic', 'periodic')
        AND b.status IN ('Active', 'active', 'Periodic', 'periodic')
        AND a.start_date <= b.end_date AND b.start_date <= a.end_date"""
)

analyze_data(
    "Tenants with different property_id than their tenancy's property_id",
    """SELECT t.id, t.first_name, t.last_name, t.property_id AS tenant_property_id,
             tn.property_id AS tenancy_property_id, tn.id AS tenancy_id
      FROM tenants t JOIN tenancies tn ON t.tenancy_id = tn.id
      WHERE t.property_id IS NOT NULL AND tn.property_id IS NOT NULL
        AND t.property_id != tn.property_id"""
)

analyze_data(
    "Units with occupied status but no active tenancy",
    """SELECT u.id, u.unit_ref, u.unit_status, u.property_id
      FROM units u
      WHERE u.unit_status IN ('Let', 'Occupied', 'occupied', 'let')
        AND u.id NOT IN (
          SELECT DISTINCT unit_id FROM tenancies
          WHERE unit_id IS NOT NULL AND status IN ('Active', 'active', 'Periodic', 'periodic')
        )"""
)

analyze_data(
    "Units with vacant status but an active tenancy",
    """SELECT u.id, u.unit_ref, u.unit_status, u.property_id
      FROM units u
      WHERE u.unit_status IN ('Available', 'Vacant', 'available', 'vacant')
        AND u.id IN (
          SELECT DISTINCT unit_id FROM tenancies
          WHERE unit_id IS NOT NULL AND status IN ('Active', 'active', 'Periodic', 'periodic')
        )"""
)

# ─────────────────────────────────────────────
# SECTION 5: SCHEMA ISSUES
# ─────────────────────────────────────────────
h1("6. Schema Issues")

h2("6.1 Primary Key Check")
for tname, info in tables_info.items():
    if not info["pk_cols"]:
        analyze_schema(
            f"Table `{tname}` has no PRIMARY KEY",
            f"Table `{tname}` has NO primary key columns defined."
        )

h2("6.2 Timestamp Columns")
for tname, info in tables_info.items():
    if not info["has_created"]:
        analyze_schema(
            f"Table `{tname}` missing `created` timestamp",
            f"Table `{tname}` has no `created` column."
        )
    if not info["has_modified"]:
        analyze_schema(
            f"Table `{tname}` missing `modified` timestamp",
            f"Table `{tname}` has no `modified` column."
        )

h2("6.3 Missing Indexes on FK Columns")
important_fks = {
    "tenancies": ["property_id"],
    "tenants": ["property_id"],
    "units": ["property_id"],
    "documents": [],
    "maintenance_jobs": ["property_id", "tenant_id"],
    "maintenance_requests": ["property_id", "tenancy_id"],
    "applicants": ["property_id", "unit_id"],
    "invoices": ["tenancy_id", "tenant_id"],
    "deposits": [],
    "referencing_forms": ["applicant_id"],
}

for tname, extra_fks in important_fks.items():
    if tname not in tables_info:
        continue
    existing_index_names = index_info.get(tname, [])
    # Get indexed columns from PRAGMA index_info
    indexed_cols = set()
    for idx_name in existing_index_names:
        idx_col_rows = q(f"PRAGMA index_info(\"{idx_name}\")")
        for r in idx_col_rows:
            col_name = r["name"]
            if col_name:
                indexed_cols.add(col_name)

    for t_fk in fk_info.get(tname, []):
        if t_fk["from_col"] not in indexed_cols:
            analyze_schema(
                f"Table `{tname}` column `{t_fk['from_col']}` (FK to {t_fk['to_table']}) lacks index",
                f"FK column `{tname}.{t_fk['from_col']}` → `{t_fk['to_table']}` has no index."
            )

    for col in extra_fks:
        if col not in indexed_cols:
            analyze_schema(
                f"Table `{tname}` column `{col}` lacks index",
                f"Column `{tname}.{col}` has no index."
            )

# ─────────────────────────────────────────────
# SECTION 6: SUMMARY
# ─────────────────────────────────────────────
h1("7. Summary")

total_issues = total_orphans + total_duplicates + total_missing_relations + total_data_issues + total_schema_issues

table(["Category", "Count"], [
    ["Total Orphan Records", total_orphans],
    ["Total Duplicate Records", total_duplicates],
    ["Total Missing Relationships", total_missing_relations],
    ["Total Data Integrity Issues", total_data_issues],
    ["Total Schema Issues", total_schema_issues],
    ["**TOTAL ISSUES**", total_issues],
])

h2("Per-Table Record Counts")
table(["Table", "Record Count"], [(t, info["total"]) for t, info in tables_info.items()])

p(f"\n*Audit completed at {datetime.now().isoformat()}*")

# ── Write report ──
report_content = "".join(report_lines)
with open(REPORT_PATH, "w") as f:
    f.write(report_content)

print(f"✅ Integrity audit complete.")
print(f"   Total orphan records:   {total_orphans}")
print(f"   Total duplicates:       {total_duplicates}")
print(f"   Total missing rels:     {total_missing_relations}")
print(f"   Total data issues:      {total_data_issues}")
print(f"   Total schema issues:    {total_schema_issues}")
print(f"   ─────────────────────────────")
print(f"   TOTAL ISSUES FOUND:     {total_issues}")
print(f"   Report saved to: {REPORT_PATH}")

conn.close()
