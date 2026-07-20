import sys
sys.path.insert(0, '.')
from banksia_os_db import get_dict_db

db = get_dict_db()

print('=== CRM DATA INTEGRITY ===')
rows = [
    ('Properties (active)', 'SELECT COUNT(*) AS c FROM properties WHERE is_active=1'),
    ('Units', 'SELECT COUNT(*) AS c FROM units'),
    ('Tenancies', 'SELECT COUNT(*) AS c FROM tenancies'),
    ('Tenants', 'SELECT COUNT(*) AS c FROM tenants'),
    ('Property Owners', 'SELECT COUNT(*) AS c FROM property_owners'),
    ('Referencing Forms', 'SELECT COUNT(*) AS c FROM referencing_forms'),
    ('Portal Users', 'SELECT COUNT(*) AS c FROM portal_users'),
    ('E-Sign Requests', 'SELECT COUNT(*) AS c FROM esignature_requests'),
    ('Signed Docs (audit)', 'SELECT COUNT(*) AS c FROM esignature_audit_log'),
    ('Transactions', 'SELECT COUNT(*) AS c FROM transactions'),
    ('Maintenance Jobs', 'SELECT COUNT(*) AS c FROM maintenance_jobs'),
    ('Comments', 'SELECT COUNT(*) AS c FROM comments'),
    ('Deposits', 'SELECT COUNT(*) AS c FROM deposits'),
]
for name, sql in rows:
    c = db.execute(sql).fetchone()['c']
    print(f'  {name:30s} {c:>6,}')

print()
print('=== LINKAGE INTEGRITY ===')
checks = [
    ('Orphan tenancies', 'SELECT COUNT(*) AS c FROM tenancies WHERE property_id NOT IN (SELECT id FROM properties)'),
    ('Orphan units', 'SELECT COUNT(*) AS c FROM units WHERE property_id NOT IN (SELECT id FROM properties)'),
    ('Orphan tenants', 'SELECT COUNT(*) AS c FROM tenants WHERE tenancy_id NOT IN (SELECT id FROM tenancies)'),
    ('Forms bad applicant', "SELECT COUNT(*) AS c FROM referencing_forms WHERE applicant_id IS NOT NULL AND applicant_id NOT IN (SELECT id FROM applicants)"),
    ('Orphan maint jobs', "SELECT COUNT(*) AS c FROM maintenance_jobs WHERE property_id NOT IN (SELECT id FROM properties) AND property_id NOT IN (SELECT id FROM units)"),
]
for name, sql in checks:
    c = db.execute(sql).fetchone()['c']
    icon = 'ZERO' if c == 0 else f'{c} BROKEN'
    print(f'  {icon:12s} {name:30s}')

print()
print('=== FINANCIAL SUMMARY ===')
row = db.execute("SELECT COALESCE(SUM(rent_amount), 0) AS total FROM tenancies WHERE status IN ('active','periodic')").fetchone()
active_ten = db.execute("SELECT COUNT(*) AS c FROM tenancies WHERE status IN ('active','periodic')").fetchone()
total_rent = row['total']
print(f'  Active tenancies:            {active_ten["c"]}')
print(f'  Total monthly rent:         {total_rent:,.2f}')
print(f'  Avg rent per tenancy:       {total_rent/max(active_ten["c"],1):,.2f}')

print()
print('=== SAMPLE RECORDS ===')
props = db.execute("SELECT id, name, city, property_type FROM properties WHERE is_active=1 LIMIT 5").fetchall()
print(f'  Sample properties ({len(props)}):')
for p in props:
    print(f'    #{p["id"]} {p["name"]} — {p["city"]} ({p["property_type"]})')

db.close()
