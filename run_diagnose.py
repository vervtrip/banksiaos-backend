import sys
sys.path.insert(0, '.')
from banksia_os_db import get_dict_db

db = get_dict_db()

# Tenancy statuses
s = db.execute('SELECT DISTINCT status FROM tenancies').fetchall()
print('Tenancy statuses:', [r['status'] for r in s])

# Active tenancies with correct statuses
active = db.execute("SELECT COUNT(*) AS c FROM tenancies WHERE status IN ('Current','Periodic')").fetchone()
print(f'Active tenancies (Current + Periodic): {active["c"]}')

# Total rent
total = db.execute("SELECT COALESCE(SUM(rent_amount), 0) AS t FROM tenancies WHERE status IN ('Current','Periodic')").fetchone()
print(f'Monthly rent from active tenancies: {total["t"]:,.2f}')

print()

# Forms with bad applicant ref
fa = db.execute("SELECT id, first_name, last_name, applicant_id FROM referencing_forms WHERE applicant_id IS NOT NULL AND applicant_id NOT IN (SELECT id FROM applicants)").fetchall()
print(f'Forms with bad applicant ref ({len(fa)}):')
for f in fa:
    print(f'  #{f["id"]} {f["first_name"]} {f["last_name"]} — applicant_id={f["applicant_id"]}')

print()

# Are these missing from applicants table, or from tenants?
for f in fa:
    aid = f['applicant_id']
    in_applicants = db.execute("SELECT COUNT(*) AS c FROM applicants WHERE id = ?", [aid]).fetchone()['c']
    in_tenants = db.execute("SELECT COUNT(*) AS c FROM tenants WHERE id = ?", [aid]).fetchone()['c']
    in_refs = db.execute("SELECT COUNT(*) AS c FROM referencing_forms WHERE id = ?", [aid]).fetchone()['c']
    print(f'  Form #{f["id"]}: applicant_id={aid} — in_applicants={in_applicants}, in_tenants={in_tenants}, in_refs={in_refs}')

print()

# Check orphan tenants
ot = db.execute("SELECT t.id, t.first_name, t.last_name, t.tenancy_id FROM tenants t WHERE t.tenancy_id NOT IN (SELECT id FROM tenancies)").fetchall()
print(f'Orphan tenants ({len(ot)}):')
for t in ot:
    tn = db.execute("SELECT id, status FROM tenancies WHERE id = ?", [t['tenancy_id']]).fetchone()
    if tn:
        print(f'  #{t["id"]} {t["first_name"]} {t["last_name"]} — tenancy #{t["tenancy_id"]} exists (status={tn["status"]})')
    else:
        print(f'  #{t["id"]} {t["first_name"]} {t["last_name"]} — tenancy #{t["tenancy_id"]} MISSING')

db.close()
