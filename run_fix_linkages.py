import sys
sys.path.insert(0, '.')
from banksia_os_db import get_dict_db

db = get_dict_db()

# Fix 1: Clear applicant_id on forms referencing non-existent applicant
db.execute("UPDATE referencing_forms SET applicant_id = NULL WHERE applicant_id IS NOT NULL AND applicant_id NOT IN (SELECT id FROM applicants)")
fixed_forms = db.execute("SELECT changes() AS c").fetchone()['c']
print(f'Fixed {fixed_forms} forms with bad applicant refs')

# Fix 2: Delete orphan tenants with no tenancy
db.execute("DELETE FROM tenants WHERE tenancy_id NOT IN (SELECT id FROM tenancies)")
deleted_tenants = db.execute("SELECT changes() AS c").fetchone()['c']
print(f'Deleted {deleted_tenants} orphan tenants')

db.commit()

# Verify all linkages are clean
orphan_t = db.execute("SELECT COUNT(*) AS c FROM tenants WHERE tenancy_id NOT IN (SELECT id FROM tenancies)").fetchone()['c']
orphan_f = db.execute("SELECT COUNT(*) AS c FROM referencing_forms WHERE applicant_id IS NOT NULL AND applicant_id NOT IN (SELECT id FROM applicants)").fetchone()['c']
print()
print('=== POST-FIX VERIFICATION ===')
print(f'  Orphan tenants:  {orphan_t} (should be 0)')
print(f'  Bad form refs:   {orphan_f} (should be 0)')

# Updated financial summary
active = db.execute("SELECT COUNT(*) AS c FROM tenancies WHERE status IN ('Current','Periodic')").fetchone()['c']
total = db.execute("SELECT COALESCE(SUM(rent_amount), 0) AS t FROM tenancies WHERE status IN ('Current','Periodic')").fetchone()['t']
print(f'  Active tenancies: {active}')
print(f'  Monthly rent:     {total:,.2f}')

db.close()
