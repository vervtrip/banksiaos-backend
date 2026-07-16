
## 2026-07-16 — sami/main — Property Owner reconciliation (B)
- Fixed audit finding C1: materialised 28 real owners into property_owners, keyed by Arthur ID.
- Removed 2 test-junk owner rows (Test Owner, Audit Owner).
- properties.property_owner_id now resolves to a real property_owners.id (FK format aligned).
- Verified via live API: list=28 owners, detail links (e.g. Supria Begum -> 8 properties).
- Backup: verv_os.db.bak_owners_20260716_144842. Migration: docs/migrations/2026-07-16_owner_reconciliation.sql
- Note: 19 properties still have no owner assigned; properties.name holds type ("multi"/"single") not a label — separate data issues, flagged not fixed.
