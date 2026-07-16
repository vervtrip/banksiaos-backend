-- Migration: Property Owner reconciliation (Audit finding C1)
-- Date: 2026-07-16
-- Problem: 28 real owners were embedded inside properties (Arthur id + name),
--          but property_owners held only 2 test-junk rows -> owners never linked.
-- Fix: materialise each real owner as a property_owners row keyed by its Arthur id
--      so properties.property_owner_id (TEXT) matches property_owners.id (INT) via CAST.
-- Backup taken before run: verv_os.db.bak_owners_20260716_144842
-- Reversible: DELETE FROM property_owners WHERE notes='Imported from Arthur owner records';

BEGIN;
DELETE FROM property_owners WHERE id IN (1,2) AND name IN ('Test Owner','Audit Owner');

INSERT INTO property_owners (id, name, company_name, status, notes, modified)
SELECT CAST(p.property_owner_id AS INTEGER),
       p.property_owner_name,
       COALESCE(NULLIF(MAX(p.owner_company),''),''),
       'active',
       'Imported from Arthur owner records',
       datetime('now')
FROM properties p
WHERE p.property_owner_id IS NOT NULL
  AND TRIM(p.property_owner_id) <> ''
  AND CAST(p.property_owner_id AS INTEGER) NOT IN (SELECT id FROM property_owners)
GROUP BY CAST(p.property_owner_id AS INTEGER), p.property_owner_name;
COMMIT;
