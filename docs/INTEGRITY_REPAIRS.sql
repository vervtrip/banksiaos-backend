-- =============================================================================
-- Banksia OS — Integrity Repairs (Categories A and H)
-- Generated: 2026-07-15T20:35:00 UTC
-- Source: integrity_audit.md, INTEGRITY_REMEDIATION_PLAN.md
-- 
-- These are safe, deterministic auto-repairs. Run as a transaction for safety.
-- =============================================================================

BEGIN TRANSACTION;

-- =============================================================================
-- CATEGORY A — Safe Auto-Repairs
-- =============================================================================

-- ---------------------------------------------------------------------------
-- A-001: Fix occupancy flags — units marked "Available" but have active tenancy
-- 4 units: 963 (R1/property 100001), 982 (U1/property 100015),
-- 989 (Room A/property 100001), 991 (Room C/property 100001)
-- These all have active tenancies but their status says "Available".
-- ---------------------------------------------------------------------------
UPDATE units
SET unit_status = 'Occupied'
WHERE id IN (963, 982, 989, 991)
  AND unit_status IN ('Available', 'Vacant', 'available', 'vacant');

-- ---------------------------------------------------------------------------
-- A-002: Fix occupancy flags — units marked "Let"/"Occupied" but no active tenancy
-- 9 units that show as "Let" but have no current active/periodic tenancy.
-- Set back to "Available" since no tenancy currently occupies them.
-- ---------------------------------------------------------------------------
UPDATE units
SET unit_status = 'Available'
WHERE id IN (815, 841, 844, 878, 879, 945, 946, 961, 962)
  AND unit_status IN ('Let', 'Occupied', 'occupied', 'let');

-- =============================================================================
-- CATEGORY H — Missing Indexes on FK Columns
-- =============================================================================

-- ---------------------------------------------------------------------------
-- H-001: Index tenancies.property_id → properties.id
-- Most common join path for tenancy queries.
-- ---------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_tenancies_property_id
    ON tenancies(property_id);

-- ---------------------------------------------------------------------------
-- H-002: Index tenants.property_id → properties.id
-- Frequently filtered when showing tenants by property.
-- ---------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_tenants_property_id
    ON tenants(property_id);

-- ---------------------------------------------------------------------------
-- H-003: Index maintenance_jobs.tenant_id → tenants.id
-- FK join support.
-- ---------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_maintenance_jobs_tenant_id
    ON maintenance_jobs(tenant_id);

-- ---------------------------------------------------------------------------
-- H-004: Index maintenance_jobs.property_id → properties.id
-- FK join support.
-- ---------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_maintenance_jobs_property_id
    ON maintenance_jobs(property_id);

-- ---------------------------------------------------------------------------
-- H-005: Index maintenance_requests.property_id → properties.id
-- FK join support.
-- ---------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_maintenance_requests_property_id
    ON maintenance_requests(property_id);

-- ---------------------------------------------------------------------------
-- H-006: Index maintenance_requests.tenancy_id → tenancies.id
-- FK join support.
-- ---------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_maintenance_requests_tenancy_id
    ON maintenance_requests(tenancy_id);

-- ---------------------------------------------------------------------------
-- H-007: Index applicants.property_id → properties.id
-- FK join support.
-- ---------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_applicants_property_id
    ON applicants(property_id);

-- ---------------------------------------------------------------------------
-- H-008: Index applicants.unit_id → units.id
-- FK join support.
-- ---------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_applicants_unit_id
    ON applicants(unit_id);

-- ---------------------------------------------------------------------------
-- H-009: Index invoices.tenancy_id → tenancies.id
-- FK join support.
-- ---------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_invoices_tenancy_id
    ON invoices(tenancy_id);

-- ---------------------------------------------------------------------------
-- H-010: Index invoices.tenant_id → tenants.id
-- FK join support.
-- ---------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_invoices_tenant_id
    ON invoices(tenant_id);

-- =============================================================================
-- Summary
-- =============================================================================
-- Category A: 2 UPDATE statements (13 units fixed)
-- Category H: 10 CREATE INDEX statements (indexes added)
--
-- Run: SELECT changes() AS rows_affected; after each to verify.
-- =============================================================================

COMMIT;
