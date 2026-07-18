# Banksia OS Backend API Audit Report

**Date**: 2026-07-16  
**DB**: `/root/banksia-dashboard/banksia_os.db`  
**Source**: `/root/banksia-dashboard/banksia_os.py`, `/root/banksia-dashboard/banksia_api.py`, `/root/banksia-dashboard/verv_os_db.py`, `/root/banksia-dashboard/referencing_api.py`

---

## Executive Summary

All API endpoints return HTTP 200 with real data. No empty responses or crashes detected. However, **6 systemic issues** were identified spanning data inconsistency, missing relationships, and duplicate data sources.

---

## Endpoint Audit Table

| # | Endpoint | HTTP | Data Count | DB Tables Used | Status |
|---|----------|------|-----------|----------------|--------|
| 1 | `/api/banksia-os/dashboard` | 200 | 34 fields | properties, units, tenancies, tenants, applicants, transactions, deposits, referencing_forms, maintenance_requests, message_threads, referencing_documents | ✅ Returns data |
| 2 | `/api/banksia-os/properties` | 200 | 67 total (paginated) | properties, units (subquery), tenancies (subquery) | ✅ Paginated |
| 3 | `/api/banksia-os/units` | 200 | 193 total (paginated) | units, properties (subquery), tenancies (subquery) | ✅ Paginated |
| 4 | `/api/banksia-os/tenants` | 200 | 536 total (paginated) | tenants, properties (subquery by arthur_id), units (subquery by arthur_id) | ✅ Paginated |
| 5 | `/api/banksia-os/tenancies` | 200 | 471 total (paginated) | tenancies, properties (subquery), units (subquery) | ✅ Paginated |
| 6 | `/api/banksia-os/applicants` | 200 | 683 total (paginated) | applicants | ✅ Paginated |
| 7 | `/api/banksia-os/guarantors` | 200 | 536 total (paginated) | tenants (guarantor fields only), properties (subquery by arthur_id) | ✅ Paginated |
| 8 | `/api/banksia-os/referencing` | 200 | 10 total | referencing_forms, applicants, properties, units | ✅ Paginated |
| 9 | `/api/banksia-os/arrears` | 200 | 565 outstanding | tenancies, transactions, properties | ✅ Paginated |
| 10 | `/api/banksia-os/deposits` | 200 | 148 held | deposits, tenancies, properties | ✅ Paginated with stats |
| 11 | `/api/banksia-os/maintenance` | 200 | 200 jobs (paginated) | maintenance_jobs, properties, maintenance_orders | ✅ Paginated |
| 12 | `/api/banksia-os/financials` | 200 | — | tenancies, transactions | ✅ Summary |
| 13 | `/api/banksia-os/finance/overview` | 200 | — | tenancies, transactions, deposits | ✅ Summary |
| 14 | `/api/banksia-os/finance/deposits` | 200 | 471 (all tenancies) | tenancies, units | ⚠️ Uses tenancies table, NOT deposits table |
| 15 | `/api/banksia-os/finance/transactions` | 200 | 7296 total | transactions | ✅ Paginated |
| 16 | `/api/banksia-os/property-owners` | 200 | 2 total | property_owners | ⚠️ Only 2 owners vs 48 properties with owner_id |
| 17 | `/api/banksia-os/submissions` | 200 | ~4 items | referencing_forms, maintenance_requests, message_threads, messages, referencing_documents | ✅ |
| 18 | `/api/banksia-os/activity` | 200 | up to 100 | activity_log | ✅ |

---

## Critical Findings

### 🔴 F1: Property Owners — Broken Relationship (48 properties, 2 owners in table)

**Problem**: `properties.property_owner_id` stores Arthur CRM's numeric owner IDs (e.g., `'353614'`, `'389248'`) as TEXT. `property_owners` table only has 2 locally-created owners with local IDs `1` and `2`.

**Consequences**:
- All 48 properties with owner IDs have **ZERO** links to the `property_owners` table
- The `/api/banksia-os/property-owners` endpoint and the property-specific owner lookup can never match
- The owner link logic uses `WHERE property_owner_id=? OR property_owner_name=?` but `property_owner_id` is an Arthur numeric string, not the local DB's `property_owners.id`
- **No foreign key** exists between `properties.property_owner_id` → `property_owners.id`

**Entities affected**: properties, property_owners

---

### 🔴 F2: Deposit Data — Two Inconsistent Sources

**Problem**: Deposit amounts are stored in two different places, producing different numbers:

| Source | Count | Total Amount |
|--------|-------|-------------|
| `deposits` table (held) | 148 | £145,601.00 |
| `tenancies.deposit_registered=1` | 36 | £32,855.00 |
| `tenancies` with any deposit_amount | 471 | £382,556.30 |

**Which endpoints use which source**:
- `/api/banksia-os/dashboard` → uses `deposits` table ✅
- `/api/banksia-os/finance/overview` → uses `deposits` table ✅
- `/api/banksia-os/financials` → uses `tenancies.deposit_registered` ❌
- `/api/banksia-os/finance/deposits` → uses `tenancies` table ❌

**dashboard reports**: total_deposits_held = £145,601  
**financials reports**: total_deposits = £32,855 (from tenancies.deposit_registered=1)  
**Difference**: £112,746 — a 77% undercount in financials

**Entities affected**: deposits, tenancies

---

### 🔴 F3: `unit_vacant` Is Manually Set, Not Derived — 7/193 Units Inconsistent

**Problem**: `unit_vacant` is a static column (`INTEGER DEFAULT 1`) set at data-entry time. It is **not derived** from actual tenancy data. 7 out of 193 units (3.6%) are inconsistent with real occupancy:

| Mismatch Type | Count | Examples |
|--------------|-------|---------|
| `unit_vacant=0` but **NO** active tenancy exists | 2 | Test Room 1 (status=Available), Audit Room (status=Available) |
| `unit_vacant=1` but **HAS** active tenancies | 5 | Room A (2 active tenancies!), 4 Studd Street, R1, U1, Room C |

**Worst case**: Unit #989 "Room A" has `unit_vacant=1` but has **2 active tenancies** (Sarah Connor, tenancy IDs 2756 & 2757).

**Dashboard impact**: The dashboard reports `vacant_units=47` and `occupied_units=146`, but actual occupied (has active tenancy) = 148. This could wrong by 2+.

**Recommendation**: Derive vacancy from `EXISTS (SELECT 1 FROM tenancies WHERE unit_id = units.id AND status IN ('Active','Periodic','Current'))` instead of using stored column.

---

### 🔴 F4: Arrears Are Stored Values from Arthur, Not Computed Locally

**Problem**: `transactions.amount_outstanding` is a stored value synced from the Arthur CRM. The `transactions` table has `is_outstanding=1` as a boolean flag set externally.

**What works**: The `/api/banksia-os/arrears` endpoint correctly joins `transactions.tenancy_id = tenancies.arthur_id` (Arthur ID mapping) and aggregates correctly.

**What's missing**: 
- No local rent roll computation from tenancy data
- The `rent_charges` table (2,084 rows) exists but is NOT used by any financial endpoint
- No link between `rent_charges` and `transactions` to show paid vs due
- The `is_outstanding` flag is stale — it reflects Arthur's state at last sync, not real-time

**Amount sync issue**: 196 transactions have **negative** `amount_outstanding` (refunds/credits) which may offset totals unexpectedly.

---

### 🟡 F5: Tenants Query Uses Wrong Property/Unit ID Mapping

**Problem**: In `/api/banksia-os/tenants`, the `tenants` table has `property_id` and `unit_id` as **Arthur IDs** (not local DB IDs). The subqueries try to convert:

```sql
-- Attempts to match by arthur_id
(SELECT ... FROM properties p2 WHERE p2.arthur_id = CAST(tn.property_id AS TEXT))
(SELECT ... FROM units u2 WHERE u2.arthur_id = CAST(tn.unit_id AS TEXT))
```

Tenants linked via `tenancy_id → tenancies.id` (local) work. But tenants queried directly with `property_id` filter or display use the Arthur-ID casting, which may fail if the Arthur ID in `tenants.property_id` doesn't match a row in `properties.arthur_id`.

**This is fragile** — converting Arthur IDs via `CAST(... AS TEXT)` assumes they're always numeric strings.

---

### 🟡 F6: No Dedicated Guarantors Table in Main Schema

**Problem**: The `guarantors` table **exists in the DB** (4 records) but is separate from the legacy guarantor fields embedded in `tenants` (guarantor_first_name, guarantor_last_name, etc.). 

- `/api/banksia-os/guarantors` queries **only** the `tenants` table's embedded fields
- The separate `guarantors` table (`REFERENCES applicants(id)`) is created but only used via `/api/banksia-os/applicants/<id>` endpoint
- Applicants route queries both embedded AND table-based guarantors via JOIN

**This creates dual data**: some guarantors live as embedded fields in tenants, others as proper rows in the `guarantors` table. No deduplication logic exists.

---

## Module Relationship Map

```
properties (67) ──┬── units (193) ──┬── tenancies (471) ──┬── tenants (536)
                  │                  │                      │
                  │                  │                      ├── tenants.guarantor fields (embedded)
                  │                  │                      │
                  │                  │              transactions (7296)
                  │                  │              └── tenancy_id → tenancies.arthur_id
                  │                  │
                  │                  └── deposits (148)
                  │                      └── tenancy_id → tenancies.id (local)
                  │
                  ├── property_owners (2) ← ⚠️ BROKEN: no FK to properties.property_owner_id
                  │
                  ├── maintenance_jobs (200)
                  │   ├── maintenance_orders
                  │   └── ll_communications
                  │
                  ├── property_images
                  └── referencing_forms (10) ── applicants (683)
                                                  └── guarantors (4) ← new-style table
                                                  └── referencing_checks
```

**Missing links**:
1. `properties.property_owner_id` → `property_owners.id` ❌
2. `tenancies.deposit_amount` → `deposits.amount` ❌ (should sync or one be authoritative)
3. `rent_charges` → `transactions` ❌ (uncharged)
4. `applicants` → `properties`/`units` ❌ (applicants table has no FK to properties)
5. `maintenance_jobs.tenant_id` → `tenants.id` (exists as FK but often NULL)

---

## Summary Statistics

| Table | Records | Notes |
|-------|---------|-------|
| properties | 67 | 48 have owner_id (Arthur text IDs) |
| units | 193 | 7 vacancy mismatches |
| tenancies | 471 | 145 active/periodic/current |
| tenants | 536 | |
| applicants | 683 | |
| transactions | 7,296 | 565 outstanding (£9,358.25 total) |
| deposits | 148 | Held: 148 (£145,601) |
| maintenance_jobs | 200 | |
| referencing_forms | 10 | 2 submitted awaiting review |
| guarantors | 4 | (new-style table) |
| property_owners | 2 | (vs 48 properties with owner_id) |
| documents | 1 | Polymorphic via related_to/related_id |

---

## Recommendations

1. **Synchronize deposit sources**: Make `deposits` table the single source of truth, migrate tenancies deposit amounts into it, remove `deposit_registered` from tenancies schema
2. **Derive unit vacancy**: Replace stored `unit_vacant` column with runtime derivation from active tenancies (or add a trigger to auto-update on tenancy create/end)
3. **Sync property owners**: Import Arthur owner records into `property_owners` table, add FK from `properties.property_owner_id` → `property_owners.arthur_id`
4. **Fix tenant property/unit queries**: Use `tenancy_id` JOIN path instead of fragile Arthur-ID casting
5. **Consolidate guarantors**: Migrate embedded tenant guarantor fields into `guarantors` table; make API query both
6. **Use rent_charges**: Build local rent computation from `rent_charges` table as fallback when transactions are stale
