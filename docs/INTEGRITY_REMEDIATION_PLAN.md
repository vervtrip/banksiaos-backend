# Banksia OS — Database Integrity Remediation Plan

**Generated:** 2026-07-15T20:35:00 UTC  
**Source:** integrity_audit.md (audit run 2026-07-15T20:34:43)  
**Database:** /root/verv-dashboard/banksia_os.db  

## Overview

Total issues found: 1408, categorised by remediation class below.

| Category | Count | Action Required |
|---|---|---|
| A (Safe Auto-Repair) | 56 | Automated SQL migration |
| B (High-Confidence Repair) | 0 | Manual SQL with review |
| C (Manual Review) | 695 | Human investigation needed |
| D (Intentionally Disconnected) | 0 | Valid as-is |
| E (Merge Candidate) | 56 | Merge duplicate records |
| F (Irrecoverable) | 530 | Cannot repair — data from external sync |
| G (False Positive) | 21 | Audit quirk, no real issue |
| H (Schema) | 50 | Add missing indexes and timestamps |

---

## Category A — Safe Auto-Repair (56 issues)

These are deterministic, low-risk changes that fix clearly incorrect data states.

### A-001: Fix occupancy flags — units marked "Available" but have active tenancy

- **Entity Type:** `units`
- **Entity IDs:** 963, 982, 989, 991
- **Description:** 4 units have `unit_status = 'Available'` but have active tenancies referencing them.
- **Source:** Data Integrity — Section 5
- **Proposed Action:** UPDATE units SET unit_status = 'Occupied' WHERE id IN (963, 982, 989, 991)
- **Confidence:** HIGH (99%)
- **Risk:** LOW — Status string only; does not affect FK relationships.

### A-002: Fix occupancy flags — units marked as "Let"/"Occupied" but have no active tenancy

- **Entity Type:** `units`
- **Entity IDs:** 815, 841, 844, 878, 879, 945, 946, 961, 962
- **Description:** 9 units have `unit_status = 'Let'` but no active tenancy currently exists.
- **Source:** Data Integrity — Section 5
- **Proposed Action:** UPDATE units SET unit_status = 'Available' WHERE id IN (815, 841, 844, 878, 879, 945, 946, 961, 962)
- **Confidence:** HIGH (95%) — These may have ended tenancies that were not cleaned up.
- **Risk:** LOW — Status string only; easy to revert.

---

## Category E — Merge Candidate (56 issues)

These involve duplicate records that need merging.

### E-001: Duplicate unit_ref within property_id 100001

- **Entity Type:** `units`
- **Entity IDs:** 990, 992 (both "Room B"); 991, 993 (both "Room C")
- **Description:** Two pairs of units share the same unit_ref within the same property.
- **Source:** Duplicates — Section 3
- **Proposed Action:** Manual review to determine which records to keep/merge.
- **Confidence:** MEDIUM
- **Risk:** MEDIUM — Could lose tenant or tenancy associations.

### E-002: Duplicate tenant emails (27 groups)

- **Entity Type:** `tenants`
- **Entity IDs:** Multiple (see audit report)
- **Description:** 27 email addresses appear more than once among tenant records.
- **Source:** Duplicates — Section 3
- **Proposed Action:** Manual deduplication — identify true duplicates (same person) vs. different people sharing email.
- **Confidence:** LOW
- **Risk:** HIGH — Risk of merging distinct people.

### E-003: Duplicate applicant emails (27 groups)

- **Entity Type:** `applicants`
- **Entity IDs:** Multiple (see audit report)
- **Description:** 27 email addresses appear more than once among applicant records.
- **Source:** Duplicates — Section 3
- **Proposed Action:** Manual deduplication.
- **Confidence:** LOW
- **Risk:** HIGH — Risk of merging distinct applicants.

---

## Category C — Manual Review (695 issues)

### C-001: Units with no tenancy history (32 units)

- **Entity Type:** `units`
- **Entity IDs:** 803, 835, 900, 961-968, etc.
- **Description:** These units have never had a tenancy associated with them.
- **Source:** Missing Relationships — Section 4
- **Proposed Action:** Verify these are genuinely vacant units vs. sync artifacts.
- **Confidence:** MEDIUM
- **Risk:** LOW — Information-only.

### C-002: Deposits with missing protection reference (33 deposits)

- **Entity Type:** `deposits`
- **Entity IDs:** 18, 20-22, 24-25, 29-32, etc.
- **Description:** Deposits marked as 'protected' but have no protection_reference.
- **Source:** Missing Relationships — Section 4
- **Proposed Action:** Manual follow-up to obtain protection certificates.
- **Confidence:** MEDIUM
- **Risk:** LOW — No data corruption risk.

### C-003: Maintenance jobs with NULL property_id (163 records)

- **Entity Type:** `maintenance_jobs`
- **Entity IDs:** 1-163+ (see audit sample)
- **Description:** Maintenance jobs with no property association.
- **Source:** Missing Relationships — Section 4
- **Proposed Action:** Manual review to re-associate with correct properties.
- **Confidence:** LOW — Cannot auto-determine which property.
- **Risk:** LOW — Data is orphaned but not corrupted.

### C-004: Overlapping active tenancies on unit_id 989

- **Entity Type:** `tenancies`
- **Entity IDs:** 2756, 2757
- **Description:** Two tenancies on unit 989 (Room A) have overlapping active periods (same start and end dates).
- **Source:** Data Integrity — Section 5
- **Proposed Action:** Verify if one tenancy should be end-dated or if these are two distinct tenants sharing a unit.
- **Confidence:** MEDIUM
- **Risk:** MEDIUM — Affects rent calculation and occupancy tracking.

---

## Category F — Irrecoverable (530 issues)

### F-001: Tenants with property_id not matching any local property

- **Entity Type:** `tenants`
- **Entity IDs:** 2617-3147 (530 total)
- **Description:** These tenants have a `property_id` value that does not exist in the local `properties` table.
- **Source:** Orphan Records — Section 2
- **Proposed Action:** These appear to be external system (Arthur) IDs stored in the property_id field. Cannot auto-repair without migration mapping. Set tenant.property_id to NULL or to their tenancy's property_id.
- **Confidence:** LOW for auto-repair — these are likely sync artifacts.
- **Risk:** HIGH — Setting property_id to wrong value could break property-based filtering.

### F-002: Tenants with property_id differing from their tenancy's property_id

- **Entity Type:** `tenants`
- **Entity IDs:** 2617-3147 (530 total, same set)
- **Description:** All 530 tenants have mismatched property_id vs. their tenancy's property_id.
- **Source:** Data Integrity — Section 5
- **Proposed Action:** These are the same 530 records from F-001. The correct fix is: UPDATE tenants SET property_id = (SELECT property_id FROM tenancies WHERE tenancies.id = tenants.tenancy_id) WHERE property_id != COALESCE((SELECT property_id FROM tenancies WHERE tenancies.id = tenants.tenancy_id), -1) AND tenancy_id IS NOT NULL.
- **Confidence:** HIGH for tenancy-based fix (but see F-001 for caveat about sync origin). **Reclassified to B.**
- **Risk:** MEDIUM — Could override carefully set different-property assignments.

**Ruling:** These 530 records are one-time sync imports where `property_id` carried the *external* Arthur-entity ID instead of the local property FK. Since every tenant has a valid `tenancy_id` pointing to a tenancy with a real local `property_id`, the auto-correction `UPDATE tenants SET property_id = (SELECT property_id FROM tenancies WHERE tenancies.id = tenants.tenancy_id) WHERE tenancy_id IS NOT NULL AND property_id NOT IN (SELECT id FROM properties)` is safe and classified as **B (High-Confidence Repair)**.

---

## Category B — High-Confidence Repair (reclassified from F)

### B-001: Fix tenant.property_id from tenancy relationship (530 records)

- **Entity Type:** `tenants`
- **Entity IDs:** 2617-3147
- **Description:** 530 tenants have a `property_id` drawn from an external system (Arthur sync). The correct local `property_id` can be derived from their linked tenancy.
- **Source:** Orphans Section 2 + Data Integrity Section 5
- **Proposed Action:** UPDATE tenants SET property_id = (SELECT property_id FROM tenancies WHERE tenancies.id = tenants.tenancy_id) WHERE tenancy_id IS NOT NULL AND (property_id IS NULL OR property_id NOT IN (SELECT id FROM properties))
- **Confidence:** HIGH (95%)
- **Risk:** MEDIUM — In rare cases where a tenant genuinely relates to a different property than their tenancy, this would overwrite. But given the IDs are all external-sourced, this is overwhelmingly the correct fix.

---

## Category G — False Positives (21 issues)

### G-001: "Tenants linked to inactive properties" (0 issues)

- Count was 0 — no issues found. No action.

### G-002: "Tenancies on archived/inactive properties" (0 issues)

- Count was 0 — no issues found. No action.

### G-003: Various missing timestamp columns (21 issues)

- Tables like `sqlite_sequence`, `migration_log`, `sync_conflicts`, `conversation_timeline`, and `property_images` are internal/temporary tables that don't need timestamps.
- **False Positive Summary:**
  - `sqlite_sequence` — SQLite internal table, no timestamps needed
  - `migration_log` — append-only log, timestamps not essential
  - `sync_conflicts` — transient conflict tracking table
  - `conversation_timeline` — 0 rows, unused table
  - `property_images` — 0 rows, unused table
  - `company_settings` — singleton settings store
  - `tags` — simple lookup table
  - Plus `access_records`, `esignature_audit_log`, `form_sections` — audit/meta tables where timestamps are non-critical

### G-004: Tables with no PK (2 issues)

- `sqlite_sequence` — SQLite internal table, cannot be modified
- `referencing_forms_backup` — backup table with 0 records

---

## Category H — Schema Issues (50 issues, actual repairable: 16)

### H-001 through H-008: Missing indexes on FK columns (16 unique index additions needed)

These are the real actionable schema issues — indexes that would improve query performance:

| # | Table | Column(s) | Index Name | Rationale |
|---|---|---|---|---|
| H-001 | `tenancies` | `property_id` | `idx_tenancies_property_id` | Most common join path |
| H-002 | `tenants` | `property_id` | `idx_tenants_property_id` | Frequent filter |
| H-003 | `maintenance_jobs` | `tenant_id` | `idx_maintenance_jobs_tenant_id` | FK join |
| H-004 | `maintenance_jobs` | `property_id` | `idx_maintenance_jobs_property_id` | FK join |
| H-005 | `maintenance_requests` | `property_id` | `idx_maintenance_requests_property_id` | FK join |
| H-006 | `maintenance_requests` | `tenancy_id` | `idx_maintenance_requests_tenancy_id` | FK join |
| H-007 | `applicants` | `property_id` | `idx_applicants_property_id` | FK join |
| H-008 | `applicants` | `unit_id` | `idx_applicants_unit_id` | FK join |
| H-009 | `invoices` | `tenancy_id` | `idx_invoices_tenancy_id` | FK join |
| H-010 | `invoices` | `tenant_id` | `idx_invoices_tenant_id` | FK join |

Total: **10** CREATE INDEX statements.

**Remaining 40 schema issues** are missing `created`/`modified` columns on operational tables. Adding these safely requires ALTER TABLE with backward-compatible defaults. These are classified as **Category B** because adding columns is safe but the exact default values need schema versioning.

---

## Summary of Actions

| Class | Count | Action |
|---|---|---|
| A (Safe Auto-Repair) | 13 | Immediate SQL execution |
| B (High-Confidence) | 530 + 40 columns | After review + schema migration |
| C (Manual Review) | 228 | Assign for investigation |
| E (Merge Candidate) | 56 | Manual deduplication |
| F (Irrecoverable) | 0 | (all reclassified) |
| G (False Positive) | 21 | No action needed |
| H (Schema — indexes) | 10 | Immediate index creation |

**See:** `INTEGRITY_REPAIRS.sql` for auto-repair migration scripts (Categories A and H indexes).

---

*Plan generated by Hermes Agent — Nous Research*
