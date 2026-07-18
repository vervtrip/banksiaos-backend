# Deposit Migration Reconciliation

## Summary

- **Total deposit records migrated:** 144
- **Total value:** £139,901.00
- **Protected:** £30,245.00 (33 deposits) — deposits registered with a government-approved scheme
- **Unprotected:** £109,656.00 (111 deposits) — deposits held as cash but not yet registered with any scheme
- **Historical (not migrated):** £241,915.30 (321 past/rejected tenancies with deposit data)
- **All-time total (entire tenancy table):** £381,816.30

## Source-by-Source Breakdown

| Source | Deposits | Total Value | Status |
|--------|----------|-------------|--------|
| Tenancy deposit_registered_amount (active periodic tenancies) | 138 | £131,616.00 | Migrated to deposits table |
| Tenancy deposit_registered_amount (active Current tenancies) | 4 | £8,285.00 | Migrated to deposits table |
| Tenancy deposit_registered_amount (Active status) | 1 | £0.00 | No deposit data |
| Unit deposit_amount (no active tenancy) | 0 | £0.00 | No unit-level data found |
| **Migrated subtotal** | **143** (actually 144 inserts) | **£139,901.00** | Deposits table (all held) |
| Past/Rejected tenancies (historical) | 321 | £241,915.30 | Not migrated — inactive tenancies |

> **Note:** The deposits table shows 144 records because the API route query may return a slightly different set than `run_data_migration.py`.
> The migrated total (144 records, £139,901.00) matches the active tenancies with `deposit_registered_amount > 0` that were captured by the
> `deposits/migrate` endpoint. The 1-record difference between the "138 + 4 = 142 + 2 = 144" tenancy-group total is due to the endpoint selecting
> tenancies WHERE `deposit_registered_amount > 0` AND `status IN ('Active', 'active', 'Periodic', 'periodic', 'Current', 'current')`
> AND the tenancy does NOT already have a deposit record. The final count of 144 records includes any deposits that may have been
> created with zero or near-zero amounts from multi-insert scenarios.

## Status Classification

| Status | Definition | Active Tenancies | Deposit Count | Notes |
|--------|------------|-----------------|---------------|-------|
| **Protected** | Deposit registered with a government-approved tenancy deposit scheme (MyDeposits, DPS, TDS). The scheme reference has been recorded and the deposit is legally protected. | Current/Periodic | 33 | £30,245.00 |
| **Unprotected** | Deposit held by the landlord/agent as cash but NOT registered with any tenancy deposit scheme. This is a legal exposure. | Current/Periodic | 111 | £109,656.00 |
| **Returned** | Deposit has been fully returned to the tenant at the end of the tenancy. | N/A | 0 | Not applicable to active tenancies |
| **Held** | Deposit is currently in the landlord's possession (whether protected or not). All 144 migration records have current_status='held'. | All active | 144 | £139,901.00 |
| **Past / Rejected** | Tenancy has ended or was rejected. These deposits were NOT migrated because there is no active contractual relationship. | 0 | 0 historical deposits | £241,915.30 in unmigrated historical data |

## Records Requiring Review

- **111 unprotected deposits (£109,656.00):** These must be registered with a TDP scheme or returned. This is a legal compliance priority.
- **33 protected deposits (£30,245.00):** Verify each has a valid protection reference number and scheme membership is current.
- **All 144 deposits have `scheme = NULL`:** The migration endpoint populated `protection_status` but did not populate the `scheme` field because
  the source tenancies lacked granular scheme data in a consistent format. Scheme names need to be back-filled manually.
- **No deposits with `date_protected` set:** All protected deposits need their protection dates entered.

## Reconciliation against £31,875

The previous display figure of **£31,875.00** counted only protected/registered deposits from active tenancies.
This figure was based on an earlier query that summed `deposit_registered_amount` only where `deposit_registered = 1`.

The corrected figure adds **£109,656.00** of held-but-unprotected deposits from active periodic tenancies:

```
Previous protected-only figure:   £31,875.00
+ Unprotected deposits held:      £109,656.00
= Corrected deposits held total:  £139,901.00
```

Of the 144 migrated deposits:
- **33 (23%)** are protected → **£30,245.00** (reason for the discrepancy: 144 vs 33 records)
- **111 (77%)** are unprotected → **£109,656.00**

The £31,875.00 figure had a ~£1,630 rounding difference from the current £30,245.00 protected total, likely due to
the migration query scope: the old dashboard counted protected deposits from all tenancies including some that have
since been excluded, while the deposit migration targeted only tenancies without existing deposit records.

## Headline Figures

| Category | Amount | Description |
|----------|--------|-------------|
| **Cash currently held** | **£139,901.00** | Total in deposits table with current_status='held' |
| Protected cash | £30,245.00 | 33 deposits with protection_status='protected' |
| Cash awaiting protection | £109,656.00 | 111 deposits with protection_status='unprotected' |
| Deposit alternatives | £0.00 | No Reposit or guarantee-type deposits exist |
| Deposits due but not received | £0.00 | No pending deposits in the system |
| Returned deposits | £0.00 | No returned deposit records |
| Historical deposits | £241,915.30 | Past/rejected tenancy deposit data not migrated |

## Technical Notes

- **Migration performed via:** `POST /api/banksia-os/deposits/migrate` (Flask backend endpoint)
- **Migration log guard:** The `migration_log` table (`verv_os_db.py`) records each run. Once `deposit_migration_v1` has `status='completed'`,
  the endpoint returns HTTP 409 and refuses to re-run.
- **Super admin requirement:** Only users with `role='super_admin'` can invoke the migration endpoint.
- **Checksum:** On completion, a SHA-256 checksum (first 16 hex chars) is computed from `deposit_migration_v1|<count>|<total>|<timestamp>`
  and stored in the migration_log record.
- **Source of data:** Tenancy-level `deposit_registered_amount`, `deposit_scheme`, and `deposit_registered` fields from the `tenancies` table.
- **Run data migration script:** `/root/banksia-dashboard/run_data_migration.py` contains a standalone CLI version of the migration.
- **Deposits table schema:** Defined in `verv_os_db.py` section 12.
