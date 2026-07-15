# Banksia OS — Unit Occupancy Derivation Policy

## Authoritative Rule

**Unit occupancy MUST derive from tenancy records — NOT from `units.unit_status`.**

The `units.unit_status` field is a **derived/cache field** only. It is recalculated from tenancy data and must NOT be independently set by users to an occupied state.

## Occupancy States

| Display State | Condition |
|--------------|-----------|
| **Occupied** | One or more qualifying tenancies exist where `start_date ≤ today` AND (`end_date IS NULL` OR `end_date > today`) |
| **Future / Reserved** | No current qualifying tenancy, but one or more qualifying tenancies exist where `start_date > today` |
| **Ending Soon** | Current qualifying tenancy exists AND `end_date` is within the configured notice period (default: 30 days from today) |
| **Vacant** | No qualifying tenancy exists for this unit |

## Qualifying Tenancy Statuses

Only these tenancy lifecycle statuses participate in occupancy calculation:

- `Active`
- `active`
- `Periodic`
- `periodic`

**Non-qualifying** (treated as no tenancy for occupancy purposes):
- `ended`, `surrendered`, `cancelled`, `rejected`, `draft`, `endedd` (typo variants)

## Precedence Rules for Conflicting Data

| Scenario | Action |
|----------|--------|
| One active current tenancy + one future tenancy | → **Occupied** (current takes priority) |
| Two overlapping active tenancies for same unit | → **Occupied** (use earliest start_date; raise integrity alert) |
| Tenancy marked `surrendered` but with open-ended `end_date` | → **Vacant** (non-qualifying status takes priority over dates) |
| Future tenancy starting `today` | → **Occupied** (`start_date = today` is current, not future) |
| End date equal to today | → **Ending Soon** (ends at midnight; still occupied for the day) |
| Tenancy with `end_date` in the past but status still `active` | → **Vacant** (date overrides status; raise integrity alert) |
| Cancelled future tenancy | → **Vacant** (cancelled is non-qualifying) |
| Multiple future tenancies | → **Reserved** (use earliest start_date for display) |

## Consistency Checks

A scheduled job should periodically check:

```sql
SELECT u.id, u.unit_status AS stored, 
  CASE 
    WHEN EXISTS (SELECT 1 FROM tenancies t WHERE t.unit_id = u.id 
      AND t.status IN ('Active','active','Periodic','periodic')
      AND t.start_date <= date('now')
      AND (t.end_date IS NULL OR t.end_date > date('now'))) THEN 'Occupied'
    WHEN EXISTS (SELECT 1 FROM tenancies t WHERE t.unit_id = u.id 
      AND t.status IN ('Active','active','Periodic','periodic')
      AND t.start_date > date('now')) THEN 'Reserved'
    ELSE 'Vacant'
  END AS computed
FROM units u
HAVING stored != computed;
```

Any discrepancies should be logged to `integrity_audit` and auto-corrected in a transactional update.

## Repairs Applied (Phase 5)

| Unit | Property | Previous | Corrected | Reason |
|------|----------|----------|-----------|--------|
| 963 (R1) | 100001 | Occupied | Reserved | Future tenancy 2755 starts 2026-08-01 |
| 982 (U1) | 100015 | Occupied | Occupied | Active tenancy 2754, no end date ✅ |
| 989 (Room A) | 100001 | Occupied | Reserved | Future tenancies 2756/2757 start 2026-08-01 |
| 991 (Room C) | 100001 | Occupied | Reserved | Future tenancy 2758 starts 2026-08-15 |
| 815 (D5) | 244 | Let | Available | No active tenancy |
| 878 (Flat 3) | 265 | Let | Available | No active tenancy |
| 879 (44 Park Grove) | 266 | Let | Available | No active tenancy |
| 945 (M2) | 284 | Let | Available | No active tenancy |
| 946 (D1) | 284 | Let | Available | No active tenancy |
