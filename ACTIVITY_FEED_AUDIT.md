# Activity Feed Genuineness Audit

**Endpoint:** `GET /api/banksia-os/dashboard/activity`
**Implementation:** `banksia_os.py`, `api_dashboard_activity()` (lines 409–503)
**DB:** `/root/banksia-dashboard/verv_os.db`
**Audit date:** 2026-07-15
**Auth:** requires an authenticated session (returns 401 unauthenticated — verified live).

## How the feed is built

The endpoint UNIONs five SQL queries in Python (one `append` loop per source), each
projecting the same shape (`id, event_type, ts, title, description, category,
link_type, link_id, related_id`). It filters each source to rows where the timestamp
column `IS NOT NULL`, concatenates them into one list, sorts by the raw `ts` string
descending (`activity.sort(key=lambda x: x.get("ts") or "", reverse=True)`, line 496),
and truncates to `limit` (default 30). Every event is a real DB row — there is no
synthetic/random data generation anywhere in the function.

## Source breakdown

### Events shown in the default (limit=30) live response

| event_type            | source table          | timestamp column | count in feed |
|-----------------------|-----------------------|------------------|---------------|
| tenancy_created       | tenancies             | created          | 20            |
| referencing_submitted | referencing_forms     | submitted_at     | 4             |
| referencing_reviewed  | referencing_forms     | reviewed_at      | 2             |
| maintenance_created   | maintenance_requests  | created          | 2             |
| message_created       | message_threads       | created          | 2             |
| **Total**             |                       |                  | **30**        |

### Full candidate pool in DB (rows with a non-null timestamp)

| source                                      | eligible rows |
|---------------------------------------------|---------------|
| referencing_forms.submitted_at              | 4             |
| referencing_forms.reviewed_at               | 2             |
| maintenance_requests.created                | 2             |
| tenancies.created                           | 465           |
| message_threads.created                     | 2             |
| **Total eligible**                          | **475**       |

The pool of 475 is sorted string-descending and capped at 30, so the visible feed is
dominated by the most recent tenancy_created rows plus all recent referencing /
maintenance / message events from mid-July 2026.

## Real record ID spot-checks

Each sampled event ID was queried in its source table; all exist and the stored
timestamp matches the value returned by the API exactly:

| feed event                       | source query                                          | stored timestamp                        | matches API |
|----------------------------------|-------------------------------------------------------|-----------------------------------------|-------------|
| tenancy_created id=2753          | `tenancies WHERE id=2753` (created)                   | `2026-07-12T17:06:22.391452+00:00`      | yes         |
| referencing_reviewed id=19       | `referencing_forms WHERE id=19` (reviewed_at)         | `2026-07-12 17:06:22`                   | yes         |
| maintenance_created id=2         | `maintenance_requests WHERE id=2` (created)           | `2026-07-12 17:28:05`                   | yes         |
| message_created id=2             | `message_threads WHERE id=2` (created)                | `2026-07-02 07:36:52`                   | yes         |

## Timestamp source per event type

Every `ts` is a genuine stored column value — none are fabricated, computed, or randomised:

- **tenancy_created** → `tenancies.created` (tz-aware ISO, e.g. `...T17:06:22.391452+00:00`)
- **referencing_submitted** → `referencing_forms.submitted_at` (naive `YYYY-MM-DD HH:MM:SS`)
- **referencing_reviewed** → `referencing_forms.reviewed_at` (naive `YYYY-MM-DD HH:MM:SS`)
- **maintenance_created** → `maintenance_requests.created` (naive `YYYY-MM-DD HH:MM:SS`)
- **message_created** → `message_threads.created` (naive `YYYY-MM-DD HH:MM:SS`)

## Sources excluded for lacking reliable timestamps

Each query includes a `WHERE <date_col> IS NOT NULL` guard, so any row without a
stored timestamp in its source column is silently excluded rather than being given a
fabricated date. No source is padded with placeholder dates. (No additional tables such
as transactions/documents/access are wired into this feed at all.)

## Finding: mixed timestamp formats break true chronological ordering

The feed is genuinely sorted **descending by the raw `ts` string** (verified — the
regression suite asserts this and it passes). However, the two format families sort
differently at the same calendar second because the ISO `T` separator (0x54) sorts
above the space separator (0x20):

- Row 0: `tenancy_created` id 2753 — `2026-07-12T17:06:22.391452+00:00`
- Row 1: `maintenance_created` id 2 — `2026-07-12 17:28:05`

Chronologically the maintenance event (17:28) is **later** than the tenancy event
(17:06) and should appear first, but string sort places the `T`-formatted tenancy row
above it. So the feed is correctly string-sorted but **not** truly chronologically
sorted where tz-aware (`tenancies`) and naive (`maintenance/messages/referencing`)
timestamps interleave on the same day. This is a cosmetic ordering quirk, not
fabricated data. A fix would normalise all timestamps to a single tz-aware format (or
parse to `datetime`) before sorting.

## Conclusion

Every event in the activity feed maps to a real DB record with a genuine stored
timestamp. No random or fabricated dates were found. The only defect is the
string-sort vs chronological-sort discrepancy caused by mixed timestamp formats across
source tables.
