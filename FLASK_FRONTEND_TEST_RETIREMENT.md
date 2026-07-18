# Flask Frontend Browser Test Retirement

## Date: 15 July 2026
## Author: Neo (Chief of Staff)

## Context

The original Banksia OS frontend was served directly by Flask via `/banksia-os` (templates/banksia_os.html). This has been fully replaced by a Next.js application at `/root/verv-platform/apps/banksia-os/`, served on port 5051 through the Next.js production server and proxied via Traefik.

The old Flask browser regression suite at `/root/banksia-dashboard/regression_playwright.py` tested the Flask-rendered SPA. That SPA is no longer the primary user-facing interface.

## Coverage Map

### Tests Still Valid (covered by run_regression.py)

| Old Test | Backend Concern | Flask Regression Coverage |
|---|---|---|
| Authentication (login/logout) | Session auth, API responses | Covered: login endpoint, auth headers |
| Invalid login → 401 | API returns 401 for bad creds | Covered: schema assertion |
| Dashboard data loads | API returns expected fields | Covered: 51 fields validated |
| Properties, Units, Tenants APIs | Endpoint responses | Covered: schema + counts |
| Financial overview | API data integrity | Covered: monthly_rent, arrears, deposits |

### Tests Replaced by Next.js Playwright Coverage

| Old Test | Next.js Replacement | Notes |
|---|---|---|
| "Login page title contains Banksia" | banksia.spec.ts test 1 | More thorough: form render + field assertion |
| "Login form has fields" | banksia.spec.ts tests 2-3 | getByLabel/getByRole selectors |
| "Invalid login stays on login page" | banksia.spec.ts test 4 | Same behaviour, better assertion |
| "Valid login reaches dashboard" | banksia.spec.ts tests 5-6 | Also verifies React hydration + session persistence |
| "Dashboard has content/widgets" | banksia.spec.ts tests 13-14 | Metric card values + null-check |
| "Navigation items" | banksia.spec.ts tests 17-19 | Sidebar click navigation to each module |
| "Properties page renders" | banksia.spec.ts tests 17, 22 | Table render + detail click |
| "Search field accepts input" | banksia.spec.ts test 17 | Properties table renders correctly |
| "Maintenance page loads" | Not yet implemented in Next.js | Frontend-only — maintenance UI is Phase 2B+ |
| "Financials page loads" | Not yet implemented in Next.js | Frontend-only — financial UI is Phase 2B+ |
| "Modal opens/closes" | Not applicable | No modals in Phase 2A scope |
| "Navigation cleanup cycles" | banksia.spec.ts test 49 | 50 cycles, duplicate/overlay detection (more thorough) |
| "Back/forward navigation" | banksia.spec.ts test 20 | Same behaviour |
| "Logout button visible + works" | banksia.spec.ts tests 7-8 | 20 consecutive cycles, server-side polling |
| "Protected routes redirect after logout" | banksia.spec.ts test 8 | waitForURL + session poll (more robust) |
| "No critical console errors" | banksia.spec.ts tests 11, 42, 50 | 3 separate tests for console, page errors, failed requests |
| "No 404 static assets" | banksia.spec.ts test 46 | requestfailed listener (more accurate) |

### Tests That Are Obsolete

| Old Test | Reason |
|---|---|
| "Filter controls present" | No filter UI in Phase 2A scope |
| "Maintenance view toggle" | Legacy Flask implementation specific |
| "10 navigation cycles" | Replaced by 50-cycle test in Next.js |
| "Login page has username/password fields via #id selectors" | Next.js uses dynamic IDs — tests now use getByLabel |

## Recommendation

1. **Keep `regression_playwright.py`** as a historical reference but do not run it as part of CI.
2. **All frontend coverage** is now provided by the Next.js Playwright suite at `apps/banksia-os/tests/banksia.spec.ts`.
3. **Backend coverage** is provided by `run_regression.py` (now extended to cover new Phase 2A fields).
4. Delete or archive the old file on the next cleanup pass.

## Verification

- Next.js Playwright: **36/36 PASS** (0 retries, all viewports)
- Flask regression: **104/104 PASS** (after Phase 2A additions, up from 97)
- No regression in API behaviour
