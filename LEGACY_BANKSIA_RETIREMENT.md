# Legacy `/banksia` Interface — Retirement Plan

## Current Status

The `/banksia` route (app.py:418-422) renders `templates/banksia.html` through the
`banksia_os_page()` function. The `/banksia-os` route (app.py:425-434) renders
`templates/banksia_os.html` through `banksia_os_dashboard()`.

**Both are currently active with `@require_auth` decorators.**

## Key Differences

| Aspect | `/banksia` (legacy) | `/banksia-os` (current) |
|--------|---------------------|------------------------|
| Template | `banksia.html` (333 lines) | `banksia_os.html` (>2200 lines) |
| API backend | `banksia_api.py` blueprint (`/api/banksia/...`) | `banksia_os.py` blueprint (`/api/banksia-os/...`) |
| API endpoints | ~8 endpoints (dashboard, portfolio, properties, units, tenancies, tenants, finance, landlords, attention) | ~40+ endpoints covering all modules |
| Frontend pattern | Single inline JS, `api('/api/banksia/...')` | `api('/...')` with `banksia-os/` prefix |
| Dashboard/Root data | `banksia_api.py:dashboard()` queries old structure | `banksia_os.py:dashboard_data()` uses current structure |
| Feature coverage | Properties, Units, Tenancies, Tenants, Finance (limited) | Full: Properties, Units, Tenants, Tenancies, Applicants, Referencing, Maintenance, Financials, Access, Messaging, Documents, Invoices, Settings |

## Caller Analysis

1. **Direct browser navigation** — Any user with the old `/banksia` bookmark can reach it
2. **`/banksia` route handler** — Defined in `app.py:418-422`, renders the legacy template
3. **No known external links** — No evidence of `/banksia` links from any other service
4. **`banksia_api.py` blueprint** — Registered in `app.py:72` as `from banksia_api import banksia; app.register_blueprint(banksia)`
5. **No cron jobs or external integrations** reference `/banksia` endpoints
6. **The legacy `banksia.html` template** has 16 `fetch()` calls all hitting `/api/banksia/*` endpoints

## Retirement Decision

### Option A — Retire Immediately ✅ (RECOMMENDED)

**Evidence:** The `/banksia-os` route covers all features of `/banksia` with a superset.
The legacy interface provides no unique functionality.

**Plan:**
1. Add HTTP 301 redirect from `/banksia` to `/banksia-os` (preserving query params)
2. Keep `banksia_api.py` blueprint registered but mark as deprecated for 30 days
3. After 30 days: remove the `/banksia` route, unregister `banksia_api.py`, archive `banksia.html` and `banksia_api.py`
4. Add regression test confirming `/banksia` → `/banksia-os` redirect works

**Risk:** Low. The new interface has all features, and no automated systems call the old endpoints.

### Risks of NOT retiring
- Two active SPAs with different API backends creates confusion
- Bug fixes must be applied in both `banksia.html` and `banksia_os.html`
- New features added to new SPA never appear on old one
- Developer overhead maintaining parallel routes

## Migration Steps

1. `app.py:418-422`: Replace `@require_auth` + `render_template("banksia.html")` with:
```python
@app.route("/banksia")
@app.route("/banksia/<path:subpath>")
def banksia_legacy_redirect(subpath=""):
    qs = request.query_string.decode() if request.query_string else ""
    target = f"/banksia-os/{subpath}" if subpath else "/banksia-os"
    if qs:
        target += f"?{qs}"
    return redirect(target, code=301)
```

2. Add regression test: `assert req(AUTH, "/banksia")[0] == 301`

3. After 30 days of no errors: remove `banksia_api.py` blueprint, `banksia.html`, and legacy template.

4. Document removal in the project README.
