# Banksia OS → Next.js Frontend Migration Plan

**Status:** Planning v1.0  
**Date:** 2026-07-15  
**Author:** Neo (Chief of Staff / Control)

---

## 1. Executive Summary

Migrate the Banksia OS frontend from a monolithic Flask SPA (4599-line inline HTML/CSS/JS template) to a Turborepo-based Next.js application. The migration preserves the existing Flask backend as the production API. All new frontend code is typed React with Next.js App Router and Tailwind CSS, shared with Sadman's operations platform via common packages.

**Phase 1 scope:** Login, Dashboard, Properties List, Property Detail, Units List — consuming live Flask APIs.

---

## 2. Proposed Monorepo Structure

```
verv-platform/
├── apps/
│   ├── banksia-os/               # Banksia OS frontend (this migration)
│   │   ├── src/
│   │   │   ├── app/              # Next.js App Router pages
│   │   │   │   ├── login/
│   │   │   │   ├── dashboard/
│   │   │   │   ├── properties/
│   │   │   │   │   └── [id]/
│   │   │   │   └── units/
│   │   │   ├── components/       # App-specific components
│   │   │   ├── api/              # API client integration (thin layer)
│   │   │   └── middleware.ts     # Auth middleware
│   │   ├── public/
│   │   ├── next.config.js
│   │   ├── tailwind.config.ts
│   │   └── package.json
│   └── operations-os/            # Sadman's operations platform (placeholder)
│       └── (future)
├── packages/
│   ├── ui/                       # Shared component library
│   │   ├── src/
│   │   │   ├── Button/
│   │   │   ├── Table/
│   │   │   ├── Form/
│   │   │   ├── Filter/
│   │   │   ├── Modal/
│   │   │   ├── Drawer/
│   │   │   ├── Card/
│   │   │   ├── StatusBadge/
│   │   │   ├── Pagination/
│   │   │   ├── LoadingState/
│   │   │   ├── EmptyState/
│   │   │   ├── ErrorState/
│   │   │   ├── Sidebar/
│   │   │   ├── TopBar/
│   │   │   ├── GlobalSearch/
│   │   │   ├── Notifications/
│   │   │   ├── UserMenu/
│   │   │   └── PageHeader/
│   │   └── package.json
│   ├── design-tokens/            # Tailwind config, CSS variables, themes
│   │   ├── src/
│   │   │   ├── tokens.ts
│   │   │   ├── colors.ts
│   │   │   ├── typography.ts
│   │   │   └── spacing.ts
│   │   ├── tailwind-preset.ts    # Shared Tailwind plugin
│   │   └── package.json
│   ├── api-client/               # Typed API client for Flask backend
│   │   ├── src/
│   │   │   ├── client.ts         # Axios/fetch wrapper with cookie auth
│   │   │   ├── endpoints/
│   │   │   │   ├── auth.ts
│   │   │   │   ├── dashboard.ts
│   │   │   │   ├── properties.ts
│   │   │   │   ├── units.ts
│   │   │   │   ├── tenancies.ts
│   │   │   │   ├── tenants.ts
│   │   │   │   ├── maintenance.ts
│   │   │   │   ├── finance.ts
│   │   │   │   └── ... (generated)
│   │   │   └── types.ts
│   │   └── package.json
│   ├── types/                    # Shared TypeScript types
│   │   ├── src/
│   │   │   ├── property.ts
│   │   │   ├── unit.ts
│   │   │   ├── tenancy.ts
│   │   │   ├── tenant.ts
│   │   │   ├── user.ts
│   │   │   ├── maintenance.ts
│   │   │   ├── finance.ts
│   │   │   └── ... (per domain)
│   │   └── package.json
│   ├── auth/                     # Auth utilities
│   │   ├── src/
│   │   │   ├── session.ts
│   │   │   ├── useAuth.ts       # React hook for auth state
│   │   │   └── withAuth.tsx     # HOC / middleware helper
│   │   └── package.json
│   ├── permissions/              # RBAC utilities
│   │   ├── src/
│   │   │   ├── roles.ts
│   │   │   ├── guards.ts
│   │   │   └── usePermissions.ts
│   │   └── package.json
│   └── validation/               # Zod schemas matching Flask validation
│       ├── src/
│       │   ├── property.ts
│       │   ├── unit.ts
│       │   └── common.ts
│       └── package.json
├── turbo.json                    # Turborepo pipeline config
├── package.json                  # Root workspace config
├── tsconfig.base.json            # Shared TypeScript config
├── .eslintrc.js
└── .prettierrc
```

---

## 3. Existing-to-New Route Map

| Flask Route | Current SPA Page | Next.js Route | Phase |
|---|---|---|---|
| `/` | Login page | `/login` | 1 |
| `/banksia-os` | Dashboard | `/dashboard` | 1 |
| `/banksia-os/properties` | Properties list | `/properties` | 1 |
| `/banksia-os/properties/{id}` | Property detail (SPA overlay) | `/properties/[id]` | 1 |
| `/banksia-os/units` | Units list | `/units` | 1 |
| `/banksia-os/tenancies` | Tenancies list | `/tenancies` | 2 |
| `/banksia-os/tenancies/{id}` | Tenancy detail (SPA overlay) | `/tenancies/[id]` | 2 |
| `/banksia-os/tenants` | Tenants list | `/tenants` | 2 |
| `/banksia-os/tenants/{id}` | Tenant detail (SPA overlay) | `/tenants/[id]` | 2 |
| `/banksia-os/applicants` | Applicants list | `/applicants` | 2 |
| `/banksia-os/maintenance` | Maintenance jobs | `/maintenance` | 2 |
| `/banksia-os/finance` | Financial overview | `/finance` | 2 |
| `/banksia-os/maintenance/{id}` | Job detail (SPA overlay) | `/maintenance/[id]` | 3 |
| `/banksia-os/messages` | Messaging | `/messages` | 3 |
| `/banksia-os/documents` | Documents | `/documents` | 3 |
| `/banksia-os/users` | User management | `/users` | 3 |
| `/banksia-os/settings` | Settings / Company | `/settings` | 3 |
| `/banksia-os/access` | Access control | `/access` | 3 |
| `/banksia-os/submissions` | Portal submissions | `/submissions` | 3 |
| `/banksia-os/referencing` | Referencing admin | `/referencing` | 3 |

### Route Component Tree (Phase 1)

```
<AppShell>                              # layout.tsx
  <Sidebar />                           # Shared UI package
  <TopBar>                               # Shared UI package
    <PageTitle />
    <GlobalSearch />                     # Shared UI package
    <Notifications />                    # Shared UI package
    <UserMenu />                         # Shared UI package
  </TopBar>
  <main>
    {children}                          # Page content
  </main>
</AppShell>

/login                                   # page.tsx
  <LoginForm />                          # App-specific
    <Input />
    <Button variant="primary" />
  <ErrorState /> (conditional)

/dashboard                               # page.tsx
  <PageHeader title="Dashboard" />
  <KpiGrid>
    <KpiCard /> (×9)
  </KpiGrid>
  <WidgetGrid>
    <RentCollectionWidget />
    <OccupancyWidget />
    <ScheduleWidget />
  </WidgetGrid>

/properties                              # page.tsx
  <PageHeader title="Properties" />
  <FilterBar />
  <TableView>
    <TableHeader />
    <PropertyRow /> (×N)
    <Pagination />
  </TableView>

/properties/[id]                         # page.tsx
  <PageHeader title={property.name} />
  <PropertyDetailCard>
    <InfoGrid />
    <TenancyList />
    <UnitList />
    <MaintenanceList />
  </PropertyDetailCard>

/units                                   # page.tsx
  <PageHeader title="Units" />
  <FilterBar />
  <TableView>
    <UniTableHeader />
    <UnitRow /> (×N)
    <Pagination />
  </TableView>
```

---

## 4. API Contract Inventory (Phase 1 Endpoints)

### Auth Endpoints (Flask → Next.js proxy)

| Method | Path | Auth | Request | Response | Notes |
|---|---|---|---|---|---|
| POST | `/api/auth/login` | None | `{username: string, password: string}` | `{success: bool, user: {username, role}}` | Session cookie set server-side. Next.js proxy forwards cookie. |
| GET | `/api/auth/user` | Session | — | `{username, role, email, biography}` | Returns current user from session |
| POST | `/api/auth/logout` | Session | — | Redirect to `/` | Clears session |

### Dashboard

| Method | Path | Auth | Query Params | Response Keys | Notes |
|---|---|---|---|---|---|
| GET | `/api/banksia-os/dashboard` | Session | — | `properties, units, tenancies, tenants, applicants, total_rent, monthly_rent_income, arrears, deposits, occupancy_rate, submissions` | Consolidated dashboard KPI data |
| GET | `/api/banksia-os/submissions` | Session | — | `{referencing, maintenance, messages, documents, total}` | Submission counts per category |

### Properties

| Method | Path | Auth | Query Params | Response Keys | Notes |
|---|---|---|---|---|---|
| GET | `/api/banksia-os/properties` | Session | `?search=X&page=N&per_page=N` | `{properties: [{id, name, address_line_1, postcode, property_type, total_units, property_owner_name, status, tags}], total, page, per_page}` | Paginated, searchable |
| GET | `/api/banksia-os/properties/enhanced` | Session | — | `{properties: [{...full + rent_roll, occupancy, health}]}` | Enriched property list with computed fields |
| GET | `/api/banksia-os/properties/{id}` | Session | — | `{id, name, address_line_1, address_line_2, city, county, postcode, ... all property columns}` | Full property detail |
| GET | `/api/banksia-os/properties/{id}/images` | Session | — | `{images: [{url, filename}]}` | Property images list |

### Units

| Method | Path | Auth | Query Params | Response Keys | Notes |
|---|---|---|---|---|---|
| GET | `/api/banksia-os/units` | Session | `?property_id=N&status=X&search=X&page=N` | `{units: [{id, property_id, unit_ref, unit_type, unit_status, unit_vacant, market_rent, deposit_amount, full_address}], total, page}` | Filterable by property & status |
| GET | `/api/banksia-os/units/{id}` | Session | — | Full unit record with all columns | Unit detail |

### Health

| Method | Path | Auth | Response | Notes |
|---|---|---|---|---|
| GET | `/health` | None | `{status, database, uptime_seconds}` | Used by watchdog + monitoring |

---

## 5. Authentication Design

### Architecture

```
                    ┌─────────────────┐
                    │   Next.js App    │
                    │  (port 5051)     │
                    │                  │
  Browser ──POST──► │  /api/auth/login ──POST──► Flask (port 5050)
  Cookie ◄──Set-──► │  ◄──Set-Cookie──◄────── │
                    │                  │
  Browser ──GET──►  │  /dashboard      │
                    │  Check cookie    │
                    │  API call with   │
                    │  cookie ────────►│ GET /api/banksia-os/dashboard
                    │                  │
                    │  SPA renders     │
                    └─────────────────┘
```

### Auth Flow

1. **Login:** Next.js login page calls `POST /api/auth/login` on Flask. The Flask server sets a session cookie (`Set-Cookie`). Next.js does **NOT** inspect or store the cookie — it simply passes the Set-Cookie header through to the browser. The cookie domain must be accessible to both `verv.app` (Next.js) and `verv.internal` (Flask).

2. **Session persistence:** The browser holds the Flask session cookie. All subsequent API calls from Next.js to Flask include the cookie. Next.js `apiClient` is a thin fetch wrapper that forwards cookies without inspecting them.

3. **SSR protection:** Next.js middleware checks for the session cookie on protected routes. If missing, redirect to `/login`. The middleware calls `GET /api/auth/user` on Flask to validate the session before rendering.

4. **Logout:** Calls `POST /api/auth/logout` on Flask, which clears the session and redirects. Next.js then redirects to `/login`.

### CORS Configuration

Flask must be configured with a CORS origin that matches the Next.js staging URL:

```python
# In app.py
from flask_cors import CORS
CORS(app, origins=["https://staging.banksia.verv.app"], supports_credentials=True)
```

---

## 6. Permission Design

### Current RBAC from Flask

| Role | Access Level | Notes |
|---|---|---|
| `super_admin` | Full access | Sami |
| `admin` | Manage operations | Roo, Norbert, Sadman, Tom, Fareeha, Edina, Waleed, Dua, Nahiyan, Saif, Alex, Hafiza, James, Rahat |
| `projects` | Limited read | Rahat (projects board only) |

### TypeScript RBAC Mapping

```typescript
// packages/permissions/src/roles.ts
export type Role = 'super_admin' | 'admin' | 'projects';

export interface Permission {
  action: 'create' | 'read' | 'update' | 'delete';
  resource: 'property' | 'unit' | 'tenancy' | 'tenant' | 'applicant'
           | 'maintenance' | 'finance' | 'user' | 'settings' | 'access'
           | 'messages' | 'documents' | 'referencing';
}

export const ROLE_PERMISSIONS: Record<Role, Permission[]> = {
  super_admin: [/* all permissions on all resources */],
  admin:       [/* all permissions on core ops, no user management */],
  projects:    [/* read permissions on projects board only */],
};
```

### Permission-Aware Navigation

```tsx
// Banksia OS sidebar reads from permissions
const NAV_ITEMS = [
  { path: '/dashboard', label: 'Dashboard', icon: '◆', permission: { action: 'read', resource: '*' } },
  { path: '/properties', label: 'Properties', icon: '◧', permission: { action: 'read', resource: 'property' } },
  { path: '/tenancies', label: 'Tenancies', icon: '≡', permission: { action: 'read', resource: 'tenancy' } },
  { path: '/users', label: 'Users', icon: '⊗', permission: { action: 'read', resource: 'user' }, roles: ['super_admin'] },
  // Items with restricted roles are conditionally rendered
];
```

---

## 7. API Client Design

```typescript
// packages/api-client/src/client.ts
export class BanksiaApiClient {
  private baseUrl: string;
  private fetch: typeof globalThis.fetch;

  constructor(baseUrl: string = process.env.NEXT_PUBLIC_API_URL || 'http://127.0.0.1:5050') {
    this.baseUrl = baseUrl;
    this.fetch = globalThis.fetch;
  }

  private async request<T>(
    method: string,
    path: string,
    body?: unknown,
    params?: Record<string, string>
  ): Promise<T> {
    const url = new URL(`${this.baseUrl}${path}`);
    if (params) Object.entries(params).forEach(([k, v]) => url.searchParams.set(k, v));

    const res = await this.fetch(url.toString(), {
      method,
      headers: { 'Content-Type': 'application/json', ...(body ? { 'X-CSRF-Token': '' } : {}) },
      body: body ? JSON.stringify(body) : undefined,
      credentials: 'include',  // Forward session cookies
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: res.statusText }));
      throw new ApiError(res.status, err.error || 'Unknown error');
    }

    return res.json();
  }

  // Auth
  login = (username: string, password: string) =>
    this.post<LoginResponse>('/api/auth/login', { username, password });
  getUser = () => this.get<User>('/api/auth/user');
  logout = () => this.post<void>('/api/auth/logout');

  // Dashboard
  getDashboard = () => this.get<DashboardData>('/api/banksia-os/dashboard');
  getSubmissions = () => this.get<SubmissionData>('/api/banksia-os/submissions');

  // Properties
  getProperties = (params?: PropertyListParams) =>
    this.get<PropertyListResponse>('/api/banksia-os/properties', params);
  getProperty = (id: number) =>
    this.get<Property>('/api/banksia-os/properties/${id}');
  getPropertyImages = (id: number) =>
    this.get<PropertyImagesResponse>('/api/banksia-os/properties/${id}/images');

  // Units
  getUnits = (params?: UnitListParams) =>
    this.get<UnitListResponse>('/api/banksia-os/units', params);
  getUnit = (id: number) =>
    this.get<Unit>('/api/banksia-os/units/${id}');

  // Generic
  get = <T>(path: string, params?: Record<string, string>) =>
    this.request<T>('GET', path, undefined, params);
  post = <T>(path: string, body?: unknown) =>
    this.request<T>('POST', path, body);
  patch = <T>(path: string, body?: unknown) =>
    this.request<T>('PATCH', path, body);
}
```

---

## 8. Shared-Package Plan with Sadman's Operations Platform

### Package Ownership

| Package | Maintainer | Sadman Alignment |
|---|---|---|
| `@verv/ui` | Neo → Sadman handoff | Design system must match Monday.com-style ops platform |
| `@verv/design-tokens` | Neo → Sadman handoff | Single source of truth for all Verv branding |
| `@verv/api-client` | Neo | Banksia-specific Flask client. Sadman extends for other APIs |
| `@verv/types` | Joint | Core domain types shared across all Verv apps |
| `@verv/auth` | Neo → Sadman handoff | Token/session utilities, can be extended for OAuth |
| `@verv/permissions` | Joint | RBAC hierarchy, role definitions |
| `@verv/validation` | Sadman | Zod schemas matching backend validation |

### Design System Alignment

The `@verv/design-tokens` package exports a Tailwind CSS preset that both `@verv/ui` (shared components) and `apps/banksia-os` use:

```typescript
// packages/design-tokens/tailwind-preset.ts
export default {
  theme: {
    extend: {
      colors: {
        primary: { 50: '...', /* Monday.com-style blue/indigo palette */ },
        sidebar: { bg: '#1e293b', text: '#94a3b8', active: '#fff' },
        surface: { card: '#fff', page: '#f1f5f9' },
      },
      fontFamily: { sans: ['Inter', ...defaultTheme.fontFamily.sans] },
      spacing: { sidebar: '240px' },
    },
  },
};
```

### Component Dependency Graph

```
@verv/design-tokens
  └─ @verv/ui (tailwind-preset.ts)
       ├─ apps/banksia-os
       └─ apps/operations-os

@verv/types
  └─ @verv/api-client
       └─ apps/banksia-os

@verv/auth + @verv/permissions
  └─ apps/banksia-os (via middleware.ts)
```

---

## 9. Deployment Design

### Phase 1 Architecture (Proof of Concept)

```
                    ┌──────────────────────────────────────┐
                    │            Traefik (443)             │
                    │                                      │
                    │  staging.banksia.verv.app ──► 5051   │
                    │  ops.banksia.verv.app  ──────► 5050   │
                    │  banksia.verv.app       ──────► 5050   │
                    └──────────────────────────────────────┘
                                │
                    ┌───────────┴───────────┐
                    │                       │
              ┌─────▼─────┐          ┌──────▼──────┐
              │ Next.js    │          │ Flask       │
              │ (port 5051)│          │ (port 5050) │
              │            │          │             │
              │ Staging    │  API     │ Production  │
              │ frontend   │◄────────►│ API backend │
              │            │ cookies  │ DB, Monday  │
              └────────────┘          └─────────────┘
```

### Traefik Configuration

```yaml
# /docker/traefik/dynamic/banksia-nextjs.yml (staging only)
http:
  routers:
    banksia-staging:
      rule: "Host(`staging.banksia.verv.app`)"
      service: banksia-nextjs
      tls:
        certResolver: letsencrypt
      middlewares:
        - cors-headers

  services:
    banksia-nextjs:
      loadBalancer:
        servers:
          - url: "http://127.0.0.1:5051"

  middlewares:
    cors-headers:
      headers:
        accessControlAllowOrigin: "https://staging.banksia.verv.app"
        accessControlAllowCredentials: "true"
        accessControlAllowMethods: "GET, POST, PUT, PATCH, DELETE, OPTIONS"
        accessControlAllowHeaders: "Content-Type, Authorization"
```

### Next.js Production Build

```bash
# In apps/banksia-os
pnpm build        # Outputs to .next/
pnpm start        # Starts on port 5051
```

The Next.js app runs behind PM2 or systemd. Staging URL will only be accessible to Sami and the dev team during POC.

### Environment Variables (Next.js)

```env
# apps/banksia-os/.env.staging
NEXT_PUBLIC_API_URL=https://ops.banksia.verv.app
NEXT_PUBLIC_APP_NAME=Banksia OS
NEXT_PUBLIC_STAGE=staging
```

---

## 10. Rollback Strategy

### Rollback Plan

1. **No production impact during POC**: The existing Flask frontend on port 5050 remains live and unchanged. All changes are additive (new port, new staging URL).

2. **If staging is broken**: Stop the Next.js dev server. Traefik has NO routing to port 5051 unless explicitly configured, so there is zero blast radius.

3. **If migration is abandoned**: Delete `apps/banksia-os` from the monorepo, remove the Traefik staging config, delete the staging DNS record. Production is untouched.

4. **After production switch (Phase 5+)**: 
   - Keep Flask frontend running on 5050 for 30 days
   - Traefik routes traffic to both, with cookie-based canary
   - If Next.js fails, change Traefik rule to point all traffic back to 5050
   - `git revert <migration-commit>` if necessary

### Git Branch Strategy

```
main (production, Flask SPA unchanged)
  └─ feat/nextjs-migration (active development)
       ├─ feat/poc-phase1  (login + dashboard + properties)
       ├─ feat/poc-phase2  (tenancies + tenants + maintenance)
       └─ feat/poc-phase3  (remaining modules)
```

---

## 11. Migration Risks (Unresolved)

| Risk | Impact | Mitigation |
|---|---|---|
| **Session cookie domain mismatch** | Auth broken if Flask and Next.js are on different domains | Use same parent domain (`verv.app`), or set up auth proxy in Next.js that shares Flask session |
| **CORS preflight latency** | Extra OPTIONS request on every API call | Configure Flask `CORS` with proper `max_age`; use same-origin during staging |
| **Flask session cookie is not HTTP-only** | XSS could steal session | Add `HttpOnly` and `Secure` flags to Flask session config |
| **Next.js SSR hydration mismatch with real-time data** | Dashboard KPIs differ between server and client render | Use `loading.tsx` + client-side fetch; skip SSR for data-heavy pages |
| **Monday.com sync flows via Flask** | Write endpoints (POST/PATCH) need CSRF protection | Flask already uses session-based auth; add CSRF middleware to Next.js for write operations |
| **Permission model is flat (3 roles)** | Future platforms need granular permissions | Design `@verv/permissions` with resource-level granularity from day one, even if Flask only knows 3 roles |
| **Flask API response shapes not versioned** | Breaking API changes break Next.js without warning | Add API version header (`X-API-Version: 1.0`); write Zod validation in `@verv/validation` as contract tests |
| **Traefik routing to Next.js on staging only** | Production URL must still point to Flask | Double-check Traefik rule uses explicit `Host(`staging.verv.app`)` — never a catch-all |
| **No TypeScript generation from Flask routes** | Manual type maintenance overhead | Consider `openapi-generator` or hand-author from `extract_routes.py` output |
| **Sami only has super_admin role** | All Phase 1 users are effectively full-access during POC | Permissions system is designed but won't be tested until Phase 3 |
| **Playwright tests were written for the Flask SPA** | Need separate test suite for Next.js frontend | Phase 1 deliverable includes new Playwright tests against the Next.js app |

---

## 12. Phase 1 Deliverables Checklist

- [ ] Turborepo monorepo scaffolded at `/root/verv-platform/`
- [ ] `packages/design-tokens` with Tailwind preset
- [ ] `packages/types` with core domain types
- [ ] `packages/api-client` with typed Banksia client
- [ ] `packages/auth` with session utilities
- [ ] `packages/permissions` with RBAC mapping
- [ ] `packages/ui` with shared component library (Button, Table, Sidebar, TopBar, etc.)
- [ ] `packages/validation` with Zod schemas for Phase 1
- [ ] `apps/banksia-os` with Next.js App Router
- [ ] Login page with real Flask auth
- [ ] Dashboard page consuming real `/api/banksia-os/dashboard`
- [ ] Properties list page with search and pagination
- [ ] Property detail page with info and relationships
- [ ] Units list page with filters
- [ ] Global shell (Sidebar, TopBar, UserMenu)
- [ ] Next.js middleware auth guard
- [ ] Staging URL configured in Traefik
- [ ] CORS configured in Flask
- [ ] Playwright tests for all Phase 1 pages
- [ ] Data comparison report (Next.js values vs Flask SPA values)
- [ ] Screenshots at desktop, tablet, and mobile widths
- [ ] Rollback procedure verified

---

## 13. Technical Decisions Record

| Decision | Choice | Rationale |
|---|---|---|
| Monorepo tool | Turborepo | Standard for Verv platform; Sadman's team expected to use same |
| Package manager | pnpm | Workspaces built-in, faster than npm/yarn |
| Styling | Tailwind CSS via design-tokens preset | Matches Monday.com-style design; tokens shared across all apps |
| API client | Fetch with `credentials: 'include'` | No need for Axios — fetch is built-in and cookie forwarding works natively |
| Auth | Session cookie passthrough | Flask session is the source of truth; no JWT or token translation needed |
| State management | React Server Components + SWR for client fetches | RSC for initial data, SWR for polling/refetching on client |
| Forms | React Hook Form + Zod | Sadman's team uses same stack |
| Testing | Playwright (matching existing regression pattern) | Consistent with the regression baseline already built |
| Hosting | Same VPS, different port | No additional infrastructure needed for POC |
| Type generation | Manual (auto-generated from `extract_routes.py`) | Python→TS type generation tools not reliable; manual types are more accurate |
