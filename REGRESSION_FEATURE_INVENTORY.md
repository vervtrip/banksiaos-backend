
BANKSIA OS — FULL FEATURE INVENTORY
====================================

AUTHENTICATION
  - Login: /, POST /api/auth/login
  - Logout: POST /api/auth/logout
  - Password reset: /api/auth/forgot-password, /api/auth/reset-password
  - Session user: /api/auth/user
  - User profile: /api/user/profile, /api/user/update-profile
  - Change password: /api/user/change-password
  - Preferences: /api/user/preferences

DASHBOARD
  - Main SPA: /banksia-os (banksia_os.html, 4599 lines)
  - Dashboard data: GET /api/banksia-os/dashboard (DB-based KPI)
  - Legacy dashboard: /dashboard, GET /api/dashboard/data (Hostaway+Arthur+Monday)
  - Legacy banksia: /banksia (banksia.html, legacy interface)
  - Summary: /api/summary
  - Global search: /api/search (cross-entity)
  - Notifications: /api/notifications, read/clear/delete
  - Connections status: /api/connections/status, /api/connections/status-extended
  - Integration health: /api/integrations/status/extended
  - Daily focus: /api/projects/daily-focus

PROPERTIES
  - List: GET /api/banksia-os/properties (paginated, search, filter)
  - Detail: GET /api/banksia-os/properties/<id>
  - Update: PATCH /api/banksia-os/properties/<id>
  - Enhanced: /api/banksia-os/properties/enhanced
  - Compliance: /api/banksia-os/properties/compliance
  - Property images: CRUD on /api/banksia-os/properties/<id>/images
  - Legacy: /api/properties, /api/properties/<id>
  - Legacy portfolio: /api/banksia/portfolio, /api/banksia/portfolio/stats

UNITS
  - List: GET /api/banksia-os/units
  - Detail: GET /api/banksia-os/units/<id>
  - Update: PATCH /api/banksia-os/units/<id>
  - Create: POST /api/banksia-os/units
  - Available: /api/referencing/units/available
  - Legacy: /api/banksia/units/<id>

TENANCIES
  - List: GET /api/banksia-os/tenancies
  - Detail: GET /api/banksia-os/tenancies/<id>
  - Update: PATCH /api/banksia-os/tenancies/<id>
  - Create: POST /api/banksia-os/tenancies
  - End tenancy: POST /api/banksia-os/tenancies/<id>/end
  - Renew: POST /api/banksia-os/tenancies/<id>/renew
  - Rent review: POST /api/banksia-os/tenancies/<id>/rent-review
  - Section 21: POST /api/banksia-os/tenancies/<id>/section-21
  - Ending soon: /api/banksia-os/tenancies/ending-soon
  - Moving in/out this month: 2 endpoints

TENANTS
  - List: GET /api/banksia-os/tenants
  - Detail: GET /api/banksia-os/tenants/<id>
  - Update: PATCH /api/banksia-os/tenants/<id>
  - Create: POST /api/banksia-os/tenants
  - Legacy: /api/banksia/tenants, /api/hmo/tenants

APPLICANTS
  - List: GET /api/banksia-os/applicants
  - Detail: GET /api/banksia-os/applicants/<id>
  - Update: PATCH /api/banksia-os/applicants/<id>
  - Create: POST /api/banksia-os/applicants
  - Status update: POST /api/banksia-os/applicants/<id>/status

REFERENCING
  - Forms: CRUD on /api/referencing/forms
  - Form by token: /api/referencing/forms/by-token
  - Send link: POST /api/referencing/forms/<id>/send-link
  - Submit: POST /api/referencing/forms/<id>/submit
  - Status: PATCH /api/referencing/forms/<id>/status
  - AI review: POST /api/referencing/forms/<id>/ai-review
  - Document upload: POST /api/referencing/documents/upload
  - Document verify: POST /api/referencing/documents/<id>/verify
  - AI document review: POST /api/referencing/documents/<id>/ai-review
  - Create tenancy from form: POST /api/referencing/tenancies/create-from-form
  - E-signature: create, send, sign, view, audit

MAINTENANCE
  - Jobs: GET/POST /api/banksia-os/maintenance/jobs
  - Job detail: GET/PATCH /api/banksia-os/maintenance/jobs/<id>
  - Orders: GET/POST /api/banksia-os/maintenance/orders
  - Order update: PATCH /api/banksia-os/maintenance/orders/<id>
  - LL Comms: GET/POST /api/banksia-os/maintenance/ll-comms
  - Sync from Monday: POST /api/banksia-os/maintenance/sync-from-monday
  - Push to Monday: POST /api/banksia_os/maintenance/push-to-monday
  - Promote from portal: POST /api/banksia-os/maintenance/promote-from-portal
  - Lookup: GET /api/banksia-os/maintenance/lookup
  - Submissions inbox: GET /api/banksia-os/submissions
  - Legacy: /api/maintenance, /api/banksia/maintenance

FINANCIALS
  - Overview: GET /api/banksia-os/finance/overview
  - Summary: GET /api/finance/summary
  - Transactions: GET /api/banksia-os/finance/transactions
  - Transaction detail: GET /api/banksia-os/finance/transactions/<id>
  - Deposits: GET /api/banksia-os/finance/deposits
  - Rent charges: GET/POST/PATCH /api/banksia-os/finance/rent-charges/<id>
  - Rent schedule: GET /api/banksia-os/finance/rent-schedule/<id>
  - Tenancy summary: GET /api/banksia-os/finance/tenancy-summary/<id>
  - Recalculate: POST /api/banksia-os/finance/recalculate
  - Arrears: GET /api/hmo/arrears
  - Legacy: /api/banksia/finance/portfolio, /api/banksia/finance/tenancies/<id>

ACCESS MANAGEMENT
  - List: GET /api/banksia-os/access
  - Detail: GET /api/banksia-os/access/<id>
  - Create: POST /api/banksia-os/access
  - Update: PUT /api/banksia-os/access/<id>
  - Available: GET /api/banksia-os/access/available

DOCUMENTS
  - Templates: GET/POST/DELETE /api/banksia-os/documents/templates
  - Generate: POST /api/banksia-os/documents/generate
  - Generated list: GET /api/banksia-os/documents/generated
  - Upload: POST /api/banksia-os/documents/upload
  - Uploaded list: GET /api/banksia-os/documents/uploaded
  - Download: GET /api/banksia-os/documents/<type>/<id>/download
  - Delete: DELETE /api/banksia-os/documents/uploaded/<id>

INVOICES
  - List: GET /api/banksia-os/invoices
  - Summary: GET /api/banksia-os/invoices/summary
  - Create: POST /api/banksia-os/invoices
  - Detail: GET /api/banksia-os/invoices/<id>
  - Pay: POST /api/banksia-os/invoices/<id>/pay
  - Cancel: DELETE /api/banksia-os/invoices/<id>

TENANT PORTAL
  - Register: POST /api/referencing/portal/register
  - Login: POST /api/referencing/portal/login
  - Logout: POST /api/referencing/portal/logout
  - Profile: GET /api/referencing/portal/me, POST /api/referencing/portal/profile
  - Rent: GET /api/referencing/portal/rent
  - Maintenance: GET/POST /api/referencing/portal/maintenance
  - Documents: GET /api/referencing/portal/documents
  - Messages: GET /api/referencing/portal/messages
  - Upload document: POST /api/referencing/portal/upload-document

MESSAGING (internal)
  - Threads: CRUD /api/banksia-os/threads
  - Messages: CRUD /api/banksia-os/messages
  - Attachments: POST/GET /api/banksia-os/threads/<id>/attachments
  - Comments: CRUD /api/banksia-os/comments

USER MANAGEMENT
  - List: GET /api/users
  - Create: POST /api/users
  - Update: GET/PATCH /api/users/<username>
  - Delete: DELETE /api/users/<username>
  - Avatar: POST /api/users/<username>/avatar
  - Autocomplete: GET /api/banksia-os/users/autocomplete

COMPANY SETTINGS
  - Get: GET /api/banksia-os/company-settings
  - Update: POST /api/banksia-os/company-settings

TAGS
  - List: GET /api/banksia-os/tags
  - Create: POST /api/banksia-os/tags
  - Update/Delete: PATCH/DELETE /api/banksia-os/tags/<id>

PROPERTY OWNERS
  - List: GET /api/banksia-os/property-owners
  - Create: POST /api/banksia-os/property-owners
  - Detail/Update: GET/PATCH /api/banksia-os/property-owners/<id>

REFERENCING ADMIN (standalone HTML)
  - /banksia-os/referencing (referencing_admin.html, loaded in iframe)

SNAPSHOTS
  - List: GET /api/snapshots
  - Create: POST /api/snapshots
  - Restore: POST /api/snapshots/restore/<hash>

HEALTH
  - /health (DB status + uptime)

KNOWN LIMITATIONS
  - /api/dashboard/data slow (external API calls to Hostaway, Arthur, Monday)
  - /api/finance/summary slow (same external API calls)
  - Legacy banksia.html (333 lines) is an older version of the same SPA
  - .db-shm and .db-wal files cleaned up during this session
  - Some endpoints in banksia_api.py duplicate functionality in banksia_os.py
  - Tenant portal is feature-incomplete (frontend client not in repo)
