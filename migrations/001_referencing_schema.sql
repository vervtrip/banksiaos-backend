-- Banksia OS — Referencing, E-Signature & Tenant Portal Schema
-- Phase 1: extends verv_os.db with the full referencing pipeline

-- ────────────────────────────────────────────
-- 1. REFERENCING FORMS
-- Stores submitted applicant referencing data.
-- Maps to Arthur's 13-section applicant form.
-- ────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS referencing_forms (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    applicant_id    INTEGER REFERENCES applicants(id) ON DELETE SET NULL,
    form_token      TEXT UNIQUE NOT NULL,       -- unique URL token for tenant access
    status          TEXT DEFAULT 'draft',        -- draft | submitted | under_review | approved | rejected
    submitted_at    TEXT,
    reviewed_by     TEXT,
    reviewed_at     TEXT,
    review_notes    TEXT,
    internal_notes  TEXT,                        -- team-only notes (not visible to applicant)

    -- Section 1: Personal Details
    title           TEXT,
    first_name      TEXT NOT NULL,
    last_name       TEXT NOT NULL,
    date_of_birth   TEXT,  -- nullable, filled by applicant
    gender          TEXT,

    -- Section 2: Contact Details
    email           TEXT NOT NULL,
    mobile_phone    TEXT,  -- nullable, filled by applicant
    current_address_line1  TEXT,
    current_address_line2  TEXT,
    current_city    TEXT,
    current_postcode TEXT,
    current_country TEXT,
    current_address_length TEXT,  -- how long at current address

    -- Section 3: Residential Status
    id_type         TEXT,                        -- passport | driving_licence | brp | visa
    id_number       TEXT,
    nationality     TEXT,
    country_of_origin TEXT,
    ni_number       TEXT,
    visa_number     TEXT,
    visa_type       TEXT,
    visa_expiry     TEXT,
    share_code      TEXT,                        -- right to rent share code

    -- Section 4: Employment
    employment_status TEXT,                      -- employed | self_employed | student | unemployed | retired
    employer_name   TEXT,
    employer_address TEXT,
    employer_email  TEXT,
    employer_phone  TEXT,
    job_title       TEXT,
    annual_salary   REAL,
    employment_length TEXT,
    employment_contract_type TEXT,               -- permanent | fixed_term | zero_hours

    -- Section 5: Self-Employment
    self_employed_company  TEXT,
    self_employed_utr     TEXT,
    self_employed_address TEXT,
    self_employed_annual_profit REAL,
    self_employed_length  TEXT,
    accountant_name  TEXT,
    accountant_email TEXT,
    accountant_phone TEXT,

    -- Section 6: Student Details
    student_university   TEXT,
    student_course_id    TEXT,
    student_course_name  TEXT,
    student_expected_graduation TEXT,
    student_loan_amount  REAL,
    student_maintenance_loan REAL,

    -- Section 7: Guarantor
    has_guarantor   INTEGER DEFAULT 0,
    guarantor_title TEXT,
    guarantor_first_name TEXT,
    guarantor_last_name  TEXT,
    guarantor_date_of_birth TEXT,
    guarantor_relation   TEXT,
    guarantor_email      TEXT,
    guarantor_phone      TEXT,
    guarantor_mobile     TEXT,
    guarantor_address_line1  TEXT,
    guarantor_address_line2  TEXT,
    guarantor_city       TEXT,
    guarantor_postcode   TEXT,
    guarantor_country    TEXT,
    guarantor_profession TEXT,
    guarantor_employment_status TEXT,
    guarantor_annual_income REAL,
    guarantor_homeowner  INTEGER DEFAULT 0,

    -- Section 8: Housing Benefit
    housing_benefit   INTEGER DEFAULT 0,
    housing_benefit_council TEXT,
    housing_benefit_number  TEXT,

    -- Section 9: Next of Kin
    kin_first_name  TEXT,
    kin_last_name   TEXT,
    kin_relation    TEXT,
    kin_email       TEXT,
    kin_phone       TEXT,
    kin_mobile      TEXT,
    kin_address     TEXT,

    -- Section 10: Bank Details
    bank_name       TEXT,
    bank_account_name TEXT,
    bank_sort_code  TEXT,
    bank_account_number TEXT,

    -- Section 11: Previous Landlord
    previous_landlord_name  TEXT,
    previous_landlord_email TEXT,
    previous_landlord_phone TEXT,
    previous_landlord_address TEXT,
    previous_landlord_reason_for_leaving TEXT,

    -- Section 12: Additional Information
    has_pet         INTEGER DEFAULT 0,
    pet_details     TEXT,
    has_ccj         INTEGER DEFAULT 0,
    ccj_details     TEXT,
    has_iva         INTEGER DEFAULT 0,
    iva_details     TEXT,
    has_bankruptcy  INTEGER DEFAULT 0,
    bankruptcy_details TEXT,
    has_eviction    INTEGER DEFAULT 0,
    eviction_details TEXT,
    smoking_preference TEXT,
    preferred_move_in_date TEXT,
    special_requirements TEXT,

    -- Section 13: Declaration
    declaration_confirmed INTEGER DEFAULT 0,
    declaration_ip_address TEXT,
    declaration_signed_at TEXT,

    -- Metadata
    created         TEXT DEFAULT (datetime('now')),
    modified        TEXT DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_ref_forms_status ON referencing_forms(status);
CREATE INDEX IF NOT EXISTS idx_ref_forms_token ON referencing_forms(form_token);
CREATE INDEX IF NOT EXISTS idx_ref_forms_applicant ON referencing_forms(applicant_id);

-- ────────────────────────────────────────────
-- 2. REFERENCING DOCUMENTS
-- Documents uploaded as part of a referencing application.
-- ────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS referencing_documents (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    form_id         INTEGER NOT NULL REFERENCES referencing_forms(id) ON DELETE CASCADE,
    category        TEXT NOT NULL,               -- passport | visa | right_to_rent | payslip | bank_statement | employment_contract | tenancy_agreement | guarantor_id | student_letter | council_tax | other
    original_filename TEXT NOT NULL,
    stored_filename TEXT NOT NULL,
    file_path       TEXT NOT NULL,
    file_size       INTEGER,
    mime_type       TEXT,
    uploaded_by     TEXT,                        -- 'applicant' | 'team'
    uploaded_at     TEXT DEFAULT (datetime('now')),
    is_verified     INTEGER DEFAULT 0,
    verified_by     TEXT,
    verified_at     TEXT,
    verification_notes TEXT,
    ai_analysis     TEXT,                        -- JSON: Neo's analysis of this document
    ai_verified     INTEGER DEFAULT 0,
    ai_confidence   REAL,
    ai_flagged      INTEGER DEFAULT 0,           -- Neo flagged potential issue
    ai_flag_reason  TEXT
);

CREATE INDEX IF NOT EXISTS idx_ref_docs_form ON referencing_documents(form_id);
CREATE INDEX IF NOT EXISTS idx_ref_docs_category ON referencing_documents(category);
CREATE INDEX IF NOT EXISTS idx_ref_docs_flagged ON referencing_documents(ai_flagged);

-- ────────────────────────────────────────────
-- 3. DOCUMENT ANALYSIS (Neo's AI Review)
-- Stores Neo's automated checks and cross-referencing results.
-- ────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS referencing_checks (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    form_id         INTEGER NOT NULL REFERENCES referencing_forms(id) ON DELETE CASCADE,
    check_type      TEXT NOT NULL,               -- identity_check | income_check | address_check | right_to_rent | guarantor_check | anti_money_laundering | fraud_check
    status          TEXT DEFAULT 'pending',       -- pending | passed | failed | flagged | inconclusive
    checked_at      TEXT,
    details         TEXT,                        -- JSON: full analysis details
    confidence      REAL,
    summary         TEXT,                        -- Human-readable summary for the review team
    created         TEXT DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_ref_checks_form ON referencing_checks(form_id);
CREATE INDEX IF NOT EXISTS idx_ref_checks_type ON referencing_checks(check_type);
CREATE INDEX IF NOT EXISTS idx_ref_checks_status ON referencing_checks(status);

-- ────────────────────────────────────────────
-- 4. E-SIGNATURE REQUESTS
-- Audit trail for in-house e-signature workflow.
-- ────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS esignature_requests (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    form_id         INTEGER REFERENCES referencing_forms(id) ON DELETE SET NULL,
    tenancy_id      INTEGER REFERENCES tenancies(id) ON DELETE SET NULL,
    document_type   TEXT NOT NULL,               -- tenancy_agreement | guarantor_deed | inventory | other
    document_title  TEXT NOT NULL,
    status          TEXT DEFAULT 'draft',        -- draft | sent | viewed | signed | completed | expired | declined
    created_for     TEXT,                        -- signer name
    created_for_email TEXT,                      -- signer email
    signer_token    TEXT UNIQUE NOT NULL,        -- unique signing link token
    sent_at         TEXT,
    viewed_at       TEXT,
    signed_at       TEXT,
    completed_at    TEXT,
    expires_at      TEXT,
    ip_address      TEXT,                        -- signer IP at time of signing
    user_agent      TEXT,                        -- signer browser
    pdf_original_path TEXT,                      -- path to original unsigned PDF
    pdf_signed_path TEXT,                        -- path to stamped/signed PDF
    created_by      TEXT,                        -- team member who created the request
    created         TEXT DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_esign_form ON esignature_requests(form_id);
CREATE INDEX IF NOT EXISTS idx_esign_status ON esignature_requests(status);
CREATE INDEX IF NOT EXISTS idx_esign_token ON esignature_requests(signer_token);

-- ────────────────────────────────────────────
-- 5. E-SIGNATURE AUDIT LOG
-- Immutable audit trail for every signature event.
-- ────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS esignature_audit_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id      INTEGER NOT NULL REFERENCES esignature_requests(id) ON DELETE CASCADE,
    event_type      TEXT NOT NULL,               -- sent | email_opened | viewed | consent_given | signature_drawn | pdf_stamped | completed | expired | declined
    event_detail    TEXT,
    ip_address      TEXT,
    user_agent      TEXT,
    occurred_at     TEXT DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_esign_audit_request ON esignature_audit_log(request_id);
CREATE INDEX IF NOT EXISTS idx_esign_audit_event ON esignature_audit_log(event_type);

-- ────────────────────────────────────────────
-- 6. TENANT PORTAL USERS
-- Login credentials for tenants/applicants to access the portal.
-- ────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS portal_users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    email           TEXT UNIQUE NOT NULL,
    password_hash   TEXT NOT NULL,
    first_name      TEXT NOT NULL,
    last_name       TEXT NOT NULL,
    phone           TEXT,
    applicant_id    INTEGER REFERENCES applicants(id) ON DELETE SET NULL,
    tenant_id       INTEGER REFERENCES tenants(id) ON DELETE SET NULL,
    portal_type     TEXT DEFAULT 'applicant',    -- applicant | tenant | guarantor
    is_active       INTEGER DEFAULT 1,
    email_verified  INTEGER DEFAULT 0,
    email_verified_at TEXT,
    last_login_at   TEXT,
    last_login_ip   TEXT,
    created         TEXT DEFAULT (datetime('now')),
    modified        TEXT DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_portal_users_email ON portal_users(email);
CREATE INDEX IF NOT EXISTS idx_portal_users_applicant ON portal_users(applicant_id);

-- ────────────────────────────────────────────
-- 7. PORTAL SESSIONS
-- Session tracking for tenant portal access.
-- ────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS portal_sessions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         INTEGER NOT NULL REFERENCES portal_users(id) ON DELETE CASCADE,
    session_token   TEXT UNIQUE NOT NULL,
    ip_address      TEXT,
    user_agent      TEXT,
    expires_at      TEXT NOT NULL,
    created         TEXT DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_portal_sessions_token ON portal_sessions(session_token);
CREATE INDEX IF NOT EXISTS idx_portal_sessions_user ON portal_sessions(user_id);

-- ────────────────────────────────────────────
-- 8. REFERENCING FORM SECTIONS
-- Tracks which sections of a form are completed/incomplete.
-- ────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS form_sections (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    form_id         INTEGER NOT NULL REFERENCES referencing_forms(id) ON DELETE CASCADE,
    section_key     TEXT NOT NULL,               -- personal | contact | residential | employment | self_employed | student | guarantor | housing_benefit | kin | bank | landlord | additional | declaration
    is_complete     INTEGER DEFAULT 0,
    completed_at    TEXT,
    UNIQUE(form_id, section_key)
);

CREATE INDEX IF NOT EXISTS idx_form_sections_form ON form_sections(form_id);
