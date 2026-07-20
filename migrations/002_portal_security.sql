-- Banksia OS — Portal Security Improvements
-- Migration 002: portal_audit_log table + last_activity on portal_sessions

-- ────────────────────────────────────────────
-- 1. PORTAL AUDIT LOG
-- Tracks login attempts (success/failure), password changes, and account activity.
-- ────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS portal_audit_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         INTEGER REFERENCES portal_users(id) ON DELETE SET NULL,
    email           TEXT NOT NULL,
    event_type      TEXT NOT NULL,   -- login_success, login_failure, password_change, signup, logout
    ip_address      TEXT,
    user_agent      TEXT,
    detail          TEXT,
    created         TEXT DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_portal_audit_log_user ON portal_audit_log(user_id);
CREATE INDEX IF NOT EXISTS idx_portal_audit_log_created ON portal_audit_log(created);
CREATE INDEX IF NOT EXISTS idx_portal_audit_log_event ON portal_audit_log(event_type);

-- ────────────────────────────────────────────
-- 2. PORTAL SESSIONS — add last_activity column
-- ────────────────────────────────────────────
ALTER TABLE portal_sessions ADD COLUMN last_activity TEXT;
ALTER TABLE portal_sessions ADD COLUMN activity_timeout_minutes INTEGER DEFAULT 60;
