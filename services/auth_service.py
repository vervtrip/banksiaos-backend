"""
Banksia OS — Authentication service layer.
User management, password hashing, login/logout, role-based access control.
"""
import json, os, hashlib, secrets, re, time, hmac as _hmac
from datetime import datetime, timezone
from flask import Blueprint, jsonify, request, session, current_app

_PBKDF2_ITERATIONS = 210_000  # OWASP-recommended floor for PBKDF2-HMAC-SHA256

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
USERS_FILE = os.path.join(BASE_DIR, "users.json")

# Track login attempts per IP for brute-force protection
_login_attempts: dict[str, list[float]] = {}
MAX_LOGIN_ATTEMPTS = 10
LOGIN_WINDOW = 300  # 5 minutes

# Canonical role set
VALID_ROLES = (
    "super_admin", "admin", "finance", "hmo_manager", "str_manager",
    "maintenance", "lettings", "projects", "viewer",
)

# ── Route-family RBAC policy ──
_FAM_FINANCE = ("/transactions", "/invoices", "/rent", "/deposits", "/finance")
_FAM_PII     = ("/tenants", "/tenancies", "/guarantors")
_FAM_APPS    = ("/applicants", "/submissions")
_FAM_MAINT   = ("/maintenance", "/contractors", "/orders")
_FAM_DOCS    = ("/documents", "/entity-documents")

ROLE_POLICY = {
    "finance":     {"block": _FAM_APPS + _FAM_MAINT,                         "read_only": False},
    "hmo_manager": {"block": _FAM_FINANCE,                                   "read_only": False},
    "str_manager": {"block": _FAM_FINANCE,                                   "read_only": False},
    "maintenance": {"block": _FAM_FINANCE + _FAM_APPS,                       "read_only": False},
    "lettings":    {"block": _FAM_FINANCE + _FAM_PII + _FAM_MAINT + _FAM_DOCS, "read_only": False},
    "projects":    {"block": _FAM_FINANCE + _FAM_PII + _FAM_MAINT + _FAM_DOCS, "read_only": False},
    "viewer":      {"block": _FAM_FINANCE + _FAM_PII + _FAM_APPS + _FAM_MAINT + _FAM_DOCS, "read_only": True},
    "_default":    {"block": _FAM_FINANCE + _FAM_PII + _FAM_APPS + _FAM_MAINT + _FAM_DOCS, "read_only": True},
}


def _hash_password(password: str) -> str:
    """PBKDF2-HMAC-SHA256 with per-password random salt."""
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, _PBKDF2_ITERATIONS)
    return f"pbkdf2${_PBKDF2_ITERATIONS}${salt.hex()}${dk.hex()}"


def _verify_password(password: str, stored: str) -> bool:
    """Verify a password against a PBKDF2 hash."""
    if not stored or not stored.startswith("pbkdf2$"):
        return False
    parts = stored.split("$")
    if len(parts) != 4:
        return False
    _, iterations_hex, salt_hex, hash_hex = parts
    try:
        iterations = int(iterations_hex)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(hash_hex)
    except (ValueError, TypeError):
        return False
    actual = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return _hmac.compare_digest(actual, expected)


def _validate_password_strength(pw: str) -> str | None:
    """Returns an error string if weak, or None if strong enough."""
    if len(pw) < 8:
        return "Password must be at least 8 characters"
    if not re.search(r"[A-Z]", pw):
        return "Password must contain an uppercase letter"
    if not re.search(r"[a-z]", pw):
        return "Password must contain a lowercase letter"
    if not re.search(r"\d", pw):
        return "Password must contain a number"
    return None


def _load_users():
    """Load users from JSON file with validation."""
    try:
        if not os.path.exists(USERS_FILE):
            return {}
        with open(USERS_FILE) as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return {}
        validated = {}
        for k, v in data.items():
            if isinstance(k, str) and isinstance(v, dict):
                validated[k] = v
        return validated
    except (json.JSONDecodeError, OSError):
        return {}


def _save_users(users):
    """Save users to JSON file atomically."""
    tmp = USERS_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(users, f, indent=2)
    os.replace(tmp, USERS_FILE)


def log_auth_event(event_type: str, username: str, details: str = None, ip: str = None):
    """Log an authentication event for audit trail."""
    try:
        from banksia_os_db import get_dict_db
        db = get_dict_db()
        db.execute(
            "INSERT INTO auth_audit_log (event_type, username, details, ip_address, created_at) VALUES (?, ?, ?, ?, ?)",
            [event_type, username, details, ip or "unknown", datetime.now(timezone.utc).isoformat()]
        )
        db.commit()
        db.close()
    except Exception:
        pass  # Audit log table may not exist yet


def ensure_audit_table():
    """Create the auth_audit_log table if it doesn't exist."""
    try:
        from banksia_os_db import get_dict_db
        db = get_dict_db()
        db.execute("""
            CREATE TABLE IF NOT EXISTS auth_audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                username TEXT NOT NULL,
                details TEXT,
                ip_address TEXT,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            )
        """)
        db.execute("CREATE INDEX IF NOT EXISTS idx_auth_audit_username ON auth_audit_log(username)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_auth_audit_created ON auth_audit_log(created_at)")
        db.commit()
        db.close()
        return True
    except Exception as e:
        current_app.logger.error(f"Failed to create auth audit table: {e}")
        return False


def check_rate_limit(ip: str) -> bool:
    """Returns True if the IP is under the rate limit."""
    now = time.time()
    if ip not in _login_attempts:
        _login_attempts[ip] = []
    window_start = now - LOGIN_WINDOW
    _login_attempts[ip] = [t for t in _login_attempts[ip] if t > window_start]
    return len(_login_attempts[ip]) < MAX_LOGIN_ATTEMPTS


def record_login_attempt(ip: str):
    """Record a login attempt for rate limiting."""
    _login_attempts.setdefault(ip, []).append(time.time())


def check_role_access(user, path, method) -> tuple[bool, str | None]:
    """
    Check if a user has role-based access to a path+methd.
    Returns (allowed, error_message).
    """
    role = (user.get("role") or "").lower()
    if role in ("super_admin", "admin"):
        return True, None

    prefix = "/api/banksia-os"
    rel = path[len(prefix):] if path.startswith(prefix) else path or "/"
    policy = ROLE_POLICY.get(role, ROLE_POLICY["_default"])

    if policy["read_only"] and method not in ("GET", "HEAD", "OPTIONS"):
        return False, "Your role has read-only access"

    if rel.startswith(policy["block"]):
        return False, "You do not have permission to access this data"

    # Destructive-action guard — only super_admin may delete core entities
    if method == "DELETE" and role != "super_admin":
        if re.match(r"^/(properties|property-owners|units|tenancies|tenants|applicants)/\d+/?$", rel):
            return False, "Only super admins can permanently delete this record"

    return True, None


# ── Flask routes (registered in app.py) ──

import re as _re
