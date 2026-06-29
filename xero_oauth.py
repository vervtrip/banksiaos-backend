#!/usr/bin/env python3
"""Xero OAuth2 integration for Verv Ops Dashboard."""
import os, json, time, base64, hashlib, secrets, urllib.request, urllib.parse

XERO_CLIENT_ID = "230F5D50CD534B1FA8FCEF6532325AF1"
XERO_CLIENT_SECRET = "QbJe7HoB1K01dsF_aovuSaZNfYExlQ7ZeRnnuT5ENlfFETho"
XERO_REDIRECT_URI = "https://www.banksialondon.com"
XERO_AUTH_URL = "https://login.xero.com/identity/connect/authorize"
XERO_TOKEN_URL = "https://identity.xero.com/connect/token"
XERO_CONNECTIONS_URL = "https://api.xero.com/connections"
XERO_API_BASE = "https://api.xero.com/api.xro/2.0"

TOKEN_PATH = "/root/.hermes/state/xero_token.json"
TENANTS_PATH = "/root/.hermes/state/xero_tenants.json"

def generate_pkce():
    """Generate PKCE code verifier and challenge."""
    verifier = secrets.token_urlsafe(64)[:128]
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()
    ).rstrip(b"=").decode()
    return verifier, challenge

def get_auth_url():
    """Generate the authorization URL for Xero OAuth."""
    verifier, challenge = generate_pkce()
    state = secrets.token_hex(16)

    # Store PKCE verifier and state temporarily
    os.makedirs(os.path.dirname(TOKEN_PATH), exist_ok=True)
    pending = {"verifier": verifier, "state": state, "created_at": time.time()}
    with open("/root/.hermes/state/xero_pending.json", "w") as f:
        json.dump(pending, f)

    params = {
        "response_type": "code",
        "client_id": XERO_CLIENT_ID,
        "redirect_uri": XERO_REDIRECT_URI,
        "scope": "openid profile email accounting.transactions accounting.contacts accounting.settings accounting.reports offline_access",
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    return f"{XERO_AUTH_URL}?{urllib.parse.urlencode(params)}"

def exchange_code(code):
    """Exchange authorization code for tokens."""
    pending_path = "/root/.hermes/state/xero_pending.json"
    if not os.path.exists(pending_path):
        return {"error": "No pending auth request. Start a new authorization."}

    with open(pending_path) as f:
        pending = json.load(f)

    verifier = pending.get("verifier", "")

    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": XERO_REDIRECT_URI,
        "client_id": XERO_CLIENT_ID,
        "client_secret": XERO_CLIENT_SECRET,
        "code_verifier": verifier,
    }

    req = urllib.request.Request(
        XERO_TOKEN_URL,
        data=urllib.parse.urlencode(data).encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            tokens = json.loads(r.read())
            tokens["acquired_at"] = time.time()
            with open(TOKEN_PATH, "w") as f:
                json.dump(tokens, f)
            os.remove(pending_path)
            return tokens
    except urllib.error.HTTPError as e:
        return {"error": f"HTTP {e.code}", "body": e.read().decode()[:300]}
    except Exception as e:
        return {"error": str(e)}

def refresh_tokens():
    """Refresh the Xero access token using refresh_token."""
    if not os.path.exists(TOKEN_PATH):
        return None
    with open(TOKEN_PATH) as f:
        tokens = json.load(f)

    refresh = tokens.get("refresh_token")
    if not refresh:
        return None

    data = {
        "grant_type": "refresh_token",
        "refresh_token": refresh,
        "client_id": XERO_CLIENT_ID,
        "client_secret": XERO_CLIENT_SECRET,
    }

    req = urllib.request.Request(
        XERO_TOKEN_URL,
        data=urllib.parse.urlencode(data).encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            tokens = json.loads(r.read())
            tokens["acquired_at"] = time.time()
            with open(TOKEN_PATH, "w") as f:
                json.dump(tokens, f)
            return tokens
    except Exception:
        return None

def get_valid_token():
    """Get a valid access token, refreshing if needed."""
    if not os.path.exists(TOKEN_PATH):
        return None
    with open(TOKEN_PATH) as f:
        tokens = json.load(f)

    # Check if expired (access_token lives 30min, refresh_token lives 60 days)
    acquired = tokens.get("acquired_at", 0)
    expires_in = tokens.get("expires_in", 1800)  # default 30 min
    if time.time() - acquired > expires_in - 60:  # refresh 60s early
        new_tokens = refresh_tokens()
        if new_tokens:
            tokens = new_tokens
        else:
            return None

    return tokens.get("access_token")

def get_connections():
    """Get Xero tenant connections."""
    token = get_valid_token()
    if not token:
        return None

    req = urllib.request.Request(
        XERO_CONNECTIONS_URL,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            tenants = json.loads(r.read())
            with open(TENANTS_PATH, "w") as f:
                json.dump(tenants, f)
            return tenants
    except Exception:
        return None

def xero_api_get(endpoint, tenant_id=None):
    """Call Xero API with proper auth."""
    token = get_valid_token()
    if not token:
        return {"error": "Xero not connected"}

    if not tenant_id:
        tenants = get_connections()
        if not tenants or len(tenants) == 0:
            return {"error": "No Xero tenants connected"}
        tenant_id = tenants[0]["tenantId"]

    headers = {
        "Authorization": f"Bearer {token}",
        "Xero-tenant-id": tenant_id,
        "Accept": "application/json",
    }
    url = f"{XERO_API_BASE}/{endpoint}"

    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        return {"error": f"HTTP {e.code}", "body": e.read().decode()[:300]}
    except Exception as e:
        return {"error": str(e)}

def get_bank_accounts(tenant_id=None):
    """Get bank accounts (uses Accounts endpoint, type=BANK)."""
    result = xero_api_get("Accounts", tenant_id)
    if "error" in result:
        return result
    accounts = result.get("Accounts", [])
    bank_accounts = [a for a in accounts if a.get("Type") == "BANK"]
    return bank_accounts

def get_organisation(tenant_id=None):
    """Get organisation info."""
    return xero_api_get("Organisation", tenant_id)

def is_connected():
    """Check if Xero is connected with valid tokens."""
    token = get_valid_token()
    if not token:
        return False
    tenants = get_connections()
    return tenants is not None and len(tenants) > 0