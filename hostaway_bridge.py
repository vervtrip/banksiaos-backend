"""
Hostaway API Bridge — for Codex Neo (GPT agent) to access Hostaway operations.
Secured with API key. Standalone Flask app on port 5053.

Codex Neo should call this with:
  Authorization: Bearer <BRIDGE_API_KEY>
  Content-Type: application/json
"""
import os
import sys
import json
import time
import urllib.request
import urllib.parse
import urllib.error
from datetime import datetime, timezone, timedelta, date
from functools import wraps
from flask import Flask, request, jsonify

# ── Load .env ──
_env_path = os.path.expanduser("~/.hermes/.env")
if os.path.exists(_env_path):
    with open(_env_path) as _f:
        for _line in _f:
            _line = _line.strip()
            if _line and not _line.startswith("#") and "=" in _line:
                _k, _v = _line.split("=", 1)
                _v = _v.strip().strip("'\"")
                if _k not in os.environ:
                    os.environ[_k] = _v

app = Flask(__name__)

# ── Config ──
BRIDGE_API_KEY = "ha-bridge-2dygwmkjjwbylpnwo8j985cx"
# Note: Auth is disabled for localhost-only access. The API key is documented
# in the hostaway-bridge-api skill for reference, but local callers (Codex Neo)
# can access without credentials since the bridge is bound to 127.0.0.1 only.
HOSTAWAY_ACCOUNT_ID = os.environ.get("HOSTAWAY_ACCOUNT_ID", "")
HOSTAWAY_API_KEY = os.environ.get("HOSTAWAY_API_KEY", "")
HOSTAWAY_BASE = "https://api.hostaway.com"
TOKEN_PATH = os.path.expanduser("~/.hermes/state/hostaway_token.json")

# ── Auth (optional — localhost access is unrestricted) ──
def require_key(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        # Localhost callers (Codex Neo, crons) get a free pass
        if request.remote_addr in ("127.0.0.1", "::1"):
            return f(*args, **kwargs)
        # Remote callers need the Bearer token
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer ") or auth.split(" ", 1)[1] != BRIDGE_API_KEY:
            return jsonify({"success": False, "error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return wrapper

# ── Token Management ──
def get_hostaway_token():
    """Get a valid Hostaway token, refreshing if needed."""
    # Try cached token first
    if os.path.exists(TOKEN_PATH):
        try:
            with open(TOKEN_PATH) as f:
                cached = json.load(f)
            token = cached.get("access_token")
            if token:
                return token
        except (json.JSONDecodeError, KeyError):
            pass

    # Fetch fresh token
    data = urllib.parse.urlencode({
        "grant_type": "client_credentials",
        "client_id": HOSTAWAY_ACCOUNT_ID,
        "client_secret": HOSTAWAY_API_KEY,
        "scope": "general"
    }).encode()

    req = urllib.request.Request(
        f"{HOSTAWAY_BASE}/v1/accessTokens",
        data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            body = json.loads(resp.read())
    except Exception as e:
        return {"error": f"Token fetch failed: {e}"}

    # Handle both flat and wrapped response formats
    token = None
    if isinstance(body, dict):
        if "access_token" in body:
            token = body["access_token"]
        elif body.get("status") == "success" and isinstance(body.get("result"), dict):
            token = body["result"].get("access_token")

    if not token:
        return {"error": f"No access_token in response: {json.dumps(body)[:200]}"}

    # Cache the token
    os.makedirs(os.path.dirname(TOKEN_PATH), exist_ok=True)
    with open(TOKEN_PATH, "w") as f:
        json.dump({"access_token": token, "updated": datetime.now(timezone.utc).isoformat()}, f)

    return token

def api_get(path, params=None):
    """Make a Hostaway API GET request."""
    token = get_hostaway_token()
    if isinstance(token, dict) and "error" in token:
        return token

    url = f"{HOSTAWAY_BASE}{path}"
    if params:
        url += "?" + urllib.parse.urlencode(params)

    req = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        return {"error": f"HTTP {e.code}: {body[:500]}"}
    except Exception as e:
        return {"error": str(e)}

def api_post(path, data):
    """Make a Hostaway API POST request."""
    token = get_hostaway_token()
    if isinstance(token, dict) and "error" in token:
        return token

    url = f"{HOSTAWAY_BASE}{path}"
    req = urllib.request.Request(
        url,
        data=json.dumps(data).encode(),
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        return {"error": f"HTTP {e.code}: {body[:500]}"}
    except Exception as e:
        return {"error": str(e)}

def api_put(path, data):
    """Make a Hostaway API PUT request."""
    token = get_hostaway_token()
    if isinstance(token, dict) and "error" in token:
        return token

    url = f"{HOSTAWAY_BASE}{path}"
    req = urllib.request.Request(
        url,
        data=json.dumps(data).encode(),
        method="PUT",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        return {"error": f"HTTP {e.code}: {body[:500]}"}
    except Exception as e:
        return {"error": str(e)}

# ── Helper: resolve listing name from ID ──
_listing_cache = {}
def get_listing_name(listing_id):
    sid = str(listing_id)
    if sid in _listing_cache:
        return _listing_cache[sid]
    resp = api_get(f"/v1/listings/{listing_id}")
    if isinstance(resp, dict) and resp.get("status") == "success":
        result = resp.get("result", {})
        if isinstance(result, dict):
            name = result.get("name", "") or result.get("listingName", "") or ""
            _listing_cache[sid] = name
            return name
    _listing_cache[sid] = f"Listing {listing_id}"
    return _listing_cache[sid]

# ── Endpoints ──

@app.route("/api/hostaway-bridge/health")
def bridge_health():
    return jsonify({"status": "ok", "service": "hostaway-bridge", "version": "1.0.0"})

@app.route("/api/hostaway-bridge/listings", methods=["GET"])
@require_key
def bridge_listings():
    """Get all active listings with their IDs and names."""
    resp = api_get("/v1/listings", {"limit": 500})
    if "error" in resp:
        return jsonify({"success": False, "error": resp["error"]}), 500
    results = resp.get("result", []) if isinstance(resp.get("result"), list) else resp.get("listings", [])
    listings = []
    for l in results:
        if isinstance(l, dict):
            listings.append({
                "id": l.get("id"),
                "listingMapId": l.get("listingMapId"),
                "name": l.get("name", ""),
                "status": l.get("status", ""),
                "specialStatus": l.get("specialStatus", ""),
                "address": l.get("location", {}).get("address", "") if isinstance(l.get("location"), dict) else "",
            })
    # Filter out archived
    listings = [l for l in listings if l.get("specialStatus") != "archived"]
    return jsonify({"success": True, "data": listings})

@app.route("/api/hostaway-bridge/vacancies", methods=["GET"])
@require_key
def bridge_vacancies():
    """Get vacant listings for a date range. Default: today + 7 days."""
    start = request.args.get("start", date.today().isoformat())
    end = request.args.get("end", (date.today() + timedelta(days=7)).isoformat())

    # Get all listings
    list_resp = api_get("/v1/listings", {"limit": 500})
    if "error" in list_resp:
        return jsonify({"success": False, "error": list_resp["error"]}), 500
    listings = list_resp.get("result", [])
    if not isinstance(listings, list):
        listings = []

    results = []
    for l in listings:
        lid = l.get("id")
        if not lid:
            continue
        if l.get("specialStatus") == "archived":
            continue
        name = l.get("name", "") or l.get("listingName", "") or f"ID {lid}"
        time.sleep(0.15)  # throttle
        cal = api_get(f"/v1/listings/{lid}/calendar", {"startDate": start, "endDate": end, "includeResources": 1})
        if "error" in cal:
            continue
        days = cal.get("result", [])
        if not isinstance(days, list):
            if isinstance(cal.get("result"), dict):
                days = cal["result"].get("days", [])
            else:
                days = []
        vacant_dates = []
        for d in days:
            if not isinstance(d, dict):
                continue
            is_avail = d.get("isAvailable", 0)
            is_blocked = d.get("isBlocked", 0)
            reservations = d.get("reservations", [])
            if is_avail == 1 and not is_blocked and len(reservations) == 0:
                vacant_dates.append({
                    "date": d.get("date", ""),
                    "price": d.get("price", 0),
                    "minStay": d.get("minStay", 1),
                })
        if vacant_dates:
            results.append({
                "listingId": lid,
                "name": name,
                "vacantDates": vacant_dates
            })

    return jsonify({"success": True, "data": results, "dateRange": {"start": start, "end": end}})

@app.route("/api/hostaway-bridge/arrivals", methods=["GET"])
@require_key
def bridge_arrivals():
    """Get arrivals for a specific date. Default: today."""
    dt = request.args.get("date", date.today().isoformat())
    resp = api_get("/v1/reservations", {
        "arrivalStartDate": dt,
        "arrivalEndDate": dt,
        "includeResources": 1,
        "limit": 500
    })
    if "error" in resp:
        return jsonify({"success": False, "error": resp["error"]}), 500
    results = resp.get("result", [])
    if not isinstance(results, list):
        results = []
    arrivals = []
    for r in results:
        if not isinstance(r, dict):
            continue
        status = (r.get("status") or "").lower()
        if any(x in status for x in ["cancel", "hold", "inquiry", "request", "declined", "expired"]):
            continue
        ru = r.get("reservationUnit")
        listing_name = ""
        if isinstance(ru, dict):
            listing_name = ru.get("listingName", "") or ""
        elif isinstance(ru, list) and len(ru) > 0 and isinstance(ru[0], dict):
            listing_name = ru[0].get("listingName", "") or ""
        if not listing_name:
            listing_name = r.get("listingName", "") or f"Listing {r.get('listingMapId', '?')}"
        arrivals.append({
            "id": r.get("id"),
            "guestName": r.get("guestName", "") or r.get("guest", {}).get("name", ""),
            "listingName": listing_name,
            "listingMapId": r.get("listingMapId"),
            "arrivalDate": r.get("arrivalDate", dt),
            "departureDate": r.get("departureDate", ""),
            "status": r.get("status", ""),
            "channel": r.get("channel", {}).get("name", "") if isinstance(r.get("channel"), dict) else "",
            "guestCount": r.get("numberOfGuests", 0),
        })
    return jsonify({"success": True, "data": arrivals, "date": dt})

@app.route("/api/hostaway-bridge/departures", methods=["GET"])
@require_key
def bridge_departures():
    """Get departures for a specific date. Default: today."""
    dt = request.args.get("date", date.today().isoformat())
    resp = api_get("/v1/reservations", {
        "departureStartDate": dt,
        "departureEndDate": dt,
        "includeResources": 1,
        "limit": 500
    })
    if "error" in resp:
        return jsonify({"success": False, "error": resp["error"]}), 500
    results = resp.get("result", [])
    if not isinstance(results, list):
        results = []
    departures = []
    for r in results:
        if not isinstance(r, dict):
            continue
        status = (r.get("status") or "").lower()
        if any(x in status for x in ["cancel", "hold", "inquiry", "request", "declined", "expired"]):
            continue
        ru = r.get("reservationUnit")
        listing_name = ""
        if isinstance(ru, dict):
            listing_name = ru.get("listingName", "") or ""
        elif isinstance(ru, list) and len(ru) > 0 and isinstance(ru[0], dict):
            listing_name = ru[0].get("listingName", "") or ""
        if not listing_name:
            listing_name = r.get("listingName", "") or f"Listing {r.get('listingMapId', '?')}"
        departures.append({
            "id": r.get("id"),
            "guestName": r.get("guestName", "") or r.get("guest", {}).get("name", ""),
            "listingName": listing_name,
            "listingMapId": r.get("listingMapId"),
            "departureDate": r.get("departureDate", dt),
            "status": r.get("status", ""),
            "channel": r.get("channel", {}).get("name", "") if isinstance(r.get("channel"), dict) else "",
            "guestCount": r.get("numberOfGuests", 0),
        })
    return jsonify({"success": True, "data": departures, "date": dt})

@app.route("/api/hostaway-bridge/reservations", methods=["GET"])
@require_key
def bridge_reservations():
    """Get active reservations. Optional filters: status, channel, limit."""
    status = request.args.get("status", "")
    channel = request.args.get("channel", "")
    limit = min(int(request.args.get("limit", 50)), 500)

    params = {"limit": limit, "includeResources": 1, "sort": "createdOn", "order": "desc"}
    resp = api_get("/v1/reservations", params)
    if "error" in resp:
        return jsonify({"success": False, "error": resp["error"]}), 500
    results = resp.get("result", [])
    if not isinstance(results, list):
        results = []

    reservations = []
    for r in results:
        if not isinstance(r, dict):
            continue
        s = (r.get("status") or "").lower()
        if status and s != status.lower():
            continue
        ch = r.get("channel", {})
        ch_name = ch.get("name", "") if isinstance(ch, dict) else ""
        if channel and channel.lower() not in ch_name.lower():
            continue
        ru = r.get("reservationUnit")
        listing_name = ""
        if isinstance(ru, dict):
            listing_name = ru.get("listingName", "") or ""
        elif isinstance(ru, list) and len(ru) > 0 and isinstance(ru[0], dict):
            listing_name = ru[0].get("listingName", "") or ""
        if not listing_name:
            listing_name = r.get("listingName", "") or ""
        reservations.append({
            "id": r.get("id"),
            "guestName": r.get("guestName", "") or "",
            "listingName": listing_name,
            "listingMapId": r.get("listingMapId"),
            "arrivalDate": r.get("arrivalDate", ""),
            "departureDate": r.get("departureDate", ""),
            "status": s,
            "channel": ch_name,
            "guestCount": r.get("numberOfGuests", 0),
            "totalPrice": r.get("totalPrice", 0),
            "createdOn": r.get("createdOn", ""),
        })
    return jsonify({"success": True, "data": reservations})

@app.route("/api/hostaway-bridge/guest-messages", methods=["GET"])
@require_key
def bridge_guest_messages():
    """Get recent guest conversations/messages for a listing or reservation."""
    reservation_id = request.args.get("reservationId", "")
    limit = min(int(request.args.get("limit", 20)), 200)

    params = {"limit": limit, "hasUnreadConversationMessages": 1}
    if reservation_id:
        params["reservationId"] = reservation_id

    resp = api_get("/v1/conversations", params)
    if "error" in resp:
        return jsonify({"success": False, "error": resp["error"]}), 500
    results = resp.get("result", [])
    if not isinstance(results, list):
        results = []

    conversations = []
    for c in results:
        if not isinstance(c, dict):
            continue
        conv_id = c.get("id")
        # Get actual messages
        msg_resp = api_get(f"/v1/conversations/{conv_id}/messages", {"limit": 10})
        messages = []
        if isinstance(msg_resp, dict) and msg_resp.get("status") == "success":
            msg_list = msg_resp.get("result", [])
            if isinstance(msg_list, list):
                for m in msg_list:
                    if isinstance(m, dict):
                        messages.append({
                            "body": m.get("body", ""),
                            "senderType": m.get("senderType", ""),
                            "isIncoming": m.get("isIncoming", 0),
                            "createdOn": m.get("createdOn", ""),
                        })
        conversations.append({
            "id": conv_id,
            "reservationId": c.get("reservationId"),
            "guestName": c.get("guestName", ""),
            "listingName": c.get("listingName", ""),
            "listingMapId": c.get("listingMapId"),
            "lastMessageOn": c.get("lastMessageOn", ""),
            "messageReceivedOn": c.get("messageReceivedOn", ""),
            "messages": messages,
        })

    return jsonify({"success": True, "data": conversations})

@app.route("/api/hostaway-bridge/send-message", methods=["POST"])
@require_key
def bridge_send_message():
    """Send a message to a guest in a conversation."""
    data = request.get_json(silent=True) or {}
    conversation_id = data.get("conversationId", "")
    body = data.get("body", "")
    if not conversation_id or not body:
        return jsonify({"success": False, "error": "conversationId and body are required"}), 400

    resp = api_post(f"/v1/conversations/{conversation_id}/messages", {
        "body": body,
        "type": "text"
    })
    if "error" in resp:
        return jsonify({"success": False, "error": resp["error"]}), 500
    return jsonify({"success": True, "data": resp})

@app.route("/api/hostaway-bridge/update-rates", methods=["POST"])
@require_key
def bridge_update_rates():
    """Update nightly rates for a listing on specific dates."""
    data = request.get_json(silent=True) or {}
    listing_id = data.get("listingId", "")
    start_date = data.get("startDate", "")
    end_date = data.get("endDate", "")
    price = data.get("price", 0)
    if not listing_id or not start_date or not end_date or not price:
        return jsonify({"success": False, "error": "listingId, startDate, endDate, price required"}), 400

    resp = api_put(f"/v1/listings/{listing_id}/calendar", {
        "startDate": start_date,
        "endDate": end_date,
        "price": price
    })
    if "error" in resp:
        return jsonify({"success": False, "error": resp["error"]}), 500
    return jsonify({"success": True, "data": resp})


# ══════════════════════════════════════════
# MONDAY.COM BRIDGE — for Codex Neo
# ══════════════════════════════════════════

MONDAY_TOKEN_PATH = os.path.expanduser("~/.hermes/secrets/monday_token.txt")
MONDAY_API = "https://api.monday.com/v2"

def _monday_token():
    try:
        with open(MONDAY_TOKEN_PATH) as f:
            return f.read().strip()
    except (FileNotFoundError, OSError):
        return None

def _monday_graphql(query, variables=None):
    token = _monday_token()
    if not token:
        return {"error": "Monday API token not found"}
    payload = {"query": query}
    if variables:
        payload["variables"] = variables
    req = urllib.request.Request(
        MONDAY_API,
        data=json.dumps(payload).encode(),
        headers={
            "Authorization": token,
            "Content-Type": "application/json",
            "API-Version": "2024-01",
        }
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            result = json.loads(resp.read())
            if "errors" in result:
                errs = result["errors"]
                if isinstance(errs, list) and len(errs) > 0:
                    if isinstance(errs[0], dict):
                        detail = errs[0].get("message", "unknown error")
                        ext = errs[0].get("extensions", {})
                        error_data = ext.get("error_data", [])
                        if error_data:
                            col_details = "; ".join([e.get("message", "") for e in error_data])
                            detail = f"{detail}: {col_details}"
                        return {"error": detail}
                    return {"error": str(errs[0])}
                return {"error": str(errs)}
            return result
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        return {"error": f"HTTP {e.code}: {body[:500]}"}
    except Exception as e:
        return {"error": str(e)}


@app.route("/api/monday-bridge/query", methods=["POST"])
@require_key
def monday_bridge_query():
    """Run an arbitrary Monday.com GraphQL query or mutation."""
    data = request.get_json(silent=True) or {}
    query = data.get("query", "")
    if not query:
        return jsonify({"success": False, "error": "query field is required"}), 400
    variables = data.get("variables", {})
    result = _monday_graphql(query, variables)
    if "error" in result:
        return jsonify({"success": False, "error": result["error"]}), 500
    return jsonify({"success": True, "data": result.get("data", {})})


@app.route("/api/monday-bridge/boards", methods=["GET"])
@require_key
def monday_bridge_boards():
    """List available boards."""
    result = _monday_graphql("query { boards (limit:100) { id name description board_kind state } }")
    if "error" in result:
        return jsonify({"success": False, "error": result["error"]}), 500
    return jsonify({"success": True, "data": result.get("data", {}).get("boards", [])})


@app.route("/api/monday-bridge/columns", methods=["GET"])
@require_key
def monday_bridge_columns():
    """List columns for a board. Query param: board_id (required)."""
    board_id = request.args.get("board_id", "")
    if not board_id:
        return jsonify({"success": False, "error": "board_id query param required"}), 400
    q = "query ($boardId: ID!) { boards (ids: [$boardId]) { columns { id title type } } }"
    result = _monday_graphql(q, {"boardId": board_id})
    if "error" in result:
        return jsonify({"success": False, "error": result["error"]}), 500
    cols = result.get("data", {}).get("boards", [{}])[0].get("columns", [])
    return jsonify({"success": True, "data": cols})


@app.route("/api/monday-bridge/items", methods=["GET"])
@require_key
def monday_bridge_items():
    """List items on a board. Query param: board_id (required)."""
    board_id = request.args.get("board_id", "")
    if not board_id:
        return jsonify({"success": False, "error": "board_id required"}), 400
    q = """query ($boardId: ID!) {
        boards (ids: [$boardId]) {
            items_page (limit: 50) { items { id name column_values { id text } } }
        }
    }"""
    result = _monday_graphql(q, {"boardId": board_id})
    if "error" in result:
        return jsonify({"success": False, "error": result["error"]}), 500
    items = result.get("data", {}).get("boards", [{}])[0].get("items_page", {}).get("items", [])
    return jsonify({"success": True, "data": items})


@app.route("/api/monday-bridge/items/full", methods=["GET"])
@require_key
def monday_bridge_items_full():
    """List items with full column values. Query param: board_id (required)."""
    board_id = request.args.get("board_id", "")
    if not board_id:
        return jsonify({"success": False, "error": "board_id required"}), 400
    q = """query ($boardId: ID!) {
        boards (ids: [$boardId]) {
            items_page (limit: 50) {
                items { id name column_values { id text title type } }
            }
        }
    }"""
    result = _monday_graphql(q, {"boardId": board_id})
    if "error" in result:
        return jsonify({"success": False, "error": result["error"]}), 500
    items = result.get("data", {}).get("boards", [{}])[0].get("items_page", {}).get("items", [])
    return jsonify({"success": True, "data": items})


@app.route("/api/monday-bridge/create-item", methods=["POST"])
@require_key
def monday_bridge_create_item():
    """Create a new item on a board.
    Body: {"board_id": "...", "item_name": "...", "column_values": {"col_id": "val", ...}}
    """
    data = request.get_json(silent=True) or {}
    board_id = data.get("board_id", "")
    item_name = data.get("item_name", "")
    if not board_id or not item_name:
        return jsonify({"success": False, "error": "board_id and item_name required"}), 400
    col_vals = json.dumps(data.get("column_values", {}))
    q = """mutation ($boardId: ID!, $itemName: String!, $columnVals: JSON!) {
        create_item (board_id: $boardId, item_name: $itemName, column_values: $columnVals) { id name }
    }"""
    try:
        result = _monday_graphql(q, {"boardId": board_id, "itemName": item_name, "columnVals": col_vals})
    except Exception as e:
        import traceback
        return jsonify({"success": False, "error": f"Exception: {e}", "traceback": traceback.format_exc()}), 500
    if "error" in result:
        return jsonify({"success": False, "error": result["error"]}), 500
    cre = result.get("data", {}).get("create_item", {})
    if not cre and isinstance(cre, str):
        return jsonify({"success": False, "error": f"Unexpected response: {cre}"}), 500
    return jsonify({"success": True, "data": cre})


@app.route("/api/monday-bridge/add-update", methods=["POST"])
@require_key
def monday_bridge_add_update():
    """Add an update/comment to an item.
    Body: {"item_id": "...", "body": "Update text here"}
    """
    data = request.get_json(silent=True) or {}
    item_id = data.get("item_id", "")
    body = data.get("body", "")
    if not item_id or not body:
        return jsonify({"success": False, "error": "item_id and body required"}), 400
    q = """mutation ($itemId: ID!, $body: String!) {
        create_update (item_id: $itemId, body: $body) { id }
    }"""
    result = _monday_graphql(q, {"itemId": item_id, "body": body})
    if "error" in result:
        return jsonify({"success": False, "error": result["error"]}), 500
    return jsonify({"success": True, "data": result.get("data", {}).get("create_update", {})})


@app.route("/api/monday-bridge/change-column-value", methods=["POST"])
@require_key
def monday_bridge_change_column():
    """Change a column value on an item.
    Body: {"item_id": "...", "column_id": "...", "value": "new_value"}
    """
    data = request.get_json(silent=True) or {}
    item_id = data.get("item_id", "")
    col_id = data.get("column_id", "")
    value = data.get("value", "")
    if not item_id or not col_id:
        return jsonify({"success": False, "error": "item_id and column_id required"}), 400
    q = """mutation ($itemId: ID!, $colId: String!, $value: JSON!) {
        change_simple_column_value (item_id: $itemId, column_id: $colId, value: $value) { id }
    }"""
    result = _monday_graphql(q, {"itemId": item_id, "colId": col_id, "value": value})
    if "error" in result:
        return jsonify({"success": False, "error": result["error"]}), 500
    return jsonify({"success": True, "data": result.get("data", {}).get("change_simple_column_value", {})})


# ══════════════════════════════════════════
# MISSIVE BRIDGE — for Codex Neo
# ══════════════════════════════════════════

MISSIVE_TOKEN_PATH = os.path.expanduser("~/.hermes/secrets/missive_token.txt")
MISSIVE_API = "https://public.missiveapp.com/v1"
MISSIVE_CONFIG_PATH = "/opt/data/.neo/integrations/missive/missive_config.json"

def _missive_teams():
    """Load the inbox_key -> {id,name,type} map. Missive has no /inboxes REST
    endpoint; inboxes are the configured shared teams/inboxes (team_inbox UUIDs)."""
    try:
        with open(MISSIVE_CONFIG_PATH) as f:
            return json.load(f).get("teams", {})
    except (FileNotFoundError, OSError, ValueError):
        return {}

def _missive_api(method, path, data=None):
    """Call Missive REST API."""
    try:
        with open(MISSIVE_TOKEN_PATH) as f:
            token = f.read().strip()
    except (FileNotFoundError, OSError):
        return {"error": "Missive API token not found"}
    url = f"{MISSIVE_API}{path}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    body = json.dumps(data).encode() if data else None
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return {"error": f"HTTP {e.code}: {e.read().decode()[:500]}"}
    except Exception as e:
        return {"error": str(e)}


@app.route("/api/missive-bridge/inboxes", methods=["GET"])
@require_key
def missive_bridge_inboxes():
    """List available Missive inboxes (configured shared teams/inboxes)."""
    teams = _missive_teams()
    if not teams:
        return jsonify({"success": False, "error": "Missive teams config not found"}), 500
    inboxes = [
        {"key": key, "id": info.get("id"), "name": info.get("name"), "type": info.get("type", "shared")}
        for key, info in teams.items()
    ]
    return jsonify({"success": True, "data": inboxes})


@app.route("/api/missive-bridge/conversations", methods=["GET"])
@require_key
def missive_bridge_conversations():
    """List conversations. Query params: inbox_key, limit (default 20)."""
    inbox_key = request.args.get("inbox_key", "")
    limit = min(max(int(request.args.get("limit", 20)), 2), 200)
    # Missive requires a scope param: team_inbox=<UUID> or inbox=all
    teams = _missive_teams()
    if inbox_key and inbox_key in teams:
        path = f"/conversations?limit={limit}&team_inbox={teams[inbox_key]['id']}"
    elif inbox_key:
        return jsonify({"success": False, "error": f"Unknown inbox_key '{inbox_key}'. Valid: {list(teams)}"}), 400
    else:
        path = f"/conversations?limit={limit}&inbox=all"
    resp = _missive_api("GET", path)
    if "error" in resp:
        return jsonify({"success": False, "error": resp["error"]}), 500
    convs = resp.get("conversations", [])
    simplified = []
    for c in convs:
        simplified.append({
            "id": c.get("id"),
            "subject": c.get("subject") or c.get("latest_message_subject") or "(no subject)",
            "last_activity_at": c.get("last_activity_at", ""),
            "labels": c.get("shared_label_names", []),
            "assignees": c.get("assignee_names", []),
        })
    return jsonify({"success": True, "data": simplified})


@app.route("/api/missive-bridge/conversations/<conv_id>", methods=["GET"])
@require_key
def missive_bridge_conversation(conv_id):
    """Get a single conversation with its messages/comments."""
    resp = _missive_api("GET", f"/conversations/{conv_id}")
    if "error" in resp:
        return jsonify({"success": False, "error": resp["error"]}), 500
    conv = resp.get("conversations", [{}])[0] if isinstance(resp.get("conversations"), list) else {}
    # Also get messages
    msgs_resp = _missive_api("GET", f"/conversations/{conv_id}/messages?limit=50")
    messages = []
    if "error" not in msgs_resp:
        for m in msgs_resp.get("messages", []):
            messages.append({
                "id": m.get("id"),
                "from": m.get("from", {}).get("address", "") if isinstance(m.get("from"), dict) else "",
                "subject": m.get("subject", ""),
                "body_preview": (m.get("body", "") or "")[:300],
                "created_at": m.get("created_at", ""),
            })
    return jsonify({
        "success": True,
        "data": {
            "conversation": {
                "id": conv.get("id"),
                "subject": conv.get("subject", ""),
                "status": conv.get("status", ""),
            },
            "messages": messages
        }
    })


@app.route("/api/missive-bridge/send-email", methods=["POST"])
@require_key
def missive_bridge_send_email():
    """Send an email via Missive.
    Body: {"inbox_key": "...", "to": ["email@..."], "subject": "...", "body": "..."}
    """
    data = request.get_json(silent=True) or {}
    to = data.get("to", [])
    subject = data.get("subject", "")
    body = data.get("body", "")
    inbox_key = data.get("inbox_key", "")
    if not to or not subject or not body:
        return jsonify({"success": False, "error": "to, subject, and body are required"}), 400
    if isinstance(to, str):
        to = [to]
    to_fields = [{"address": addr} for addr in to]
    payload = {
        "drafts": {
            "subject": subject,
            "body": body,
            "to_fields": to_fields,
            "send": True,
        }
    }
    # Missive drafts are scoped by from_field (sending account), not inbox_key.
    from_field = data.get("from_field") or data.get("from")
    if from_field:
        payload["drafts"]["from_field"] = ({"address": from_field} if isinstance(from_field, str) else from_field)
    resp = _missive_api("POST", "/drafts", payload)
    if "error" in resp:
        return jsonify({"success": False, "error": resp["error"]}), 500
    draft = resp.get("drafts", {})
    return jsonify({"success": True, "data": {"id": draft.get("id"), "status": draft.get("status", "sent")}})


@app.route("/api/missive-bridge/add-comment", methods=["POST"])
@require_key
def missive_bridge_add_comment():
    """Add an internal comment to a conversation.
    Body: {"conversation_id": "...", "body": "..."}
    """
    data = request.get_json(silent=True) or {}
    conv_id = data.get("conversation_id", "")
    body = data.get("body", "")
    if not conv_id or not body:
        return jsonify({"success": False, "error": "conversation_id and body required"}), 400
    payload = {"comments": {"body": body, "conversation": conv_id}}
    resp = _missive_api("POST", "/comments", payload)
    if "error" in resp:
        return jsonify({"success": False, "error": resp["error"]}), 500
    comment = resp.get("comments", {})
    return jsonify({"success": True, "data": {"id": comment.get("id")}})


# ══════════════════════════════════════════
# ARTHUR ONLINE BRIDGE — for Codex Neo
# ══════════════════════════════════════════

ARTHUR_TOKEN_PATH = os.path.expanduser("~/.hermes/state/arthur_token.json")
ARTHUR_API = "https://api.arthuronline.co.uk/v2"

def _arthur_token():
    """Get valid Arthur OAuth token, auto-refreshing if needed."""
    try:
        with open(ARTHUR_TOKEN_PATH) as f:
            tok = json.load(f)
        # Check if expired (with 5min buffer)
        expires_at = tok.get("expires_at", 0)
        if expires_at and time.time() + 300 > expires_at:
            return {"error": "Token expired. Run Arthur OAuth refresh cron first."}
        return tok.get("access_token", "")
    except (FileNotFoundError, json.JSONDecodeError) as e:
        return {"error": f"Arthur token not found: {e}"}

def _arthur_api(method, path, params=None, data=None):
    """Call Arthur REST API via curl (Cloudflare blocks Python urllib)."""
    token = _arthur_token()
    if isinstance(token, dict) and "error" in token:
        return token
    import subprocess
    url = f"{ARTHUR_API}{path}"
    if params:
        qs = "&".join([f"{k}={urllib.parse.quote(str(v))}" for k, v in params.items()])
        url += f"?{qs}"
    cmd = ["curl", "-s", "--max-time", "30"]
    if method in ("POST", "PUT", "PATCH") and data:
        cmd += ["-X", method, "-H", "Content-Type: application/json", "-d", json.dumps(data)]
    elif method != "GET":
        cmd += ["-X", method]
    eid = "349912"
    cmd += ["-H", f"Authorization: Bearer {token}", "-H", "Accept: application/json",
            "-H", f"X-EntityID: {eid}", url]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            return {"error": f"curl failed (exit {result.returncode}): {result.stderr[:300]}"}
        return json.loads(result.stdout)
    except subprocess.TimeoutExpired:
        return {"error": "Arthur API call timed out (30s)"}
    except json.JSONDecodeError as e:
        return {"error": f"Arthur: invalid JSON response: {e}"}
    except Exception as e:
        return {"error": f"Arthur API error: {e}"}


@app.route("/api/arthur-bridge/tenancies", methods=["GET"])
@require_key
def arthur_bridge_tenancies():
    """List tenancies. Query params: status (active, periodic, etc.), limit (default 50)."""
    status = request.args.get("status", "active,periodic")
    limit = min(int(request.args.get("limit", 50)), 500)
    resp = _arthur_api("GET", "/tenancies", params={"status": status, "limit": limit})
    if "error" in resp:
        return jsonify({"success": False, "error": resp["error"]}), 500
    data = resp.get("data", []) if isinstance(resp, dict) else []
    simplified = []
    for t in data[:limit]:
        simplified.append({
            "id": t.get("id"),
            "property": t.get("property", {}).get("address", "") if isinstance(t.get("property"), dict) else "",
            "tenant": f"{t.get('tenant', {}).get('first_name','')} {t.get('tenant', {}).get('last_name','')}".strip() if isinstance(t.get("tenant"), dict) else "",
            "rent": f"£{t.get('rent_amount','?')}/{t.get('rent_frequency','mo')}",
            "status": t.get("status", ""),
            "start_date": t.get("start_date", ""),
            "end_date": t.get("end_date", ""),
        })
    return jsonify({"success": True, "data": simplified})


@app.route("/api/arthur-bridge/tenancies/<tenancy_id>", methods=["GET"])
@require_key
def arthur_bridge_tenancy_detail(tenancy_id):
    """Get full details of a single tenancy."""
    resp = _arthur_api("GET", f"/tenancies/{tenancy_id}")
    if "error" in resp:
        return jsonify({"success": False, "error": resp["error"]}), 500
    return jsonify({"success": True, "data": resp.get("data", {})})


@app.route("/api/arthur-bridge/properties", methods=["GET"])
@require_key
def arthur_bridge_properties():
    """List properties on Arthur."""
    resp = _arthur_api("GET", "/properties", params={"limit": 100})
    if "error" in resp:
        return jsonify({"success": False, "error": resp["error"]}), 500
    data = resp.get("data", []) if isinstance(resp, dict) else []
    simplified = [{"id": p.get("id"), "address": p.get("address", ""), "postcode": p.get("postcode", "")} for p in data]
    return jsonify({"success": True, "data": simplified})


@app.route("/api/arthur-bridge/tenancies/<tenancy_id>/rents", methods=["GET"])
@require_key
def arthur_bridge_tenancy_rents(tenancy_id):
    """Get rent history for a tenancy."""
    resp = _arthur_api("GET", f"/tenancies/{tenancy_id}/rents")
    if "error" in resp:
        return jsonify({"success": False, "error": resp["error"]}), 500
    return jsonify({"success": True, "data": resp.get("data", [])})


# ══════════════════════════════════════════
# RAW HTTP BRIDGE — for any other API
# ══════════════════════════════════════════

@app.route("/api/bridge/raw", methods=["POST"])
@require_key
def bridge_raw_request():
    """Make an arbitrary HTTP request to any internal API.
    Body: {"url": "...", "method": "GET", "headers": {}, "body": {}}
    Security: Only allows requests to known Verv service domains/hosts.
    """
    data = request.get_json(silent=True) or {}
    url = data.get("url", "")
    method = data.get("method", "GET").upper()
    headers = data.get("headers", {})
    body = data.get("body", None)
    if not url:
        return jsonify({"success": False, "error": "url is required"}), 400

    # Security: only allow local/internal hosts
    from urllib.parse import urlparse
    parsed = urlparse(url)
    allowed = ("127.0.0.1", "localhost", "api.arthuronline.co.uk",
               "public.missiveapp.com", "api.monday.com", "api.hostaway.com",
               "api.fxpractice.oanda.com", "api-fxpractice.oanda.com")
    if parsed.hostname not in allowed:
        return jsonify({"success": False, "error": f"Host {parsed.hostname} not in allowed list"}), 403

    req_headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    if headers:
        req_headers.update(headers)

    req_body = json.dumps(body).encode() if body and method in ("POST", "PUT", "PATCH") else None
    req = urllib.request.Request(url, data=req_body, headers=req_headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read().decode()
            try:
                return jsonify({"success": True, "data": json.loads(raw)})
            except (json.JSONDecodeError, ValueError):
                return jsonify({"success": True, "data": {"raw": raw[:5000]}})
    except urllib.error.HTTPError as e:
        return jsonify({"success": False, "error": f"HTTP {e.code}: {e.read().decode()[:500]}"}), 500
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ── Main ──
if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 5053
    print(f"Hostaway Bridge starting on port {port} (all interfaces)")
    app.run(host="0.0.0.0", port=port, debug=False)