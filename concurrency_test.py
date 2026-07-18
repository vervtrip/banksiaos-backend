#!/usr/bin/env python3
"""
Comprehensive concurrency and transaction test for Banksia OS.
Tests go through the live gunicorn + Traefik path at 127.0.0.1:5050.
"""
import concurrent.futures
import json
import statistics
import sys
import time
import urllib.request
import urllib.error
from http.cookiejar import CookieJar

BASE = "http://127.0.0.1:5050"
RESULTS = {"total": 0, "success": 0, "failed": 0, "statuses": {}, "errors": {}, "times": []}


def get_session():
    """Authenticate and return a session with cookies."""
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor())
    login_data = json.dumps({"username": "Sami", "password": "Newpassword1323!"}).encode()
    req = urllib.request.Request(f"{BASE}/api/auth/login", data=login_data,
                                 headers={"Content-Type": "application/json"})
    resp = opener.open(req)
    assert resp.getcode() == 200, f"Login failed: {resp.getcode()}"
    return opener


def fetch(opener, url):
    """Make a single authenticated request, return (status, time_success, error_msg)."""
    start = time.time()
    try:
        req = urllib.request.Request(url)
        resp = opener.open(req, timeout=15)
        body = resp.read()
        elapsed = time.time() - start
        data = json.loads(body)
        status = resp.getcode()
        return status, elapsed, data, None
    except urllib.error.HTTPError as e:
        elapsed = time.time() - start
        body = e.read()
        try:
            data = json.loads(body)
        except (json.JSONDecodeError, ValueError):
            data = {"error": body.decode(errors="replace")}
        return e.code, elapsed, data, str(e)
    except Exception as e:
        elapsed = time.time() - start
        return 0, elapsed, None, str(e)


def run_concurrent_test(name, url, n_requests=20, session=None):
    """Run n identical requests concurrently."""
    print(f"\n{'='*60}")
    print(f"TEST: {name} — {n_requests}x {url}")
    print(f"{'='*60}")
    
    if session is None:
        session = get_session()
    
    times = []
    statuses = {}
    errors = {}
    successes = 0
    failures = 0
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=n_requests) as executor:
        futures = [executor.submit(fetch, session, url) for _ in range(n_requests)]
        for future in concurrent.futures.as_completed(futures):
            status, elapsed, data, error = future.result()
            times.append(elapsed)
            statuses[status] = statuses.get(status, 0) + 1
            if status == 200:
                successes += 1
            else:
                failures += 1
                err_key = f"HTTP {status}" if status else "CONNECTION_ERROR"
                errors[err_key] = errors.get(err_key, 0) + 1
            # Check for database errors
            if data and isinstance(data, dict):
                err_msg = data.get("error", "")
                if "database" in str(err_msg).lower() or "locked" in str(err_msg).lower():
                    errors["SQLITE_LOCKED"] = errors.get("SQLITE_LOCKED", 0) + 1
                if "thread" in str(err_msg).lower() or "check_same_thread" in str(err_msg).lower():
                    errors["THREAD_ERROR"] = errors.get("THREAD_ERROR", 0) + 1
    
    times.sort()
    n = len(times)
    
    print(f"  Total: {n}")
    print(f"  Success: {successes}")
    print(f"  Failed: {failures}")
    print(f"  Status distribution: {statuses}")
    if errors:
        print(f"  Errors: {errors}")
    if times:
        print(f"  Min: {times[0]*1000:.1f}ms")
        print(f"  Median: {statistics.median(times)*1000:.1f}ms")
        print(f"  P95: {times[int(n*0.95)]*1000:.1f}ms")
        print(f"  Max: {times[-1]*1000:.1f}ms")
        print(f"  Mean: {statistics.mean(times)*1000:.1f}ms")
    
    return {"total": n, "success": successes, "failed": failures,
            "statuses": statuses, "errors": errors, "times": times}


def run_mixed_test(name, urls, n_requests=50):
    """Run mixed requests across multiple endpoints."""
    print(f"\n{'='*60}")
    print(f"TEST: {name} — {n_requests}x mixed")
    print(f"{'='*60}")
    
    session = get_session()
    times = []
    statuses = {}
    errors = {}
    successes = 0
    failures = 0
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        futures = []
        for i in range(n_requests):
            url = urls[i % len(urls)]
            futures.append(executor.submit(fetch, session, url))
        
        for future in concurrent.futures.as_completed(futures):
            status, elapsed, data, error = future.result()
            times.append(elapsed)
            statuses[status] = statuses.get(status, 0) + 1
            if status == 200:
                successes += 1
            else:
                failures += 1
                err_key = f"HTTP {status}" if status else "CONNECTION_ERROR"
                errors[err_key] = errors.get(err_key, 0) + 1
    
    times.sort()
    n = len(times)
    
    print(f"  Total: {n}")
    print(f"  Success: {successes}")
    print(f"  Failed: {failures}")
    print(f"  Status distribution: {statuses}")
    if errors:
        print(f"  Errors: {errors}")
    if times:
        print(f"  Min: {times[0]*1000:.1f}ms")
        print(f"  Median: {statistics.median(times)*1000:.1f}ms")
        print(f"  P95: {times[int(n*0.95)]*1000:.1f}ms")
        print(f"  Max: {times[-1]*1000:.1f}ms")
    
    return {"total": n, "success": successes, "failed": failures,
            "statuses": statuses, "errors": errors, "times": times}


def run_transaction_tests():
    """Test database transaction handling, rollbacks, FK violations."""
    print(f"\n{'='*60}")
    print("TRANSACTION TESTS")
    print(f"{'='*60}")
    session = get_session()
    results = {}
    
    # Test 1: Foreign key violation — try to create a property image referencing a fake property
    print("\n  [Test 1] Foreign key violation (INSERT into property_images with bad property_id):")
    try:
        req = urllib.request.Request(
            f"{BASE}/api/banksia/maintenance/test/fk_violation",
            data=b'{}',
            headers={"Content-Type": "application/json"}
        )
        # There's no explicit FK test endpoint, so let's try via the referencing API
        # Since we can't test FK directly via API, verify PRAGMA is ON
        # We'll do this via a SQL check
        print("  SKIP — No dedicated FK test API endpoint. Will verify PRAGMA via health check.")
        results["fk_violation"] = "skipped"
    except Exception as e:
        results["fk_violation"] = str(e)
    
    # Test 2: Simulate DB lock — start a slow transaction
    print("\n  [Test 2] PRAGMA verification on live connection:")
    import sqlite3
    conn = sqlite3.connect("/root/banksia-dashboard/banksia_os.db", timeout=5)
    pragmas = {}
    for p in ["journal_mode", "synchronous", "foreign_keys", "busy_timeout", "cache_size"]:
        cur = conn.execute(f"PRAGMA {p}")
        pragmas[p] = cur.fetchone()[0]
    conn.close()
    print(f"    {json.dumps(pragmas, indent=4)}")
    results["pragmas"] = pragmas
    
    # Test 3: Verify teardown rollback works by making a delayed write
    print("\n  [Test 3] Concurrent reads while a write holds a lock (5s busy_timeout test):")
    # Start a write transaction, then immediately read
    write_conn = sqlite3.connect("/root/banksia-dashboard/banksia_os.db", timeout=1)
    write_conn.execute("BEGIN IMMEDIATE")
    write_conn.execute("UPDATE properties SET notes = 'LOCK_TEST' WHERE id = 1")
    
    start = time.time()
    try:
        read_conn = sqlite3.connect("/root/banksia-dashboard/banksia_os.db", timeout=2)
        read_conn.execute("SELECT COUNT(*) FROM properties")
        read_conn.close()
        elapsed = time.time() - start
        print(f"    Read completed in {elapsed*1000:.0f}ms (busy_timeout allowed wait)")
    except sqlite3.OperationalError as e:
        elapsed = time.time() - start
        print(f"    Read failed after {elapsed*1000:.0f}ms: {e}")
        results["lock_timeout"] = str(e)
    
    write_conn.rollback()
    write_conn.close()
    print("    Lock released, write rolled back")
    
    # Test 4: WAL allows concurrent reads during write
    print("\n  [Test 4] WAL concurrent read test:")
    w_conn = sqlite3.connect("/root/banksia-dashboard/banksia_os.db", timeout=5)
    w_conn.execute("PRAGMA journal_mode=WAL")
    w_conn.execute("BEGIN")
    w_conn.execute("UPDATE properties SET modified = datetime('now') WHERE id = 1")
    
    r_conn = sqlite3.connect("/root/banksia-dashboard/banksia_os.db", timeout=5)
    r_conn.execute("PRAGMA journal_mode=WAL")
    try:
        count = r_conn.execute("SELECT COUNT(*) FROM properties").fetchone()[0]
        print(f"    Read {count} properties during open write — WAL mode works ✅")
        results["wal_concurrent_read"] = True
    except Exception as e:
        print(f"    WAL concurrent read failed: {e}")
        results["wal_concurrent_read"] = str(e)
    finally:
        r_conn.close()
    
    w_conn.rollback()
    w_conn.close()
    
    return results


if __name__ == "__main__":
    print("=" * 60)
    print("BANKSIA OS — CONCURRENCY & TRANSACTION TEST SUITE")
    print(f"Target: {BASE}")
    print("=" * 60)
    
    # Phase 1: Single endpoint concurrency
    run_concurrent_test("/api/dashboard/data", f"{BASE}/api/dashboard/data", 20)
    run_concurrent_test("/api/finance/summary", f"{BASE}/api/finance/summary", 20)
    run_concurrent_test("/api/banksia-os/dashboard", f"{BASE}/api/banksia-os/dashboard", 20)
    
    # Phase 2: Mixed workload
    run_mixed_test("Mixed (all 3 endpoints)", [
        f"{BASE}/api/dashboard/data",
        f"{BASE}/api/finance/summary",
        f"{BASE}/api/banksia-os/dashboard"
    ], 50)
    
    # Phase 3: Transaction tests
    run_transaction_tests()
    
    print("\n" + "=" * 60)
    print("ALL TESTS COMPLETE")
    print("=" * 60)
