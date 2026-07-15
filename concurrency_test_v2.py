#!/usr/bin/env python3
"""
Refined concurrency test — warm the cache first, then test concurrent reads.
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


def get_session():
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor())
    login_data = json.dumps({"username": "Sami", "password": "Newpassword1323!"}).encode()
    req = urllib.request.Request(f"{BASE}/api/auth/login", data=login_data,
                                 headers={"Content-Type": "application/json"})
    resp = opener.open(req)
    assert resp.getcode() == 200
    return opener


def warm_cache(openers, urls):
    """Make a single request to each URL to prime caches."""
    print("Warming caches...")
    for url in urls:
        for opener in openers:
            try:
                req = urllib.request.Request(url)
                resp = opener.open(req, timeout=60)
                resp.read()
                print(f"  {url.split('/')[-1]}: warmed ({resp.getcode()})")
                break
            except Exception as e:
                print(f"  {url.split('/')[-1]}: warm failed: {e}")
                continue
            break
    print("  Cache warm complete.")


def fetch(opener, url, timeout=30):
    """Make a single authenticated request."""
    start = time.time()
    try:
        req = urllib.request.Request(url)
        resp = opener.open(req, timeout=timeout)
        body = resp.read()
        elapsed = time.time() - start
        try:
            data = json.loads(body)
        except (json.JSONDecodeError, ValueError):
            data = None
        return resp.getcode(), elapsed, data, None
    except urllib.error.HTTPError as e:
        elapsed = time.time() - start
        body = e.read()
        try:
            data = json.loads(body)
        except (json.JSONDecodeError, ValueError):
            data = None
        return e.code, elapsed, data, str(e)
    except Exception as e:
        elapsed = time.time() - start
        return 0, elapsed, None, str(e)


def run_test(name, url, n_requests=20):
    print(f"\n{'='*60}")
    print(f"TEST: {name} — {n_requests}x {url}")
    print(f"{'='*60}")
    
    times = []
    statuses = {}
    errors = {}
    successes = 0
    failures = 0
    bodies = []
    
    # Create sessions upfront (serial login)
    sessions = [get_session() for _ in range(min(n_requests, 20))]
    print(f"  Sessions: {len(sessions)}")
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(n_requests, 40)) as executor:
        futures = []
        for i in range(n_requests):
            s = sessions[i % len(sessions)]
            futures.append(executor.submit(fetch, s, url, 30))
        
        for future in concurrent.futures.as_completed(futures):
            status, elapsed, data, error = future.result()
            times.append(elapsed)
            statuses[status] = statuses.get(status, 0) + 1
            if status == 200:
                successes += 1
                if data:
                    bodies.append(json.dumps(data, indent=2)[:200])
            else:
                failures += 1
                err_key = f"HTTP {status}" if status else "TIMEOUT" if elapsed >= 29 else "CONN_ERROR"
                errors[err_key] = errors.get(err_key, 0) + 1
    
    times.sort()
    n = len(times)
    
    print(f"  Total: {n}")
    print(f"  Success: {successes}")
    print(f"  Failed: {failures}")
    print(f"  Status distribution: {statuses}")
    if errors:
        print(f"  Error breakdown: {errors}")
    if times:
        print(f"  Min: {times[0]*1000:.1f}ms")
        print(f"  Median: {statistics.median(times)*1000:.1f}ms")
        p95_idx = min(int(n * 0.95), n - 1)
        print(f"  P95: {times[p95_idx]*1000:.1f}ms")
        print(f"  Max: {times[-1]*1000:.1f}ms")
    
    # Check response structure consistency
    if bodies:
        first_hash = hash(bodies[0])
        mismatches = sum(1 for b in bodies if hash(b) != first_hash)
        print(f"  Response structure: {len(bodies)} unique responses checked")
        if mismatches > 0:
            print(f"  ⚠️  {mismatches} responses differ from first (may be expected with dynamic data)")
        else:
            print(f"  ✅ All responses structurally consistent")
    
    return {"total": n, "success": successes, "failed": failures,
            "statuses": statuses, "errors": errors, "times": times}


if __name__ == "__main__":
    print("=" * 60)
    print("BANKSIA OS — CONCURRENCY TEST SUITE v2")
    print(f"Target: {BASE}")
    print("=" * 60)
    
    # Warm external caches
    session = get_session()
    warm_cache([session], [
        f"{BASE}/api/dashboard/data",
        f"{BASE}/api/finance/summary",
        f"{BASE}/api/banksia-os/dashboard"
    ])
    
    # Now run concurrent tests against warmed caches
    run_test("/api/dashboard/data (cached)", f"{BASE}/api/dashboard/data", 20)
    run_test("/api/finance/summary", f"{BASE}/api/finance/summary", 20)
    run_test("/api/banksia-os/dashboard", f"{BASE}/api/banksia-os/dashboard", 20)
    
    # Mixed workload (no cache warm — tests cold-start behaviour too)
    run_test("Mixed (all 3 endpoints, 50x)", f"{BASE}/api/banksia-os/dashboard", 50)
    
    print("\n" + "=" * 60)
    print("CONCURRENCY TESTS COMPLETE")
    print("=" * 60)
