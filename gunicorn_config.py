"""
Banksia OS — Hardened Gunicorn Configuration.

Designed for gthread workers behind Traefik.
- 4 workers × 4 threads = 16 concurrent requests handled
- Max 10,000 requests per worker then recycle (prevents memory leaks)
- Graceful timeout of 30s for clean shutdown
- Health check endpoint exempted
"""

import multiprocessing

# ── Worker settings ──
workers = 4                      # Match CPU cores (small VPS)
worker_class = 'gthread'
threads = 4                      # 4 threads per worker = 16 concurrent I/O
worker_connections = 40          # Max simultaneous connections per worker
max_requests = 10000             # Recycle worker after 10K requests
max_requests_jitter = 1000       # +/- random jitter to stagger recycles
timeout = 60                     # Hard request timeout (seconds)
graceful_timeout = 30            # Seconds to wait for worker shutdown
keepalive = 5                    # Connection reuse timeout

# ── Bind ──
bind = '127.0.0.1:5050'

# ── Logging ──
accesslog = '-'
errorlog = '-'
loglevel = 'info'
access_log_format = '%({x-forwarded-for}i)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(D)s'

# ── Process management ──
daemon = False
pidfile = None
umask = 0o007
user = None
group = None

# ── Production hardening ──
limit_request_line = 4096        # Max URL length
limit_request_fields = 100       # Max headers per request
limit_request_field_size = 8190  # Max header size

# ── Resource limits ──
worker_connections = 40
backlog = 2048                   # Connection queue length (helps with traffic spikes)

# ── Security ──
forwarded_allow_ips = '*'        # Trust Traefik (only accessible via 127.0.0.1:5050)
proxy_allow_ips = '*'            # Trust proxied IPs (Traefik handles auth)

# ── Preload app for faster spawn + memory sharing ──
preload_app = True

def on_starting(server):
    """Log startup event."""
    server.log.info("Banksia OS Dashboard starting — %d workers × %d threads",
                    workers, threads)

def when_ready(server):
    server.log.info("Banksia OS Dashboard ready — listening on %s", bind)

def on_exit(server):
    server.log.info("Banksia OS Dashboard shutting down")

def worker_abort(worker):
    worker.log.error("Worker %s aborted — recycling", worker.pid)
