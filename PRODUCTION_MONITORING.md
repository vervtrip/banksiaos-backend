# Production Monitoring — Banksia OS Dashboard

## Health Watchdog

### Retained Watchdog (Authoritative)

| Property | Value |
|----------|-------|
| **Job ID** | `a94d5bf0a39a` |
| **Name** | Verv Dashboard Health Check |
| **Schedule** | Every 3 minutes |
| **Script** | `~/.hermes/scripts/dashboard_health_check.sh` |
| **Threshold** | 3 consecutive failures before restart |
| **Restart action** | `systemctl restart banksia-backend.service` |
| **Log output** | Cron job delivery: `local` (saved to `~/.hermes/cron/output/`) |
| **Fail counter** | `/tmp/verv_dash_failures` (auto-cleared on success or restart) |
| **No-agent mode** | Yes (script-only, no LLM overhead) |

### Behaviour
1. Every 3 minutes, the script checks `http://127.0.0.1:5050/` for HTTP 200.
2. If the check succeeds: the failure counter (`/tmp/verv_dash_failures`) is deleted.
3. If the check fails: the counter increments. On the 3rd consecutive failure, the service is restarted and the counter is cleared.
4. A cooldown of at least 3 more minutes follows (the next 3 checks would need to fail again to trigger another restart).

### Restart Loop Protection
The 3-failure threshold prevents restart loops from transient network blips. A single failed health check will NOT restart the service.

### Disabled Watchdog (Duplicate)

| Property | Value |
|----------|-------|
| **Job ID** | `3610cbffa75d` |
| **Name** | Dashboard Health Watchdog |
| **Schedule** | Every 1 minute |
| **Script** | `~/.hermes/scripts/dashboard_watchdog.sh` |
| **Threshold** | 1 failure → immediate restart |
| **Status** | **PAUSED** (2026-07-14) |

**Reason for disabling:** The 1-minute, single-failure watchdog was aggressive and risked restart cascades during brief network interruptions. The 3-minute, 3-failure threshold watchdog (`a94d5bf0a39a`) is strictly superior for production stability.

**Re-enabling:** To restore the duplicate watchdog, run:
```
hermes cron job run 3610cbffa75d
```
Or via cron resume:
```python
cronjob(action='resume', job_id='3610cbffa75d')
```

**Permanent removal:** To remove entirely:
```python
cronjob(action='remove', job_id='3610cbffa75d')
```

### Manual Health Check
```bash
curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:5050/health
# Expected: 200

systemctl status banksia-backend.service --no-pager -l
```

### Dashboard Restart
```bash
systemctl restart banksia-backend.service
```
Allow 2 seconds for startup, then verify:
```bash
curl -s http://127.0.0.1:5050/health
```
