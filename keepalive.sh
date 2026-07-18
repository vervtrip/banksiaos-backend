#!/bin/bash
# Banksia OS dashboard keep-alive — restarts the Flask app on port 5050 if it's down.
# Uses the hermes venv python (has Flask). Runs from cron every 5 min.
PORT=5050
DIR=/root/banksia-dashboard
PY=/usr/local/lib/hermes-agent/venv/bin/python
LOG=/tmp/banksia_5050.log

if ss -tlnp 2>/dev/null | grep -q ":${PORT} "; then
    exit 0   # already up
fi

cd "$DIR" || exit 1
nohup "$PY" app.py >> "$LOG" 2>&1 &
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) [keepalive] restarted dashboard on ${PORT} (pid $!)" >> "$LOG"
