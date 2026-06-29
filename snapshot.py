#!/usr/bin/env python3
"""Dashboard Snapshot Manager — version control for the Verv dashboard.

Usage:
  python3 snapshot.py save [name]    — Take a snapshot with optional name
  python3 snapshot.py list            — List all snapshots
  python3 snapshot.py restore <id>    — Restore to a snapshot by commit hash
  python3 snapshot.py auto            — Auto-snapshot with timestamp
"""
import subprocess, sys, os, json
from datetime import datetime

DASH_DIR = os.path.dirname(os.path.abspath(__file__))

def run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True, cwd=DASH_DIR)

def save_snapshot(name=None):
    # Stage all changes
    run(["git", "add", "-A"])
    # Check if there's anything to commit
    status = run(["git", "status", "--porcelain"])
    if not status.stdout.strip():
        return {"status": "unchanged", "message": "No changes to snapshot."}
    # Commit
    label = name or f"auto-snapshot-{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    result = run(["git", "commit", "-m", f"snapshot: {label}"])
    if result.returncode == 0:
        sha = run(["git", "rev-parse", "HEAD"]).stdout.strip()[:8]
        return {"status": "saved", "label": label, "commit": sha}
    return {"status": "error", "message": result.stderr}

def list_snapshots():
    result = run(["git", "log", "--oneline", "--no-abbrev-commit", "-n", "30"])
    commits = []
    for line in result.stdout.strip().split("\n"):
        if not line.strip():
            continue
        parts = line.split(" ", 1)
        sha = parts[0][:8]
        msg = parts[1] if len(parts) > 1 else ""
        commits.append({"commit": sha, "label": msg.replace("snapshot: ", "")})
    return {"snapshots": commits, "count": len(commits)}

def restore(commit_hash):
    # First save current state as a snapshot for safety
    save_snapshot(f"pre-restore-{commit_hash}")
    # Hard reset to the target commit
    result = run(["git", "reset", "--hard", commit_hash])
    if result.returncode == 0:
        return {"status": "restored", "commit": commit_hash[:8]}
    return {"status": "error", "message": result.stderr}

if __name__ == "__main__":
    action = sys.argv[1] if len(sys.argv) > 1 else "list"
    
    if action == "save":
        name = sys.argv[2] if len(sys.argv) > 2 else None
        result = save_snapshot(name)
    elif action == "list":
        result = list_snapshots()
    elif action == "restore":
        if len(sys.argv) < 3:
            result = {"error": "Commit hash required"}
        else:
            result = restore(sys.argv[2])
    elif action == "auto":
        result = save_snapshot()
    else:
        result = {"error": f"Unknown action: {action}"}
    
    print(json.dumps(result, indent=2))