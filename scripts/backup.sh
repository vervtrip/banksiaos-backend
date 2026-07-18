#!/bin/bash
# Banksia OS — Automated Backup
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASE_DIR="/root/banksia-dashboard"
BACKUP_DIR="${BACKUP_DIR:-/root/banksia-backups}"
RETENTION_DAYS="${RETENTION_DAYS:-30}"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
DB_PATH="${BASE_DIR}/banksia_os.db"
DB_BACKUP="${BACKUP_DIR}/banksia_os_${TIMESTAMP}.db"
FILES_BACKUP="${BACKUP_DIR}/banksia_os_files_${TIMESTAMP}.tar.gz"
mkdir -p "${BACKUP_DIR}"
echo "[$(date '+%H:%M:%S')] Starting Banksia OS backup..."
if [ -f "$DB_PATH" ]; then
    sqlite3 "${DB_PATH}" "VACUUM INTO '${DB_BACKUP}'"
    gzip -f "${DB_BACKUP}"
    DB_BACKUP="${DB_BACKUP}.gz"
    DB_SIZE=$(stat --format=%s "${DB_BACKUP}" 2>/dev/null | numfmt --to=iec 2>/dev/null || echo "unknown")
    echo "  ✓ Database: ${DB_BACKUP##*/} (${DB_SIZE})"
else
    echo "  ⚠ No database found at ${DB_PATH}"
fi
tar czf "${FILES_BACKUP}" -C "${BASE_DIR}" users.json .flask_secret_key 2>/dev/null || true
FILES_SIZE=$(stat --format=%s "${FILES_BACKUP}" 2>/dev/null | numfmt --to=iec 2>/dev/null || echo "unknown")
echo "  ✓ Config: ${FILES_BACKUP##*/} (${FILES_SIZE})"
find "${BACKUP_DIR}" -name "banksia_os_*.db*" -mtime "+${RETENTION_DAYS}" -delete 2>/dev/null
find "${BACKUP_DIR}" -name "banksia_os_files_*.tar.gz" -mtime "+${RETENTION_DAYS}" -delete 2>/dev/null
if [ -n "${RCLONE_REMOTE:-}" ]; then
    echo "  → Syncing to cloud: ${RCLONE_REMOTE}"
    rclone copy "${BACKUP_DIR}" "${RCLONE_REMOTE}/$(date +%Y/%m)" --include "banksia_os_${TIMESTAMP}*" --quiet 2>&1 || echo "  ⚠ Cloud sync failed"
fi
echo "[$(date '+%H:%M:%S')] Backup complete — ${BACKUP_DIR}/"
echo "  Retention: ${RETENTION_DAYS} days"
