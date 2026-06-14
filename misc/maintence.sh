#!/bin/bash
# DHCP Server Maintenance — run daily via cron (installed as dhcp-maintenance).
#
#   1. Archive server.log -> misc/logs/YYYY/MM/DD/server.log, then truncate it
#      (daily rotation, mirroring the DNS server's dns_log).
#      server.log is CSV: timestamp,event,mac,client_id,hostname,ip
#   2. Back up the members.txt snapshot (device_id,mac,ip,hostname).
#   3. Trim archives/backups past the retention window.
#   4. Health-check the server PID.
#
# members.txt is NOT pruned here — the running server keeps it a current
# snapshot and rewrites it from the live lease table every hour.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVER_PATH="$(dirname "$SCRIPT_DIR")"
MEMBERS_FILE="$SERVER_PATH/misc/members.txt"
SERVER_LOG="$SERVER_PATH/misc/server.log"
PID_FILE="$SERVER_PATH/misc/server.pid"

LOG_ARCHIVE_DIR="$SERVER_PATH/misc/logs"
BACKUP_DIR="$SERVER_PATH/misc/backups"
RETENTION_DAYS=30

mkdir -p "$BACKUP_DIR"

echo "$(date '+%Y-%m-%d %H:%M:%S') - Starting DHCP maintenance"

# 1. Archive + truncate server.log (daily) ----------------------------------
if [ -s "$SERVER_LOG" ]; then
    DEST="$LOG_ARCHIVE_DIR/$(date +%Y)/$(date +%m)/$(date +%d)"
    mkdir -p "$DEST"
    (
        flock -x -w 60 200 || exit 1
        if [ -s "$SERVER_LOG" ]; then
            cp "$SERVER_LOG" "$DEST/server.log"
            chmod 0644 "$DEST/server.log"
            : > "$SERVER_LOG"
            echo "  Archived server.log -> $DEST/server.log"
        fi
    ) 200>"$SERVER_LOG.lock"
fi

# 2. Back up members.txt snapshot -------------------------------------------
if [ -f "$MEMBERS_FILE" ]; then
    cp "$MEMBERS_FILE" "$BACKUP_DIR/members.txt.$(date +%Y%m%d)"
    echo "  Backed up members.txt ($(wc -l < "$MEMBERS_FILE") active leases)"
fi

# 3. Trim old archives and backups ------------------------------------------
find "$BACKUP_DIR"      -type f -mtime +$RETENTION_DAYS -delete 2>/dev/null || true
find "$LOG_ARCHIVE_DIR" -type f -name 'server.log' -mtime +$RETENTION_DAYS -delete 2>/dev/null || true
find "$LOG_ARCHIVE_DIR" -type d -empty -delete 2>/dev/null || true

# 4. Health check ------------------------------------------------------------
if [ -f "$PID_FILE" ]; then
    PID=$(cat "$PID_FILE")
    if ps -p "$PID" > /dev/null 2>&1; then
        echo "  Server running (PID $PID)"
    else
        echo "  WARNING: stale PID file (PID $PID not running)"
        rm -f "$PID_FILE"
    fi
else
    echo "  WARNING: no PID file — server may be down"
fi

# 5. Stats -------------------------------------------------------------------
if [ -f "$SERVER_LOG" ]; then
    TODAY=$(date +%Y-%m-%d)
    echo "  Today's DHCP events: $(grep -c "^$TODAY" "$SERVER_LOG" 2>/dev/null || echo 0)"
fi

echo "$(date '+%Y-%m-%d %H:%M:%S') - Maintenance complete"
echo "----------------------------------------"
