#!/bin/bash
# DHCP Server Maintenance — run daily via cron (installed as dhcp-maintenance).
#
#   1. Archive server.log -> misc/logs/YYYY/MM/DD/server.log, then truncate it
#      (daily rotation, mirroring the DNS server's dns_log).
#      server.log is CSV: timestamp,event,mac,client_id,hostname,ip
#   2. Back up the lease journal (the real database) and the members.txt
#      snapshot (device_id,mac,ip,hostname,expires,node).
#   3. Trim archives/backups past the retention window.
#   4. Health-check the server PID.
#
# Done for the main server (misc/) and every extra instance on this machine
# (misc/instances/<ID>/).
#
# Neither file is pruned here — the server compacts the journal hourly and
# rewrites members.txt from memory whenever a lease changes.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVER_PATH="$(dirname "$SCRIPT_DIR")"
RETENTION_DAYS=30

echo "$(date '+%Y-%m-%d %H:%M:%S') - Starting DHCP maintenance"

# Runs every step for one server's directory: misc/ for the main server, then
# misc/instances/<ID>/ for each extra cluster node on this machine.
maintain() {
    local DIR="$1" LABEL="$2"
    local MEMBERS_FILE="$DIR/members.txt"
    local JOURNAL_FILE="$DIR/leases.journal"
    local SERVER_LOG="$DIR/server.log"
    local PID_FILE="$DIR/server.pid"
    local LOG_ARCHIVE_DIR="$DIR/logs"
    local BACKUP_DIR="$DIR/backups"

    echo " [$LABEL]"
    mkdir -p "$BACKUP_DIR"

    # 1. Archive + truncate server.log (daily) ------------------------------
    if [ -s "$SERVER_LOG" ]; then
        local DEST="$LOG_ARCHIVE_DIR/$(date +%Y)/$(date +%m)/$(date +%d)"
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

    # 2. Back up the journal and the members.txt snapshot ---------------------
    if [ -f "$JOURNAL_FILE" ]; then
        cp "$JOURNAL_FILE" "$BACKUP_DIR/leases.journal.$(date +%Y%m%d)"
        echo "  Backed up leases.journal ($(grep -vc '^#' "$JOURNAL_FILE") records)"
    fi
    if [ -f "$MEMBERS_FILE" ]; then
        cp "$MEMBERS_FILE" "$BACKUP_DIR/members.txt.$(date +%Y%m%d)"
        echo "  Backed up members.txt ($(grep -vc '^#' "$MEMBERS_FILE") entries)"
    fi

    # 3. Trim old archives and backups --------------------------------------
    find "$BACKUP_DIR"      -type f -mtime +$RETENTION_DAYS -delete 2>/dev/null || true
    find "$LOG_ARCHIVE_DIR" -type f -name 'server.log' -mtime +$RETENTION_DAYS -delete 2>/dev/null || true
    find "$LOG_ARCHIVE_DIR" -type d -empty -delete 2>/dev/null || true

    # 4. Health check --------------------------------------------------------
    if [ -f "$PID_FILE" ]; then
        local PID
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

    # 5. Stats ---------------------------------------------------------------
    if [ -f "$SERVER_LOG" ]; then
        local TODAY
        TODAY=$(date +%Y-%m-%d)
        echo "  Today's DHCP events: $(grep -c "^$TODAY" "$SERVER_LOG" 2>/dev/null || true)"
    fi
}

maintain "$SERVER_PATH/misc" "main"
for inst in "$SERVER_PATH"/misc/instances/*/; do
    if [ -f "$inst/dhcp.conf" ]; then
        maintain "${inst%/}" "instance $(basename "$inst")"
    fi
done

echo "$(date '+%Y-%m-%d %H:%M:%S') - Maintenance complete"
echo "----------------------------------------"
