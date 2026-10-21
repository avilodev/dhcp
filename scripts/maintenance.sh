#!/bin/bash
# DHCP Server Maintenance — run daily via cron (installed as dhcp-maintenance).
#
#   1. Archive server.log -> etc/logs/YYYY/MM/DD/server.log (daily rotation,
#      mirroring the DNS server's dns_log).
#      server.log is CSV: timestamp,event,mac,client_id,hostname,ip
#   2. Back up the lease journal (the real database) and the members.txt
#      snapshot (device_id,mac,ip,hostname,expires,node).
#   3. Trim archives/backups past the retention window.
#   4. Health-check the server PID.
#
# Done for the main server (etc/) and every extra instance on this machine
# (etc/instances/<ID>/).
#
# Neither file is pruned here — the server compacts the journal hourly and
# rewrites members.txt from memory whenever a lease changes.
#
# No `set -e`: one failed step (or one broken instance) shouldn't skip the
# rest — each step reports its own failure instead.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVER_PATH="$(dirname "$SCRIPT_DIR")"
SERVER_BIN="$(readlink -f "$SERVER_PATH/bin/dhcp_server")"
RETENTION_DAYS=30

echo "$(date '+%Y-%m-%d %H:%M:%S') - Starting DHCP maintenance"

# Is $1 the PID of a running dhcp_server?  `ps -p` alone isn't enough: PIDs
# repeat almost exactly from boot to boot, so a stale pid file can name an
# unrelated process.
is_server_pid() {
    local pid="$1" exe
    case "$pid" in ''|*[!0-9]*) return 1 ;; esac
    if exe="$(readlink "/proc/$pid/exe" 2>/dev/null)"; then
        [ "${exe% (deleted)}" = "$SERVER_BIN" ]    # "(deleted)" after a rebuild
    else
        # A server that dropped root can't be inspected that way, even by its
        # own user — go by its process name
        [ "$(cat "/proc/$pid/comm" 2>/dev/null)" = dhcp_server ]
    fi
}

# Runs every step for one server's directory: etc/ for the main server, then
# etc/instances/<ID>/ for each extra cluster node on this machine.
maintain() {
    local DIR="$1" LABEL="$2"
    local MEMBERS_FILE="$DIR/members.txt"
    local JOURNAL_FILE="$DIR/leases.journal"
    local SERVER_LOG="$DIR/server.log"
    local PID_FILE="$DIR/server.pid"
    local LOG_ARCHIVE_DIR="$DIR/logs"
    local BACKUP_DIR="$DIR/backups"
    local STAMP
    STAMP=$(date +%Y%m%d)

    echo " [$LABEL]"
    mkdir -p "$BACKUP_DIR" || echo "  ERROR: cannot create $BACKUP_DIR"

    # 1. Archive server.log (daily) -----------------------------------------
    # mv, not cp + truncate: the server opens server.log afresh for every line
    # it writes, so after the rename its next line starts a new file and
    # nothing written in between is lost.  If today's archive already exists
    # (a second run today), the new chunk is appended to it, not overwritten.
    if [ -s "$SERVER_LOG" ]; then
        local DEST CHUNK
        DEST="$LOG_ARCHIVE_DIR/$(date +%Y)/$(date +%m)/$(date +%d)"
        CHUNK="$DEST/server.log.$$"
        if mkdir -p "$DEST" && mv "$SERVER_LOG" "$CHUNK"; then
            echo "  DHCP events since last rotation: $(grep -c ',DHCP[A-Z]*,' "$CHUNK")"
            if [ -e "$DEST/server.log" ]; then
                cat "$CHUNK" >> "$DEST/server.log" && rm -f "$CHUNK"
            else
                mv "$CHUNK" "$DEST/server.log"
            fi
            chmod 0644 "$DEST/server.log"
            echo "  Archived server.log -> $DEST/server.log"
        else
            echo "  ERROR: could not archive $SERVER_LOG to $DEST"
        fi
    fi

    # 2. Back up the journal and the members.txt snapshot ---------------------
    if [ -f "$JOURNAL_FILE" ]; then
        if cp "$JOURNAL_FILE" "$BACKUP_DIR/leases.journal.$STAMP"; then
            echo "  Backed up leases.journal ($(grep -vc '^#' "$JOURNAL_FILE") records)"
        else
            echo "  ERROR: could not back up $JOURNAL_FILE"
        fi
    fi
    if [ -f "$MEMBERS_FILE" ]; then
        if cp "$MEMBERS_FILE" "$BACKUP_DIR/members.txt.$STAMP"; then
            echo "  Backed up members.txt ($(grep -vc '^#' "$MEMBERS_FILE") entries)"
        else
            echo "  ERROR: could not back up $MEMBERS_FILE"
        fi
    fi

    # 3. Trim old archives and backups --------------------------------------
    find "$BACKUP_DIR"      -type f -mtime +$RETENTION_DAYS -delete 2>/dev/null
    find "$LOG_ARCHIVE_DIR" -type f -name 'server.log' -mtime +$RETENTION_DAYS -delete 2>/dev/null
    find "$LOG_ARCHIVE_DIR" -mindepth 1 -type d -empty -delete 2>/dev/null

    # 4. Health check --------------------------------------------------------
    # Report only — scripts/dhcp-startup (every 5 minutes) restarts a
    # dead server, and a stale PID file is harmless (the server locks it).
    if [ -f "$PID_FILE" ]; then
        local PID
        PID=$(cat "$PID_FILE")
        if is_server_pid "$PID"; then
            echo "  Server running (PID $PID)"
        else
            echo "  WARNING: server not running (stale PID file names $PID)"
        fi
    else
        echo "  WARNING: no PID file — server may be down"
    fi
}

maintain "$SERVER_PATH/etc" "main"
for inst in "$SERVER_PATH"/etc/instances/*/; do
    if [ -f "$inst/dhcp.conf" ]; then
        maintain "${inst%/}" "instance $(basename "$inst")"
    fi
done

echo "$(date '+%Y-%m-%d %H:%M:%S') - Maintenance complete"
echo "----------------------------------------"
