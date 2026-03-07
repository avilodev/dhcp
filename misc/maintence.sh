#!/bin/bash

# DHCP Server Maintenance Script
# Run this daily via cron to keep the server healthy
# Add to crontab: 0 3 * * * /path/to/dhcp/misc/maintence.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVER_PATH="$(dirname "$SCRIPT_DIR")"
MEMBERS_FILE="$SERVER_PATH/misc/members.txt"
SERVER_LOG="$SERVER_PATH/misc/server.log"
PID_FILE="$SERVER_PATH/misc/server.pid"

LOG_RETENTION_DAYS=30
BACKUP_DIR="$SERVER_PATH/misc/backups"

# Create backup directory if it doesn't exist
mkdir -p "$BACKUP_DIR"

echo "$(date '+%Y-%m-%d %H:%M:%S') - Starting DHCP server maintenance"

# 1. Prune expired leases from members.txt
#
# members.txt is a canonical file: one entry per active device, written on
# DHCPACK and removed on DHCPRELEASE.  Leases that expire without a RELEASE
# are swept from in-memory state by the server but not removed from the file,
# so we clean them here.  Format: device_id mac ip hostname expiry_ts
#
# Note: SIGHUP now triggers a hot-reload of static_list.txt and blacklist.txt,
# NOT a compaction.  Compaction is no longer needed.
if [ -f "$MEMBERS_FILE" ]; then
    echo "Pruning expired leases from members.txt..."
    BACKUP_FILE="$BACKUP_DIR/members.txt.$(date +%Y%m%d)"
    cp "$MEMBERS_FILE" "$BACKUP_FILE"

    NOW=$(date +%s)
    BEFORE=$(wc -l < "$MEMBERS_FILE")
    # Keep lines where field 5 (expiry_ts) exists and is in the future.
    # Malformed lines (fewer than 5 fields) are also dropped.
    awk -v now="$NOW" 'NF>=5 && $5+0 > now {print}' "$MEMBERS_FILE" \
        > "$MEMBERS_FILE.tmp" \
        && mv "$MEMBERS_FILE.tmp" "$MEMBERS_FILE"
    AFTER=$(wc -l < "$MEMBERS_FILE")
    REMOVED=$((BEFORE - AFTER))
    echo "  Removed $REMOVED expired lease entries"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - Pruned $REMOVED expired lease entries" >> "$SERVER_LOG"

    # If the server is running, send SIGHUP to reload static assignments and
    # blacklist in case either file was updated alongside this run.
    if [ -f "$PID_FILE" ]; then
        PID=$(cat "$PID_FILE")
        if ps -p "$PID" > /dev/null 2>&1; then
            kill -HUP "$PID"
            echo "  Sent SIGHUP to server (PID $PID) — reloading static/blacklist"
            echo "$(date '+%Y-%m-%d %H:%M:%S') - Sent SIGHUP for hot-reload" >> "$SERVER_LOG"
        fi
    fi
fi

# 2. Rotate server.log if it's too large (>10MB)
if [ -f "$SERVER_LOG" ]; then
    LOG_SIZE=$(stat -f%z "$SERVER_LOG" 2>/dev/null || stat -c%s "$SERVER_LOG" 2>/dev/null)
    if [ "$LOG_SIZE" -gt 10485760 ]; then
        echo "Rotating server.log (size: $LOG_SIZE bytes)..."
        ROTATE_FILE="$BACKUP_DIR/server.log.$(date +%Y%m%d-%H%M%S)"
        mv "$SERVER_LOG" "$ROTATE_FILE"
        touch "$SERVER_LOG"
        chmod 644 "$SERVER_LOG"
        echo "  Rotated to $ROTATE_FILE"
        echo "$(date '+%Y-%m-%d %H:%M:%S') - Log rotated (size exceeded 10MB)" >> "$SERVER_LOG"
    fi
fi

# 3. Delete old backup files
if [ -d "$BACKUP_DIR" ]; then
    echo "Cleaning old backups (older than $LOG_RETENTION_DAYS days)..."
    find "$BACKUP_DIR" -type f -mtime +$LOG_RETENTION_DAYS -delete
    REMAINING=$(find "$BACKUP_DIR" -type f | wc -l)
    echo "  $REMAINING backup files remaining"
fi

# 4. Check if server is running
if [ -f "$PID_FILE" ]; then
    PID=$(cat "$PID_FILE")
    if ! ps -p "$PID" > /dev/null 2>&1; then
        echo "WARNING: Server PID $PID not running but PID file exists"
        echo "$(date '+%Y-%m-%d %H:%M:%S') - WARNING: Dead PID file detected" >> "$SERVER_LOG"
        rm -f "$PID_FILE"
    else
        echo "Server is running (PID: $PID)"
    fi
else
    echo "WARNING: PID file not found - server may not be running"
fi

# 5. Report statistics
if [ -f "$MEMBERS_FILE" ]; then
    MEMBER_COUNT=$(wc -l < "$MEMBERS_FILE")
    echo "Current active members: $MEMBER_COUNT"
fi

if [ -f "$SERVER_LOG" ]; then
    LOG_SIZE=$(stat -f%z "$SERVER_LOG" 2>/dev/null || stat -c%s "$SERVER_LOG" 2>/dev/null)
    LOG_SIZE_MB=$((LOG_SIZE / 1048576))
    echo "Server log size: ${LOG_SIZE_MB}MB"
    
    # Count today's interactions
    TODAY=$(date +%Y-%m-%d)
    TODAY_COUNT=$(grep -c "^\[$TODAY" "$SERVER_LOG" 2>/dev/null || echo "0")
    echo "Today's interactions: $TODAY_COUNT"
fi

echo "$(date '+%Y-%m-%d %H:%M:%S') - Maintenance completed successfully"
echo "----------------------------------------"