#!/bin/bash

# Configuration
LOGFILE="/var/log/nethogs/nethogs.jsonl"
PIDFILE="/run/nethogs-monitor.pid"
NETHOGS_BIN="/opt/nethogs-monitor/nethogs"

cleanup() {
    echo "Stopping nethogs monitor..."
    if [ -f "$PIDFILE" ]; then
        rm -f "$PIDFILE"
    fi
    exit 0
}
trap cleanup SIGTERM SIGINT

# Write PID
echo $$ > "$PIDFILE"

# Ensure logfile directory
mkdir -p "$(dirname "$LOGFILE")"

# Main loop
while true; do
    # Execute nethogs
    "$NETHOGS_BIN" -j -v 6 -z -C -d 10 >> "$LOGFILE" 2>&1

    # Si nethogs falla, esperar antes de reintentar
    if [ $? -ne 0 ]; then
        echo "$(date): Error executing nethogs, retrying in 10 seconds ..."
        sleep 10
    fi
done