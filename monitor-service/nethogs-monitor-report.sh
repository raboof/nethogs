#!/bin/bash

set -e

# Configuration
NETHOGS_LOG="/var/log/nethogs/nethogs.jsonl"
TEMPLATE_FILE="/opt/nethogs-monitor/nethogs-monitor-dashboard-template.html"
TEMP_DIR=$(mktemp -d)
HOURS_BACK="${1:-24}"
OUTPUT_FILE="${2:-${PWD}/nethogs-dashboard.html}"
MAX_LINES=10000

log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1" >&2
}

cleanup() {
    rm -rf "$TEMP_DIR"
}

trap cleanup EXIT

# Function to extract recent data from JSONL
extract_recent_data() {
    local hours_back=$1
    local output_file="$TEMP_DIR/recent_data.jsonl"

    if [ ! -f "$NETHOGS_LOG" ]; then
        log "Warning: File $NETHOGS_LOG not found"
        echo "[]" > "$output_file"
        return
    fi

    # Calculate timestamp limit
    local time_limit=$(date -d "$hours_back hours ago" +%s)

    # Extract last lines and filter by time
    echo "[" > "$output_file"
    tail -n $MAX_LINES "$NETHOGS_LOG" | while IFS= read -r line; do
        if [ -n "$line" ]; then
            # Extract timestamp and convert to epoch
            local timestamp_iso=$(echo "$line" | jq -r '.timestamp // empty' 2>/dev/null || echo "")
            if [ -n "$timestamp_iso" ]; then
                local timestamp_epoch=$(date -d "$timestamp_iso" +%s 2>/dev/null || echo "0")
                if [ "$timestamp_epoch" -ge "$time_limit" ]; then
                    echo "${line},"
                fi
            fi
        fi
    done >> "$output_file"
    echo "]" >> "$output_file"

    # If no data, create valid empty file
    if [ ! -s "$output_file" ]; then
        echo "[]" > "$output_file"
    fi
}

# Function to generate HTML with embedded data
generate_html() {
    local data_file="$1"
    local output="$2"

    # Verify template exists
    if [ ! -f "$TEMPLATE_FILE" ]; then
        log "Error: Template not found at $TEMPLATE_FILE"
        exit 1
    fi

    # Generate generation timestamp
    local generation_time=$(date -Iseconds)

    # Copy template and replace placeholders
    cp "$TEMPLATE_FILE" "$output"

    #sed -i "s|JSON_DATA_PLACEHOLDER|$json_data|g" "$output"
    sed -i "/JSON_DATA_PLACEHOLDER/{
        r $data_file
        d
    }" "$output"
    sed -i "s|GENERATION_TIME_PLACEHOLDER|$generation_time|g" "$output"
    sed -i "s|HOURS_BACK_PLACEHOLDER|$HOURS_BACK|g" "$output"

    log "Dashboard HTML generated: $output"
}

# Main function
main() {
    log "Starting dashboard generation"
    log "Extracting data from last $HOURS_BACK hours..."

    # Check dependencies
    if ! command -v jq &> /dev/null; then
        log "Error: jq is not installed. Install with: sudo apt install jq"
        exit 1
    fi

    # Extract recent data
    extract_recent_data "$HOURS_BACK"

    # Verify data exists
    local data_file="$TEMP_DIR/recent_data.jsonl"
    local record_count=$(wc -l < "$data_file")
    log "Processing $record_count records"

    # Generate HTML
    log "Generating dashboard HTML..."
    generate_html "$data_file" "$OUTPUT_FILE"

    # Create output directory if it doesn't exist
    mkdir -p "$(dirname "$OUTPUT_FILE")"

    log "Dashboard generated successfully: $OUTPUT_FILE"
    log "File size: $(du -h "$OUTPUT_FILE" | cut -f1)"

    xdg-open "$OUTPUT_FILE"
}

# Show help
if [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
    echo "Usage: $0 [HOURS] [OUTPUT_FILE]"
    echo
    echo "HOURS: Number of hours to look back for data (default: 24)"
    echo "OUTPUT_FILE: Output HTML file (default: ${PWD}/nethogs-dashboard.html)"
    echo
    echo "Examples:"
    echo "  $0                           # Last 24 hours, default output"
    echo "  $0 6                         # Last 6 hours"
    echo "  $0 168 /var/www/html/week.html  # Last week"
    echo
    echo "Dependencies: jq"
    exit 0
fi

# Execute main function
main "$@"