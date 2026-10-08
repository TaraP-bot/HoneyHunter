#!/usr/bin/env bash
# Fetch defanged CSV exports from the droplet into exports/YYYY-MM-DD/.
# Run on your PC (WSL) with the SSH key loaded and "ssh honeypot" working.
#
#   bash export.sh [hours]       default: the last 24 hours
#
# Files: logins.csv, ips.csv, dns.csv (that window) and samples.csv (all
# captured samples). The folder sits beside the repo: ../../exports.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
HOURS=${1:-24}
OUT="$HERE/../../exports/$(date +%F)"
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)

fetch() {  # remote command, output name
    local tmp="$OUT/.$2.csv.tmp"
    # Defang on this machine before anything is written; only complete
    # files replace the final name
    ssh -o BatchMode=yes honeypot "$1" | python3 "$HERE/defang_csv.py" > "$tmp"
    mv "$tmp" "$OUT/$2.csv"
    echo "  $2.csv: $(($(wc -l < "$OUT/$2.csv") - 1)) rows"
}

echo "Exporting the last $HOURS hours to $OUT"
for kind in logins ips dns; do
    fetch "cd /opt/honeypot && set -a && . ./.env && set +a && python3 es_export.py $kind --hours $HOURS" "$kind"
done
fetch "docker exec honeypot python analyze_telemetry.py ./honeypot_data --samples-csv" samples
