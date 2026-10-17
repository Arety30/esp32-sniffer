#!/usr/bin/env bash
# Start the ESP32 packet-monitor web dashboard.
# Runs as root so it can read the laptop's own traffic (SNI + flow rates).
DEV="${1:-/dev/esp32}"
PORT="${2:-8799}"
DIR="$(cd "$(dirname "$0")" && pwd)"
exec sudo PYTHONPATH="$DIR" /usr/bin/python3 -u "$DIR/server.py" "$DEV" "$PORT"
