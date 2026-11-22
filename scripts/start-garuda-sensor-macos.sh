#!/usr/bin/env bash
# Run from an OWNED Mac with an explicitly chosen, authorized interface:
#   bash scripts/start-garuda-sensor-macos.sh en0
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "This bootstrap is for macOS. Use python -m garuda_v3.sensor_runner on other OSes." >&2
  exit 2
fi
IFACE="${1:-}"
if [[ -z "$IFACE" || ! "$IFACE" =~ ^[A-Za-z0-9_.:-]{1,32}$ ]]; then
  echo "Usage: bash scripts/start-garuda-sensor-macos.sh <OWN_INTERFACE> [--once]" >&2
  echo "Check your own interface name with: route -n get default | grep interface:" >&2
  exit 2
fi

PYTHON=""
for name in python3.12 python3.13 python3.14; do
  if command -v "$name" >/dev/null 2>&1; then
    PYTHON="$name"
    break
  fi
done
if [[ -z "$PYTHON" ]]; then
  echo "Python 3.12+ required. Install official Python, then rerun." >&2
  exit 2
fi
if [[ ! -x ".venv-garuda-sensor/bin/python" ]]; then
  "$PYTHON" -m venv .venv-garuda-sensor
fi
.venv-garuda-sensor/bin/python -m pip install --disable-pip-version-check "numpy==2.3.5"
EXTRA=()
if [[ "${2:-}" == "--once" ]]; then EXTRA+=(--once); fi

echo "Starting packet-trained Garuda shadow sensor on YOUR authorized interface: $IFACE"
echo "Only tcpdump obtains OS capture permission. No packet payloads leave this Mac."
echo "Forecasts are 60/120/180/240s from genuine completed 600s PCAP batches."
echo "To stop the sensor, press Ctrl+C in this Terminal."
exec .venv-garuda-sensor/bin/python -m garuda_v3.sensor_runner \
  --interface "$IFACE" --authorized "${EXTRA[@]}"
