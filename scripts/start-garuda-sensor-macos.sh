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
# Detect, but never silently authorize, this Mac's default interface.
# The final capture still needs the operator to confirm the interface.
IFACE="${1:-}"
MODE="${2:-}"
if [[ "$IFACE" == "--once" ]]; then
  MODE="--once"
  IFACE=""
fi
if [[ -z "$IFACE" ]]; then
  IFACE="$(route -n get default 2>/dev/null | awk '$1=="interface:" {print $2; exit}')"
fi
if [[ -z "$IFACE" || "$IFACE" == -* || ! "$IFACE" =~ ^[A-Za-z0-9_.:-]{1,32}$ ]] ||
   ! ifconfig "$IFACE" >/dev/null 2>&1; then
  echo "Cannot verify an owned local network interface." >&2
  echo "Usage: bash scripts/start-garuda-sensor-macos.sh [OWN_INTERFACE] [--once]" >&2
  echo "Find an authorized interface: route -n get default | grep interface:" >&2
  exit 2
fi
if [[ -n "$MODE" && "$MODE" != "--once" ]]; then
  echo "Only optional --once mode is supported" >&2
  exit 2
fi
echo "Selected local interface: $IFACE"
echo "Packet capture can include sensitive traffic from your own network."
echo "Monitor only interfaces you own or have explicit authorization to inspect."
read -r -p "Type AUTHORIZED to confirm lawful local packet monitoring: " ACK
if [[ "$ACK" != "AUTHORIZED" ]]; then
  echo "Sensor not started; no capture permission was granted." >&2
  exit 3
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
if [[ "$MODE" == "--once" ]]; then EXTRA+=(--once); fi

echo "Starting packet-trained Garuda shadow sensor on YOUR authorized interface: $IFACE"
echo "Only tcpdump obtains OS capture permission. No packet payloads leave this Mac."
echo "Forecasts are 60/120/180/240s from genuine completed 600s PCAP batches."
echo "To stop the sensor, press Ctrl+C in this Terminal."
exec .venv-garuda-sensor/bin/python -m garuda_v3.sensor_runner \
  --interface "$IFACE" --authorized "${EXTRA[@]}"
