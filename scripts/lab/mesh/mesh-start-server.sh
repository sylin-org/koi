#!/bin/sh
# Start (or restart) the dogfood daemon as a transient systemd unit.
# Usage: sudo sh mesh-start-server.sh <unit-name>
# The daemon serves STANDARD ports (5641 http / 5642 mtls / 5643 acme) and a
# persistent data root at ~/koi-dogfood/data. Run mesh-fetch.sh first.
set -eu
UNIT="${1:-koi-dogfood}"
# Explicit root: when launched via `sudo`, HOME is /root and the dogfood tree
# lives in the invoking user's home — pass it as arg 2.
ROOT="${2:-$HOME/koi-dogfood}"
RUNTIME_DIR="$ROOT/runtime"
mkdir -p "$RUNTIME_DIR"
# Stop a previous incarnation of the same unit, never anything else.
systemctl stop "$UNIT" 2>/dev/null || true
systemd-run --unit="$UNIT" --description="Koi dogfood mesh participant" \
  env KOI_DATA_DIR="$ROOT/data" \
      XDG_RUNTIME_DIR="$RUNTIME_DIR" \
      KOI_DNS_ZONE=internal \
      KOI_NO_CREDENTIAL_STORE=1 \
      "$ROOT/koi" --daemon --http-bind 0.0.0.0
sleep 1
for i in $(seq 1 50); do
  curl -sf http://127.0.0.1:5641/healthz > /dev/null && break
  sleep 0.2
done
curl -sf http://127.0.0.1:5641/healthz > /dev/null && echo "HEALTH_OK unit=$UNIT"
