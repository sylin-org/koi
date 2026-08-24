#!/bin/sh
# Start (or restart) the dogfood daemon as a plain user process — for
# workstation-class hosts without passwordless sudo (ADR-029 host classes).
# Usage: sh mesh-start-user.sh [root]
# Cyclical by design: dies on shutdown/reboot; rerun this after boot. The
# persistent data root preserves mesh membership across restarts.
set -eu
ROOT="${1:-$HOME/koi-dogfood}"
RUNTIME_DIR="$ROOT/runtime"
mkdir -p "$ROOT/runtime"
# Stop a previous incarnation owned by this exact install, never anything else.
if [ -f "$RUNTIME_DIR/daemon.pid" ]; then
  pid=$(cat "$RUNTIME_DIR/daemon.pid")
  case "$pid" in ''|*[!0-9]*) echo BAD_PID; exit 76;; esac
  exe=$(readlink -f "/proc/$pid/exe" 2>/dev/null || true)
  case "$exe" in
    "$ROOT"/koi) kill "$pid" 2>/dev/null || true;;
    *) echo "REFUSED_WRONG_EXE: $exe"; exit 75;;
  esac
  i=0; while kill -0 "$pid" 2>/dev/null && [ "$i" -lt 50 ]; do sleep 0.1; i=$((i+1)); done
  rm -f "$RUNTIME_DIR/daemon.pid"
fi
setsid -f sh -c "echo \$\$ > $RUNTIME_DIR/daemon.pid; exec env KOI_DATA_DIR=$ROOT/data KOI_DNS_ZONE=internal XDG_RUNTIME_DIR=$RUNTIME_DIR KOI_NO_CREDENTIAL_STORE=1 $ROOT/koi --daemon --http-bind 0.0.0.0 >>$ROOT/daemon.log 2>&1"
i=0
while ! curl -sf http://127.0.0.1:5641/healthz >/dev/null 2>&1 && [ "$i" -lt 50 ]; do
  sleep 0.2; i=$((i+1))
done
curl -sf http://127.0.0.1:5641/healthz >/dev/null && echo "HEALTH_OK root=$ROOT"
