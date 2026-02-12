#!/usr/bin/env bash
set -euo pipefail

NO_BUILD=false
REQUESTS=50
PARALLEL=10

while [ $# -gt 0 ]; do
    case "$1" in
        --no-build)  NO_BUILD=true ;;
        --requests)  shift; REQUESTS="$1" ;;
        --parallel)  shift; PARALLEL="$1" ;;
        *) echo "Unknown arg: $1"; exit 1 ;;
    esac
    shift
done

TEST_PORT=$((16000 + ($$ % 1000)))
TEST_DIR=$(mktemp -d)
TEST_LOG="$TEST_DIR/koi-concurrency.log"
BREADCRUMB_DIR="$TEST_DIR/breadcrumb"
DATA_DIR="$TEST_DIR/data"
DNS_PORT=$((17000 + ($$ % 1000)))
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
KOI_BIN="$SCRIPT_DIR/../target/release/koi"
ENDPOINT="http://127.0.0.1:$TEST_PORT"
DAEMON_PID=""

json_get_file() {
    local file="$1" field="$2"
    if command -v jq &>/dev/null; then
        jq -r ".$field // empty" "$file" 2>/dev/null
    elif command -v python3 &>/dev/null; then
        python3 -c "import json,sys,functools; d=json.load(open('$file'));\n\
try:\n\
 v=functools.reduce(lambda o,k:o[k], '$field'.split('.'), d);\n\
 print(v if v is not None else '')\n\
except Exception:\n\
 pass" 2>/dev/null
    fi
}

cleanup() {
    if [ -n "$DAEMON_PID" ] && kill -0 "$DAEMON_PID" 2>/dev/null; then
        curl -s -X POST "$ENDPOINT/v1/admin/shutdown" >/dev/null 2>&1 || true
        kill "$DAEMON_PID" 2>/dev/null || true
        wait "$DAEMON_PID" 2>/dev/null || true
    fi
    rm -rf "$TEST_DIR"
}
trap cleanup EXIT

if [ "$NO_BUILD" = false ]; then
    cargo build --release
fi

if [ ! -x "$KOI_BIN" ]; then
    echo "Binary not found at $KOI_BIN" >&2
    exit 1
fi

mkdir -p "$BREADCRUMB_DIR" "$DATA_DIR"

XDG_RUNTIME_DIR="$BREADCRUMB_DIR" KOI_DATA_DIR="$DATA_DIR" \
    "$KOI_BIN" --daemon --port "$TEST_PORT" --dns-port "$DNS_PORT" --no-ipc --log-file "$TEST_LOG" -v \
    >/dev/null 2>&1 &
DAEMON_PID=$!

# Wait for health
for i in $(seq 1 30); do
    if curl -s -f "$ENDPOINT/healthz" >/dev/null 2>&1; then
        break
    fi
    sleep 0.2
done

if ! curl -s -f "$ENDPOINT/healthz" >/dev/null 2>&1; then
    echo "Daemon failed to start" >&2
    exit 1
fi

RESP_DIR="$TEST_DIR/responses"
mkdir -p "$RESP_DIR"

# Register in parallel
for i in $(seq 1 "$REQUESTS"); do
    (
        body="{\"name\":\"Burst$i\",\"type\":\"_http._tcp\",\"port\":$((18000 + i)),\"lease_secs\":0}"
        resp=$(curl -s -X POST "$ENDPOINT/v1/mdns/services" -H 'Content-Type: application/json' -d "$body")
        echo "$resp" > "$RESP_DIR/$i.json"
    ) &
    while [ "$(jobs -r | wc -l | tr -d ' ')" -ge "$PARALLEL" ]; do
        sleep 0.1
    done
done
wait

ids=()
for f in "$RESP_DIR"/*.json; do
    id=$(json_get_file "$f" "registered.id")
    if [ -n "$id" ]; then
        ids+=("$id")
    fi
done

if [ "${#ids[@]}" -ne "$REQUESTS" ]; then
    echo "Expected $REQUESTS registrations, got ${#ids[@]}" >&2
    exit 1
fi

uniq_count=$(printf "%s\n" "${ids[@]}" | sort -u | wc -l | tr -d ' ')
if [ "$uniq_count" -ne "$REQUESTS" ]; then
    echo "Expected $REQUESTS unique IDs, got $uniq_count" >&2
    exit 1
fi

echo "Registered $REQUESTS services ($uniq_count unique IDs)."

# Heartbeat in parallel
for id in "${ids[@]}"; do
    (
        curl -s -X PUT "$ENDPOINT/v1/mdns/services/$id/heartbeat" >/dev/null 2>&1
    ) &
    while [ "$(jobs -r | wc -l | tr -d ' ')" -ge "$PARALLEL" ]; do
        sleep 0.1
    done
done
wait

echo "Heartbeat completed."

# Unregister in parallel
for id in "${ids[@]}"; do
    (
        curl -s -X DELETE "$ENDPOINT/v1/mdns/services/$id" >/dev/null 2>&1
    ) &
    while [ "$(jobs -r | wc -l | tr -d ' ')" -ge "$PARALLEL" ]; do
        sleep 0.1
    done
done
wait

echo "Unregister completed."

curl -s -X POST "$ENDPOINT/v1/admin/shutdown" >/dev/null 2>&1 || true
wait "$DAEMON_PID" 2>/dev/null || true
DAEMON_PID=""

exit 0
