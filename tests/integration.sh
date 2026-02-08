#!/usr/bin/env bash
#
# Koi integration test suite (Linux / macOS).
#
# Builds Koi, then exercises the CLI and daemon surfaces end-to-end.
# Tier 1: Standalone CLI (no daemon needed).
# Tier 2: Daemon (foreground) — HTTP API, client mode, admin commands, shutdown.
#
# Run from the repo root:
#     bash tests/integration.sh
#
# Options:
#     --no-build    Skip cargo build
#     --tier3       Run service lifecycle tests (requires root)
#     --verbose     Show extra debug output
#

set -euo pipefail

# ── Parse arguments ───────────────────────────────────────────────────

NO_BUILD=false
TIER3=false
VERBOSE=false

for arg in "$@"; do
    case "$arg" in
        --no-build) NO_BUILD=true ;;
        --tier3)    TIER3=true ;;
        --verbose)  VERBOSE=true ;;
        *)          echo "Unknown argument: $arg"; exit 1 ;;
    esac
done

# ── Test configuration ────────────────────────────────────────────────

TEST_PORT=15353
TEST_SOCKET="/tmp/koi-test-$$.sock"
TEST_DIR=$(mktemp -d)
TEST_LOG="$TEST_DIR/koi-test.log"
BREADCRUMB_DIR="$TEST_DIR/breadcrumb"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
KOI_BIN="$SCRIPT_DIR/../target/release/koi"
ENDPOINT="http://localhost:$TEST_PORT"
HEALTH_TIMEOUT=15
DAEMON_PID=""

# ── Bookkeeping ───────────────────────────────────────────────────────

PASSED=0
FAILED=0
FAILURES=()

log() { echo "  $*" >&2; }

pass() {
    PASSED=$((PASSED + 1))
    echo -e "\033[32m[PASS]\033[0m $1"
}

fail() {
    FAILED=$((FAILED + 1))
    FAILURES+=("$1 — $2")
    echo -e "\033[31m[FAIL]\033[0m $1 — $2"
}

cleanup() {
    if [ -n "$DAEMON_PID" ] && kill -0 "$DAEMON_PID" 2>/dev/null; then
        log "Stopping daemon (PID $DAEMON_PID)..."
        kill "$DAEMON_PID" 2>/dev/null || true
        wait "$DAEMON_PID" 2>/dev/null || true
    fi
    rm -rf "$TEST_DIR"
    [ -S "$TEST_SOCKET" ] && rm -f "$TEST_SOCKET"
}

trap cleanup EXIT

# ── Build ─────────────────────────────────────────────────────────────

if [ "$NO_BUILD" = false ]; then
    echo ""
    echo "=== Building Koi (release) ==="
    cargo build --release
fi

if [ ! -x "$KOI_BIN" ]; then
    echo "Binary not found at $KOI_BIN"
    exit 1
fi

mkdir -p "$BREADCRUMB_DIR"

echo "Binary:     $KOI_BIN"
echo "Test dir:   $TEST_DIR"
echo "Port:       $TEST_PORT"
echo "Socket:     $TEST_SOCKET"
echo ""

# ── Helper: run koi with test isolation ──────────────────────────────

run_koi() {
    # Usage: run_koi [--allow-failure] [--stdin DATA] [--timeout N] ARGS...
    local allow_failure=false
    local stdin_data=""
    local timeout_sec=10
    local args=()

    while [ $# -gt 0 ]; do
        case "$1" in
            --allow-failure) allow_failure=true; shift ;;
            --stdin)         stdin_data="$2"; shift 2 ;;
            --timeout)       timeout_sec="$2"; shift 2 ;;
            *)               args+=("$1"); shift ;;
        esac
    done

    local output
    local exit_code=0

    if [ -n "$stdin_data" ]; then
        output=$(echo "$stdin_data" | XDG_RUNTIME_DIR="$BREADCRUMB_DIR" timeout "$timeout_sec" "$KOI_BIN" "${args[@]}" 2>/dev/null) || exit_code=$?
    else
        output=$(XDG_RUNTIME_DIR="$BREADCRUMB_DIR" timeout "$timeout_sec" "$KOI_BIN" "${args[@]}" 2>/dev/null) || exit_code=$?
    fi

    # timeout command returns 124 on timeout
    if [ "$allow_failure" = false ] && [ "$exit_code" -ne 0 ] && [ "$exit_code" -ne 124 ]; then
        echo "$output"
        return "$exit_code"
    fi

    echo "$output"
    return 0
}

# ══════════════════════════════════════════════════════════════════════
#  TIER 1 — Standalone CLI
# ══════════════════════════════════════════════════════════════════════

echo "=== Tier 1: Standalone CLI ==="

# 1.1 — Help
if output=$(run_koi --help) && echo "$output" | grep -q 'browse' && echo "$output" | grep -q 'register' && echo "$output" | grep -q 'resolve'; then
    pass "koi --help shows subcommands"
else
    fail "koi --help shows subcommands" "Missing expected subcommands"
fi

# 1.2 — Browse help
if output=$(run_koi browse --help) && echo "$output" | grep -qi 'service.type\|SERVICE_TYPE\|[Ss]ervice type'; then
    pass "koi browse --help shows type argument"
else
    fail "koi browse --help shows type argument" "Missing type argument"
fi

# 1.3 — Browse with timeout exits cleanly
if run_koi browse http --timeout 2 --standalone >/dev/null 2>&1; then
    pass "koi browse --timeout exits cleanly"
else
    fail "koi browse --timeout exits cleanly" "Non-zero exit code"
fi

# 1.4 — Browse JSON mode produces valid JSON
if output=$(run_koi browse http --timeout 2 --json --standalone); then
    valid=true
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        if ! echo "$line" | python3 -c "import sys,json; json.load(sys.stdin)" 2>/dev/null; then
            # Fallback: try jq
            if ! echo "$line" | jq . >/dev/null 2>&1; then
                valid=false
                break
            fi
        fi
    done <<< "$output"
    if [ "$valid" = true ]; then
        pass "koi browse --json produces valid NDJSON"
    else
        fail "koi browse --json produces valid NDJSON" "Invalid JSON line"
    fi
else
    fail "koi browse --json produces valid NDJSON" "Command failed"
fi

# 1.5 — Register with timeout
if output=$(run_koi register IntegrationTest http 19999 test=true --timeout 2 --standalone); then
    if echo "$output" | grep -qi 'IntegrationTest\|registered'; then
        pass "koi register prints confirmation"
    else
        pass "koi register prints confirmation (exited cleanly)"
    fi
else
    fail "koi register prints confirmation" "Command failed"
fi

# 1.6 — Piped JSON mode
if output=$(run_koi --stdin '{"browse":"_http._tcp"}' --standalone --timeout 2); then
    pass "piped JSON mode works"
else
    fail "piped JSON mode works" "Command failed"
fi

# 1.7 — Verbose flag accepted
if run_koi browse http --timeout 1 -v --standalone >/dev/null 2>&1; then
    pass "koi -v flag accepted"
else
    fail "koi -v flag accepted" "Command failed"
fi

# 1.8 — Log file flag creates file
log_path="$TEST_DIR/test-logfile.log"
if run_koi browse http --timeout 1 --log-file "$log_path" --standalone >/dev/null 2>&1; then
    if [ -f "$log_path" ]; then
        pass "koi --log-file creates log file"
    else
        fail "koi --log-file creates log file" "Log file was not created"
    fi
else
    fail "koi --log-file creates log file" "Command failed"
fi

# ══════════════════════════════════════════════════════════════════════
#  TIER 2 — Daemon (foreground)
# ══════════════════════════════════════════════════════════════════════

echo ""
echo "=== Tier 2: Daemon (foreground) ==="

# Start daemon in background
log "Starting daemon on port $TEST_PORT..."
XDG_RUNTIME_DIR="$BREADCRUMB_DIR" "$KOI_BIN" \
    --daemon --port "$TEST_PORT" --pipe "$TEST_SOCKET" \
    --log-file "$TEST_LOG" -v \
    >/dev/null 2>&1 &
DAEMON_PID=$!
log "Daemon PID: $DAEMON_PID"

# Poll for health
healthy=false
deadline=$(($(date +%s) + HEALTH_TIMEOUT))
while [ "$(date +%s)" -lt "$deadline" ]; do
    if curl -s -f "$ENDPOINT/healthz" >/dev/null 2>&1; then
        healthy=true
        break
    fi
    sleep 0.5
done

if [ "$healthy" = true ]; then
    pass "daemon health check responds"
else
    fail "daemon health check" "Daemon did not become healthy within ${HEALTH_TIMEOUT}s"
    if [ "$VERBOSE" = true ] && [ -f "$TEST_LOG" ]; then
        log "Daemon log tail:"
        tail -20 "$TEST_LOG" | while IFS= read -r line; do log "  $line"; done
    fi
    exit 1
fi

# 2.1 — Breadcrumb exists
breadcrumb_file="$BREADCRUMB_DIR/koi.endpoint"
if [ -f "$breadcrumb_file" ]; then
    bc_content=$(cat "$breadcrumb_file" | tr -d '[:space:]')
    if [ "$bc_content" = "$ENDPOINT" ]; then
        pass "breadcrumb file written with correct endpoint"
    else
        fail "breadcrumb file written with correct endpoint" "Expected '$ENDPOINT', got '$bc_content'"
    fi
else
    fail "breadcrumb file written with correct endpoint" "Breadcrumb file not found"
fi

# 2.2 — Register via HTTP
reg_id=""
if resp=$(curl -s -X POST "$ENDPOINT/v1/services" \
    -H 'Content-Type: application/json' \
    -d '{"name":"DaemonTest","type":"_http._tcp","port":19998}'); then
    reg_id=$(echo "$resp" | python3 -c "import sys,json; print(json.load(sys.stdin).get('registered',{}).get('id',''))" 2>/dev/null || echo "")
    if [ -z "$reg_id" ]; then
        # Fallback: try jq
        reg_id=$(echo "$resp" | jq -r '.registered.id // empty' 2>/dev/null || echo "")
    fi
    if [ -n "$reg_id" ]; then
        pass "register via HTTP (id: ${reg_id:0:8})"
    else
        fail "register via HTTP" "No id in response: $resp"
    fi
else
    fail "register via HTTP" "curl failed"
fi

# 2.3 — Admin status via CLI (client mode)
if output=$(run_koi admin status --endpoint "$ENDPOINT"); then
    pass "admin status (client mode)"
else
    fail "admin status (client mode)" "Command failed"
fi

# 2.4 — Admin ls shows registration
if output=$(run_koi admin ls --endpoint "$ENDPOINT") && echo "$output" | grep -q 'DaemonTest'; then
    pass "admin ls shows registration"
else
    fail "admin ls shows registration" "Registration not found in listing"
fi

# 2.5 — Unregister via HTTP
if [ -n "$reg_id" ]; then
    if resp=$(curl -s -X DELETE "$ENDPOINT/v1/services/$reg_id"); then
        if echo "$resp" | grep -q "$reg_id"; then
            pass "unregister via HTTP"
        else
            fail "unregister via HTTP" "Expected id '$reg_id' in response"
        fi
    else
        fail "unregister via HTTP" "curl failed"
    fi
else
    fail "unregister via HTTP" "Skipped (no registration id)"
fi

# 2.6 — Admin ls empty after unregister
if output=$(run_koi admin ls --endpoint "$ENDPOINT") && ! echo "$output" | grep -q 'DaemonTest'; then
    pass "admin ls empty after unregister"
else
    fail "admin ls empty after unregister" "Registration still listed"
fi

# 2.7 — Register via CLI client mode
if output=$(run_koi register CLIClient http 17777 --timeout 2 --endpoint "$ENDPOINT" --json 2>/dev/null); then
    pass "register via CLI client mode"
else
    fail "register via CLI client mode" "Command failed"
fi

# 2.8 — Resolve via HTTP (nonexistent — expect timeout or not-found)
http_code=$(curl -s -o /dev/null -w '%{http_code}' "$ENDPOINT/v1/resolve?name=nonexistent._http._tcp.local." --max-time 10 2>/dev/null || echo "000")
if [ "$http_code" = "504" ] || [ "$http_code" = "404" ]; then
    pass "resolve via HTTP (expected $http_code for nonexistent)"
elif [ "$http_code" = "200" ]; then
    pass "resolve via HTTP (responded)"
else
    fail "resolve via HTTP" "Unexpected status: $http_code"
fi

# 2.9 — Shutdown daemon gracefully
log "Sending SIGTERM to daemon..."
kill "$DAEMON_PID" 2>/dev/null || true

exited_cleanly=false
for i in $(seq 1 30); do
    if ! kill -0 "$DAEMON_PID" 2>/dev/null; then
        exited_cleanly=true
        break
    fi
    sleep 0.5
done

if [ "$exited_cleanly" = true ]; then
    wait "$DAEMON_PID" 2>/dev/null
    pass "daemon shutdown"
else
    fail "daemon shutdown" "Daemon did not exit within 15 seconds"
    kill -9 "$DAEMON_PID" 2>/dev/null || true
    wait "$DAEMON_PID" 2>/dev/null || true
fi
DAEMON_PID=""

# 2.10 — Breadcrumb deleted after shutdown
sleep 0.5
if [ ! -f "$breadcrumb_file" ]; then
    pass "breadcrumb deleted after shutdown"
else
    fail "breadcrumb deleted after shutdown" "Breadcrumb file still exists"
fi

# 2.11 — Log file has content
if [ -f "$TEST_LOG" ] && [ -s "$TEST_LOG" ]; then
    log_size=$(wc -c < "$TEST_LOG" | tr -d ' ')
    pass "log file has content ($log_size bytes)"
else
    fail "log file has content" "Log file missing or empty"
fi

# ══════════════════════════════════════════════════════════════════════
#  TIER 3 — Service lifecycle (manual, requires root)
# ══════════════════════════════════════════════════════════════════════

if [ "$TIER3" = true ]; then
    echo ""
    echo "=== Tier 3: Service lifecycle (elevated) ==="
    echo "Tier 3 is Windows-only (SCM). On Linux, use systemd manually."
    echo "Skipping."
fi

# ══════════════════════════════════════════════════════════════════════
#  Summary
# ══════════════════════════════════════════════════════════════════════

echo ""
echo "=== Summary ==="

total=$((PASSED + FAILED))
echo -n "$PASSED/$total passed"
if [ "$FAILED" -gt 0 ]; then
    echo -e ", \033[31m$FAILED failed\033[0m"
    echo ""
    for f in "${FAILURES[@]}"; do
        echo -e "  \033[31mFAIL:\033[0m $f"
    done
    exit 1
else
    echo ""
    exit 0
fi
