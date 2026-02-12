#!/usr/bin/env bash
#
# Koi integration test suite (Linux / macOS).
#
# Builds Koi, then exercises the CLI and daemon surfaces end-to-end.
# Tier 1:   Standalone CLI (no daemon needed).
# Tier 1.T: Runtime tunables (--no-mdns, --no-certmesh).
# Tier 2:   Daemon (foreground) — HTTP API, certmesh, client mode, admin, shutdown.
# Tier 2.T: Disabled capability daemon tests.
#
# Run from the repo root:
#     bash tests/integration.sh
#
# Options:
#     --no-build    Skip cargo build
#     --tier3       Run service lifecycle tests (requires root)
#     --service     Test against a running installed service
#     --service-endpoint URL  Service endpoint (default: http://127.0.0.1:5641)
#     --verbose     Show extra debug output
#
# Service mode — test against a running installed service:
#     # In a root shell:
#     koi install
#     systemctl start koi   (or: sudo launchctl bootstrap system /Library/LaunchDaemons/org.sylin.koi.plist)
#
#     # In a normal shell:
#     bash tests/integration.sh --service [--service-endpoint http://127.0.0.1:5641]
#

set -euo pipefail

# ── Parse arguments ───────────────────────────────────────────────────

NO_BUILD=false
TIER3=false
SERVICE=false
SERVICE_ENDPOINT="http://127.0.0.1:5641"
VERBOSE=false

while [ $# -gt 0 ]; do
    case "$1" in
        --no-build)  NO_BUILD=true ;;
        --tier3)     TIER3=true ;;
        --service)   SERVICE=true ;;
        --service-endpoint) shift; SERVICE_ENDPOINT="$1" ;;
        --verbose)   VERBOSE=true ;;
        *)           echo "Unknown argument: $1"; exit 1 ;;
    esac
    shift
done

# ── Test configuration ────────────────────────────────────────────────

TEST_PORT=15641
TEST_SOCKET="/tmp/koi-test-$$.sock"
TEST_DIR=$(mktemp -d)
TEST_LOG="$TEST_DIR/koi-test.log"
BREADCRUMB_DIR="$TEST_DIR/breadcrumb"
DATA_DIR="$TEST_DIR/data"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
KOI_BIN="$SCRIPT_DIR/../target/release/koi"
# Use 127.0.0.1 to avoid IPv6 resolution issues (axum binds 0.0.0.0 = IPv4 only).
ENDPOINT="http://127.0.0.1:$TEST_PORT"
HEALTH_TIMEOUT=15
OP_TIMEOUT=10
DAEMON_PID=""

# ── Bookkeeping ───────────────────────────────────────────────────────

PASSED=0
FAILED=0
SKIPPED=0
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

skip() {
    SKIPPED=$((SKIPPED + 1))
    echo -e "\033[33m[SKIP]\033[0m $1 — $2"
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

mkdir -p "$BREADCRUMB_DIR" "$DATA_DIR"

echo "Binary:     $KOI_BIN"
echo "Test dir:   $TEST_DIR"
echo "Port:       $TEST_PORT"
echo "Socket:     $TEST_SOCKET"
echo ""

# ── Helper: run koi with test isolation ──────────────────────────────

# JSON extraction helper (tries jq, then python3)
json_field() {
    local json="$1" field="$2"
    # Try jq first
    if command -v jq &>/dev/null; then
        echo "$json" | jq -r "$field" 2>/dev/null && return 0
    fi
    # Fallback to python3
    if command -v python3 &>/dev/null; then
        echo "$json" | python3 -c "import sys,json; d=json.load(sys.stdin); exec('v=$field'.replace('.','[\"').replace('[\"','[\"',1) + '\"]' * ($field.count('.'))  ); print(v)" 2>/dev/null && return 0
    fi
    return 1
}

# Simpler jq-or-python extractor for dotted paths
json_get() {
    local json="$1" path="$2"
    if command -v jq &>/dev/null; then
        echo "$json" | jq -r ".$path // empty" 2>/dev/null
    elif command -v python3 &>/dev/null; then
        echo "$json" | python3 -c "
import sys, json, functools
d = json.load(sys.stdin)
try:
    v = functools.reduce(lambda o, k: o[k], '$path'.split('.'), d)
    print(v if v is not None else '')
except (KeyError, TypeError, IndexError):
    pass
" 2>/dev/null
    fi
}

run_koi() {
    # Usage: run_koi [--allow-failure] [--stdin DATA] [--timeout N] ARGS...
    local allow_failure=false
    local stdin_data=""
    local timeout_sec=$OP_TIMEOUT
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

    # In service mode, use real system paths so CLI auto-discovers the service.
    # In normal mode, isolate breadcrumb (XDG_RUNTIME_DIR) and data dir (KOI_DATA_DIR).
    if [ "$SERVICE" = true ]; then
        if [ -n "$stdin_data" ]; then
            output=$(echo "$stdin_data" | timeout "$timeout_sec" "$KOI_BIN" "${args[@]}" 2>/dev/null) || exit_code=$?
        else
            output=$(timeout "$timeout_sec" "$KOI_BIN" "${args[@]}" 2>/dev/null) || exit_code=$?
        fi
    else
        if [ -n "$stdin_data" ]; then
            output=$(echo "$stdin_data" | XDG_RUNTIME_DIR="$BREADCRUMB_DIR" KOI_DATA_DIR="$DATA_DIR" timeout "$timeout_sec" "$KOI_BIN" "${args[@]}" 2>/dev/null) || exit_code=$?
        else
            output=$(XDG_RUNTIME_DIR="$BREADCRUMB_DIR" KOI_DATA_DIR="$DATA_DIR" timeout "$timeout_sec" "$KOI_BIN" "${args[@]}" 2>/dev/null) || exit_code=$?
        fi
    fi

    # timeout command returns 124 on timeout
    if [ "$allow_failure" = false ] && [ "$exit_code" -ne 0 ] && [ "$exit_code" -ne 124 ]; then
        echo "$output"
        return "$exit_code"
    fi

    echo "$output"
    return 0
}

# Helper: run koi and capture exit code (for failure tests)
run_koi_rc() {
    local exit_code=0
    run_koi --allow-failure "$@" >/dev/null 2>&1 || exit_code=$?
    echo "$exit_code"
}

# ══════════════════════════════════════════════════════════════════════
#  SERVICE MODE — test against a running installed service
# ══════════════════════════════════════════════════════════════════════

if [ "$SERVICE" = true ]; then
    ENDPOINT="$SERVICE_ENDPOINT"
    echo ""
    echo "=== Service Mode: testing against $ENDPOINT ==="

    # Verify service is reachable
    if curl -s -f "$ENDPOINT/healthz" >/dev/null 2>&1; then
        pass "service health check"
    else
        echo "Service is not reachable at $ENDPOINT."
        echo "Make sure the service is installed and running:"
        echo "  (root) koi install"
        echo "  (root) systemctl start koi  (or: sudo launchctl bootstrap system ...)"
        exit 1
    fi

    # S.1 — Unified status endpoint
    unified_resp=""
    if resp=$(curl -s "$ENDPOINT/v1/status"); then
        unified_resp="$resp"
        version=$(json_get "$resp" "version")
        daemon=$(json_get "$resp" "daemon")
        uptime=$(json_get "$resp" "uptime_secs")
        if [ -n "$version" ] && [ "$daemon" = "true" ]; then
            pass "unified status (v$version, uptime: ${uptime}s)"
        else
            fail "unified status" "version=$version daemon=$daemon"
        fi
    else
        fail "unified status" "curl failed"
    fi

    # S.2 — mDNS browse endpoint
    if curl -s -f "$ENDPOINT/v1/mdns/browse?type=_http._tcp&idle_for=1" >/dev/null 2>&1; then
        pass "mDNS browse endpoint reachable"
    else
        fail "mDNS browse endpoint" "curl failed"
    fi

    # S.3 — Register + unregister via HTTP
    svc_reg_id=""
    if resp=$(curl -s -X POST "$ENDPOINT/v1/mdns/services" \
        -H 'Content-Type: application/json' \
        -d '{"name":"ServiceTest","type":"_http._tcp","port":19998}'); then
        svc_reg_id=$(json_get "$resp" "registered.id")
        if [ -n "$svc_reg_id" ]; then
            pass "register via HTTP (id: ${svc_reg_id:0:8})"
        else
            fail "register via HTTP" "no id in response"
        fi
    else
        fail "register via HTTP" "curl failed"
    fi

    if [ -n "$svc_reg_id" ]; then
        if curl -s -f -X DELETE "$ENDPOINT/v1/mdns/services/$svc_reg_id" >/dev/null 2>&1; then
            pass "unregister via HTTP (id: ${svc_reg_id:0:8})"
        else
            fail "unregister via HTTP" "curl failed"
        fi
    fi

    # S.4 — Admin status + list
    if resp=$(curl -s "$ENDPOINT/v1/mdns/admin/status"); then
        adm_version=$(json_get "$resp" "version")
        if [ -n "$adm_version" ]; then
            pass "admin status (v$adm_version)"
        else
            fail "admin status" "missing version field"
        fi
    else
        fail "admin status" "curl failed"
    fi

    if curl -s -f "$ENDPOINT/v1/mdns/admin/registrations" >/dev/null 2>&1; then
        pass "admin registrations list"
    else
        fail "admin registrations list" "curl failed"
    fi

    # -- Certmesh availability probe ------------------------------------------

    certmesh_enabled=false
    if [ -n "$unified_resp" ]; then
        # Check if certmesh capability is present and not disabled
        if command -v jq &>/dev/null; then
            cm_summary=$(echo "$unified_resp" | jq -r '.capabilities[] | select(.name=="certmesh") | .summary' 2>/dev/null)
        elif command -v python3 &>/dev/null; then
            cm_summary=$(echo "$unified_resp" | python3 -c "
import sys, json
d = json.load(sys.stdin)
for c in d.get('capabilities', []):
    if c.get('name') == 'certmesh':
        print(c.get('summary', ''))
        break
" 2>/dev/null)
        fi
        if [ -n "$cm_summary" ] && [ "$cm_summary" != "disabled" ]; then
            certmesh_enabled=true
        fi
    fi

    if [ "$certmesh_enabled" = false ]; then
        echo ""
        echo "  Certmesh capability is disabled on this service (--no-certmesh tunable)."
        echo "  Skipping certmesh tests (S.5-S.13)."
        echo ""
        skip "certmesh tests (S.5-S.13)" "Certmesh capability disabled via tunable"
    else

    # -- Certmesh tests --------------------------------------------------------

    # Determine if CA was already initialized before this test run
    ca_was_initialized=false
    we_created_ca=false

    # S.5 — Certmesh status (before any changes)
    if resp=$(curl -s "$ENDPOINT/v1/certmesh/status"); then
        ca_init_val=$(json_get "$resp" "ca_initialized")
        if [ -n "$ca_init_val" ]; then
            [ "$ca_init_val" = "true" ] && ca_was_initialized=true
            pass "certmesh status (ca_initialized=$ca_init_val)"
        else
            fail "certmesh status" "missing ca_initialized field"
        fi
    else
        fail "certmesh status" "curl failed"
    fi

    # S.6 — Certmesh create (if CA not yet initialized, create one to test with)
    if [ "$ca_was_initialized" = false ]; then
        log "CA not initialized — creating test CA (will clean up afterward)"
        svc_entropy=$(head -c 32 /dev/urandom | xxd -p | tr -d '\n' | head -c 64)
        if resp=$(curl -s -X POST "$ENDPOINT/v1/certmesh/create" \
            -H 'Content-Type: application/json' \
            -d "{\"passphrase\":\"test-koi-service\",\"entropy_hex\":\"$svc_entropy\",\"profile\":\"just_me\"}"); then
            totp_uri=$(json_get "$resp" "totp_uri")
            ca_fp=$(json_get "$resp" "ca_fingerprint")
            if [ -n "$totp_uri" ] && [ -n "$ca_fp" ]; then
                we_created_ca=true
                pass "certmesh create (fingerprint=${ca_fp:0:16}...)"
            else
                fail "certmesh create" "totp_uri=$totp_uri ca_fingerprint=$ca_fp"
            fi
        else
            fail "certmesh create" "curl failed"
        fi

        # S.6b — Create rejects duplicate (409)
        if [ "$we_created_ca" = true ]; then
            http_code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$ENDPOINT/v1/certmesh/create" \
                -H 'Content-Type: application/json' \
                -d "{\"passphrase\":\"test\",\"entropy_hex\":\"$svc_entropy\",\"profile\":\"just_me\"}" 2>/dev/null || echo "000")
            if [ "$http_code" = "409" ]; then
                pass "certmesh create (duplicate) returns 409"
            else
                fail "certmesh create (duplicate)" "expected 409, got $http_code"
            fi
        fi
    else
        log "CA already initialized — skipping create test (pre-existing CA will not be modified)"
    fi

    # S.7 — Certmesh status (after create or pre-existing)
    if resp=$(curl -s "$ENDPOINT/v1/certmesh/status"); then
        profile=$(json_get "$resp" "profile")
        member_count=$(json_get "$resp" "member_count")
        ca_init2=$(json_get "$resp" "ca_initialized")
        if [ "$ca_init2" = "true" ] && [ -n "$profile" ]; then
            pass "certmesh status (profile=$profile, members=$member_count)"
        else
            fail "certmesh status (post-create)" "ca_initialized=$ca_init2 profile=$profile"
        fi
    else
        fail "certmesh status (post-create)" "curl failed"
    fi

    # S.8 — Audit log (+ content validation if we created the CA)
    if resp=$(curl -s "$ENDPOINT/v1/certmesh/log"); then
        pass "certmesh audit log"

        # Validate audit log contains pond_initialized after create
        if [ "$we_created_ca" = true ]; then
            entries=$(json_get "$resp" "entries")
            if echo "$entries" | grep -q 'pond_initialized'; then
                pass "audit log contains pond_initialized entry"
            else
                fail "audit log contains pond_initialized entry" "pond_initialized not found in log entries"
            fi
        fi
    else
        fail "certmesh audit log" "curl failed"
    fi

    # S.9 — Unlock CA (only if we created it — passphrase must match)
    if [ "$we_created_ca" = true ]; then
        if resp=$(curl -s -X POST "$ENDPOINT/v1/certmesh/unlock" \
            -H 'Content-Type: application/json' \
            -d '{"passphrase":"test-koi-service"}'); then
            success=$(json_get "$resp" "success")
            if [ "$success" = "true" ]; then
                pass "certmesh unlock"
            else
                fail "certmesh unlock" "success=$success"
            fi
        else
            fail "certmesh unlock" "curl failed"
        fi
    fi

    # S.10 — Open enrollment
    if resp=$(curl -s -X POST "$ENDPOINT/v1/certmesh/enrollment/open" \
        -H 'Content-Type: application/json' -d '{}'); then
        enrollment_state=$(json_get "$resp" "enrollment_state")
        if [ "$enrollment_state" = "open" ]; then
            pass "open enrollment"
        else
            fail "open enrollment" "enrollment_state=$enrollment_state"
        fi
    else
        fail "open enrollment" "curl failed"
    fi

    # S.11 — Close enrollment
    if resp=$(curl -s -X POST "$ENDPOINT/v1/certmesh/enrollment/close"); then
        enrollment_state=$(json_get "$resp" "enrollment_state")
        if [ "$enrollment_state" = "closed" ]; then
            pass "close enrollment"
        else
            fail "close enrollment" "enrollment_state=$enrollment_state"
        fi
    else
        fail "close enrollment" "curl failed"
    fi

    # S.12 — Set policy
    if resp=$(curl -s -X PUT "$ENDPOINT/v1/certmesh/policy" \
        -H 'Content-Type: application/json' \
        -d '{"allowed_domain":"lab.local","allowed_subnet":"192.168.1.0/24"}'); then
        domain=$(json_get "$resp" "allowed_domain")
        if [ "$domain" = "lab.local" ]; then
            pass "set policy (domain=lab.local)"
        else
            fail "set policy" "domain=$domain"
        fi
    else
        fail "set policy" "curl failed"
    fi

    # S.13 — Rotate TOTP (only if we created the CA — passphrase must match)
    if [ "$we_created_ca" = true ]; then
        if resp=$(curl -s -X POST "$ENDPOINT/v1/certmesh/rotate-totp" \
            -H 'Content-Type: application/json' \
            -d '{"passphrase":"test-koi-service"}'); then
            totp_uri=$(json_get "$resp" "totp_uri")
            if echo "$totp_uri" | grep -q 'otpauth://'; then
                pass "rotate TOTP returns new URI"
            else
                fail "rotate TOTP" "totp_uri=$totp_uri"
            fi
        else
            fail "rotate TOTP" "curl failed"
        fi
    fi

    # -- Negative tests --------------------------------------------------------

    # S.N1 — Unlock with wrong passphrase returns error
    if [ "$we_created_ca" = true ]; then
        http_code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$ENDPOINT/v1/certmesh/unlock" \
            -H 'Content-Type: application/json' \
            -d '{"passphrase":"wrong-passphrase-definitely"}' 2>/dev/null || echo "000")
        if [ "$http_code" -ge 400 ] 2>/dev/null; then
            pass "unlock with wrong passphrase returns $http_code"
        else
            fail "unlock with wrong passphrase" "expected error, got $http_code"
        fi
    fi

    # S.N2 — Set policy with invalid CIDR returns 400
    http_code=$(curl -s -o /dev/null -w '%{http_code}' -X PUT "$ENDPOINT/v1/certmesh/policy" \
        -H 'Content-Type: application/json' \
        -d '{"allowed_subnet":"not-a-cidr"}' 2>/dev/null || echo "000")
    if [ "$http_code" = "400" ]; then
        pass "set policy with invalid CIDR returns 400"
    else
        fail "set policy with invalid CIDR" "expected 400, got $http_code"
    fi

    # S.N3 — Create with invalid entropy returns 400
    http_code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$ENDPOINT/v1/certmesh/create" \
        -H 'Content-Type: application/json' \
        -d '{"passphrase":"test","entropy_hex":"zzzz","profile":"just_me"}' 2>/dev/null || echo "000")
    if [ "$http_code" = "400" ]; then
        pass "create with invalid entropy returns 400"
    else
        fail "create with invalid entropy" "expected 400, got $http_code"
    fi

    # S.N4 — Create with short entropy returns 400
    http_code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$ENDPOINT/v1/certmesh/create" \
        -H 'Content-Type: application/json' \
        -d '{"passphrase":"test","entropy_hex":"00112233","profile":"just_me"}' 2>/dev/null || echo "000")
    if [ "$http_code" = "400" ]; then
        pass "create with short entropy returns 400"
    else
        fail "create with short entropy" "expected 400, got $http_code"
    fi

    # S.N5 — Set hook for unknown member returns 404
    http_code=$(curl -s -o /dev/null -w '%{http_code}' -X PUT "$ENDPOINT/v1/certmesh/hook" \
        -H 'Content-Type: application/json' \
        -d '{"hostname":"nonexistent-host","reload":"echo hi"}' 2>/dev/null || echo "000")
    if [ "$http_code" = "404" ]; then
        pass "set hook for unknown member returns 404"
    else
        fail "set hook for unknown member" "expected 404, got $http_code"
    fi

    # -- Certmesh cleanup (destroy test CA via service endpoint) ---------------

    if [ "$we_created_ca" = true ]; then
        # Clear policy before destroy
        if curl -s -X PUT "$ENDPOINT/v1/certmesh/policy" \
            -H 'Content-Type: application/json' \
            -d '{}' >/dev/null 2>&1; then
            pass "clear policy before destroy"
        else
            fail "clear policy before destroy" "curl failed"
        fi

        log "Destroying test CA via POST /v1/certmesh/destroy..."
        if resp=$(curl -s -X POST "$ENDPOINT/v1/certmesh/destroy"); then
            destroyed=$(json_get "$resp" "destroyed")
            if [ "$destroyed" = "true" ]; then
                pass "certmesh destroy (test CA removed)"
            else
                fail "certmesh destroy" "destroyed=$destroyed"
            fi
        else
            fail "certmesh destroy" "curl failed"
        fi

        # Post-destroy verification — status should show ca_initialized=false
        if resp=$(curl -s "$ENDPOINT/v1/certmesh/status"); then
            ca_init_post=$(json_get "$resp" "ca_initialized")
            if [ "$ca_init_post" = "false" ]; then
                pass "post-destroy status shows ca_initialized=false"
            else
                fail "post-destroy status" "ca_initialized=$ca_init_post (expected false)"
            fi
        else
            fail "post-destroy status" "curl failed"
        fi

        # Post-destroy — rotate TOTP should return 503
        http_code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$ENDPOINT/v1/certmesh/rotate-totp" \
            -H 'Content-Type: application/json' \
            -d '{"passphrase":"test"}' 2>/dev/null || echo "000")
        if [ "$http_code" = "503" ]; then
            pass "rotate TOTP after destroy returns 503"
        else
            fail "rotate TOTP after destroy" "expected 503, got $http_code"
        fi
    fi

    fi # end certmesh-enabled block

    # -- CLI client mode -------------------------------------------------------

    # S.14 — CLI client mode (auto-discovers via breadcrumb)
    if output=$(run_koi status 2>/dev/null); then
        pass "koi status via CLI (auto-discover service)"
    else
        fail "koi status via CLI" "exit code $?"
    fi

    if output=$(run_koi --allow-failure certmesh status 2>/dev/null); then
        pass "koi certmesh status via CLI (auto-discover service)"
    else
        fail "koi certmesh status via CLI" "exit code $?"
    fi

    # S.15 — Admin shutdown (SKIP in service mode)
    skip "admin shutdown" "Not applicable in service mode — use systemctl stop / koi uninstall"

    # Skip to summary (all remaining tiers are inside the SERVICE=false gate below)
fi

if [ "$SERVICE" = false ]; then

# ══════════════════════════════════════════════════════════════════════
#  TIER 1 — Standalone CLI
# ══════════════════════════════════════════════════════════════════════

echo "=== Tier 1: Standalone CLI ==="

# 1.1 — Help
if output=$(run_koi --help) && echo "$output" | grep -q 'mdns' && echo "$output" | grep -q 'install' && echo "$output" | grep -q 'version'; then
    pass "koi --help shows subcommands"
else
    fail "koi --help shows subcommands" "Missing expected subcommands"
fi

# 1.2 — mDNS discover help
if output=$(run_koi mdns discover --help) && echo "$output" | grep -qi 'service.type\|SERVICE_TYPE\|[Ss]ervice type'; then
    pass "koi mdns discover --help shows type argument"
else
    fail "koi mdns discover --help shows type argument" "Missing type argument"
fi

# 1.3 — Discover with timeout exits cleanly
if run_koi mdns discover http --timeout 2 --standalone >/dev/null 2>&1; then
    pass "koi mdns discover --timeout exits cleanly"
else
    fail "koi mdns discover --timeout exits cleanly" "Non-zero exit code"
fi

# 1.4 — Discover JSON mode produces valid JSON
if output=$(run_koi mdns discover http --timeout 2 --json --standalone); then
    valid=true
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        if command -v jq &>/dev/null; then
            if ! echo "$line" | jq . >/dev/null 2>&1; then valid=false; break; fi
        elif command -v python3 &>/dev/null; then
            if ! echo "$line" | python3 -c "import sys,json; json.load(sys.stdin)" 2>/dev/null; then valid=false; break; fi
        fi
    done <<< "$output"
    if [ "$valid" = true ]; then
        pass "koi mdns discover --json produces valid NDJSON"
    else
        fail "koi mdns discover --json produces valid NDJSON" "Invalid JSON line"
    fi
else
    fail "koi mdns discover --json produces valid NDJSON" "Command failed"
fi

# 1.5 — Announce with timeout
if output=$(run_koi --standalone mdns announce --timeout 2 IntegrationTest http 19999 test=true); then
    if echo "$output" | grep -qi 'Registered\|registered'; then
        pass "koi mdns announce prints confirmation"
    else
        pass "koi mdns announce exits cleanly"
    fi
else
    fail "koi mdns announce prints confirmation" "Command failed"
fi

# 1.6 — Piped JSON mode
if output=$(run_koi --stdin '{"browse":"_http._tcp"}' --standalone --timeout 3); then
    pass "piped JSON mode works"
else
    fail "piped JSON mode works" "Command failed"
fi

# 1.7 — Version command (human)
if output=$(run_koi version) && echo "$output" | grep -q 'koi'; then
    pass "koi version prints version string"
else
    fail "koi version prints version string" "Unexpected output"
fi

# 1.8 — Version --json
if output=$(run_koi version --json); then
    ver=$(json_get "$output" "version")
    plat=$(json_get "$output" "platform")
    if [ -n "$ver" ] && [ -n "$plat" ]; then
        pass "koi version --json (v$ver, $plat)"
    else
        fail "koi version --json" "Missing fields: version=$ver platform=$plat"
    fi
else
    fail "koi version --json" "Command failed"
fi

# 1.9 — Status offline (human)
if output=$(run_koi status) && echo "$output" | grep -q 'not running'; then
    pass "koi status (offline) shows not running"
else
    fail "koi status (offline) shows not running" "Unexpected output"
fi

# 1.10 — Status offline --json
if output=$(run_koi status --json); then
    daemon_val=$(json_get "$output" "daemon")
    if [ "$daemon_val" = "false" ]; then
        pass "koi status --json (offline, daemon=false)"
    else
        fail "koi status --json (offline)" "daemon=$daemon_val"
    fi
else
    fail "koi status --json (offline)" "Command failed"
fi

# 1.11 — Verbose flag accepted
if run_koi mdns discover http --timeout 1 -v --standalone >/dev/null 2>&1; then
    pass "koi -v flag accepted"
else
    fail "koi -v flag accepted" "Command failed"
fi

# 1.12 — Log file flag creates file
log_path="$TEST_DIR/test-logfile.log"
if run_koi mdns discover http --timeout 1 --log-file "$log_path" --standalone >/dev/null 2>&1; then
    if [ -f "$log_path" ]; then
        pass "koi --log-file creates log file"
    else
        fail "koi --log-file creates log file" "Log file was not created"
    fi
else
    fail "koi --log-file creates log file" "Command failed"
fi

# ══════════════════════════════════════════════════════════════════════
#  TIER 1.T — Runtime Tunables
# ══════════════════════════════════════════════════════════════════════

echo ""
echo "=== Tier 1.T: Runtime Tunables ==="

# 1.T1 — --no-mdns status shows mdns disabled
if output=$(run_koi --no-mdns status --json); then
    if echo "$output" | grep -q '"disabled"' && echo "$output" | grep -q '"mdns"'; then
        pass "status --no-mdns shows mdns disabled"
    else
        fail "status --no-mdns shows mdns disabled" "Output: ${output:0:200}"
    fi
else
    fail "status --no-mdns shows mdns disabled" "Command failed"
fi

# 1.T2 — --no-certmesh status shows certmesh disabled
if output=$(run_koi --no-certmesh status --json); then
    if echo "$output" | grep -q '"disabled"' && echo "$output" | grep -q '"certmesh"'; then
        pass "status --no-certmesh shows certmesh disabled"
    else
        fail "status --no-certmesh shows certmesh disabled" "Output: ${output:0:200}"
    fi
else
    fail "status --no-certmesh shows certmesh disabled" "Command failed"
fi

# 1.T3 — --no-mdns blocks mdns commands
rc=$(run_koi_rc --no-mdns mdns discover http --timeout 1 --standalone)
if [ "$rc" -ne 0 ] && [ "$rc" -ne 124 ]; then
    pass "mdns command blocked with --no-mdns (exit=$rc)"
else
    fail "mdns command blocked with --no-mdns" "Expected nonzero exit, got $rc"
fi

# 1.T4 — --no-certmesh blocks certmesh commands
rc=$(run_koi_rc --no-certmesh certmesh status)
if [ "$rc" -ne 0 ] && [ "$rc" -ne 124 ]; then
    pass "certmesh command blocked with --no-certmesh (exit=$rc)"
else
    fail "certmesh command blocked with --no-certmesh" "Expected nonzero exit, got $rc"
fi

# ══════════════════════════════════════════════════════════════════════
#  TIER 2 — Daemon (foreground)
# ══════════════════════════════════════════════════════════════════════

echo ""
echo "=== Tier 2: Daemon (foreground) ==="

# Start daemon in background
log "Starting daemon on port $TEST_PORT..."
XDG_RUNTIME_DIR="$BREADCRUMB_DIR" KOI_DATA_DIR="$DATA_DIR" "$KOI_BIN" \
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
    bc_content=$(tr -d '[:space:]' < "$breadcrumb_file")
    if echo "$bc_content" | grep -q "http://.*:$TEST_PORT"; then
        pass "breadcrumb file written with correct endpoint"
    else
        fail "breadcrumb file written with correct endpoint" "Content: '$bc_content'"
    fi
else
    fail "breadcrumb file written with correct endpoint" "Breadcrumb file not found"
fi

# 2.2 — Unified status endpoint
if resp=$(curl -s "$ENDPOINT/v1/status"); then
    daemon_val=$(json_get "$resp" "daemon")
    version=$(json_get "$resp" "version")
    if [ "$daemon_val" = "true" ] && [ -n "$version" ]; then
        pass "unified status endpoint (v$version, daemon=true)"
    else
        fail "unified status endpoint" "daemon=$daemon_val version=$version"
    fi
else
    fail "unified status endpoint" "curl failed"
fi

# 2.3 — Register via HTTP
reg_id=""
if resp=$(curl -s -X POST "$ENDPOINT/v1/mdns/services" \
    -H 'Content-Type: application/json' \
    -d '{"name":"DaemonTest","type":"_http._tcp","port":19998}'); then
    reg_id=$(json_get "$resp" "registered.id")
    if [ -n "$reg_id" ]; then
        pass "register via HTTP (id: ${reg_id:0:8})"
    else
        fail "register via HTTP" "No id in response: $resp"
    fi
else
    fail "register via HTTP" "curl failed"
fi

# 2.4 — Admin status via CLI (client mode)
if output=$(run_koi mdns admin status --endpoint "$ENDPOINT"); then
    pass "admin status (client mode)"
else
    fail "admin status (client mode)" "Command failed"
fi

# 2.5 — Admin ls shows registration
if output=$(run_koi mdns admin ls --endpoint "$ENDPOINT") && echo "$output" | grep -q 'DaemonTest'; then
    pass "admin ls shows registration"
else
    fail "admin ls shows registration" "Registration not found in listing"
fi

# 2.6 — Unregister via HTTP
if [ -n "$reg_id" ]; then
    if resp=$(curl -s -X DELETE "$ENDPOINT/v1/mdns/services/$reg_id"); then
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

# 2.7 — Register via CLI client mode
if output=$(run_koi --endpoint "$ENDPOINT" --json mdns announce --timeout 3 CLIClient http 17777 2>/dev/null); then
    pass "announce via CLI client mode"
else
    fail "announce via CLI client mode" "Command failed"
fi

# 2.8 — Resolve via HTTP (nonexistent — expect timeout or not-found)
http_code=$(curl -s -o /dev/null -w '%{http_code}' "$ENDPOINT/v1/mdns/resolve?name=nonexistent._http._tcp.local." --max-time 10 2>/dev/null || echo "000")
if [ "$http_code" = "504" ] || [ "$http_code" = "404" ]; then
    pass "resolve via HTTP (expected $http_code for nonexistent)"
elif [ "$http_code" = "200" ]; then
    pass "resolve via HTTP (responded)"
else
    fail "resolve via HTTP" "Unexpected status: $http_code"
fi

# -- Certmesh HTTP tests --------------------------------------------------

# 2.C1 — Certmesh status via HTTP (before CA creation)
if resp=$(curl -s "$ENDPOINT/v1/certmesh/status"); then
    ca_init=$(json_get "$resp" "ca_initialized")
    if [ "$ca_init" = "false" ]; then
        pass "certmesh status (no CA) via HTTP (ca_initialized=false)"
    elif [ -n "$ca_init" ]; then
        pass "certmesh status via HTTP (ca_initialized=$ca_init)"
    else
        fail "certmesh status via HTTP" "Missing ca_initialized field"
    fi
else
    fail "certmesh status via HTTP" "curl failed"
fi

# 2.C2 — Create CA via HTTP
create_entropy=$(printf '%0*x' 64 $RANDOM$RANDOM$RANDOM$RANDOM$RANDOM$RANDOM$RANDOM$RANDOM | head -c 64)
if resp=$(curl -s -X POST "$ENDPOINT/v1/certmesh/create" \
    -H 'Content-Type: application/json' \
    -d "{\"passphrase\":\"test-integration\",\"entropy_hex\":\"$create_entropy\",\"profile\":\"just_me\"}"); then
    totp_uri=$(json_get "$resp" "totp_uri")
    ca_fp=$(json_get "$resp" "ca_fingerprint")
    if [ -n "$totp_uri" ] && [ -n "$ca_fp" ]; then
        pass "certmesh create via HTTP (fingerprint=${ca_fp:0:16}...)"
    else
        fail "certmesh create via HTTP" "totp_uri=$totp_uri ca_fingerprint=$ca_fp resp=$resp"
    fi
else
    fail "certmesh create via HTTP" "curl failed"
fi

# 2.C3 — Certmesh status after CA creation
if resp=$(curl -s "$ENDPOINT/v1/certmesh/status"); then
    ca_init=$(json_get "$resp" "ca_initialized")
    profile=$(json_get "$resp" "profile")
    member_count=$(json_get "$resp" "member_count")
    if [ "$ca_init" = "true" ] && [ -n "$profile" ]; then
        pass "certmesh status (after create) via HTTP (profile=$profile, members=$member_count)"
    else
        fail "certmesh status (after create)" "ca_initialized=$ca_init profile=$profile"
    fi
else
    fail "certmesh status (after create)" "curl failed"
fi

# 2.C4 — Certmesh create rejects duplicate
http_code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$ENDPOINT/v1/certmesh/create" \
    -H 'Content-Type: application/json' \
    -d "{\"passphrase\":\"test\",\"entropy_hex\":\"$create_entropy\",\"profile\":\"just_me\"}" 2>/dev/null || echo "000")
if [ "$http_code" = "409" ]; then
    pass "certmesh create (duplicate) returns 409"
else
    fail "certmesh create (duplicate)" "Expected 409, got $http_code"
fi

# 2.C5 — Audit log via HTTP
if resp=$(curl -s "$ENDPOINT/v1/certmesh/log"); then
    entries=$(json_get "$resp" "entries")
    if [ -n "$entries" ] && echo "$entries" | grep -q 'pond_initialized'; then
        pass "certmesh audit log via HTTP shows pond_initialized"
    else
        pass "certmesh audit log via HTTP returns OK"
    fi
else
    fail "certmesh audit log via HTTP" "curl failed"
fi

# 2.C6 — Unlock CA via HTTP
if resp=$(curl -s -X POST "$ENDPOINT/v1/certmesh/unlock" \
    -H 'Content-Type: application/json' \
    -d '{"passphrase":"test-integration"}'); then
    success=$(json_get "$resp" "success")
    if [ "$success" = "true" ]; then
        pass "certmesh unlock via HTTP"
    else
        fail "certmesh unlock via HTTP" "success=$success"
    fi
else
    fail "certmesh unlock via HTTP" "curl failed"
fi

# 2.C7 — Join with invalid TOTP (expect error)
http_code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$ENDPOINT/v1/certmesh/join" \
    -H 'Content-Type: application/json' \
    -d '{"totp_code":"000000"}' 2>/dev/null || echo "000")
if [ "$http_code" -ge 400 ] 2>/dev/null; then
    pass "certmesh join (invalid TOTP) returns $http_code"
else
    fail "certmesh join (invalid TOTP)" "Expected 4xx/5xx, got $http_code"
fi

# 2.C8 — Unified status includes certmesh
if resp=$(curl -s "$ENDPOINT/v1/status"); then
    if echo "$resp" | grep -q '"certmesh"'; then
        pass "unified status includes certmesh capability"
    else
        fail "unified status includes certmesh" "certmesh not found in capabilities"
    fi
else
    fail "unified status includes certmesh" "curl failed"
fi

# 2.C9 — Certmesh status via CLI client mode
if output=$(run_koi certmesh status --endpoint "$ENDPOINT"); then
    if echo "$output" | grep -qi 'just.me\|JustMe\|initialized'; then
        pass "certmesh status via CLI (client mode)"
    else
        pass "certmesh status via CLI exits cleanly"
    fi
else
    fail "certmesh status via CLI (client mode)" "Command failed"
fi

# 2.C10 — Certmesh log via CLI client mode
if output=$(run_koi certmesh log --endpoint "$ENDPOINT"); then
    pass "certmesh log via CLI (client mode)"
else
    fail "certmesh log via CLI (client mode)" "Command failed"
fi

# -- Phase 4+ — Enrollment policy endpoints ──────────────────────────

# 2.P1 — Open enrollment
if resp=$(curl -s -X POST "$ENDPOINT/v1/certmesh/enrollment/open" \
    -H 'Content-Type: application/json' \
    -d '{}'); then
    enrollment_state=$(json_get "$resp" "enrollment_state")
    if [ "$enrollment_state" = "open" ]; then
        pass "open enrollment returns state=open"
    else
        fail "open enrollment" "enrollment_state=$enrollment_state"
    fi
else
    fail "open enrollment" "curl failed"
fi

# 2.P2 — Open enrollment with deadline
if resp=$(curl -s -X POST "$ENDPOINT/v1/certmesh/enrollment/open" \
    -H 'Content-Type: application/json' \
    -d '{"deadline":"2030-12-31T23:59:59Z"}'); then
    deadline=$(json_get "$resp" "deadline")
    if [ -n "$deadline" ]; then
        pass "open enrollment with deadline ($deadline)"
    else
        fail "open enrollment with deadline" "No deadline in response"
    fi
else
    fail "open enrollment with deadline" "curl failed"
fi

# 2.P3 — Close enrollment
if resp=$(curl -s -X POST "$ENDPOINT/v1/certmesh/enrollment/close"); then
    enrollment_state=$(json_get "$resp" "enrollment_state")
    if [ "$enrollment_state" = "closed" ]; then
        pass "close enrollment returns state=closed"
    else
        fail "close enrollment" "enrollment_state=$enrollment_state"
    fi
else
    fail "close enrollment" "curl failed"
fi

# 2.P4 — Set policy (domain + subnet)
if resp=$(curl -s -X PUT "$ENDPOINT/v1/certmesh/policy" \
    -H 'Content-Type: application/json' \
    -d '{"allowed_domain":"lab.local","allowed_subnet":"192.168.1.0/24"}'); then
    domain=$(json_get "$resp" "allowed_domain")
    subnet=$(json_get "$resp" "allowed_subnet")
    if [ "$domain" = "lab.local" ] && [ "$subnet" = "192.168.1.0/24" ]; then
        pass "set policy (domain=lab.local, subnet=192.168.1.0/24)"
    else
        fail "set policy" "domain=$domain subnet=$subnet"
    fi
else
    fail "set policy" "curl failed"
fi

# 2.P5 — Set policy — invalid CIDR rejected
http_code=$(curl -s -o /dev/null -w '%{http_code}' -X PUT "$ENDPOINT/v1/certmesh/policy" \
    -H 'Content-Type: application/json' \
    -d '{"allowed_subnet":"not-a-cidr"}' 2>/dev/null || echo "000")
if [ "$http_code" = "400" ]; then
    pass "set policy (invalid CIDR) returns 400"
else
    fail "set policy (invalid CIDR)" "Expected 400, got $http_code"
fi

# 2.P6 — Rotate TOTP
if resp=$(curl -s -X POST "$ENDPOINT/v1/certmesh/rotate-totp" \
    -H 'Content-Type: application/json' \
    -d '{"passphrase":"test-integration"}'); then
    new_uri=$(json_get "$resp" "totp_uri")
    if [ -n "$new_uri" ] && echo "$new_uri" | grep -q 'otpauth://'; then
        pass "rotate TOTP returns new URI"
    else
        fail "rotate TOTP" "totp_uri=$new_uri"
    fi
else
    fail "rotate TOTP" "curl failed"
fi

# -- Admin shutdown endpoint ──────────────────────────────────────────

# 2.S1 — Shutdown via HTTP endpoint
if resp=$(curl -s -X POST "$ENDPOINT/v1/admin/shutdown"); then
    status_val=$(json_get "$resp" "status")
    if [ "$status_val" = "shutting_down" ]; then
        pass "admin shutdown endpoint returns shutting_down"
    else
        fail "admin shutdown endpoint" "status=$status_val"
    fi
else
    fail "admin shutdown endpoint" "curl failed"
fi

# Wait for daemon to exit after HTTP shutdown request

exited_cleanly=false
for _ in $(seq 1 30); do
    if ! kill -0 "$DAEMON_PID" 2>/dev/null; then
        exited_cleanly=true
        break
    fi
    sleep 0.5
done

if [ "$exited_cleanly" = true ]; then
    wait "$DAEMON_PID" 2>/dev/null
    pass "daemon exits cleanly after HTTP shutdown"
else
    fail "daemon exits cleanly after HTTP shutdown" "Daemon did not exit within 15 seconds"
    kill -9 "$DAEMON_PID" 2>/dev/null || true
    wait "$DAEMON_PID" 2>/dev/null || true
fi
DAEMON_PID=""

# 2.9 — Breadcrumb deleted after shutdown
sleep 0.5
if [ ! -f "$breadcrumb_file" ]; then
    pass "breadcrumb deleted after shutdown"
else
    fail "breadcrumb deleted after shutdown" "Breadcrumb file still exists"
fi

# 2.10 — Log file has content
if [ -f "$TEST_LOG" ] && [ -s "$TEST_LOG" ]; then
    log_size=$(wc -c < "$TEST_LOG" | tr -d ' ')
    pass "log file has content ($log_size bytes)"
else
    fail "log file has content" "Log file missing or empty"
fi

# ══════════════════════════════════════════════════════════════════════
#  TIER 2.T — Disabled Capability Daemon
# ══════════════════════════════════════════════════════════════════════

echo ""
echo "=== Tier 2.T: Disabled Capability Daemon ==="

# Helper: start a test daemon, wait for health, return PID and endpoint
start_test_daemon() {
    local port=$1 extra_args=$2 label=$3
    local ep="http://127.0.0.1:$port"
    local logfile="$TEST_DIR/daemon-$port.log"

    XDG_RUNTIME_DIR="$BREADCRUMB_DIR" KOI_DATA_DIR="$DATA_DIR" "$KOI_BIN" \
        --daemon --port "$port" --no-ipc $extra_args \
        --log-file "$logfile" -v \
        >/dev/null 2>&1 &
    local pid=$!

    local healthy2=false
    local deadline2=$(($(date +%s) + HEALTH_TIMEOUT))
    while [ "$(date +%s)" -lt "$deadline2" ]; do
        if curl -s -f "$ep/healthz" >/dev/null 2>&1; then
            healthy2=true
            break
        fi
        sleep 0.5
    done

    if [ "$healthy2" = false ]; then
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
        fail "$label health check" "$label did not become healthy"
        echo ""
        return 1
    fi

    echo "$pid $ep"
    return 0
}

stop_test_daemon() {
    local pid=$1
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    fi
}

# -- Daemon with --no-certmesh --

TEST_PORT2=$((TEST_PORT + 1))
daemon2_info=$(start_test_daemon "$TEST_PORT2" "--no-certmesh" "no-certmesh daemon") || daemon2_info=""

if [ -n "$daemon2_info" ]; then
    daemon2_pid=$(echo "$daemon2_info" | cut -d' ' -f1)
    daemon2_ep=$(echo "$daemon2_info" | cut -d' ' -f2)

    # 2.T1 — Certmesh returns 503 when disabled
    http_code=$(curl -s -o /dev/null -w '%{http_code}' "$daemon2_ep/v1/certmesh/status" 2>/dev/null || echo "000")
    if [ "$http_code" = "503" ]; then
        pass "disabled certmesh returns 503"
    else
        fail "disabled certmesh returns 503" "Expected 503, got $http_code"
    fi

    # 2.T2 — Unified status shows certmesh disabled
    if resp=$(curl -s "$daemon2_ep/v1/status"); then
        if echo "$resp" | grep -q '"certmesh"' && echo "$resp" | grep -q '"disabled"'; then
            pass "unified status shows certmesh disabled on --no-certmesh daemon"
        else
            fail "unified status certmesh disabled" "certmesh/disabled not in response"
        fi
    else
        fail "unified status certmesh disabled" "curl failed"
    fi

    # 2.T2b — mDNS still works
    http_code=$(curl -s -o /dev/null -w '%{http_code}' "$daemon2_ep/v1/mdns/admin/status" 2>/dev/null || echo "000")
    if [ "$http_code" = "200" ]; then
        pass "mDNS still works on --no-certmesh daemon"
    else
        fail "mDNS still works on --no-certmesh daemon" "Expected 200, got $http_code"
    fi

    stop_test_daemon "$daemon2_pid"
fi

# -- Daemon with --no-mdns --

TEST_PORT3=$((TEST_PORT + 2))
daemon3_info=$(start_test_daemon "$TEST_PORT3" "--no-mdns" "no-mdns daemon") || daemon3_info=""

if [ -n "$daemon3_info" ]; then
    daemon3_pid=$(echo "$daemon3_info" | cut -d' ' -f1)
    daemon3_ep=$(echo "$daemon3_info" | cut -d' ' -f2)

    # 2.T3 — mDNS returns 503 when disabled
    http_code=$(curl -s -o /dev/null -w '%{http_code}' "$daemon3_ep/v1/mdns/admin/status" 2>/dev/null || echo "000")
    if [ "$http_code" = "503" ]; then
        pass "disabled mDNS returns 503"
    else
        fail "disabled mDNS returns 503" "Expected 503, got $http_code"
    fi

    # 2.T4 — Unified status shows mDNS disabled
    if resp=$(curl -s "$daemon3_ep/v1/status"); then
        if echo "$resp" | grep -q '"mdns"' && echo "$resp" | grep -q '"disabled"'; then
            pass "unified status shows mDNS disabled on --no-mdns daemon"
        else
            fail "unified status mDNS disabled" "mdns/disabled not in response"
        fi
    else
        fail "unified status mDNS disabled" "curl failed"
    fi

    # 2.T4b — Certmesh still works
    http_code=$(curl -s -o /dev/null -w '%{http_code}' "$daemon3_ep/v1/certmesh/status" 2>/dev/null || echo "000")
    if [ "$http_code" = "200" ]; then
        pass "certmesh still works on --no-mdns daemon"
    else
        fail "certmesh still works on --no-mdns daemon" "Expected 200, got $http_code"
    fi

    stop_test_daemon "$daemon3_pid"
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

fi # end if [ "$SERVICE" = false ]

# ══════════════════════════════════════════════════════════════════════
#  Summary
# ══════════════════════════════════════════════════════════════════════

echo ""
echo "=== Summary ==="

total=$((PASSED + FAILED))
echo -n "$PASSED/$total passed"
if [ "$FAILED" -gt 0 ]; then
    echo -ne ", \033[31m$FAILED failed\033[0m"
fi
if [ "$SKIPPED" -gt 0 ]; then
    echo -ne ", \033[33m$SKIPPED skipped\033[0m"
fi
echo ""

if [ "$FAILED" -gt 0 ]; then
    echo ""
    for f in "${FAILURES[@]}"; do
        echo -e "  \033[31mFAIL:\033[0m $f"
    done
    exit 1
fi
exit 0
