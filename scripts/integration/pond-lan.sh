#!/usr/bin/env bash
# ADR-042 installed-service Pond gate.
#
# The subject is this machine's one installed Koi. Peers act as independent LAN
# browsers. The gate never starts another Koi process or exposes the operator API.
set -Eeuo pipefail

usage() {
  cat <<'EOF'
Usage: pond-lan.sh --peer USER@HOST [--peer USER@HOST ...]

Required:
  --peer USER@HOST       Independent physical LAN client (repeatable).

Optional environment:
  UI_ROOT                Five-file koi-desktop UI directory
                         (default: sibling koi-desktop checkout)
  KOI_LOCAL_SOCKET       Installed local-control socket (default /run/koi.sock)
  KOI_SERVICE_MANAGER    auto, systemd-system, systemd-user, or openrc
                         (default auto)
  SUDO_ASKPASS           Executable local sudo askpass helper
  PEER_PORT              SSH port (default 22)
  PEER_SSH_ASKPASS       Executable SSH askpass helper
  PEER_KNOWN_HOSTS       Pinned known-hosts file
  PEER_ACCEPT_NEW_HOST_KEY=1
                         Test-lab escape hatch: do not persist/check peer key
  EVIDENCE_ROOT          Output parent (default target/pond-lan)

The local operator must be authorized for Koi's local-control socket. Every peer
needs Python 3. The gate publishes and arms Pond, exercises all public routes and
negative routes from every peer, stops it, re-arms it, restarts the installed
service, verifies intent recovery, and restores the baseline desired state.
It never records the daemon access token.
EOF
}

PEERS=()
while (($#)); do
  case "$1" in
    --peer)
      shift
      [[ -n "${1:-}" ]] || { usage >&2; exit 2; }
      PEERS+=("$1")
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
  shift
done
if ((${#PEERS[@]} == 0)); then
  usage >&2
  exit 2
fi

for command in awk base64 curl grep jq pgrep readlink sed sha256sum sort ssh ss; do
  command -v "$command" >/dev/null || {
    echo "missing required command: $command" >&2
    exit 2
  }
done
if command -v socat >/dev/null; then
  LOCAL_CONTROL_CLIENT=socat
elif command -v python3 >/dev/null; then
  LOCAL_CONTROL_CLIENT=python3
else
  echo "local control requires socat or python3" >&2
  exit 2
fi

ROOT="$(git rev-parse --show-toplevel)"
UI_ROOT="${UI_ROOT:-$ROOT/../koi-desktop/ui}"
KOI_LOCAL_SOCKET="${KOI_LOCAL_SOCKET:-/run/koi.sock}"
KOI_SERVICE_MANAGER="${KOI_SERVICE_MANAGER:-auto}"
PEER_PORT="${PEER_PORT:-22}"
EVIDENCE_ROOT="${EVIDENCE_ROOT:-target/pond-lan}"
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-$$"
EVIDENCE_DIR="$EVIDENCE_ROOT/$RUN_ID"
mkdir -p "$EVIDENCE_DIR"

for file in index.html app.js styles.css sentences.js koi.png; do
  [[ -f "$UI_ROOT/$file" ]] || {
    echo "missing Pond UI file: $UI_ROOT/$file" >&2
    exit 2
  }
done

if [[ "$KOI_SERVICE_MANAGER" == auto ]]; then
  if [[ -d /run/systemd/system ]] && command -v systemctl >/dev/null; then
    KOI_SERVICE_MANAGER=systemd-system
  elif command -v rc-service >/dev/null; then
    KOI_SERVICE_MANAGER=openrc
  else
    echo "could not detect systemd or OpenRC; set KOI_SERVICE_MANAGER" >&2
    exit 2
  fi
fi

case "$KOI_SERVICE_MANAGER" in
  systemd-system|openrc)
    if [[ "$KOI_SERVICE_MANAGER" == systemd-system ]]; then
      SERVICE_RESTART=(systemctl restart koi)
    else
      SERVICE_RESTART=(rc-service koi restart)
    fi
    if ((EUID == 0)); then
      PRIV=()
    else
      command -v sudo >/dev/null || { echo "sudo is required" >&2; exit 2; }
      if [[ -n "${SUDO_ASKPASS:-}" ]]; then
        [[ -x "$SUDO_ASKPASS" ]] || {
          echo "SUDO_ASKPASS is not executable: $SUDO_ASKPASS" >&2
          exit 2
        }
        PRIV=(sudo -A)
      else
        PRIV=(sudo)
      fi
      "${PRIV[@]}" -v
    fi
    ;;
  systemd-user)
    command -v systemctl >/dev/null || { echo "systemctl is required" >&2; exit 2; }
    ((EUID != 0)) || {
      echo "a user service gate must run as its owning user" >&2
      exit 2
    }
    SERVICE_RESTART=(systemctl --user restart koi)
    PRIV=()
    ;;
  *)
    echo "KOI_SERVICE_MANAGER must be auto, systemd-system, systemd-user, or openrc" >&2
    exit 2
    ;;
esac

SSH_BASE=(ssh -p "$PEER_PORT" -o ConnectTimeout=8)
if [[ -n "${PEER_SSH_ASKPASS:-}" ]]; then
  command -v setsid >/dev/null || {
    echo "PEER_SSH_ASKPASS requires setsid" >&2
    exit 2
  }
  [[ -x "$PEER_SSH_ASKPASS" ]] || {
    echo "PEER_SSH_ASKPASS is not executable: $PEER_SSH_ASKPASS" >&2
    exit 2
  }
  if setsid --help 2>&1 | grep -q -- '-w'; then
    SSH_BASE=(env DISPLAY=koi-lab SSH_ASKPASS_REQUIRE=force \
      SSH_ASKPASS="$PEER_SSH_ASKPASS" setsid -w "${SSH_BASE[@]}" \
      -o BatchMode=no -o NumberOfPasswordPrompts=1)
  else
    SSH_BASE=(env DISPLAY=koi-lab SSH_ASKPASS_REQUIRE=force \
      SSH_ASKPASS="$PEER_SSH_ASKPASS" "${SSH_BASE[@]}" \
      -o BatchMode=no -o NumberOfPasswordPrompts=1)
  fi
else
  SSH_BASE+=(-o BatchMode=yes)
fi
if [[ -n "${PEER_KNOWN_HOSTS:-}" ]]; then
  SSH_BASE+=(-o UserKnownHostsFile="$PEER_KNOWN_HOSTS" -o StrictHostKeyChecking=yes)
elif [[ "${PEER_ACCEPT_NEW_HOST_KEY:-0}" == 1 ]]; then
  SSH_BASE+=(-o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no)
fi

peer_run() {
  local peer="$1"
  shift
  "${SSH_BASE[@]}" "$peer" "$@"
}

access_json() {
  local response
  if [[ "$LOCAL_CONTROL_CLIENT" == socat ]]; then
    response="$(printf '%s\n' '{"request":"access","version":1}' \
      | socat -T 5 - "UNIX-CONNECT:$KOI_LOCAL_SOCKET")"
  else
    response="$(python3 - "$KOI_LOCAL_SOCKET" <<'PY'
import socket
import sys

client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
client.settimeout(5)
client.connect(sys.argv[1])
client.sendall(b'{"request":"access","version":1}\n')
response = bytearray()
while b'\n' not in response:
    chunk = client.recv(65536)
    if not chunk:
        break
    response.extend(chunk)
sys.stdout.buffer.write(response)
PY
)"
  fi
  jq -e 'select(.response == "access" and .version == 1)' <<<"$response"
}

refresh_access() {
  local access
  access="$(access_json)"
  API="$(jq -er '.endpoint' <<<"$access")"
  TOKEN="$(jq -er '.token' <<<"$access")"
}

operator_request() {
  local method="$1" path="$2"
  shift 2
  curl -fsS --max-time 12 -X "$method" -H "x-koi-token: $TOKEN" "$@" "$API$path"
}

single_koi() {
  local candidate executable
  local -a candidates=() pids=()
  # procps matches `-x` against the process comm while BusyBox matches argv[0],
  # which is `/usr/local/bin/koi` for an OpenRC service. Use pgrep only to
  # narrow the set, then make the executable itself authoritative.
  mapfile -t candidates < <(pgrep -f '(^|/)koi([[:space:]]|$)' || true)
  for candidate in "${candidates[@]}"; do
    executable="$("${PRIV[@]}" readlink -f "/proc/$candidate/exe" 2>/dev/null || true)"
    if [[ "${executable##*/}" == koi ]]; then
      pids+=("$candidate")
    fi
  done
  ((${#pids[@]} == 1)) || {
    echo "expected exactly one koi process, found ${#pids[@]}" >&2
    return 1
  }
  printf '%s' "${pids[0]}"
}

process_executable() {
  local pid="$1"
  "${PRIV[@]}" readlink -f "/proc/$pid/exe"
}

executable_hash() {
  local executable="$1"
  "${PRIV[@]}" sha256sum "$executable" | awk '{print $1}'
}

peer_public_gate() {
  local peer="$1" base="$2" phase="$3"
  local url_key output
  url_key="$(sed 's/[^A-Za-z0-9_.-]/_/g' <<<"$base")"
  output="$EVIDENCE_DIR/${peer//@/_}-$phase-$url_key.txt"
  peer_run "$peer" python3 - "${base%/}" >"$output" <<'REMOTE'
import sys
import urllib.error
import urllib.request

base = sys.argv[1]

def request(method, path):
    try:
        with urllib.request.urlopen(
            urllib.request.Request(base + path, method=method), timeout=8
        ) as response:
            response.read()
            return response.status
    except urllib.error.HTTPError as error:
        error.read()
        return error.code

for path in (
    "/",
    "/app.js",
    "/styles.css",
    "/sentences.js",
    "/koi.png",
    "/healthz",
    "/v1/status",
    "/v1/mdns/browser/snapshot",
    "/v1/dns/entries",
):
    code = request("GET", path)
    if code != 200:
        raise SystemExit(f"{path} -> {code}")
    print(f"{path} -> {code}")
for method, path in (
    ("POST", "/v1/dns/add"),
    ("GET", "/v1/certmesh/log"),
    ("GET", "/v1/pond"),
    ("GET", "/openapi.json"),
):
    code = request(method, path)
    if code != 404:
        raise SystemExit(f"{method} {path} unexpectedly returned {code}")
    print(f"{method} {path} -> absent")
REMOTE
}

peer_stopped_gate() {
  local peer="$1" base="$2"
  if peer_run "$peer" python3 - "${base%/}" >/dev/null 2>&1 <<'REMOTE'
import sys
import urllib.request

with urllib.request.urlopen(sys.argv[1] + "/healthz", timeout=3) as response:
    response.read()
REMOTE
  then
    echo "$peer still reached stopped Pond at $base" >&2
    return 1
  fi
}

BASE_DESIRED=""
BASELINE_RESTORED=0
API=""
TOKEN=""
POND_URLS=()
CLEANING=0

restore_baseline() {
  local deadline status port
  if [[ -z "$BASE_DESIRED" ]]; then
    BASELINE_RESTORED=1
    return 0
  fi

  refresh_access || {
    echo "could not reacquire local control while restoring Pond" >&2
    return 1
  }
  if [[ "$BASE_DESIRED" == true ]]; then
    operator_request PUT /v1/pond >/dev/null
  else
    operator_request DELETE /v1/pond >/dev/null
  fi

  deadline=$((SECONDS + 15))
  while ((SECONDS < deadline)); do
    status="$(operator_request GET /v1/pond 2>/dev/null || true)"
    if [[ "$BASE_DESIRED" == true ]]; then
      if jq -e '
          .desired == true and .running == true and .state == "running"
          and (.urls | length > 0)
        ' <<<"$status" >/dev/null 2>&1; then
        printf '%s\n' "$status" | jq . >"$EVIDENCE_DIR/final-restoration.json"
        BASELINE_RESTORED=1
        return 0
      fi
    elif jq -e '
        .desired == false and .running == false and .state == "disabled"
      ' <<<"$status" >/dev/null 2>&1; then
      port="$(jq -er '.port' <<<"$status")"
      if ! ss -lntH "sport = :$port" | grep -q .; then
        printf '%s\n' "$status" | jq . >"$EVIDENCE_DIR/final-restoration.json"
        BASELINE_RESTORED=1
        return 0
      fi
    fi
    sleep 0.25
  done

  printf '%s\n' "${status:-unavailable}" >"$EVIDENCE_DIR/final-restoration-error.txt"
  echo "Pond did not return to baseline desired=$BASE_DESIRED" >&2
  return 1
}

cleanup() {
  local result="${1:-$?}"
  ((CLEANING == 0)) || exit "$result"
  CLEANING=1
  trap - EXIT INT TERM
  if [[ "$BASELINE_RESTORED" != 1 ]] && ! restore_baseline; then
    result=1
  fi
  exit "$result"
}
trap 'cleanup $?' EXIT
trap 'cleanup 130' INT
trap 'cleanup 143' TERM

for peer in "${PEERS[@]}"; do
  peer_run "$peer" command -v python3 >/dev/null
done

INITIAL_PID="$(single_koi)"
INITIAL_EXE="$(process_executable "$INITIAL_PID")"
INITIAL_HASH="$(executable_hash "$INITIAL_EXE")"
refresh_access
curl -fsS --max-time 5 "$API/healthz" >/dev/null
BASELINE="$(operator_request GET /v1/pond)"
BASE_DESIRED="$(jq -er '
  if .desired == true then "true"
  elif .desired == false then "false"
  else error("Pond status is missing a desired boolean")
  end
' <<<"$BASELINE")"
jq 'del(.url, .urls)' <<<"$BASELINE" >"$EVIDENCE_DIR/baseline.json"

HTTP_PORT="$(sed -E 's#.*:([0-9]+)/?$#\1#' <<<"$API")"
BEFORE_HTTP_BIND="$(ss -lntH "sport = :$HTTP_PORT" | awk '{print $4}' | sort -u)"
[[ -n "$BEFORE_HTTP_BIND" ]] || { echo "operator listener is absent" >&2; exit 1; }

PNG="$(base64 -w0 "$UI_ROOT/koi.png")"
PAYLOAD="$(jq -n \
  --rawfile index "$UI_ROOT/index.html" \
  --rawfile app "$UI_ROOT/app.js" \
  --rawfile styles "$UI_ROOT/styles.css" \
  --rawfile sentences "$UI_ROOT/sentences.js" \
  --arg png "$PNG" \
  '{files:[
    {path:"index.html",content:$index},
    {path:"app.js",content:$app},
    {path:"styles.css",content:$styles},
    {path:"sentences.js",content:$sentences},
    {path:"koi.png",content:$png}
  ]}')"
printf '%s' "$PAYLOAD" \
  | operator_request PUT /v1/ui -H 'content-type: application/json' --data-binary @- \
    >"$EVIDENCE_DIR/publish.json"
ENABLED="$(operator_request PUT /v1/pond)"
jq -e '.desired == true and .running == true and .state == "running" and (.urls | length > 0)' \
  <<<"$ENABLED" >/dev/null
printf '%s\n' "$ENABLED" | jq . >"$EVIDENCE_DIR/enabled.json"
mapfile -t POND_URLS < <(jq -er '.urls[]' <<<"$ENABLED")

AFTER_HTTP_BIND="$(ss -lntH "sport = :$HTTP_PORT" | awk '{print $4}' | sort -u)"
[[ "$AFTER_HTTP_BIND" == "$BEFORE_HTTP_BIND" ]] || {
  echo "operator HTTP bind changed while arming Pond" >&2
  exit 1
}

for peer in "${PEERS[@]}"; do
  for url in "${POND_URLS[@]}"; do
    peer_public_gate "$peer" "$url" enabled
  done
done

operator_request DELETE /v1/pond >"$EVIDENCE_DIR/stopped.json"
for _ in {1..20}; do
  if ! ss -lntH "sport = :$(jq -r '.port' <<<"$ENABLED")" | grep -q .; then
    break
  fi
  sleep 0.25
done
if ss -lntH "sport = :$(jq -r '.port' <<<"$ENABLED")" | grep -q .; then
  echo "Pond socket remained after explicit stop" >&2
  exit 1
fi
for peer in "${PEERS[@]}"; do
  for url in "${POND_URLS[@]}"; do
    peer_stopped_gate "$peer" "$url"
  done
done

operator_request PUT /v1/pond >/dev/null
"${PRIV[@]}" "${SERVICE_RESTART[@]}"
RECOVERED='{}'
for _ in {1..60}; do
  if refresh_access >/dev/null 2>&1 && curl -fsS --max-time 2 "$API/healthz" >/dev/null 2>&1; then
    RECOVERED="$(operator_request GET /v1/pond 2>/dev/null || true)"
    if jq -e '.desired == true and .running == true and .state == "running"' \
      >/dev/null 2>&1 <<<"$RECOVERED"; then
      break
    fi
  fi
  sleep 0.5
done
jq -e '.desired == true and .running == true and .state == "running"' \
  <<<"$RECOVERED" >/dev/null
printf '%s\n' "$RECOVERED" | jq . >"$EVIDENCE_DIR/recovered.json"
mapfile -t POND_URLS < <(jq -er '.urls[]' <<<"$RECOVERED")
for peer in "${PEERS[@]}"; do
  for url in "${POND_URLS[@]}"; do
    peer_public_gate "$peer" "$url" recovered
  done
done

restore_baseline
if [[ "$BASE_DESIRED" == false ]]; then
  for peer in "${PEERS[@]}"; do
    for url in "${POND_URLS[@]}"; do
      peer_stopped_gate "$peer" "$url"
    done
  done
fi

FINAL_PID="$(single_koi)"
FINAL_EXE="$(process_executable "$FINAL_PID")"
FINAL_HASH="$(executable_hash "$FINAL_EXE")"
[[ "$FINAL_HASH" == "$INITIAL_HASH" ]] || {
  echo "installed executable changed during the gate" >&2
  exit 1
}
jq -n \
  --arg run_id "$RUN_ID" --arg initial_pid "$INITIAL_PID" --arg final_pid "$FINAL_PID" \
  --arg sha256 "$FINAL_HASH" --argjson baseline_desired "$BASE_DESIRED" \
  --argjson final_desired "$(jq '.desired' "$EVIDENCE_DIR/final-restoration.json")" \
  --argjson peers "$(printf '%s\n' "${PEERS[@]}" | jq -R . | jq -s .)" \
  '{run_id:$run_id, initial_pid:($initial_pid|tonumber), final_pid:($final_pid|tonumber),
    sha256:$sha256, peers:$peers, baseline_desired:$baseline_desired,
    final_desired:$final_desired, restoration:"pass", result:"pass"}' \
  >"$EVIDENCE_DIR/verdict.json"

trap - EXIT INT TERM
echo "Pond LAN gate PASS: $RUN_ID"
echo "  peers: ${PEERS[*]}"
echo "  service PID: $INITIAL_PID -> $FINAL_PID"
echo "  artifact: $FINAL_HASH"
echo "  evidence: $EVIDENCE_DIR"
