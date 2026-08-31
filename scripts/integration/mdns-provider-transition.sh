#!/usr/bin/env bash
# ADR-038 installed-service, two-host provider transition gate.
#
# The subject is the machine running this script. It keeps the one installed Koi
# service alive while Avahi and systemd-resolved are removed/restored underneath
# it. The peer is an independent LAN host with avahi-browse/publish tools. This
# script never starts a Koi process and never mutates the peer's system services.
set -Eeuo pipefail

usage() {
  cat <<'EOF'
Usage: mdns-provider-transition.sh --allow-system-mutation --peer USER@HOST

Required:
  --allow-system-mutation  Acknowledge temporary provider configuration and
                           service changes with exact restoration.
  --peer USER@HOST         Independent LAN peer reachable through OpenSSH.

Optional environment:
  KOI_API                  Installed Koi API (default http://127.0.0.1:5641)
  KOI_SERVICE_SCOPE        Installed unit scope: system or user (default system)
  KOI_BREADCRUMB           Endpoint breadcrumb (default follows service scope)
  PEER_PORT                SSH port (default 22)
  PEER_IDENTITY            SSH identity file
  EVIDENCE_ROOT            Evidence parent (default target/mdns-provider-transition)

Run on the real subject host, not in a container. The caller needs privilege to
control local system services and preconfigured SSH authentication to the peer.
EOF
}

ALLOW_MUTATION=0
PEER=""
while (($#)); do
  case "$1" in
    --allow-system-mutation) ALLOW_MUTATION=1 ;;
    --peer)
      shift
      PEER="${1:-}"
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

if [[ "$ALLOW_MUTATION" != 1 || -z "$PEER" ]]; then
  usage >&2
  exit 2
fi

for command in curl jq ssh sha256sum systemctl pgrep flock ss ip readlink resolvectl; do
  command -v "$command" >/dev/null || {
    echo "missing required command: $command" >&2
    exit 2
  }
done

KOI_API="${KOI_API:-http://127.0.0.1:5641}"
KOI_SERVICE_SCOPE="${KOI_SERVICE_SCOPE:-system}"
case "$KOI_SERVICE_SCOPE" in
  system)
    KOI_SYSTEMCTL=(systemctl)
    DEFAULT_KOI_BREADCRUMB=/run/koi.endpoint
    ;;
  user)
    if ((EUID == 0)); then
      echo "KOI_SERVICE_SCOPE=user must run as the user who owns koi.service" >&2
      exit 2
    fi
    KOI_SYSTEMCTL=(systemctl --user)
    DEFAULT_KOI_BREADCRUMB="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/koi.endpoint"
    ;;
  *)
    echo "KOI_SERVICE_SCOPE must be 'system' or 'user'" >&2
    exit 2
    ;;
esac
KOI_BREADCRUMB="${KOI_BREADCRUMB:-$DEFAULT_KOI_BREADCRUMB}"
PEER_PORT="${PEER_PORT:-22}"
EVIDENCE_ROOT="${EVIDENCE_ROOT:-target/mdns-provider-transition}"
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-$$"
EVIDENCE_DIR="$EVIDENCE_ROOT/$RUN_ID"
SERVICE_TYPE="_koi-provider-gate._tcp"
KOI_NAME="koi-subject-$RUN_ID"
KOI_EXPLICIT_NAME="koi-explicit-$RUN_ID"
PEER_NAME=""
REMOTE_DIR="/tmp/koi-mdns-provider-$RUN_ID"
REMOTE_PID=""
REGULAR_ID=""
EXPLICIT_ID=""
SUBSCRIBE_PID=""
INITIAL_PID=""
INITIAL_HASH=""
CLEANING=0
RESOLVED_GLOBAL_ARMED=0
RESOLVED_LINK_ARMED=0
RESOLVED_DROPIN_DIR=/run/systemd/resolved.conf.d
RESOLVED_DROPIN="$RESOLVED_DROPIN_DIR/70-koi-provider-transition.conf"
RESOLVED_DROPIN_DIR_EXISTED=0

mkdir -p "$EVIDENCE_DIR"
exec 9>"$EVIDENCE_ROOT/.lock"
if ! flock -n 9; then
  echo "another mDNS provider transition gate is already running" >&2
  exit 2
fi

if ((EUID == 0)); then
  PRIV=()
else
  command -v sudo >/dev/null || {
    echo "run as root or install sudo for local service control" >&2
    exit 2
  }
  sudo -v
  PRIV=(sudo)
fi

SSH=(ssh -p "$PEER_PORT" -o BatchMode=yes -o ConnectTimeout=8)
if [[ -n "${PEER_IDENTITY:-}" ]]; then
  SSH+=(-i "$PEER_IDENTITY")
fi
SSH+=("$PEER")

PEER_HOST="${PEER#*@}"
LAN_LINK="$(ip -json route get "$PEER_HOST" | jq -r '.[0].dev // empty' 2>/dev/null || true)"
if [[ -z "$LAN_LINK" ]]; then
  echo "cannot determine the LAN interface used to reach $PEER_HOST" >&2
  exit 2
fi

unit_active() {
  systemctl is-active "$1" 2>/dev/null || true
}

unit_enabled() {
  systemctl is-enabled "$1" 2>/dev/null || true
}

koi_unit_active() {
  "${KOI_SYSTEMCTL[@]}" is-active koi.service 2>/dev/null || true
}

koi_unit_enabled() {
  "${KOI_SYSTEMCTL[@]}" is-enabled koi.service 2>/dev/null || true
}

restore_active() {
  local unit="$1" baseline="$2"
  if [[ "$baseline" == active || "$baseline" == activating ]]; then
    "${PRIV[@]}" systemctl start "$unit"
  else
    "${PRIV[@]}" systemctl stop "$unit"
  fi
}

resolved_global_mdns() {
  resolvectl mdns 2>/dev/null | awk '$1 == "Global:" {print $2; exit}' || true
}

resolved_link_mdns() {
  local link="$1"
  resolvectl mdns 2>/dev/null \
    | awk -v target="($link):" '$3 == target {print $4; exit}' || true
}

arm_resolved_for_gate() {
  case "$BASE_RESOLVED_GLOBAL_MDNS" in
    yes|resolve) ;;
    no)
      if "${PRIV[@]}" test -e "$RESOLVED_DROPIN"; then
        echo "refusing to replace existing resolved gate drop-in: $RESOLVED_DROPIN" >&2
        return 1
      fi
      if "${PRIV[@]}" test -d "$RESOLVED_DROPIN_DIR"; then
        RESOLVED_DROPIN_DIR_EXISTED=1
      fi
      RESOLVED_GLOBAL_ARMED=1
      "${PRIV[@]}" install -d -m 0755 "$RESOLVED_DROPIN_DIR"
      printf '[Resolve]\nMulticastDNS=yes\n' \
        | "${PRIV[@]}" tee "$RESOLVED_DROPIN" >/dev/null
      "${PRIV[@]}" systemctl restart systemd-resolved.service
      ;;
    *)
      echo "cannot safely arm unknown resolved global mDNS mode: ${BASE_RESOLVED_GLOBAL_MDNS:-empty}" >&2
      return 1
      ;;
  esac

  case "$BASE_RESOLVED_LINK_MDNS" in
    yes|resolve) ;;
    no)
      RESOLVED_LINK_ARMED=1
      "${PRIV[@]}" resolvectl mdns "$LAN_LINK" yes
      ;;
    *)
      echo "cannot safely arm unknown resolved mDNS mode for $LAN_LINK: ${BASE_RESOLVED_LINK_MDNS:-empty}" >&2
      return 1
      ;;
  esac
}

start_resolved_for_gate() {
  restore_active systemd-resolved.service "$BASE_RESOLVED_ACTIVE"
  if [[ "$RESOLVED_LINK_ARMED" == 1 ]]; then
    "${PRIV[@]}" resolvectl mdns "$LAN_LINK" yes
  fi
}

restore_resolved_baseline() {
  if [[ "$RESOLVED_GLOBAL_ARMED" == 1 ]]; then
    "${PRIV[@]}" rm -f "$RESOLVED_DROPIN"
    if [[ "$RESOLVED_DROPIN_DIR_EXISTED" == 0 ]]; then
      "${PRIV[@]}" rmdir "$RESOLVED_DROPIN_DIR" 2>/dev/null || true
    fi
    if [[ "$BASE_RESOLVED_ACTIVE" == active || "$BASE_RESOLVED_ACTIVE" == activating ]]; then
      "${PRIV[@]}" systemctl restart systemd-resolved.service
    else
      "${PRIV[@]}" systemctl stop systemd-resolved.service
    fi
  else
    restore_active systemd-resolved.service "$BASE_RESOLVED_ACTIVE"
  fi
  if [[ "$RESOLVED_LINK_ARMED" == 1 \
     && ( "$BASE_RESOLVED_ACTIVE" == active || "$BASE_RESOLVED_ACTIVE" == activating ) ]]; then
    "${PRIV[@]}" resolvectl mdns "$LAN_LINK" "$BASE_RESOLVED_LINK_MDNS"
  fi
}

status_json() {
  curl -fsS --max-time 5 "$KOI_API/v1/status"
}

mdns_status() {
  status_json | jq -c '.capabilities[] | select(.name == "mdns")'
}

token() {
  "${PRIV[@]}" awk -F: '$1 == "dat" {sub(/^dat:/, ""); print; exit}' "$KOI_BREADCRUMB"
}

koi_pid() {
  "${KOI_SYSTEMCTL[@]}" show koi.service --property MainPID --value
}

assert_single_koi() {
  local pid hash
  pid="$(koi_pid)"
  [[ "$pid" =~ ^[1-9][0-9]*$ ]] || {
    echo "installed $KOI_SERVICE_SCOPE koi.service has no live MainPID" >&2
    return 1
  }
  mapfile -t koi_pids < <(pgrep -x koi || true)
  if ((${#koi_pids[@]} != 1)) || [[ "${koi_pids[0]:-}" != "$pid" ]]; then
    echo "expected exactly one koi process (service PID $pid), saw: ${koi_pids[*]:-none}" >&2
    return 1
  fi
  hash="$("${PRIV[@]}" sha256sum "/proc/$pid/exe" | awk '{print $1}')"
  if [[ -n "$INITIAL_PID" && "$pid" != "$INITIAL_PID" ]]; then
    echo "Koi restarted during provider transition: $INITIAL_PID -> $pid" >&2
    return 1
  fi
  if [[ -n "$INITIAL_HASH" && "$hash" != "$INITIAL_HASH" ]]; then
    echo "Koi executable changed during provider transition" >&2
    return 1
  fi
}

snapshot() {
  local label="$1"
  {
    echo "label=$label"
    echo "utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "koi_pid=$(koi_pid)"
    echo "koi_hash=$INITIAL_HASH"
    echo "koi_scope=$KOI_SERVICE_SCOPE"
    echo "koi_active=$(koi_unit_active)"
    echo "avahi_service_active=$(unit_active avahi-daemon.service)"
    echo "avahi_socket_active=$(unit_active avahi-daemon.socket)"
    echo "resolved_active=$(unit_active systemd-resolved.service)"
    echo "resolved_global_mdns=$(resolved_global_mdns)"
    echo "resolved_${LAN_LINK}_mdns=$(resolved_link_mdns "$LAN_LINK")"
    echo "mdns=$(mdns_status)"
    echo "udp_5353:"
    "${PRIV[@]}" ss -H -lunp 'sport = :5353' || true
  } >"$EVIDENCE_DIR/$label.txt"
}

await_plan() {
  local label="$1" pattern="$2" deadline=$((SECONDS + 30)) status
  while ((SECONDS < deadline)); do
    status="$(mdns_status 2>/dev/null || true)"
    if jq -r '.summary' <<<"$status" | grep -Eq "$pattern"; then
      printf '%s\n' "$status" >"$EVIDENCE_DIR/$label-status.json"
      return 0
    fi
    sleep 1
  done
  printf '%s\n' "${status:-unavailable}" >"$EVIDENCE_DIR/$label-status.json"
  echo "timed out waiting for provider plan /$pattern/: ${status:-unavailable}" >&2
  return 1
}

heartbeat() {
  local auth id
  auth="$(token)"
  for id in "$REGULAR_ID" "$EXPLICIT_ID"; do
    [[ -z "$id" ]] || curl -fsS --max-time 5 -X PUT \
      -H "x-koi-token: $auth" "$KOI_API/v1/mdns/heartbeat/$id" >/dev/null
  done
}

peer_observes_subject() {
  local label="$1" output
  output="$("${SSH[@]}" timeout 20 avahi-browse -prt "$SERVICE_TYPE" 2>&1 || true)"
  printf '%s\n' "$output" >"$EVIDENCE_DIR/$label-peer-browse.txt"
  grep -Fq "$KOI_NAME" <<<"$output" || {
    echo "peer did not observe ordinary Koi publication during $label" >&2
    return 1
  }
  grep -Fq "$KOI_EXPLICIT_NAME" <<<"$output" || {
    echo "peer did not observe explicit-address Koi publication during $label" >&2
    return 1
  }
}

subject_resolves_peer() {
  local label="$1" instance deadline response
  instance="$PEER_NAME.$SERVICE_TYPE.local."
  deadline=$((SECONDS + 25))
  while ((SECONDS < deadline)); do
    response="$(curl -GsS --max-time 8 "$KOI_API/v1/mdns/resolve" \
      --data-urlencode "name=$instance" 2>&1 || true)"
    if jq -e --arg name "$PEER_NAME" '.resolved.name == $name' <<<"$response" >/dev/null 2>&1; then
      printf '%s\n' "$response" >"$EVIDENCE_DIR/$label-subject-resolve.json"
      return 0
    fi
    sleep 1
  done
  printf '%s\n' "${response:-unavailable}" >"$EVIDENCE_DIR/$label-subject-resolve.json"
  echo "Koi did not resolve the peer publication during $label" >&2
  return 1
}

await_subscription() {
  local name="$1" event="${2:-}" deadline=$((SECONDS + 20))
  while ((SECONDS < deadline)); do
    if grep -F "$name" "$EVIDENCE_DIR/subject-subscription.sse" \
      | grep -Fq "$event"; then
      return 0
    fi
    sleep 1
  done
  echo "long-lived Koi subscription did not observe '$event' for $name" >&2
  return 1
}

assert_phase() {
  local label="$1" pattern="$2"
  await_plan "$label" "$pattern"
  assert_single_koi
  heartbeat
  PEER_NAME="koi-peer-$label-$RUN_ID"
  remote_start_publisher
  peer_observes_subject "$label"
  subject_resolves_peer "$label"
  await_subscription "$PEER_NAME"
  if ! mdns_status | jq -e '.healthy == true' >/dev/null; then
    echo "mDNS did not become healthy after explicit peer traffic during $label" >&2
    return 1
  fi
  kill -0 "$SUBSCRIBE_PID"
  snapshot "$label"
  remote_stop_publisher
  await_subscription "$PEER_NAME" 'removed'
  echo "PASS $label"
}

remote_start_publisher() {
  "${SSH[@]}" sh -s -- "$REMOTE_DIR" "$PEER_NAME" "$SERVICE_TYPE" "$RUN_ID" <<'REMOTE'
set -eu
dir="$1" name="$2" service_type="$3" run_id="$4"
command -v avahi-publish-service >/dev/null
command -v avahi-browse >/dev/null
umask 077
mkdir "$dir"
nohup avahi-publish-service "$name" "$service_type" 43192 "run=$run_id" "side=peer" \
  >"$dir/publish.log" 2>&1 </dev/null &
pid=$!
printf '%s\n' "$pid" >"$dir/pid"
sleep 1
kill -0 "$pid"
REMOTE
  REMOTE_PID="$("${SSH[@]}" awk 'NR == 1 {print; exit}' "$REMOTE_DIR/pid")"
  [[ "$REMOTE_PID" =~ ^[1-9][0-9]*$ ]]
}

remote_stop_publisher() {
  [[ -z "$REMOTE_PID" ]] && return 0
  "${SSH[@]}" sh -s -- "$REMOTE_DIR" "$REMOTE_PID" "$RUN_ID" <<'REMOTE' || true
set -eu
dir="$1" expected_pid="$2" run_id="$3"
actual_pid="$(awk 'NR == 1 {print; exit}' "$dir/pid" 2>/dev/null || true)"
if [ "$actual_pid" = "$expected_pid" ] && [ -r "/proc/$actual_pid/cmdline" ]; then
  cmdline="$(tr '\0' ' ' <"/proc/$actual_pid/cmdline")"
  case "$cmdline" in
    *avahi-publish-service*"$run_id"*) kill "$actual_pid" 2>/dev/null || true ;;
    *) echo "refusing to kill remote PID with unexpected identity: $cmdline" >&2; exit 1 ;;
  esac
fi
rm -f "$dir/pid" "$dir/publish.log"
rmdir "$dir" 2>/dev/null || true
REMOTE
  REMOTE_PID=""
}

unregister_subject() {
  local auth id
  auth="$(token 2>/dev/null || true)"
  [[ -z "$auth" ]] && return 0
  for id in "$REGULAR_ID" "$EXPLICIT_ID"; do
    [[ -z "$id" ]] || curl -fsS --max-time 5 -X DELETE \
      -H "x-koi-token: $auth" "$KOI_API/v1/mdns/unregister/$id" >/dev/null 2>&1 || true
  done
  REGULAR_ID=""
  EXPLICIT_ID=""
}

cleanup() {
  local exit_code=$?
  [[ "$CLEANING" == 1 ]] && return
  CLEANING=1
  trap - EXIT INT TERM
  [[ -z "$SUBSCRIBE_PID" ]] || kill "$SUBSCRIBE_PID" 2>/dev/null || true
  unregister_subject
  remote_stop_publisher
  restore_resolved_baseline || true
  restore_active avahi-daemon.socket "$BASE_AVAHI_SOCKET_ACTIVE" || true
  restore_active avahi-daemon.service "$BASE_AVAHI_SERVICE_ACTIVE" || true
  sleep 2
  {
    echo "exit_code=$exit_code"
    echo "koi_scope=$KOI_SERVICE_SCOPE"
    echo "koi_active=$(koi_unit_active)"
    echo "koi_enabled=$(koi_unit_enabled)"
    echo "avahi_service_active=$(unit_active avahi-daemon.service)"
    echo "avahi_socket_active=$(unit_active avahi-daemon.socket)"
    echo "resolved_active=$(unit_active systemd-resolved.service)"
    echo "resolved_global_mdns=$(resolved_global_mdns)"
    echo "resolved_${LAN_LINK}_mdns=$(resolved_link_mdns "$LAN_LINK")"
    echo "avahi_service_enabled=$(unit_enabled avahi-daemon.service)"
    echo "avahi_socket_enabled=$(unit_enabled avahi-daemon.socket)"
    echo "resolved_enabled=$(unit_enabled systemd-resolved.service)"
  } >"$EVIDENCE_DIR/final-restoration.txt"
  if [[ "$(unit_active avahi-daemon.service)" != "$BASE_AVAHI_SERVICE_ACTIVE" \
     || "$(unit_active avahi-daemon.socket)" != "$BASE_AVAHI_SOCKET_ACTIVE" \
     || "$(unit_active systemd-resolved.service)" != "$BASE_RESOLVED_ACTIVE" ]]; then
    echo "ERROR: provider service state did not restore to baseline; inspect $EVIDENCE_DIR" >&2
    exit_code=1
  fi
  if [[ "$(unit_enabled avahi-daemon.service)" != "$BASE_AVAHI_SERVICE_ENABLED" \
     || "$(unit_enabled avahi-daemon.socket)" != "$BASE_AVAHI_SOCKET_ENABLED" \
     || "$(unit_enabled systemd-resolved.service)" != "$BASE_RESOLVED_ENABLED" ]]; then
    echo "ERROR: provider enablement changed; inspect $EVIDENCE_DIR" >&2
    exit_code=1
  fi
  if [[ "$(resolved_global_mdns)" != "$BASE_RESOLVED_GLOBAL_MDNS" \
     || "$(resolved_link_mdns "$LAN_LINK")" != "$BASE_RESOLVED_LINK_MDNS" ]]; then
    echo "ERROR: resolved mDNS configuration did not restore to baseline; inspect $EVIDENCE_DIR" >&2
    exit_code=1
  fi
  if [[ "$(koi_unit_active)" != "$BASE_KOI_ACTIVE" \
     || "$(koi_unit_enabled)" != "$BASE_KOI_ENABLED" ]]; then
    echo "ERROR: installed Koi unit state did not match baseline; inspect $EVIDENCE_DIR" >&2
    exit_code=1
  fi
  assert_single_koi || exit_code=1
  echo "Evidence: $EVIDENCE_DIR"
  exit "$exit_code"
}

BASE_AVAHI_SERVICE_ACTIVE="$(unit_active avahi-daemon.service)"
BASE_AVAHI_SOCKET_ACTIVE="$(unit_active avahi-daemon.socket)"
BASE_RESOLVED_ACTIVE="$(unit_active systemd-resolved.service)"
BASE_AVAHI_SERVICE_ENABLED="$(unit_enabled avahi-daemon.service)"
BASE_AVAHI_SOCKET_ENABLED="$(unit_enabled avahi-daemon.socket)"
BASE_RESOLVED_ENABLED="$(unit_enabled systemd-resolved.service)"
BASE_RESOLVED_GLOBAL_MDNS="$(resolved_global_mdns)"
BASE_RESOLVED_LINK_MDNS="$(resolved_link_mdns "$LAN_LINK")"
BASE_KOI_ACTIVE="$(koi_unit_active)"
BASE_KOI_ENABLED="$(koi_unit_enabled)"
trap cleanup EXIT INT TERM

if [[ "$BASE_KOI_ACTIVE" != active ]]; then
  echo "installed $KOI_SERVICE_SCOPE koi.service must be active at baseline" >&2
  exit 2
fi

if [[ "$BASE_AVAHI_SERVICE_ACTIVE" != active \
   || "$BASE_AVAHI_SOCKET_ACTIVE" != active \
   || "$BASE_RESOLVED_ACTIVE" != active ]]; then
  echo "this Linux transition profile requires active Avahi service/socket and systemd-resolved at baseline" >&2
  exit 2
fi

curl -fsS --max-time 5 "$KOI_API/healthz" >/dev/null
"${SSH[@]}" 'command -v avahi-publish-service >/dev/null && command -v avahi-browse >/dev/null'
INITIAL_PID="$(koi_pid)"
[[ "$INITIAL_PID" =~ ^[1-9][0-9]*$ ]]
INITIAL_HASH="$("${PRIV[@]}" sha256sum "/proc/$INITIAL_PID/exe" | awk '{print $1}')"
assert_single_koi
{
  echo "run_id=$RUN_ID"
  echo "subject=$(hostname)"
  echo "peer=$PEER"
  echo "koi_scope=$KOI_SERVICE_SCOPE"
  echo "koi_pid=$INITIAL_PID"
  echo "koi_hash=$INITIAL_HASH"
  echo "koi_executable=$("${PRIV[@]}" readlink -f "/proc/$INITIAL_PID/exe")"
  echo "koi_active=$BASE_KOI_ACTIVE"
  echo "koi_enabled=$BASE_KOI_ENABLED"
  echo "avahi_service_active=$BASE_AVAHI_SERVICE_ACTIVE"
  echo "avahi_service_enabled=$BASE_AVAHI_SERVICE_ENABLED"
  echo "avahi_socket_active=$BASE_AVAHI_SOCKET_ACTIVE"
  echo "avahi_socket_enabled=$BASE_AVAHI_SOCKET_ENABLED"
  echo "resolved_active=$BASE_RESOLVED_ACTIVE"
  echo "resolved_enabled=$BASE_RESOLVED_ENABLED"
  echo "resolved_global_mdns=$BASE_RESOLVED_GLOBAL_MDNS"
  echo "resolved_${LAN_LINK}_mdns=$BASE_RESOLVED_LINK_MDNS"
} >"$EVIDENCE_DIR/baseline.txt"
snapshot baseline

arm_resolved_for_gate

AUTH="$(token)"
[[ -n "$AUTH" ]] || {
  echo "no DAT found in $KOI_BREADCRUMB" >&2
  exit 1
}
LOCAL_IP="$(ip -json route get "${PEER#*@}" | jq -r '.[0].prefsrc // empty' 2>/dev/null || true)"
[[ -n "$LOCAL_IP" ]] || LOCAL_IP="$(hostname -I | awk '{print $1}')"

register_subject() {
  local name="$1" explicit_ip="${2:-}" payload response
  payload="$(jq -n \
    --arg name "$name" \
    --arg type "$SERVICE_TYPE" \
    --arg run "$RUN_ID" \
    --arg ip "$explicit_ip" \
    '{name:$name, type:$type, port:43191, lease_secs:600,
      txt:{run:$run, side:"subject"}}
      + (if $ip == "" then {} else {ip:$ip} end)')"
  response="$(curl -fsS --max-time 8 -X POST \
    -H "x-koi-token: $AUTH" -H 'content-type: application/json' \
    --data "$payload" "$KOI_API/v1/mdns/announce")"
  jq -er '.registered.id' <<<"$response"
}

REGULAR_ID="$(register_subject "$KOI_NAME")"
EXPLICIT_ID="$(register_subject "$KOI_EXPLICIT_NAME" "$LOCAL_IP")"
curl -GsSN "$KOI_API/v1/mdns/subscribe" \
  --data-urlencode "type=$SERVICE_TYPE" --data-urlencode 'idle_for=0' \
  >"$EVIDENCE_DIR/subject-subscription.sse" 2>"$EVIDENCE_DIR/subject-subscription.err" &
SUBSCRIBE_PID=$!

assert_phase avahi 'provider avahi \('

"${PRIV[@]}" systemctl stop avahi-daemon.service avahi-daemon.socket
assert_phase resolved-native 'provider systemd-resolved\+native \('

"${PRIV[@]}" systemctl stop systemd-resolved.service
assert_phase native-only 'provider native \('

start_resolved_for_gate
assert_phase resolved-restored 'provider systemd-resolved\+native \('

restore_active avahi-daemon.socket "$BASE_AVAHI_SOCKET_ACTIVE"
restore_active avahi-daemon.service "$BASE_AVAHI_SERVICE_ACTIVE"
assert_phase avahi-restored 'provider avahi \('

unregister_subject
remote_stop_publisher
sleep 3
if "${SSH[@]}" timeout 8 avahi-browse -prt "$SERVICE_TYPE" 2>&1 \
  | grep -Fq "$KOI_NAME"; then
  echo "peer retained the withdrawn Koi publication" >&2
  exit 1
fi
snapshot completed
echo "PASS installed-service provider transition gate"
