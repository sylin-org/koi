#!/usr/bin/env bash
# ADR-039 installed-service, two-host provider transition gate.
#
# The subject is the machine running this script. It keeps the one installed Koi
# service alive while Avahi and systemd-resolved are removed/restored underneath
# it. The peer contributes its one installed Koi service, so every publication,
# browse, resolve, and withdrawal crosses both the LAN and a real Koi boundary.
# This script never starts a Koi process and never mutates the peer's providers.
set -Eeuo pipefail

usage() {
  cat <<'EOF'
Usage: mdns-provider-transition.sh --allow-system-mutation --peer USER@HOST

Required:
  --allow-system-mutation  Acknowledge temporary provider configuration and
                           service changes with exact restoration.
  --peer USER@HOST         Independent LAN host with one installed Koi service.

Optional environment:
  KOI_API                  Installed Koi API (default http://127.0.0.1:5641)
  KOI_SERVICE_SCOPE        Installed unit scope: system or user (default system)
  KOI_BREADCRUMB           Endpoint breadcrumb (default follows service scope)
  PEER_KOI_API             Peer-local Koi API (default http://127.0.0.1:5641)
  PEER_KOI_SERVICE_SCOPE   Peer unit scope: system or user (default system)
  PEER_KOI_BREADCRUMB      Peer breadcrumb (default follows peer service scope)
  PEER_SUDO_ASKPASS        Executable askpass helper already present on the peer
  PEER_PORT                SSH port (default 22)
  PEER_IDENTITY            SSH identity file
  PEER_KNOWN_HOSTS         Pinned OpenSSH known-hosts file
  PEER_SSH_ASKPASS         Executable SSH askpass helper (otherwise key-only)
  SUDO_ASKPASS             Standard non-interactive sudo credential helper
  EVIDENCE_ROOT            Evidence parent (default target/mdns-provider-transition)

Run on the real subject host, not in a container. The caller needs privilege to
control local system services and preconfigured SSH authentication to the peer.
The peer login must be able to read its breadcrumb and hash its running service
executable directly, through passwordless sudo, or through PEER_SUDO_ASKPASS.
Secrets never leave the peer.
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
PEER_KOI_API="${PEER_KOI_API:-http://127.0.0.1:5641}"
PEER_KOI_SERVICE_SCOPE="${PEER_KOI_SERVICE_SCOPE:-system}"
case "$PEER_KOI_SERVICE_SCOPE" in
  system) DEFAULT_PEER_KOI_BREADCRUMB=/run/koi.endpoint ;;
  user) DEFAULT_PEER_KOI_BREADCRUMB=auto-user ;;
  *)
    echo "PEER_KOI_SERVICE_SCOPE must be 'system' or 'user'" >&2
    exit 2
    ;;
esac
PEER_KOI_BREADCRUMB="${PEER_KOI_BREADCRUMB:-$DEFAULT_PEER_KOI_BREADCRUMB}"
PEER_SUDO_ASKPASS="${PEER_SUDO_ASKPASS:-}"
PEER_PORT="${PEER_PORT:-22}"
EVIDENCE_ROOT="${EVIDENCE_ROOT:-target/mdns-provider-transition}"
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-$$"
EVIDENCE_DIR="$EVIDENCE_ROOT/$RUN_ID"
SERVICE_TYPE="_koi-gate._tcp"
KOI_NAME="koi-subject-$RUN_ID"
KOI_EXPLICIT_NAME="koi-explicit-$RUN_ID"
PEER_NAME=""
PEER_REGISTRATION_ID=""
REGULAR_ID=""
EXPLICIT_ID=""
SUBSCRIBE_PID=""
INITIAL_PID=""
INITIAL_HASH=""
LAST_GENERATION=-1
PEER_BASELINE=""
CLEANING=0
AVAHI_RUNTIME_MASKED=0
RESOLVED_GLOBAL_ARMED=0
RESOLVED_LINK_ARMED=0
RESOLVED_BASELINE_RESTORED=0
RESOLVED_DROPIN_DIR=/run/systemd/resolved.conf.d
RESOLVED_DROPIN="$RESOLVED_DROPIN_DIR/70-koi-provider-transition.conf"
RESOLVED_DROPIN_DIR_EXISTED=0
RESOLVED_RUNTIME_MASKED=0
RESOLVED_TRIGGER_UNITS=()
declare -A BASE_RESOLVED_TRIGGER_ACTIVE=()
declare -A BASE_RESOLVED_TRIGGER_ENABLED=()

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

SSH=(ssh -p "$PEER_PORT" -o ConnectTimeout=8)
if [[ -n "${PEER_SSH_ASKPASS:-}" ]]; then
  command -v setsid >/dev/null || {
    echo "PEER_SSH_ASKPASS requires setsid" >&2
    exit 2
  }
  [[ -x "$PEER_SSH_ASKPASS" ]] || {
    echo "PEER_SSH_ASKPASS is not executable: $PEER_SSH_ASKPASS" >&2
    exit 2
  }
  SSH=(env SSH_ASKPASS_REQUIRE=force SSH_ASKPASS="$PEER_SSH_ASKPASS" DISPLAY=koi-lab \
    setsid -w "${SSH[@]}" -o BatchMode=no -o NumberOfPasswordPrompts=1)
else
  SSH+=(-o BatchMode=yes)
fi
if [[ -n "${PEER_IDENTITY:-}" ]]; then
  SSH+=(-i "$PEER_IDENTITY" -o IdentitiesOnly=yes)
fi
if [[ -n "${PEER_KNOWN_HOSTS:-}" ]]; then
  SSH+=(-o UserKnownHostsFile="$PEER_KNOWN_HOSTS" -o StrictHostKeyChecking=yes)
fi
SSH+=("$PEER")

peer_mutation() {
  local operation="$1"
  local askpass_arg="${PEER_SUDO_ASKPASS:--}"
  shift
  "${SSH[@]}" sh -s -- \
    "$operation" "$PEER_KOI_API" "$PEER_KOI_BREADCRUMB" \
    "$askpass_arg" "$@" <<'REMOTE'
set -eu
operation="$1"
api="$2"
breadcrumb="$3"
askpass="$4"
shift 4
if [ "$askpass" = - ]; then
  askpass=""
fi

if [ "$breadcrumb" = auto-user ]; then
  breadcrumb="/run/user/$(id -u)/koi.endpoint"
fi

read_token() {
  if [ -r "$breadcrumb" ]; then
    awk -F: '$1 == "dat" {sub(/^dat:/, ""); print; exit}' "$breadcrumb"
  elif [ -n "$askpass" ]; then
    [ -x "$askpass" ] || {
      echo "peer askpass helper is not executable: $askpass" >&2
      return 1
    }
    SUDO_ASKPASS="$askpass" sudo -A awk -F: \
      '$1 == "dat" {sub(/^dat:/, ""); print; exit}' "$breadcrumb"
  else
    sudo -n awk -F: '$1 == "dat" {sub(/^dat:/, ""); print; exit}' "$breadcrumb"
  fi
}

case "$operation" in
  probe)
    for command in curl jq sha256sum systemctl pgrep awk; do
      command -v "$command" >/dev/null || {
        echo "peer is missing required command: $command" >&2
        exit 2
      }
    done
    token="$(read_token)"
    [ -n "$token" ]
    curl -fsS --max-time 5 "$api/healthz" >/dev/null
    curl -fsS --max-time 5 "$api/v1/mdns/admin/status" >/dev/null
    ;;
  register)
    name="$1"
    service_type="$2"
    run_id="$3"
    token="$(read_token)"
    payload="$(jq -n \
      --arg name "$name" --arg type "$service_type" --arg run "$run_id" \
      '{name:$name, type:$type, port:43192, lease_secs:600,
        txt:{run:$run, side:"peer-koi"}}')"
    curl -fsS --max-time 8 -X POST \
      -H "x-koi-token: $token" -H 'content-type: application/json' \
      --data "$payload" "$api/v1/mdns/announce"
    ;;
  unregister)
    id="$1"
    token="$(read_token)"
    curl -fsS --max-time 8 -X DELETE \
      -H "x-koi-token: $token" "$api/v1/mdns/unregister/$id" >/dev/null
    ;;
  *)
    echo "unknown peer mutation: $operation" >&2
    exit 2
    ;;
esac
REMOTE
}

peer_status() {
  "${SSH[@]}" curl -fsS --max-time 5 \
    "$PEER_KOI_API/v1/mdns/admin/status"
}

peer_resolve() {
  local instance="$1"
  "${SSH[@]}" curl -GsS --max-time 8 \
    "$PEER_KOI_API/v1/mdns/resolve" --data-urlencode "name=$instance"
}

peer_control_facts() {
  local askpass_arg="${PEER_SUDO_ASKPASS:--}"
  "${SSH[@]}" sh -s -- "$PEER_KOI_SERVICE_SCOPE" "$askpass_arg" <<'REMOTE'
set -eu
scope="$1"
askpass="$2"
if [ "$askpass" = - ]; then
  askpass=""
fi

sha256_process_executable() {
  process_path="$1"
  if sha256sum "$process_path" 2>/dev/null; then
    return
  fi
  if [ -n "$askpass" ]; then
    [ -x "$askpass" ] || {
      echo "peer askpass helper is not executable: $askpass" >&2
      return 1
    }
    SUDO_ASKPASS="$askpass" sudo -A sha256sum "$process_path"
  else
    sudo -n sha256sum "$process_path"
  fi
}

if [ "$scope" = user ]; then
  ctl() { systemctl --user "$@"; }
else
  ctl() { systemctl "$@"; }
fi
pid="$(ctl show koi.service --property MainPID --value)"
case "$pid" in
  ''|0|*[!0-9]*) echo "peer koi.service has no live MainPID" >&2; exit 1 ;;
esac
set -- $(pgrep -x koi || true)
[ "$#" -eq 1 ] && [ "$1" = "$pid" ] || {
  echo "expected exactly one peer Koi process (service PID $pid), saw: $*" >&2
  exit 1
}
printf 'koi_pid=%s\n' "$pid"
printf 'koi_hash=%s\n' "$(sha256_process_executable "/proc/$pid/exe" | awk '{print $1}')"
printf 'koi_active=%s\n' "$(ctl is-active koi.service 2>/dev/null || true)"
printf 'koi_enabled=%s\n' "$(ctl is-enabled koi.service 2>/dev/null || true)"
for unit in avahi-daemon.service avahi-daemon.socket systemd-resolved.service; do
  printf '%s_active=%s\n' "$unit" "$(systemctl is-active "$unit" 2>/dev/null || true)"
  printf '%s_enabled=%s\n' "$unit" "$(systemctl is-enabled "$unit" 2>/dev/null || true)"
done
REMOTE
}

assert_peer_koi_unchanged() {
  local facts
  facts="$(peer_control_facts)"
  if [[ -n "$PEER_BASELINE" && "$facts" != "$PEER_BASELINE" ]]; then
    printf '%s\n' "$facts" >"$EVIDENCE_DIR/peer-current.txt"
    echo "peer Koi or provider service state changed; compare peer-baseline.txt" >&2
    return 1
  fi
}

PEER_HOST="${PEER#*@}"
LAN_LINK="$(ip -json route get "$PEER_HOST" | jq -r '.[0].dev // empty' 2>/dev/null || true)"
if [[ -z "$LAN_LINK" ]]; then
  echo "cannot determine the LAN interface used to reach $PEER_HOST" >&2
  exit 2
fi
for unit in systemd-resolved-varlink.socket systemd-resolved-monitor.socket; do
  if [[ "$(systemctl show "$unit" -p LoadState --value 2>/dev/null || true)" == loaded ]]; then
    RESOLVED_TRIGGER_UNITS+=("$unit")
  fi
done

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

stop_avahi_for_gate() {
  # The service requires the socket, and the socket can activate the service.
  # Mask both activation paths first, then stop them in dependency order.
  AVAHI_RUNTIME_MASKED=1
  "${PRIV[@]}" systemctl --runtime mask \
    avahi-daemon.service avahi-daemon.socket
  "${PRIV[@]}" systemctl stop avahi-daemon.service
  "${PRIV[@]}" systemctl stop avahi-daemon.socket
}

restore_avahi_baseline() {
  if [[ "$AVAHI_RUNTIME_MASKED" == 1 ]]; then
    "${PRIV[@]}" systemctl --runtime unmask \
      avahi-daemon.service avahi-daemon.socket
    AVAHI_RUNTIME_MASKED=0
  fi
  restore_active avahi-daemon.socket "$BASE_AVAHI_SOCKET_ACTIVE"
  restore_active avahi-daemon.service "$BASE_AVAHI_SERVICE_ACTIVE"
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
  RESOLVED_BASELINE_RESTORED=0
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

restore_resolved_triggers() {
  local unit
  for unit in "${RESOLVED_TRIGGER_UNITS[@]}"; do
    restore_active "$unit" "${BASE_RESOLVED_TRIGGER_ACTIVE[$unit]}"
  done
}

start_resolved_for_gate() {
  unmask_resolved_for_gate
  restore_active systemd-resolved.service "$BASE_RESOLVED_ACTIVE"
  restore_resolved_triggers
  if [[ "$RESOLVED_LINK_ARMED" == 1 ]]; then
    "${PRIV[@]}" resolvectl mdns "$LAN_LINK" yes
  fi
}

stop_resolved_for_gate() {
  RESOLVED_RUNTIME_MASKED=1
  "${PRIV[@]}" systemctl --runtime mask --now \
    "${RESOLVED_TRIGGER_UNITS[@]}" systemd-resolved.service
}

unmask_resolved_for_gate() {
  if [[ "$RESOLVED_RUNTIME_MASKED" == 1 ]]; then
    "${PRIV[@]}" systemctl --runtime unmask \
      "${RESOLVED_TRIGGER_UNITS[@]}" systemd-resolved.service
    RESOLVED_RUNTIME_MASKED=0
  fi
}

restore_resolved_baseline() {
  if [[ "$RESOLVED_BASELINE_RESTORED" == 1 ]]; then
    return 0
  fi
  unmask_resolved_for_gate
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
  restore_resolved_triggers
  if [[ "$RESOLVED_LINK_ARMED" == 1 \
     && ( "$BASE_RESOLVED_ACTIVE" == active || "$BASE_RESOLVED_ACTIVE" == activating ) ]]; then
    "${PRIV[@]}" resolvectl mdns "$LAN_LINK" "$BASE_RESOLVED_LINK_MDNS"
  fi
  RESOLVED_GLOBAL_ARMED=0
  RESOLVED_LINK_ARMED=0
  RESOLVED_BASELINE_RESTORED=1
}

require_unit_activity() {
  local unit="$1" expected="$2" actual
  actual="$(unit_active "$unit")"
  if [[ "$actual" != "$expected" ]]; then
    echo "provider lifecycle expected $unit to be $expected, got $actual" >&2
    return 1
  fi
}

require_resolved_baseline() {
  local global link
  global="$(resolved_global_mdns)"
  link="$(resolved_link_mdns "$LAN_LINK")"
  if [[ "$global" != "$BASE_RESOLVED_GLOBAL_MDNS" \
     || "$link" != "$BASE_RESOLVED_LINK_MDNS" ]]; then
    echo "resolved mDNS must match baseline before Avahi starts (global=$global, $LAN_LINK=$link)" >&2
    return 1
  fi
}

# Own external provider mutation as a break-before-make lifecycle. Avahi and
# resolved are host responders, not inert route flags: enabling both can put
# either daemon into hostname-conflict recovery before Koi makes a route choice.
# Route assertions intentionally remain in assert_phase() below.
enter_provider_phase() {
  local phase="$1"
  case "$phase" in
    avahi)
      require_unit_activity avahi-daemon.service active
      require_unit_activity avahi-daemon.socket active
      ;;
    resolved)
      stop_avahi_for_gate
      require_unit_activity avahi-daemon.service inactive
      require_unit_activity avahi-daemon.socket inactive
      arm_resolved_for_gate
      require_unit_activity systemd-resolved.service active
      ;;
    native)
      require_unit_activity avahi-daemon.service inactive
      require_unit_activity avahi-daemon.socket inactive
      stop_resolved_for_gate
      require_unit_activity systemd-resolved.service inactive
      ;;
    resolved-restored)
      require_unit_activity avahi-daemon.service inactive
      require_unit_activity avahi-daemon.socket inactive
      start_resolved_for_gate
      require_unit_activity systemd-resolved.service active
      ;;
    avahi-restored)
      # Remove every gate-owned resolved announcement before Avahi rejoins the
      # network. A baseline that already enabled both is preserved verbatim.
      restore_resolved_baseline
      require_resolved_baseline
      restore_avahi_baseline
      require_unit_activity avahi-daemon.socket "$BASE_AVAHI_SOCKET_ACTIVE"
      require_unit_activity avahi-daemon.service "$BASE_AVAHI_SERVICE_ACTIVE"
      ;;
    *)
      echo "unknown provider lifecycle phase: $phase" >&2
      return 2
      ;;
  esac
}

mdns_status() {
  curl -fsS --max-time 5 "$KOI_API/v1/mdns/admin/status" \
    | jq -c '.control_plane'
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
  mdns_status | jq . >"$EVIDENCE_DIR/$label-control-plane.json"
  peer_status | jq . >"$EVIDENCE_DIR/$label-peer-status.json"
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
    for unit in "${RESOLVED_TRIGGER_UNITS[@]}"; do
      echo "${unit}_active=$(unit_active "$unit")"
    done
    echo "mdns_control_plane=$label-control-plane.json"
    echo "peer_mdns_status=$label-peer-status.json"
    echo "udp_5353:"
    "${PRIV[@]}" ss -H -lunp 'sport = :5353' || true
  } >"$EVIDENCE_DIR/$label.txt"
}

status_matches_routes() {
  local status="$1" publish="$2" explicit="$3" browse="$4" resolve="$5"
  jq -e \
    --arg publish "$publish" \
    --arg explicit "$explicit" \
    --arg browse "$browse" \
    --arg resolve "$resolve" '
      . as $root
      | ([.routes.publish, .routes.explicit_publish, .routes.browse,
           .routes.resolve] | map(select(. != null)) | unique) as $selected
      | .state == "ready"
        and .routes.publish == $publish
        and .routes.explicit_publish == $explicit
        and .routes.browse == $browse
        and (if $resolve == "none"
             then .routes.resolve == null
             else .routes.resolve == $resolve end)
        and .publications.desired == .publications.established
        and .publications.pending == 0
        and .publications.failed == 0
        and all($selected[]; . as $name
          | any($root.providers[];
              .name == $name
              and .availability == "ready"
              and .session == "ready"))
    ' <<<"$status" >/dev/null
}

await_routes() {
  local label="$1" publish="$2" explicit="$3" browse="$4" resolve="$5"
  local require_advance="${6:-1}" deadline=$((SECONDS + 60)) status generation
  while ((SECONDS < deadline)); do
    status="$(mdns_status 2>/dev/null || true)"
    if status_matches_routes "$status" "$publish" "$explicit" "$browse" "$resolve"; then
      generation="$(jq -r '.generation' <<<"$status")"
      if [[ "$require_advance" == 0 || "$generation" -gt "$LAST_GENERATION" ]]; then
        printf '%s\n' "$status" | jq . >"$EVIDENCE_DIR/$label-status.json"
        if [[ "$require_advance" == 1 ]]; then
          LAST_GENERATION="$generation"
        fi
        return 0
      fi
    fi
    sleep 1
  done
  printf '%s\n' "${status:-null}" | jq . >"$EVIDENCE_DIR/$label-status.json" 2>/dev/null \
    || printf '%s\n' "${status:-unavailable}" >"$EVIDENCE_DIR/$label-status.json"
  echo "timed out waiting for structured routes publish=$publish explicit=$explicit browse=$browse resolve=$resolve after generation $LAST_GENERATION" >&2
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
  local label="$1" response deadline=$((SECONDS + 30)) regular=0 explicit=0
  : >"$EVIDENCE_DIR/$label-peer-resolve.ndjson"
  while ((SECONDS < deadline)); do
    response="$(peer_resolve "$KOI_NAME.$SERVICE_TYPE.local." 2>&1 || true)"
    printf '%s\n' "$response" >>"$EVIDENCE_DIR/$label-peer-resolve.ndjson"
    jq -e --arg name "$KOI_NAME" '.resolved.name == $name' \
      <<<"$response" >/dev/null 2>&1 && regular=1
    response="$(peer_resolve "$KOI_EXPLICIT_NAME.$SERVICE_TYPE.local." 2>&1 || true)"
    printf '%s\n' "$response" >>"$EVIDENCE_DIR/$label-peer-resolve.ndjson"
    jq -e --arg name "$KOI_EXPLICIT_NAME" '.resolved.name == $name' \
      <<<"$response" >/dev/null 2>&1 && explicit=1
    if [[ "$regular" == 1 && "$explicit" == 1 ]]; then
      return 0
    fi
    sleep 1
  done
  if [[ "$regular" != 1 ]]; then
    echo "peer Koi did not resolve the subject publication during $label" >&2
  fi
  if [[ "$explicit" != 1 ]]; then
    echo "peer Koi did not resolve the explicit-address publication during $label" >&2
  fi
  return 1
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
    if [[ -z "$event" ]]; then
      grep -Fq "$name" "$EVIDENCE_DIR/subject-subscription.sse" && return 0
    elif grep -F "$name" "$EVIDENCE_DIR/subject-subscription.sse" \
      | grep -F "$event" >/dev/null; then
      return 0
    fi
    sleep 1
  done
  echo "long-lived Koi subscription did not observe '$event' for $name" >&2
  return 1
}

assert_phase() {
  local label="$1" publish="$2" explicit="$3" browse="$4" resolve="$5"
  await_routes "$label" "$publish" "$explicit" "$browse" "$resolve"
  assert_single_koi
  assert_peer_koi_unchanged
  heartbeat
  PEER_NAME="koi-peer-$label-$RUN_ID"
  remote_start_publisher
  peer_observes_subject "$label"
  subject_resolves_peer "$label"
  await_subscription "$PEER_NAME"
  if ! await_peer_synced "$label"; then
    return 1
  fi
  kill -0 "$SUBSCRIBE_PID"
  await_routes "$label-final" "$publish" "$explicit" "$browse" "$resolve" 0
  snapshot "$label"
  remote_stop_publisher
  await_subscription "$PEER_NAME" 'removed'
  echo "PASS $label"
}

remote_start_publisher() {
  local response
  response="$(peer_mutation register "$PEER_NAME" "$SERVICE_TYPE" "$RUN_ID")"
  printf '%s\n' "$response" >"$EVIDENCE_DIR/peer-register-$PEER_NAME.json"
  PEER_REGISTRATION_ID="$(jq -er '.registered.id' <<<"$response")"
}

remote_stop_publisher() {
  [[ -z "$PEER_REGISTRATION_ID" ]] && return 0
  if ! peer_mutation unregister "$PEER_REGISTRATION_ID"; then
    return 1
  fi
  PEER_REGISTRATION_ID=""
}

await_peer_synced() {
  local label="${1:-cleanup}" deadline=$((SECONDS + 30)) status
  while ((SECONDS < deadline)); do
    status="$(peer_status 2>/dev/null || true)"
    if jq -e '
        .control_plane.state == "ready"
        and .control_plane.publications.desired == .control_plane.publications.established
        and .control_plane.publications.pending == 0
        and .control_plane.publications.failed == 0
      ' <<<"$status" >/dev/null 2>&1; then
      printf '%s\n' "$status" | jq . \
        >"$EVIDENCE_DIR/$label-peer-synced-status.json"
      return 0
    fi
    sleep 1
  done
  printf '%s\n' "${status:-unavailable}" \
    >"$EVIDENCE_DIR/$label-peer-synced-status.json"
  echo "peer Koi did not return to a ready, synchronized control plane" >&2
  return 1
}

peer_rejects_withdrawn_subject() {
  local deadline=$((SECONDS + 30)) regular explicit
  while ((SECONDS < deadline)); do
    regular="$(peer_resolve "$KOI_NAME.$SERVICE_TYPE.local." 2>&1 || true)"
    explicit="$(peer_resolve "$KOI_EXPLICIT_NAME.$SERVICE_TYPE.local." 2>&1 || true)"
    if ! jq -e --arg name "$KOI_NAME" '.resolved.name == $name' \
        <<<"$regular" >/dev/null 2>&1 \
       && ! jq -e --arg name "$KOI_EXPLICIT_NAME" '.resolved.name == $name' \
        <<<"$explicit" >/dev/null 2>&1; then
      printf '%s\n%s\n' "$regular" "$explicit" \
        >"$EVIDENCE_DIR/peer-withdrawal.ndjson"
      return 0
    fi
    sleep 1
  done
  printf '%s\n%s\n' "$regular" "$explicit" \
    >"$EVIDENCE_DIR/peer-withdrawal.ndjson"
  echo "peer Koi retained a withdrawn subject publication" >&2
  return 1
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
  if ! remote_stop_publisher; then
    echo "ERROR: run-owned peer Koi registration did not clean up" >&2
    exit_code=1
  fi
  restore_resolved_baseline || true
  restore_avahi_baseline || true
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
    for unit in "${RESOLVED_TRIGGER_UNITS[@]}"; do
      echo "${unit}_active=$(unit_active "$unit")"
      echo "${unit}_enabled=$(unit_enabled "$unit")"
    done
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
  for unit in "${RESOLVED_TRIGGER_UNITS[@]}"; do
    if [[ "$(unit_active "$unit")" != "${BASE_RESOLVED_TRIGGER_ACTIVE[$unit]}" \
       || "$(unit_enabled "$unit")" != "${BASE_RESOLVED_TRIGGER_ENABLED[$unit]}" ]]; then
      echo "ERROR: resolved trigger $unit did not restore to baseline" >&2
      exit_code=1
    fi
  done
  if [[ "$(koi_unit_active)" != "$BASE_KOI_ACTIVE" \
     || "$(koi_unit_enabled)" != "$BASE_KOI_ENABLED" ]]; then
    echo "ERROR: installed Koi unit state did not match baseline; inspect $EVIDENCE_DIR" >&2
    exit_code=1
  fi
  assert_single_koi || exit_code=1
  await_peer_synced || exit_code=1
  peer_control_facts >"$EVIDENCE_DIR/peer-final.txt" || exit_code=1
  assert_peer_koi_unchanged || exit_code=1
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
for unit in "${RESOLVED_TRIGGER_UNITS[@]}"; do
  BASE_RESOLVED_TRIGGER_ACTIVE[$unit]="$(unit_active "$unit")"
  BASE_RESOLVED_TRIGGER_ENABLED[$unit]="$(unit_enabled "$unit")"
done
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
peer_mutation probe
INITIAL_PID="$(koi_pid)"
[[ "$INITIAL_PID" =~ ^[1-9][0-9]*$ ]]
INITIAL_HASH="$("${PRIV[@]}" sha256sum "/proc/$INITIAL_PID/exe" | awk '{print $1}')"
assert_single_koi
PEER_BASELINE="$(peer_control_facts)"
printf '%s\n' "$PEER_BASELINE" >"$EVIDENCE_DIR/peer-baseline.txt"
assert_peer_koi_unchanged
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
  for unit in "${RESOLVED_TRIGGER_UNITS[@]}"; do
    echo "${unit}_active=${BASE_RESOLVED_TRIGGER_ACTIVE[$unit]}"
    echo "${unit}_enabled=${BASE_RESOLVED_TRIGGER_ENABLED[$unit]}"
  done
} >"$EVIDENCE_DIR/baseline.txt"
snapshot baseline

AUTH="$(token)"
[[ -n "$AUTH" ]] || {
  echo "no DAT found in $KOI_BREADCRUMB" >&2
  exit 1
}
LOCAL_IP="$(ip -json route get "${PEER#*@}" | jq -r '.[0].prefsrc // empty' 2>/dev/null || true)"
[[ -n "$LOCAL_IP" ]] || LOCAL_IP="$(hostname -I | awk '{print $1}')"

register_subject() {
  local name="$1" explicit_ip="${2:-}" payload response http_code
  payload="$(jq -n \
    --arg name "$name" \
    --arg type "$SERVICE_TYPE" \
    --arg run "$RUN_ID" \
    --arg ip "$explicit_ip" \
    '{name:$name, type:$type, port:43191, lease_secs:600,
      txt:{run:$run, side:"subject"}}
      + (if $ip == "" then {} else {ip:$ip} end)')"
  response="$(curl -sS --max-time 8 -X POST \
    -H "x-koi-token: $AUTH" -H 'content-type: application/json' \
    --data "$payload" -w $'\n%{http_code}' "$KOI_API/v1/mdns/announce")"
  http_code="${response##*$'\n'}"
  response="${response%$'\n'*}"
  if [[ "$http_code" != 201 ]]; then
    printf '%s\n' "$response" >"$EVIDENCE_DIR/register-$name-error.json"
    echo "Koi registration '$name' failed with HTTP $http_code" >&2
    return 1
  fi
  jq -er '.registered.id' <<<"$response"
}

REGULAR_ID="$(register_subject "$KOI_NAME")"
EXPLICIT_ID="$(register_subject "$KOI_EXPLICIT_NAME" "$LOCAL_IP")"
curl -GsSN "$KOI_API/v1/mdns/subscribe" \
  --data-urlencode "type=$SERVICE_TYPE" --data-urlencode 'idle_for=0' \
  >"$EVIDENCE_DIR/subject-subscription.sse" 2>"$EVIDENCE_DIR/subject-subscription.err" &
SUBSCRIBE_PID=$!

enter_provider_phase avahi
assert_phase avahi avahi avahi avahi avahi

enter_provider_phase resolved
assert_phase resolved-native systemd-resolved native native systemd-resolved

enter_provider_phase native
assert_phase native-only native native native none

enter_provider_phase resolved-restored
assert_phase resolved-restored systemd-resolved native native systemd-resolved

enter_provider_phase avahi-restored
assert_phase avahi-restored avahi avahi avahi avahi

unregister_subject
remote_stop_publisher
peer_rejects_withdrawn_subject
snapshot completed
echo "PASS installed-service provider transition gate"
