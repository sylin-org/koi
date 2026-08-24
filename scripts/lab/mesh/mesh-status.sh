#!/bin/sh
# Mesh health collector (one host, one JSON evidence line per invocation).
# Appends to $ROOT/evidence.jsonl: service state, healthz, certmesh posture,
# and disk of the dogfood data root. Evidence, not assertion — a down daemon,
# a missing unit, or an unreachable endpoint still records a line (ADR-029:
# snapshots tolerate gaps; workstations may be absent).
#
# Runs ON a Linux mesh host. Stage it there and run under sh regardless of the
# account's login shell (RL-4/RL-5):
#   pscp -hostkey <key> mesh-status.sh user@host:/tmp/koi-mesh-status.sh
#   plink -batch -ssh -hostkey <key> user@host "sh -c 'sh /tmp/koi-mesh-status.sh'"
# The script removes itself when it finishes.
#
# Usage (on host): sh koi-mesh-status.sh [root]   # root defaults to ~/koi-dogfood
set -u

ROOT="${1:-$HOME/koi-dogfood}"
HTTP="http://127.0.0.1:5641"

# Self-cleanup only for the staged /tmp copy, never a repo checkout.
case "$0" in
  /tmp/*) trap 'rm -f -- "$0"' EXIT;;
esac

jstr() {
  # Minimal JSON string escaping for controlled values (hostnames, versions,
  # unit names): backslash and double quote only; everything else is passed.
  printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'
}

now=$(date -u +%Y-%m-%dT%H:%M:%SZ)
hostname_now=$(hostname 2>/dev/null || echo unknown)

# --- service shape -----------------------------------------------------------
# Server class runs a transient systemd unit; workstation class runs a plain
# user process with a pidfile (mesh-start-server.sh / mesh-start-user.sh).
units_json=""
if command -v systemctl >/dev/null 2>&1; then
  # 'koi*' (not 'koi-*') so a resurrected legacy unit shows up as drift.
  units=$(systemctl list-units --type=service --no-legend --plain 'koi*' 2>/dev/null \
    | awk '{gsub(/"/,""); printf "%s\"%s\":\"%s\"", sep, $1, $3; sep=","}')
  units_json="{$units}"
else
  units_json="{}"
fi

user_alive=false
pidfile="$ROOT/runtime/daemon.pid"
if [ -f "$pidfile" ]; then
  pid=$(cat "$pidfile" 2>/dev/null)
  case "$pid" in ''|*[!0-9]*) pid="";; esac
  if [ -n "$pid" ] && [ -d "/proc/$pid" ]; then
    exe=$(readlink -f "/proc/$pid/exe" 2>/dev/null || true)
    case "$exe" in
      "$ROOT"/koi) user_alive=true;;
    esac
  fi
fi

shape="absent"
case "$units_json" in
  *'"active"'*) shape="systemd";;
esac
if [ "$user_alive" = true ] && [ "$shape" = absent ]; then
  shape="user"
fi

# --- healthz -----------------------------------------------------------------
healthz=false
curl -sf --max-time 5 "$HTTP/healthz" >/dev/null 2>&1 && healthz=true

# --- certmesh status (token-free read, same as mesh-create-ca.sh) -------------
cm_ca_init="" ; cm_enroll="" ; cm_members="" ; cm_role="" ; cm_status=""
cm_json=$(curl -sf --max-time 5 "$HTTP/v1/certmesh/status" 2>/dev/null || true)
if [ -n "$cm_json" ] && command -v python3 >/dev/null 2>&1; then
  parsed=$(printf '%s' "$cm_json" | python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)
except Exception:
    sys.exit(0)
def b(v): return "true" if v else "false"
out = ["ca_initialized=" + b(d.get("ca_initialized", False)),
       "enrollment_open=" + b(d.get("enrollment_open", False)),
       "member_count=" + str(int(d.get("member_count", 0)))]
me = None
for m in d.get("members", []):
    if m.get("hostname") == sys.argv[1]:
        me = m
        break
if me is not None:
    out.append("role=" + str(me.get("role", "")))
    out.append("member_status=" + str(me.get("status", "")))
print("\n".join(out))
' "$hostname_now" 2>/dev/null) || parsed=""
  for kv in $parsed; do
    key=${kv%%=*}; val=${kv#*=}
    case "$key" in
      ca_initialized) cm_ca_init=$val ;;
      enrollment_open) cm_enroll=$val ;;
      member_count) cm_members=$val ;;
      role) cm_role=$val ;;
      member_status) cm_status=$val ;;
    esac
  done
fi

# --- disk of the data root ----------------------------------------------------
disk_avail="" ; disk_pct=""
if [ -d "$ROOT" ]; then
  dfline=$(df -Pm "$ROOT" 2>/dev/null | tail -n 1)
  # filesystem total used avail capacity mount
  disk_avail=$(printf '%s' "$dfline" | awk '{print $4}')
  disk_pct=$(printf '%s' "$dfline" | awk '{print $5}' | tr -d '%')
fi

# --- member posture (meaningful on members; empty on a CA-only primary) -------
# Local CSR custody + trust diagnosis, exactly like mesh-verify-member.sh.
m_custody=false ; m_overall="" ; m_healthy="" ; m_total=""
if [ -f "$ROOT/data/certs/$hostname_now/key.pem" ]; then
  m_custody=true
fi
diag=$(env KOI_DATA_DIR="$ROOT/data" KOI_DNS_ZONE=internal KOI_NO_CREDENTIAL_STORE=1 \
  "$ROOT/koi" trust diagnose --json 2>/dev/null || true)
if [ -n "$diag" ] && command -v python3 >/dev/null 2>&1; then
  dparsed=$(printf '%s' "$diag" | python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)
except Exception:
    sys.exit(0)
checks = d.get("checks", [])
healthy = sum(1 for c in checks if str(c.get("status", "")) in ("ok", "not_applicable"))
print("overall=" + str(d.get("overall", "")))
print("healthy=%d" % healthy)
print("total=%d" % len(checks))
' 2>/dev/null) || dparsed=""
  for kv in $dparsed; do
    key=${kv%%=*}; val=${kv#*=}
    case "$key" in
      overall) m_overall=$val ;;
      healthy) m_healthy=$val ;;
      total) m_total=$val ;;
    esac
  done
fi

# --- artifact identity --------------------------------------------------------
version=$("$ROOT/koi" --version 2>/dev/null | head -n 1 || true)

# --- one evidence line --------------------------------------------------------
cm_reachable=false
[ -n "$cm_json" ] && cm_reachable=true

line=$(printf '{"ts":"%s","host":"%s","shape":"%s","units":%s,"user_daemon_alive":%s,"healthz":%s,"certmesh":{"reachable":%s,"ca_initialized":%s,"enrollment_open":%s,"member_count":%s,"role":"%s","member_status":"%s"},"member":{"custody":%s,"overall":"%s","checks_healthy":%s,"checks_total":%s},"data_root":"%s","disk":{"avail_mb":%s,"used_pct":%s},"version":"%s"}' \
  "$now" \
  "$(jstr "$hostname_now")" \
  "$shape" \
  "$units_json" \
  "$user_alive" \
  "$healthz" \
  "$cm_reachable" \
  "${cm_ca_init:-null}" \
  "${cm_enroll:-null}" \
  "${cm_members:-null}" \
  "$(jstr "$cm_role")" \
  "$(jstr "$cm_status")" \
  "$m_custody" \
  "$(jstr "$m_overall")" \
  "${m_healthy:-null}" \
  "${m_total:-null}" \
  "$(jstr "$ROOT")" \
  "${disk_avail:-null}" \
  "${disk_pct:-null}" \
  "$(jstr "$version")")

mkdir -p "$ROOT"
printf '%s\n' "$line" >> "$ROOT/evidence.jsonl"
printf '%s\n' "$line"
