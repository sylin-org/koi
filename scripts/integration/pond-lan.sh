#!/usr/bin/env bash
# ADR-042 installed-service Pond gate.
#
# The subject is this machine's one installed Koi. Peers act as independent LAN
# browsers: each captures Pond's selector and loads one immutable UI generation.
# The gate never starts another Koi process or exposes the operator API.
set -Eeuo pipefail

usage() {
  cat <<'EOF'
Usage: pond-lan.sh [--allow-firewall-mutation] --peer USER@HOST [--peer USER@HOST ...]

Required:
  --peer USER@HOST       Independent physical LAN client (repeatable).

Required environment:
  EXPECTED_KOI_SHA256    SHA-256 of the exact installed candidate binary

Optional mutation:
  --allow-firewall-mutation
                         Temporarily admit Pond through active UFW/firewalld,
                         with captured baseline and trap-guarded exact restoration

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
  KOI_GATE_LOCK          Shared installed-service gate lock
                         (default target/integration/.installed-koi-SCOPE.lock)

The local operator must be authorized for Koi's local-control socket. Every peer
needs Python 3. The gate publishes generation A and arms Pond, captures and opens
that no-store selection, publishes generation B while A remains addressable, and
verifies both exact immutable generations before and after a service restart. It
also verifies the public/negative routes, explicit stop, recovered intent/current
selection, and baseline desired-state restoration. It never records the daemon
access token.
EOF
}

PEERS=()
ALLOW_FIREWALL_MUTATION=0
while (($#)); do
  case "$1" in
    --allow-firewall-mutation)
      ALLOW_FIREWALL_MUTATION=1
      ;;
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

for command in awk base64 cmp cp curl flock getent grep ip jq mv pgrep readlink rm sed sha256sum sort ssh ss stat sync; do
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
EXPECTED_KOI_SHA256="${EXPECTED_KOI_SHA256:-}"
PEER_PORT="${PEER_PORT:-22}"
EVIDENCE_ROOT="${EVIDENCE_ROOT:-target/pond-lan}"
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-$$"
EVIDENCE_DIR="$EVIDENCE_ROOT/$RUN_ID"
mkdir -p "$EVIDENCE_DIR"

if [[ ! "$EXPECTED_KOI_SHA256" =~ ^[0-9a-f]{64}$ ]]; then
  echo "EXPECTED_KOI_SHA256 must name the exact candidate as 64 lowercase hex characters" >&2
  exit 2
fi

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
    KOI_SERVICE_SCOPE=system
    ;;
  systemd-user)
    command -v systemctl >/dev/null || { echo "systemctl is required" >&2; exit 2; }
    ((EUID != 0)) || {
      echo "a user service gate must run as its owning user" >&2
      exit 2
    }
    SERVICE_RESTART=(systemctl --user restart koi)
    PRIV=()
    KOI_SERVICE_SCOPE=user
    ;;
  *)
    echo "KOI_SERVICE_MANAGER must be auto, systemd-system, systemd-user, or openrc" >&2
    exit 2
    ;;
esac

mkdir -p "$ROOT/target/integration"
KOI_GATE_LOCK="${KOI_GATE_LOCK:-$ROOT/target/integration/.installed-koi-$KOI_SERVICE_SCOPE.lock}"
exec 9>>"$KOI_GATE_LOCK"
if ! flock -n 9; then
  echo "another installed-service integration gate is already running: $KOI_GATE_LOCK" >&2
  exit 2
fi

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

koi_unit_active() {
  case "$KOI_SERVICE_MANAGER" in
    systemd-system) systemctl is-active koi.service 2>/dev/null || true ;;
    systemd-user) systemctl --user is-active koi.service 2>/dev/null || true ;;
    openrc)
      if rc-service koi status >/dev/null 2>&1; then
        echo active
      else
        echo inactive
      fi
      ;;
  esac
}

koi_unit_enabled() {
  case "$KOI_SERVICE_MANAGER" in
    systemd-system) systemctl is-enabled koi.service 2>/dev/null || true ;;
    systemd-user) systemctl --user is-enabled koi.service 2>/dev/null || true ;;
    openrc)
      if rc-update show default 2>/dev/null \
          | grep -Eq '^[[:space:]]*koi[[:space:]]*\|.*default'; then
        echo enabled
      else
        echo disabled
      fi
      ;;
  esac
}

koi_service_pid() {
  case "$KOI_SERVICE_MANAGER" in
    systemd-system) systemctl show koi.service --property MainPID --value ;;
    systemd-user) systemctl --user show koi.service --property MainPID --value ;;
    openrc) single_koi ;;
  esac
}

assert_supervised_koi() {
  local pid service_pid active enabled
  active="$(koi_unit_active)"
  enabled="$(koi_unit_enabled)"
  [[ "$active" == active ]] || {
    echo "installed $KOI_SERVICE_SCOPE Koi service must be active, got $active" >&2
    return 1
  }
  [[ "$enabled" == enabled ]] || {
    echo "installed $KOI_SERVICE_SCOPE Koi service must be enabled, got $enabled" >&2
    return 1
  }
  pid="$(single_koi)"
  service_pid="$(koi_service_pid)"
  [[ "$service_pid" =~ ^[1-9][0-9]*$ && "$pid" == "$service_pid" ]] || {
    echo "the sole Koi process $pid is not the installed service PID ${service_pid:-missing}" >&2
    return 1
  }
  printf '%s' "$pid"
}

peer_public_gate() {
  local peer="$1" base="$2" phase="$3" generation_revision="$4" current_revision="$5"
  local index_sha256="$6" app_sha256="$7" styles_sha256="$8"
  local sentences_sha256="$9" png_sha256="${10}"
  local url_key output
  url_key="$(sed 's/[^A-Za-z0-9_.-]/_/g' <<<"$base")"
  output="$EVIDENCE_DIR/${peer//@/_}-$phase-$url_key.txt"
  peer_run "$peer" python3 - "${base%/}" "$generation_revision" "$current_revision" \
    "$index_sha256" "$app_sha256" "$styles_sha256" \
    "$sentences_sha256" "$png_sha256" >"$output" <<'REMOTE'
import hashlib
from html.parser import HTMLParser
import json
import sys
import urllib.error
import urllib.parse
import urllib.request

(
    base,
    generation_revision,
    current_revision,
    expected_index_sha256,
    expected_app_sha256,
    expected_styles_sha256,
    expected_sentences_sha256,
    expected_png_sha256,
) = sys.argv[1:]


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, new_url):
        return None


no_redirect = urllib.request.build_opener(NoRedirect)


def request(method, url):
    http_request = urllib.request.Request(url, method=method)
    try:
        with no_redirect.open(http_request, timeout=8) as response:
            return (
                response.status,
                {key.lower(): value for key, value in response.headers.items()},
                response.read(),
            )
    except urllib.error.HTTPError as error:
        return (
            error.code,
            {key.lower(): value for key, value in error.headers.items()},
            error.read(),
        )


def require_status(method, path, expected):
    status, _, _ = request(method, base + path)
    if status != expected:
        raise SystemExit(f"{method} {path} -> {status}, expected {expected}")
    print(f"{method} {path} -> {status}")


def json_object(label, headers, body):
    mime = headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if mime != "application/json":
        raise SystemExit(f"{label} content-type -> {mime!r}, expected 'application/json'")
    try:
        value = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SystemExit(f"{label} did not return JSON: {error}") from error
    if not isinstance(value, dict):
        raise SystemExit(f"{label} JSON -> {type(value).__name__}, expected object")
    return value


def require_optional_read(path, capability, validate):
    status, headers, body = request("GET", base + path)
    value = json_object(f"GET {path}", headers, body)
    if status == 200:
        validate(value)
        print(f"GET {path} -> 200 valid {capability} data")
        return
    if status == 503:
        if value.get("error") != "capability_disabled":
            raise SystemExit(f"GET {path} 503 JSON -> {value!r}")
        message = value.get("message")
        if not isinstance(message, str) or capability not in message:
            raise SystemExit(f"GET {path} disabled message -> {message!r}")
        print(f"GET {path} -> 503 typed {capability} capability-disabled response")
        return
    raise SystemExit(f"GET {path} -> {status}, expected 200 or typed 503")


def validate_browser_snapshot(value):
    required = {
        "revision": int,
        "total_types": int,
        "total_instances": int,
        "service_types": list,
        "instances": list,
        "cache_age_secs": int,
        "burst": dict,
    }
    for field, expected_type in required.items():
        if not isinstance(value.get(field), expected_type):
            raise SystemExit(
                f"mDNS browser field {field!r} -> {value.get(field)!r}, "
                f"expected {expected_type.__name__}"
            )


def validate_dns_entries(value):
    entries = value.get("entries")
    if not isinstance(entries, list):
        raise SystemExit(f"DNS entries -> {entries!r}, expected list")
    for entry in entries:
        if not isinstance(entry, dict):
            raise SystemExit(f"DNS entry -> {entry!r}, expected object")
        if not isinstance(entry.get("name"), str) or not isinstance(entry.get("ip"), str):
            raise SystemExit(f"DNS entry is missing string name/ip: {entry!r}")


def require_generation_response(url, label, expected_mime, expected_sha256):
    status, headers, body = request("GET", url)
    if status != 200:
        raise SystemExit(f"{label} -> {status}, expected 200")

    mime = headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if mime != expected_mime:
        raise SystemExit(f"{label} content-type -> {mime!r}, expected {expected_mime!r}")

    cache_tokens = {
        token.strip().lower()
        for token in headers.get("cache-control", "").split(",")
        if token.strip()
    }
    required_cache = {"public", "max-age=31536000", "immutable"}
    if not required_cache.issubset(cache_tokens):
        raise SystemExit(f"{label} cache-control -> {sorted(cache_tokens)!r}")
    if headers.get("x-content-type-options", "").lower() != "nosniff":
        raise SystemExit(f"{label} is missing X-Content-Type-Options: nosniff")

    actual_sha256 = hashlib.sha256(body).hexdigest()
    if actual_sha256 != expected_sha256:
        raise SystemExit(
            f"{label} sha256 -> {actual_sha256}, expected {expected_sha256}"
        )
    print(f"GET {label} -> 200 {mime} sha256={actual_sha256}")
    return headers, body


class BundleReferences(HTMLParser):
    def __init__(self):
        super().__init__()
        self.references = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "link" and "href" in attrs:
            self.references.append(attrs["href"])
        elif tag in {"img", "script"} and "src" in attrs:
            self.references.append(attrs["src"])


selector_status, selector_headers, _ = request("GET", base + "/")
if selector_status != 307:
    raise SystemExit(f"GET / -> {selector_status}, expected 307")
location = selector_headers.get("location", "")
expected_location = f"/_koi/ui/{current_revision}/"
if location != expected_location:
    raise SystemExit(f"GET / location -> {location!r}, expected {expected_location!r}")
selector_cache = {
    token.strip().lower()
    for token in selector_headers.get("cache-control", "").split(",")
    if token.strip()
}
if "no-store" not in selector_cache:
    raise SystemExit(f"GET / cache-control -> {sorted(selector_cache)!r}")
print(f"GET / -> 307 {location} cache-control={sorted(selector_cache)!r}")

generation_path = f"/_koi/ui/{generation_revision}/"
generation_url = urllib.parse.urljoin(base + "/", generation_path)
index_headers, index_body = require_generation_response(
    generation_url,
    generation_path,
    "text/html",
    expected_index_sha256,
)

csp_directives = {}
for directive in index_headers.get("content-security-policy", "").split(";"):
    fields = directive.strip().split()
    if fields:
        csp_directives[fields[0].lower()] = {field.lower() for field in fields[1:]}
script_sources = csp_directives.get("script-src", set())
if "'self'" not in script_sources or "'unsafe-inline'" in script_sources:
    raise SystemExit(f"generation CSP script-src -> {sorted(script_sources)!r}")
if csp_directives.get("base-uri") != {"'none'"}:
    raise SystemExit(
        f"generation CSP base-uri -> {sorted(csp_directives.get('base-uri', set()))!r}"
    )
print("generation CSP -> external self scripts allowed; base URI disabled")

# This exact list deliberately validates the selected koi-desktop source fixture.
# Pond's wire contract requires relative, generation-local references; it does not
# otherwise freeze the desktop's future HTML shape.
parser = BundleReferences()
try:
    parser.feed(index_body.decode("utf-8"))
except UnicodeDecodeError as error:
    raise SystemExit(f"generation index is not UTF-8: {error}") from error
expected_references = [
    "styles.css",
    "koi.png",
    "koi.png",
    "sentences.js",
    "app.js",
]
if parser.references != expected_references:
    raise SystemExit(
        f"generation index references -> {parser.references!r}, expected {expected_references!r}"
    )

assets = {
    "app.js": ("text/javascript", expected_app_sha256),
    "styles.css": ("text/css", expected_styles_sha256),
    "sentences.js": ("text/javascript", expected_sentences_sha256),
    "koi.png": ("image/png", expected_png_sha256),
}
for asset, (mime, expected_sha256) in assets.items():
    asset_url = urllib.parse.urljoin(generation_url, asset)
    expected_url = generation_url + asset
    if asset_url != expected_url:
        raise SystemExit(f"relative {asset} resolved to {asset_url!r}, expected {expected_url!r}")
    require_generation_response(asset_url, generation_path + asset, mime, expected_sha256)

for path in (
    "/app.js",
    "/styles.css",
    "/sentences.js",
    "/koi.png",
):
    require_status("GET", path, 404)
for path in ("/healthz", "/v1/status"):
    require_status("GET", path, 200)
require_optional_read(
    "/v1/mdns/browser/snapshot", "mdns-browser", validate_browser_snapshot
)
require_optional_read("/v1/dns/entries", "dns", validate_dns_entries)
for method, path in (
    ("POST", "/v1/dns/add"),
    ("GET", "/v1/certmesh/log"),
    ("GET", "/v1/pond"),
    ("GET", "/openapi.json"),
):
    require_status(method, path, 404)
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
BASE_UI_AVAILABLE=""
BASE_UI_REVISION=""
BASE_UI_PAYLOAD_PATH=""
BASE_STATUS_VIEW=""
BASELINE_RESTORED=0
API=""
TOKEN=""
POND_URLS=()
CLEANING=0
FIREWALL_ADAPTER=inactive
FIREWALL_MUTATED=0
FIREWALL_WAS_MUTATED=0
FIREWALL_RESTORED=0
FIREWALL_ZONE=""
FIREWALL_LAN_LINK=""
FIREWALL_LOCAL_IP=""
FIREWALL_BASELINE_DIR="$EVIDENCE_DIR/firewall-baseline"
FIREWALL_FINAL_DIR="$EVIDENCE_DIR/firewall-final"
FIREWALL_RULE_COMMENTS=()
FIREWALL_RULE_SOURCES=()
FIREWALL_PORT=""

resolve_firewall_route() {
  local route
  route="$(ip -json route get "${FIREWALL_RULE_SOURCES[0]}" 2>/dev/null || true)"
  FIREWALL_LAN_LINK="$(jq -r '.[0].dev // empty' <<<"$route")"
  FIREWALL_LOCAL_IP="$(jq -r '.[0].prefsrc // empty' <<<"$route")"
  if [[ -z "$FIREWALL_LAN_LINK" || -z "$FIREWALL_LOCAL_IP" ]]; then
    echo "cannot identify the LAN interface/address used to reach ${PEERS[0]}" >&2
    return 1
  fi
}

resolve_firewall_sources() {
  local peer host source existing
  FIREWALL_RULE_SOURCES=()
  for peer in "${PEERS[@]}"; do
    host="${peer#*@}"
    source="$(getent ahostsv4 "$host" | awk '$2 == "STREAM" {print $1; exit}')"
    [[ "$source" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ && "$source" != 127.* ]] || {
      echo "Pond firewall mutation requires a non-loopback IPv4 peer, got $host -> ${source:-none}" >&2
      return 1
    }
    existing=0
    for candidate in "${FIREWALL_RULE_SOURCES[@]}"; do
      [[ "$candidate" == "$source" ]] && existing=1
    done
    [[ "$existing" == 1 ]] || FIREWALL_RULE_SOURCES+=("$source")
  done
}

ufw_allows_tcp_port() {
  local port="$1" status="$2"
  awk -v port="$port" '
    /^Default: allow \(incoming\)/ { default_admitted = 1 }
    {
      target = $1
      action = ""
      for (field = 2; field <= NF; field++) {
        if ($field == "ALLOW" || $field == "LIMIT" ||
            $field == "DENY" || $field == "REJECT") {
          action = $field
          break
        }
      }
      split(target, with_protocol, "/")
      if (with_protocol[1] !~ /^[0-9]+(:[0-9]+)?$/) next
      if (length(with_protocol[2]) && tolower(with_protocol[2]) != "tcp") next
      split(with_protocol[1], range, ":")
      start = range[1] + 0
      finish = length(range[2]) ? range[2] + 0 : start
      if (length(action) && start <= port && port <= finish) {
        decided = 1
        admitted = action == "ALLOW" || action == "LIMIT"
        exit
      }
    }
    END {
      if (!decided) admitted = default_admitted
      exit admitted ? 0 : 1
    }
  ' <<<"$status"
}

firewall_unit_state() {
  local unit="$1" active enabled
  if ! command -v systemctl >/dev/null; then
    printf 'active=unavailable\nenabled=unavailable\n'
    return
  fi
  active="$("${PRIV[@]}" systemctl is-active "$unit" 2>/dev/null || true)"
  enabled="$("${PRIV[@]}" systemctl is-enabled "$unit" 2>/dev/null || true)"
  printf 'active=%s\nenabled=%s\n' "${active:-unknown}" "${enabled:-unknown}"
}

capture_ufw_snapshot() {
  local destination="$1" path source_sha backup_sha
  mkdir -p "$destination"
  "${PRIV[@]}" ufw status verbose >"$destination/ufw-status-verbose.txt"
  "${PRIV[@]}" ufw status numbered >"$destination/ufw-status-numbered.txt"
  firewall_unit_state ufw.service >"$destination/ufw-unit.txt"
  for path in /etc/ufw/user.rules /etc/ufw/user6.rules; do
    "${PRIV[@]}" test -f "$path" || {
      echo "active UFW is missing authoritative rule file $path" >&2
      return 1
    }
    "${PRIV[@]}" cp -a "$path" "$destination/${path##*/}"
    source_sha="$("${PRIV[@]}" sha256sum "$path" | awk '{print $1}')"
    backup_sha="$("${PRIV[@]}" sha256sum "$destination/${path##*/}" | awk '{print $1}')"
    [[ "$source_sha" == "$backup_sha" ]] || {
      echo "UFW snapshot copy does not match $path" >&2
      return 1
    }
    printf '%s\n' "$source_sha" >"$destination/${path##*/}.sha256"
    "${PRIV[@]}" stat -c '%a %u %g %s %Y' "$path" \
      >"$destination/${path##*/}.metadata"
  done
}

ufw_snapshots_match() {
  local left="$1" right="$2"
  cmp -s "$left/ufw-status-verbose.txt" "$right/ufw-status-verbose.txt" \
    && cmp -s "$left/ufw-status-numbered.txt" "$right/ufw-status-numbered.txt" \
    && "${PRIV[@]}" cmp -s "$left/user.rules" "$right/user.rules" \
    && "${PRIV[@]}" cmp -s "$left/user6.rules" "$right/user6.rules" \
    && cmp -s "$left/user.rules.sha256" "$right/user.rules.sha256" \
    && cmp -s "$left/user6.rules.sha256" "$right/user6.rules.sha256" \
    && cmp -s "$left/user.rules.metadata" "$right/user.rules.metadata" \
    && cmp -s "$left/user6.rules.metadata" "$right/user6.rules.metadata" \
    && cmp -s "$left/ufw-unit.txt" "$right/ufw-unit.txt"
}

restore_ufw_files_atomically() {
  local pass path temporary expected_sha backup_sha
  # The first pass supplies UFW's supported reload boundary. UFW may rewrite the
  # authoritative files while reloading, including their mtimes, so a second
  # atomic pass restores the captured disk state after the runtime rules match it.
  for pass in before-reload after-reload; do
    for path in /etc/ufw/user.rules /etc/ufw/user6.rules; do
      expected_sha="$(<"$FIREWALL_BASELINE_DIR/${path##*/}.sha256")"
      backup_sha="$("${PRIV[@]}" sha256sum \
        "$FIREWALL_BASELINE_DIR/${path##*/}" | awk '{print $1}')"
      [[ "$backup_sha" == "$expected_sha" ]] || {
        echo "captured UFW backup changed before restore: ${path##*/}" >&2
        return 1
      }
      temporary="${path}.koi-pond-${RUN_ID}.restore"
      # RUN_ID contains only an internally generated UTC timestamp and PID. Clearing
      # this one exact stage makes a failed first rollback retryable from the EXIT trap.
      "${PRIV[@]}" rm -f -- "$temporary" || return 1
      if ! "${PRIV[@]}" cp -a "$FIREWALL_BASELINE_DIR/${path##*/}" "$temporary"; then
        "${PRIV[@]}" rm -f -- "$temporary" || true
        return 1
      fi
      if ! "${PRIV[@]}" mv -f "$temporary" "$path"; then
        "${PRIV[@]}" rm -f -- "$temporary" || true
        return 1
      fi
      "${PRIV[@]}" sync -f "$path" || return 1
    done
    "${PRIV[@]}" sync -f /etc/ufw || return 1
    if [[ "$pass" == before-reload ]]; then
      "${PRIV[@]}" ufw --force reload >/dev/null || return 1
    fi
  done
}

capture_firewalld_snapshot() {
  local destination="$1"
  mkdir -p "$destination"
  "${PRIV[@]}" firewall-cmd --list-all-zones \
    >"$destination/firewalld-runtime.txt"
  "${PRIV[@]}" firewall-cmd --permanent --list-all-zones \
    >"$destination/firewalld-permanent.txt"
  firewall_unit_state firewalld.service >"$destination/firewalld-unit.txt"
}

prepare_firewall() {
  local port="$1" ufw_status ufw_numbered source comment index=0
  FIREWALL_PORT="$port"
  resolve_firewall_sources
  resolve_firewall_route
  mkdir -p "$FIREWALL_FINAL_DIR"
  printf '%s\n' "${FIREWALL_RULE_SOURCES[@]}" >"$EVIDENCE_DIR/firewall-peer-addresses.txt"

  if command -v firewall-cmd >/dev/null \
      && [[ "$("${PRIV[@]}" firewall-cmd --state 2>/dev/null || true)" == running ]]; then
    FIREWALL_ADAPTER=firewalld
    FIREWALL_ZONE="$("${PRIV[@]}" firewall-cmd \
      --get-zone-of-interface="$FIREWALL_LAN_LINK" 2>/dev/null || true)"
    [[ -n "$FIREWALL_ZONE" ]] \
      || FIREWALL_ZONE="$("${PRIV[@]}" firewall-cmd --get-default-zone)"
    capture_firewalld_snapshot "$FIREWALL_BASELINE_DIR"
    if "${PRIV[@]}" firewall-cmd --zone="$FIREWALL_ZONE" \
        --query-port="$port/tcp" >/dev/null; then
      return 0
    fi
    [[ "$ALLOW_FIREWALL_MUTATION" == 1 ]] || {
      echo "firewalld blocks Pond TCP $port; rerun with --allow-firewall-mutation for a trap-restored runtime rule" >&2
      return 2
    }
    FIREWALL_MUTATED=1
    FIREWALL_WAS_MUTATED=1
    # Runtime-only, interface-zone-scoped, and self-expiring if this process is killed
    # before its EXIT trap can remove the rule.
    "${PRIV[@]}" firewall-cmd --zone="$FIREWALL_ZONE" \
      --add-port="$port/tcp" --timeout=300
    "${PRIV[@]}" firewall-cmd --zone="$FIREWALL_ZONE" \
      --query-port="$port/tcp" >/dev/null || {
      echo "temporary firewalld rule did not admit Pond TCP $port" >&2
      return 1
    }
    return 0
  fi

  if command -v ufw >/dev/null; then
    ufw_status="$("${PRIV[@]}" ufw status verbose 2>/dev/null || true)"
    if grep -q '^Status: active$' <<<"$ufw_status"; then
      FIREWALL_ADAPTER=ufw
      capture_ufw_snapshot "$FIREWALL_BASELINE_DIR"
      if ufw_allows_tcp_port "$port" "$ufw_status"; then
        return 0
      fi
      [[ "$ALLOW_FIREWALL_MUTATION" == 1 ]] || {
        echo "UFW blocks Pond TCP $port; rerun with --allow-firewall-mutation for peer-scoped trap restoration" >&2
        return 2
      }
      FIREWALL_MUTATED=1
      FIREWALL_WAS_MUTATED=1
      for source in "${FIREWALL_RULE_SOURCES[@]}"; do
        index=$((index + 1))
        comment="koi-pond-gate-$RUN_ID-$index"
        FIREWALL_RULE_COMMENTS+=("$comment")
        # Insert ahead of a broader deny while limiting the exception to the observed
        # peer, route interface, local address, protocol, and Pond port.
        "${PRIV[@]}" ufw insert 1 allow in on "$FIREWALL_LAN_LINK" \
          from "$source" to "$FIREWALL_LOCAL_IP" port "$port" proto tcp \
          comment "$comment"
      done
      ufw_numbered="$("${PRIV[@]}" ufw status numbered)"
      for comment in "${FIREWALL_RULE_COMMENTS[@]}"; do
        grep -Fq -- "# $comment" <<<"$ufw_numbered" || {
          echo "temporary UFW rule $comment was not installed" >&2
          return 1
        }
      done
      return 0
    fi
  fi

  FIREWALL_ADAPTER=inactive
  FIREWALL_RESTORED=1
}

restore_firewall() {
  local result=0 comment number
  local -a rule_numbers=()
  if [[ "$FIREWALL_ADAPTER" == inactive ]]; then
    FIREWALL_RESTORED=1
    return 0
  fi

  case "$FIREWALL_ADAPTER" in
    firewalld)
      if [[ "$FIREWALL_MUTATED" == 1 ]] \
          && "${PRIV[@]}" firewall-cmd --zone="$FIREWALL_ZONE" \
            --query-port="$FIREWALL_PORT/tcp" >/dev/null 2>&1; then
        "${PRIV[@]}" firewall-cmd --zone="$FIREWALL_ZONE" \
          --remove-port="$FIREWALL_PORT/tcp" >/dev/null || result=1
      fi
      capture_firewalld_snapshot "$FIREWALL_FINAL_DIR" || result=1
      cmp -s "$FIREWALL_BASELINE_DIR/firewalld-runtime.txt" \
        "$FIREWALL_FINAL_DIR/firewalld-runtime.txt" || result=1
      cmp -s "$FIREWALL_BASELINE_DIR/firewalld-permanent.txt" \
        "$FIREWALL_FINAL_DIR/firewalld-permanent.txt" || result=1
      cmp -s "$FIREWALL_BASELINE_DIR/firewalld-unit.txt" \
        "$FIREWALL_FINAL_DIR/firewalld-unit.txt" || result=1
      ;;
    ufw)
      if [[ "$FIREWALL_MUTATED" == 1 ]]; then
        for comment in "${FIREWALL_RULE_COMMENTS[@]}"; do
          while IFS= read -r number; do
            [[ -n "$number" ]] && rule_numbers+=("$number")
          done < <("${PRIV[@]}" ufw status numbered \
            | sed -n -E "/# ${comment}([[:space:]]|$)/s/^\\[[[:space:]]*([0-9]+)\\].*/\\1/p")
        done
        if ((${#rule_numbers[@]})); then
          mapfile -t rule_numbers < <(printf '%s\n' "${rule_numbers[@]}" | sort -rn -u)
          for number in "${rule_numbers[@]}"; do
            # This is a best-effort surgical first pass. The captured authoritative
            # files below are the unconditional recovery boundary.
            "${PRIV[@]}" ufw --force delete "$number" >/dev/null || true
          done
        fi
        # Always reinstall the captured byte-exact pair and cross UFW's supported
        # reload boundary after a mutation, even if rule deletion looked identical.
        restore_ufw_files_atomically || result=1
      fi
      capture_ufw_snapshot "$FIREWALL_FINAL_DIR" || result=1
      ufw_snapshots_match "$FIREWALL_BASELINE_DIR" "$FIREWALL_FINAL_DIR" || result=1
      ;;
  esac

  if [[ "$result" == 0 ]]; then
    FIREWALL_MUTATED=0
    FIREWALL_RESTORED=1
    return 0
  fi
  echo "firewall state did not restore exactly; inspect $FIREWALL_FINAL_DIR" >&2
  return 1
}

pond_restorable_status() {
  jq -S '{
    desired,
    running,
    state,
    port,
    urls: (.urls | sort),
    firewall,
    ui,
    reason: (.reason // null)
  }'
}

verify_baseline_ui_content() {
  local deadline status port safe_revision local_base verify_dir file
  [[ "$BASE_UI_AVAILABLE" == true && -n "$BASE_UI_PAYLOAD_PATH" ]] || return 0

  operator_request PUT /v1/pond >/dev/null || {
    echo "could not arm Pond to verify the restored UI bytes" >&2
    return 1
  }
  deadline=$((SECONDS + 15))
  status='{}'
  while ((SECONDS < deadline)); do
    status="$(operator_request GET /v1/pond 2>/dev/null || true)"
    if jq -e --arg revision "$BASE_UI_REVISION" '
        .running == true and .ui.available == true and .ui.revision == $revision
      ' <<<"$status" >/dev/null 2>&1; then
      break
    fi
    sleep 0.25
  done
  port="$(jq -er --arg revision "$BASE_UI_REVISION" '
    select(.running == true and .ui.available == true and .ui.revision == $revision) | .port
  ' <<<"$status")" || {
    echo "Pond did not expose the restored UI selection for byte verification" >&2
    return 1
  }

  safe_revision="${BASE_UI_REVISION#sha256:}"
  local_base="http://127.0.0.1:$port/_koi/ui/$safe_revision"
  verify_dir="$EVIDENCE_DIR/final-ui"
  mkdir -p "$verify_dir"
  curl -fsS --max-time 8 "$local_base/" -o "$verify_dir/index.html" || return 1
  for file in app.js styles.css sentences.js koi.png; do
    curl -fsS --max-time 8 "$local_base/$file" -o "$verify_dir/$file" || return 1
  done
  for file in index.html app.js styles.css sentences.js koi.png; do
    cmp -s "$EVIDENCE_DIR/baseline-ui/$file" "$verify_dir/$file" || {
      echo "restored Pond UI file differs from baseline: $file" >&2
      return 1
    }
  done
  sha256sum \
    "$verify_dir/index.html" "$verify_dir/app.js" "$verify_dir/styles.css" \
    "$verify_dir/sentences.js" "$verify_dir/koi.png" \
    >"$verify_dir/sha256.txt"
}

reacquire_operator_for_restore() {
  local attempt
  for attempt in {1..20}; do
    if refresh_access >/dev/null 2>&1 \
        && curl -fsS --max-time 2 "$API/healthz" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.25
  done

  # A failed restart inside the gate may leave the installed supervisor down.
  # Retry only that same supervisor; never launch a parallel daemon.
  "${PRIV[@]}" "${SERVICE_RESTART[@]}" || return 1
  for attempt in {1..60}; do
    if refresh_access >/dev/null 2>&1 \
        && curl -fsS --max-time 2 "$API/healthz" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.5
  done
  return 1
}

verify_installed_service_baseline() {
  local pid executable hash
  pid="$(assert_supervised_koi)" || return 1
  executable="$(process_executable "$pid")" || return 1
  hash="$(executable_hash "$executable")" || return 1
  [[ "$hash" == "$EXPECTED_KOI_SHA256" && "$hash" == "$INITIAL_HASH" ]] || return 1
  [[ "$(koi_unit_active)" == "$BASE_KOI_ACTIVE" \
     && "$(koi_unit_enabled)" == "$BASE_KOI_ENABLED" ]]
}

restore_baseline() {
  local deadline status restored_ui actual_view access_ready=1 result=0
  if [[ -z "$BASE_DESIRED" ]]; then
    restore_firewall || return 1
    BASELINE_RESTORED=1
    return 0
  fi

  if ! reacquire_operator_for_restore; then
    echo "could not reacquire local control while restoring Pond" >&2
    access_ready=0
    result=1
  fi

  if [[ "$access_ready" == 1 ]]; then
    if [[ "$BASE_UI_AVAILABLE" == true && -n "$BASE_UI_PAYLOAD_PATH" ]]; then
      if restored_ui="$(operator_request PUT /v1/ui \
        -H 'content-type: application/json' --data-binary "@$BASE_UI_PAYLOAD_PATH")"; then
        if [[ "$(jq -er '.revision' <<<"$restored_ui" 2>/dev/null || true)" \
            != "$BASE_UI_REVISION" ]]; then
          echo "captured Pond UI bytes did not restore revision $BASE_UI_REVISION" >&2
          result=1
        elif ! verify_baseline_ui_content; then
          result=1
        fi
      else
        echo "could not re-publish the captured Pond UI selection" >&2
        result=1
      fi
    elif [[ "$BASE_UI_AVAILABLE" == false ]]; then
      if ! operator_request DELETE /v1/ui >/dev/null; then
        echo "could not restore the captured empty Pond UI selection" >&2
        result=1
      fi
    else
      echo "Pond UI baseline was not captured" >&2
      result=1
    fi
  fi

  # UI byte verification may need the temporary exception. Remove it before
  # reconciling the original desire so the final observed firewall truth can match.
  if ! restore_firewall; then
    result=1
  fi

  if [[ "$access_ready" == 1 ]]; then
    if [[ "$BASE_DESIRED" == true ]]; then
      operator_request PUT /v1/pond >/dev/null || result=1
    else
      operator_request DELETE /v1/pond >/dev/null || result=1
    fi

    deadline=$((SECONDS + 20))
    status='{}'
    while ((SECONDS < deadline)); do
      status="$(operator_request GET /v1/pond 2>/dev/null || true)"
      actual_view="$(pond_restorable_status <<<"$status" 2>/dev/null || true)"
      if [[ -n "$actual_view" && "$actual_view" == "$BASE_STATUS_VIEW" ]]; then
        if [[ "$BASE_DESIRED" == false ]]; then
          if ss -lntH "sport = :$(jq -er '.port' <<<"$status")" | grep -q .; then
            sleep 0.25
            continue
          fi
        fi
        printf '%s\n' "$status" | jq . >"$EVIDENCE_DIR/final-restoration.json"
        printf '%s\n' "$actual_view" >"$EVIDENCE_DIR/final-restorable-status.json"
        verify_installed_service_baseline || result=1
        if [[ "$result" == 0 ]]; then
          BASELINE_RESTORED=1
          return 0
        fi
        return 1
      fi
      sleep 0.25
    done
  fi

  printf '%s\n' "${status:-unavailable}" >"$EVIDENCE_DIR/final-restoration-error.txt"
  echo "Pond did not return exactly to its captured restorable state" >&2
  return 1
}

capture_baseline_ui() {
  local deadline status port safe_revision local_base capture_dir png
  [[ "$BASE_UI_AVAILABLE" == true ]] || return 0
  safe_revision="${BASE_UI_REVISION#sha256:}"
  capture_dir="$EVIDENCE_DIR/baseline-ui"
  mkdir -p "$capture_dir"

  if [[ "$BASE_DESIRED" == false ]]; then
    operator_request PUT /v1/pond >/dev/null
  fi
  deadline=$((SECONDS + 15))
  status='{}'
  while ((SECONDS < deadline)); do
    status="$(operator_request GET /v1/pond 2>/dev/null || true)"
    if jq -e --arg revision "$BASE_UI_REVISION" '
        .running == true and .ui.available == true and .ui.revision == $revision
      ' <<<"$status" >/dev/null 2>&1; then
      break
    fi
    sleep 0.25
  done
  port="$(jq -er --arg revision "$BASE_UI_REVISION" '
    select(.running == true and .ui.available == true and .ui.revision == $revision) | .port
  ' <<<"$status")" || {
    echo "could not bind Pond temporarily to capture its selected UI" >&2
    return 1
  }
  local_base="http://127.0.0.1:$port/_koi/ui/$safe_revision"
  curl -fsS --max-time 8 "$local_base/" -o "$capture_dir/index.html"
  for file in app.js styles.css sentences.js koi.png; do
    curl -fsS --max-time 8 "$local_base/$file" -o "$capture_dir/$file"
  done
  sha256sum \
    "$capture_dir/index.html" "$capture_dir/app.js" "$capture_dir/styles.css" \
    "$capture_dir/sentences.js" "$capture_dir/koi.png" \
    >"$capture_dir/sha256.txt"
  png="$(base64 -w0 "$capture_dir/koi.png")"
  BASE_UI_PAYLOAD_PATH="$capture_dir/publish.json"
  jq -n \
    --rawfile index "$capture_dir/index.html" \
    --rawfile app "$capture_dir/app.js" \
    --rawfile styles "$capture_dir/styles.css" \
    --rawfile sentences "$capture_dir/sentences.js" \
    --arg png "$png" \
    '{files:[
      {path:"index.html",content:$index},
      {path:"app.js",content:$app},
      {path:"styles.css",content:$styles},
      {path:"sentences.js",content:$sentences},
      {path:"koi.png",content:$png}
    ]}' >"$BASE_UI_PAYLOAD_PATH"

  if [[ "$BASE_DESIRED" == false ]]; then
    operator_request DELETE /v1/pond >/dev/null
    deadline=$((SECONDS + 15))
    while ((SECONDS < deadline)); do
      status="$(operator_request GET /v1/pond 2>/dev/null || true)"
      if jq -e '.desired == false and .running == false and .state == "disabled"' \
          <<<"$status" >/dev/null 2>&1; then
        return 0
      fi
      sleep 0.25
    done
    echo "temporary Pond UI capture did not restore the disabled listener" >&2
    return 1
  fi
}

cleanup() {
  local result="${1:-$?}"
  ((CLEANING == 0)) || exit "$result"
  CLEANING=1
  trap - EXIT
  # Once rollback begins, a second terminal signal must not split the UFW file
  # pair or interrupt Pond selection/desire restoration midway.
  trap '' INT TERM
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

BASE_KOI_ACTIVE="$(koi_unit_active)"
BASE_KOI_ENABLED="$(koi_unit_enabled)"
INITIAL_PID="$(assert_supervised_koi)"
INITIAL_EXE="$(process_executable "$INITIAL_PID")"
INITIAL_HASH="$(executable_hash "$INITIAL_EXE")"
[[ "$INITIAL_HASH" == "$EXPECTED_KOI_SHA256" ]] || {
  echo "installed Koi hash $INITIAL_HASH does not match expected candidate $EXPECTED_KOI_SHA256" >&2
  exit 2
}
refresh_access
curl -fsS --max-time 5 "$API/healthz" >/dev/null
BASELINE="$(operator_request GET /v1/pond)"
BASE_DESIRED="$(jq -er '
  if .desired == true then "true"
  elif .desired == false then "false"
  else error("Pond status is missing a desired boolean")
  end
' <<<"$BASELINE")"
BASE_UI_AVAILABLE="$(jq -er '
  if .ui.available == true then "true"
  elif .ui.available == false then "false"
  else error("Pond status is missing ui.available")
  end
' <<<"$BASELINE")"
if [[ "$BASE_UI_AVAILABLE" == true ]]; then
  BASE_UI_REVISION="$(jq -er '
    .ui.revision | select(type == "string" and test("^sha256:[0-9a-f]{64}$"))
  ' <<<"$BASELINE")"
fi
jq . <<<"$BASELINE" >"$EVIDENCE_DIR/baseline.json"
BASE_STATUS_VIEW="$(pond_restorable_status <<<"$BASELINE")"
printf '%s\n' "$BASE_STATUS_VIEW" >"$EVIDENCE_DIR/baseline-restorable-status.json"
prepare_firewall "$(jq -er '.port' <<<"$BASELINE")"
capture_baseline_ui

HTTP_PORT="$(sed -E 's#.*:([0-9]+)/?$#\1#' <<<"$API")"
BEFORE_HTTP_BIND="$(ss -lntH "sport = :$HTTP_PORT" | awk '{print $4}' | sort -u)"
[[ -n "$BEFORE_HTTP_BIND" ]] || { echo "operator listener is absent" >&2; exit 1; }

PNG="$(base64 -w0 "$UI_ROOT/koi.png")"
GENERATION_A_MARKER="koi-pond-integration-generation-a-$RUN_ID"
PAYLOAD_A="$(jq -n \
  --rawfile index "$UI_ROOT/index.html" \
  --rawfile app "$UI_ROOT/app.js" \
  --rawfile styles "$UI_ROOT/styles.css" \
  --rawfile sentences "$UI_ROOT/sentences.js" \
  --arg png "$PNG" \
  --arg marker "$GENERATION_A_MARKER" \
  '{files:[
    {path:"index.html",content:($index + "\n<!-- " + $marker + " -->\n")},
    {path:"app.js",content:($app + "\n/* " + $marker + " */\n")},
    {path:"styles.css",content:($styles + "\n/* " + $marker + " */\n")},
    {path:"sentences.js",content:($sentences + "\n/* " + $marker + " */\n")},
    {path:"koi.png",content:$png}
  ]}')"
PAYLOAD_B="$(jq -n \
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
UI_A_INDEX_SHA256="$(jq -jr '.files[] | select(.path == "index.html") | .content' \
  <<<"$PAYLOAD_A" | sha256sum | awk '{print $1}')"
UI_A_APP_SHA256="$(jq -jr '.files[] | select(.path == "app.js") | .content' \
  <<<"$PAYLOAD_A" | sha256sum | awk '{print $1}')"
UI_A_STYLES_SHA256="$(jq -jr '.files[] | select(.path == "styles.css") | .content' \
  <<<"$PAYLOAD_A" | sha256sum | awk '{print $1}')"
UI_A_SENTENCES_SHA256="$(jq -jr '.files[] | select(.path == "sentences.js") | .content' \
  <<<"$PAYLOAD_A" | sha256sum | awk '{print $1}')"
UI_A_PNG_SHA256="$(sha256sum "$UI_ROOT/koi.png" | awk '{print $1}')"
UI_B_INDEX_SHA256="$(sha256sum "$UI_ROOT/index.html" | awk '{print $1}')"
UI_B_APP_SHA256="$(sha256sum "$UI_ROOT/app.js" | awk '{print $1}')"
UI_B_STYLES_SHA256="$(sha256sum "$UI_ROOT/styles.css" | awk '{print $1}')"
UI_B_SENTENCES_SHA256="$(sha256sum "$UI_ROOT/sentences.js" | awk '{print $1}')"
UI_B_PNG_SHA256="$UI_A_PNG_SHA256"

printf '%s' "$PAYLOAD_A" \
  | operator_request PUT /v1/ui -H 'content-type: application/json' --data-binary @- \
    >"$EVIDENCE_DIR/publish-a.json"
PUBLISHED_A_REVISION="$(jq -er '
  .revision | select(type == "string" and test("^sha256:[0-9a-f]{64}$"))
' "$EVIDENCE_DIR/publish-a.json")"
PUBLISHED_A_SAFE_REVISION="${PUBLISHED_A_REVISION#sha256:}"
ENABLED="$(operator_request PUT /v1/pond)"
jq -e --arg revision "$PUBLISHED_A_REVISION" '
  .desired == true and .running == true and .state == "running"
  and (.urls | length > 0) and .ui.revision == $revision
' \
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
    peer_public_gate "$peer" "$url" selected-a \
      "$PUBLISHED_A_SAFE_REVISION" "$PUBLISHED_A_SAFE_REVISION" \
      "$UI_A_INDEX_SHA256" "$UI_A_APP_SHA256" "$UI_A_STYLES_SHA256" \
      "$UI_A_SENTENCES_SHA256" "$UI_A_PNG_SHA256"
  done
done

# Publish the exact source fixture as B while the byte-distinct, behavior-identical
# A URL remains live. A's text comments make cross-generation mixing visible; B
# leaves the unmodified desktop bundle current after the gate.
printf '%s' "$PAYLOAD_B" \
  | operator_request PUT /v1/ui -H 'content-type: application/json' --data-binary @- \
    >"$EVIDENCE_DIR/publish-b.json"
PUBLISHED_B_REVISION="$(jq -er '
  .revision | select(type == "string" and test("^sha256:[0-9a-f]{64}$"))
' "$EVIDENCE_DIR/publish-b.json")"
PUBLISHED_B_SAFE_REVISION="${PUBLISHED_B_REVISION#sha256:}"
[[ "$PUBLISHED_B_REVISION" != "$PUBLISHED_A_REVISION" ]] || {
  echo "generation B did not produce a distinct content revision" >&2
  exit 1
}
AFTER_B="$(operator_request GET /v1/pond)"
jq -e --arg revision "$PUBLISHED_B_REVISION" '
  .desired == true and .running == true and .state == "running"
  and (.urls | length > 0) and .ui.revision == $revision
' <<<"$AFTER_B" >/dev/null
printf '%s\n' "$AFTER_B" | jq . >"$EVIDENCE_DIR/after-publish-b.json"
mapfile -t POND_URLS < <(jq -er '.urls[]' <<<"$AFTER_B")
for peer in "${PEERS[@]}"; do
  for url in "${POND_URLS[@]}"; do
    peer_public_gate "$peer" "$url" retained-a-after-b \
      "$PUBLISHED_A_SAFE_REVISION" "$PUBLISHED_B_SAFE_REVISION" \
      "$UI_A_INDEX_SHA256" "$UI_A_APP_SHA256" "$UI_A_STYLES_SHA256" \
      "$UI_A_SENTENCES_SHA256" "$UI_A_PNG_SHA256"
    peer_public_gate "$peer" "$url" current-b \
      "$PUBLISHED_B_SAFE_REVISION" "$PUBLISHED_B_SAFE_REVISION" \
      "$UI_B_INDEX_SHA256" "$UI_B_APP_SHA256" "$UI_B_STYLES_SHA256" \
      "$UI_B_SENTENCES_SHA256" "$UI_B_PNG_SHA256"
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
jq -e --arg revision "$PUBLISHED_B_REVISION" '
  .desired == true and .running == true and .state == "running"
  and .ui.revision == $revision
' \
  <<<"$RECOVERED" >/dev/null
printf '%s\n' "$RECOVERED" | jq . >"$EVIDENCE_DIR/recovered.json"
mapfile -t POND_URLS < <(jq -er '.urls[]' <<<"$RECOVERED")
for peer in "${PEERS[@]}"; do
  for url in "${POND_URLS[@]}"; do
    peer_public_gate "$peer" "$url" restart-retained-a \
      "$PUBLISHED_A_SAFE_REVISION" "$PUBLISHED_B_SAFE_REVISION" \
      "$UI_A_INDEX_SHA256" "$UI_A_APP_SHA256" "$UI_A_STYLES_SHA256" \
      "$UI_A_SENTENCES_SHA256" "$UI_A_PNG_SHA256"
    peer_public_gate "$peer" "$url" restart-current-b \
      "$PUBLISHED_B_SAFE_REVISION" "$PUBLISHED_B_SAFE_REVISION" \
      "$UI_B_INDEX_SHA256" "$UI_B_APP_SHA256" "$UI_B_STYLES_SHA256" \
      "$UI_B_SENTENCES_SHA256" "$UI_B_PNG_SHA256"
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

FINAL_PID="$(assert_supervised_koi)"
FINAL_EXE="$(process_executable "$FINAL_PID")"
FINAL_HASH="$(executable_hash "$FINAL_EXE")"
[[ "$FINAL_HASH" == "$INITIAL_HASH" && "$FINAL_HASH" == "$EXPECTED_KOI_SHA256" ]] || {
  echo "installed executable changed or no longer matches the expected candidate" >&2
  exit 1
}
[[ "$(koi_unit_active)" == "$BASE_KOI_ACTIVE" \
   && "$(koi_unit_enabled)" == "$BASE_KOI_ENABLED" ]] || {
  echo "installed Koi service state changed during the gate" >&2
  exit 1
}
jq -n \
  --arg run_id "$RUN_ID" --arg initial_pid "$INITIAL_PID" --arg final_pid "$FINAL_PID" \
  --arg sha256 "$FINAL_HASH" --arg generation_a "$PUBLISHED_A_REVISION" \
  --arg generation_b "$PUBLISHED_B_REVISION" --arg baseline_ui_revision "$BASE_UI_REVISION" \
  --arg firewall_adapter "$FIREWALL_ADAPTER" \
  --argjson baseline_ui_available "$BASE_UI_AVAILABLE" \
  --argjson firewall_mutated "$FIREWALL_WAS_MUTATED" \
  --argjson firewall_restored "$FIREWALL_RESTORED" \
  --argjson baseline_desired "$BASE_DESIRED" \
  --argjson final_desired "$(jq '.desired' "$EVIDENCE_DIR/final-restoration.json")" \
  --argjson peers "$(printf '%s\n' "${PEERS[@]}" | jq -R . | jq -s .)" \
  '{run_id:$run_id, initial_pid:($initial_pid|tonumber), final_pid:($final_pid|tonumber),
    sha256:$sha256, generations:[$generation_a,$generation_b], peers:$peers,
    baseline_desired:$baseline_desired,
    baseline_ui:{available:$baseline_ui_available,
      revision:(if $baseline_ui_available then $baseline_ui_revision else null end)},
    firewall:{adapter:$firewall_adapter, temporary_mutation:($firewall_mutated == 1),
      exact_restoration:($firewall_restored == 1)},
    final_desired:$final_desired, restoration:"pass", result:"pass"}' \
  >"$EVIDENCE_DIR/verdict.json"

trap - EXIT INT TERM
echo "Pond LAN gate PASS: $RUN_ID"
echo "  peers: ${PEERS[*]}"
echo "  service PID: $INITIAL_PID -> $FINAL_PID"
echo "  artifact: $FINAL_HASH"
echo "  evidence: $EVIDENCE_DIR"
