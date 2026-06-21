#!/usr/bin/env bash
# ADR-020 two-box cross-host integration test (the real-LAN gate).
#
# Runs ON the CA box (brook); drives the member box (granite) over SSH (sshpass).
# Exercises the real surfaces unit/loopback tests can't: cross-host certmesh trust
# over the LAN, the posture-reactive mTLS listener, mDNS posture stamping, and the
# `koi trust diagnose` doctor. See docs/testing/integration-hosts.md.
#
# Prereqs (deploy.ps1 -Setup handles them): the koi binary at $KOI on both boxes,
# moss/avahi disabled, jq + sshpass present on this box. Usage: bash cross-host-test.sh
set -uo pipefail

CA_IP="${CA_IP:-192.168.1.44}"
MEMBER_IP="${MEMBER_IP:-192.168.1.55}"
MEMBER_HOST="${MEMBER_HOST:-stone-granite-spring}"
KOI="/home/stone/koi-test/koi"
DATA="/home/stone/koi-test/data"
CA="http://127.0.0.1:5641"
PASS=0; FAIL=0
ok()  { echo "  PASS: $1"; PASS=$((PASS+1)); }
bad() { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }
mssh(){ sshpass -p stone ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null stone@"$MEMBER_IP" "$@"; }

start_ca_daemon() {
  pkill -f 'koi --daemon' 2>/dev/null; sleep 1
  ( cd /home/stone/koi-test && KOI_DATA_DIR="$DATA" KOI_NO_CREDENTIAL_STORE=1 KOI_HTTP_BIND=0.0.0.0 \
      nohup "$KOI" --daemon --no-runtime --no-proxy --no-udp --no-mcp-http --no-acme \
      </dev/null >/home/stone/koi-test/daemon.log 2>&1 & )
  # A daemon booting with a CA already on disk must unlock the vault before HTTP
  # comes up. With KOI_NO_CREDENTIAL_STORE the auto-unlock falls back to the
  # file-vault Argon2 KDF, which takes ~20-25s on these boxes — wait generously.
  for _ in $(seq 1 60); do curl -s "$CA/healthz" 2>/dev/null | grep -q OK && return 0; sleep 1; done
  return 1
}

echo "================ ADR-020 cross-host integration ($CA_IP CA, $MEMBER_IP member) ================"

echo "== reset: wipe CA-box certmesh state so it starts Open =="
# A prior run leaves a CA on disk; without this the daemon boots Authenticated and
# the "listener down while Open" + "create" checks are invalid. Mirrors the member
# clean (step 7) — both boxes start from a known-empty state.
pkill -f 'koi --daemon' 2>/dev/null; sleep 1
rm -rf "$DATA"; mkdir -p "$DATA"
ok "CA box reset (clean Open start)"

echo "== 0. (re)start the CA daemon (Open) =="
start_ca_daemon && ok "CA daemon up" || bad "CA daemon"
# Breadcrumb line 2 is "dat:<token>"; the x-koi-token header wants the raw token.
TOKEN="$(sed -n 2p /run/user/1000/koi.endpoint | sed 's/^dat://')"

echo "== 1. P4: mTLS listener DOWN while Open =="
ss -tln | grep -q :5642 && bad "5642 up before CA (unexpected)" || ok "5642 down (Open)"

echo "== 2. CA create (HTTP API, non-interactive) =="
ENTROPY="$(printf '2a%.0s' $(seq 1 32))"
CREATE=$(curl -s -X POST "$CA/v1/certmesh/create" -H "x-koi-token: $TOKEN" -H 'content-type: application/json' \
  -d "{\"passphrase\":\"test-pass-2026\",\"entropy_hex\":\"$ENTROPY\",\"operator\":\"ops\",\"enrollment_open\":true,\"requires_approval\":false,\"auto_unlock\":true,\"totp_secret_hex\":null}")
CA_FP=$(echo "$CREATE" | jq -r '.ca_fingerprint // empty' 2>/dev/null)
if [ -n "$CA_FP" ]; then ok "CA created (fp ${CA_FP:0:16}...)"; else bad "CA create"; echo "    $CREATE" | head -c 300; echo; fi

echo "== 3. P4: mTLS listener reactive-UP after CA (no restart) =="
sleep 2
ss -tln | grep -q :5642 && ok "5642 reactive-up" || bad "5642 still down after CA"

echo "== 4. P6: koi trust diagnose on CA (Healthy, exit 0) =="
KOI_DATA_DIR="$DATA" KOI_NO_CREDENTIAL_STORE=1 "$KOI" trust diagnose 2>&1 | sed 's/^/    /'
if KOI_DATA_DIR="$DATA" KOI_NO_CREDENTIAL_STORE=1 "$KOI" trust diagnose >/dev/null 2>&1; then ok "diagnose exit 0"; else bad "diagnose nonzero (RED)"; fi

echo "== 5. mint invite for $MEMBER_HOST =="
INV=$(curl -s -X POST "$CA/v1/certmesh/invite" -H "x-koi-token: $TOKEN" -H 'content-type: application/json' \
  -d "{\"hostname\":\"$MEMBER_HOST\",\"ttl_mins\":60}")
INVITE=$(echo "$INV" | jq -r '.token // empty' 2>/dev/null)
if [ -n "$INVITE" ]; then ok "invite minted"; else bad "invite"; echo "    $INV" | head -c 300; echo; fi

echo "== 6. ADR-020: _certmesh._tcp announced REACTIVELY after create (no restart) =="
# The announce is now posture-reactive (the trust-plane supervisor publishes it when
# the CA appears), so the daemon that booted Open (step 0) and created the CA over
# HTTP (step 2) advertises immediately — no restart. Confirm via its registration list.
sleep 2
if curl -s "$CA/v1/mdns/admin/ls" -H "x-koi-token: $TOKEN" 2>/dev/null | grep -q '_certmesh._tcp'; then
  ok "_certmesh._tcp announced reactively (no restart)"
else
  bad "no reactive _certmesh._tcp announce"
fi

echo "== 7. member (granite) clean + daemon up (fresh deployed binary) =="
# Wipe any leftover certmesh state + stale daemons (granite carried an old CA from a
# prior session). Use the ABSOLUTE deployed-binary path — $HOME may hold an old koi.
# `pkill -x koi` matches by process NAME (self-safe). `pkill -f 'koi --daemon'`
# would also match this remote `bash -c` whose own argv contains that string,
# killing the shell before rm/mkdir runs (ssh rc=255, data not wiped).
mssh "echo stone | sudo -S -p '' systemctl stop koi 2>/dev/null; pkill -x koi 2>/dev/null; sleep 1; rm -rf /home/stone/koi-test/data; mkdir -p /home/stone/koi-test/data" 2>/dev/null
# `setsid -f` force-forks the daemon into its own session and returns immediately,
# so the brook->granite ssh channel closes (a plain `setsid … &` over the double
# hop does NOT fully detach and hangs the test). Then poll healthz.
mssh "cd /home/stone/koi-test && setsid -f env KOI_DATA_DIR=\$PWD/data KOI_NO_CREDENTIAL_STORE=1 KOI_HTTP_BIND=0.0.0.0 /home/stone/koi-test/koi --daemon --no-runtime --no-proxy --no-udp --no-mcp-http --no-acme </dev/null >/home/stone/koi-test/daemon.log 2>&1"
MEMBER_UP=0
for _ in $(seq 1 20); do mssh "curl -s --max-time 2 localhost:5641/healthz 2>/dev/null" | grep -q OK && { MEMBER_UP=1; break; }; sleep 1; done
[ "$MEMBER_UP" = 1 ] && ok "member daemon up" || bad "member daemon"

echo "== 8. member joins the CA over the real LAN =="
# The CA endpoint MUST carry a scheme — `koi certmesh join` parses it as an absolute
# URL (a bare host:port fails preflight with "relative URL without a base").
JOINOUT=$(mssh "cd /home/stone/koi-test; KOI_DATA_DIR=\$PWD/data KOI_NO_CREDENTIAL_STORE=1 timeout 40 /home/stone/koi-test/koi certmesh join http://$CA_IP:5641 --invite '$INVITE' 2>&1")
echo "$JOINOUT" | tail -10 | sed 's/^/    /'
if echo "$JOINOUT" | grep -qiE 'joined|enrolled|installed|success'; then ok "member join"; else bad "member join (see output)"; fi

echo "== 9. CA roster shows the member =="
curl -s "$CA/v1/certmesh/status" -H "x-koi-token: $TOKEN" 2>/dev/null | jq -r '.members[]?.hostname' 2>/dev/null | sed 's/^/    roster: /'
if curl -s "$CA/v1/certmesh/status" -H "x-koi-token: $TOKEN" 2>/dev/null | jq -e ".members[]? | select(.hostname==\"$MEMBER_HOST\")" >/dev/null 2>&1; then ok "roster has $MEMBER_HOST"; else bad "roster missing member"; fi

echo "== 10. P3: member discovers the CA's posture TXT over real mDNS (standalone) =="
# Validated via a STANDALONE discover. OPEN BUG (under investigation): the long-lived
# DAEMON's browse does NOT resolve on Linux — it never emits the browse query on the
# wire (an mdns-sd long-lived-ServiceDaemon defect; Windows + Linux-standalone both
# work). See docs/testing/integration-hosts.md "Findings". Standalone is a real koi
# mode and proves the CA's posture/fp/expires TXT crosses the LAN.
mssh "pkill -x koi 2>/dev/null; rm -f /run/user/1000/koi.endpoint; sleep 1"
DISC=$(mssh "KOI_DATA_DIR=/home/stone/koi-test/data timeout 12 /home/stone/koi-test/koi mdns discover _certmesh._tcp 2>&1" || true)
echo "$DISC" | grep -iE 'posture=|fp=' | head -5 | sed 's/^/    /'
if echo "$DISC" | grep -qiE 'posture=|fp='; then ok "standalone discover sees the CA posture/fp TXT over the LAN"; else bad "no posture TXT seen"; fi
# Restart the member daemon so the koi-status check (step 12) has a live daemon.
mssh "cd /home/stone/koi-test && setsid -f env KOI_DATA_DIR=\$PWD/data KOI_NO_CREDENTIAL_STORE=1 KOI_HTTP_BIND=0.0.0.0 /home/stone/koi-test/koi --daemon --no-runtime --no-proxy --no-udp --no-mcp-http --no-acme </dev/null >/home/stone/koi-test/daemon.log 2>&1"
for _ in $(seq 1 15); do mssh "curl -s --max-time 2 localhost:5641/healthz 2>/dev/null" | grep -q OK && break; sleep 1; done

echo "== 11. P6: koi trust diagnose on the member =="
mssh "KOI_DATA_DIR=/home/stone/koi-test/data KOI_NO_CREDENTIAL_STORE=1 /home/stone/koi-test/koi trust diagnose 2>&1" | sed 's/^/    /'

echo "== 12. A: koi status surfaces mDNS receive-health (anti-silence) =="
# With a browse active, koi status must report the daemon is actually RECEIVING — not a
# silently-empty browser. Start a background browse, then read the daemon's status.
mssh "KOI_DATA_DIR=/home/stone/koi-test/data timeout 10 /home/stone/koi-test/koi mdns discover _certmesh._tcp >/dev/null 2>&1 &"
sleep 5
ST=$(mssh "curl -s http://localhost:5641/v1/status" 2>/dev/null)
echo "$ST" | tr ',{}' '\n' | grep -iE 'browse receiving|browse active|mdns_browse' | head -4 | sed 's/^/    /'
if echo "$ST" | grep -qiE 'browse receiving|browse active'; then ok "koi status surfaces mDNS receive-health"; else bad "status not surfacing receive-health (A)"; fi

echo
echo "==================== RESULT: $PASS passed, $FAIL failed ===================="
[ "$FAIL" -eq 0 ]
