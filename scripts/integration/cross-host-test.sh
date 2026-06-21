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
  for _ in $(seq 1 20); do curl -s "$CA/healthz" 2>/dev/null | grep -q OK && return 0; sleep 1; done
  return 1
}

echo "================ ADR-020 cross-host integration ($CA_IP CA, $MEMBER_IP member) ================"

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
INVITE=$(echo "$INV" | jq -r '.invite // .invite_code // empty' 2>/dev/null)
if [ -n "$INVITE" ]; then ok "invite minted"; else bad "invite"; echo "    $INV" | head -c 300; echo; fi

echo "== 6. restart CA daemon so it announces _certmesh._tcp (announce is startup-gated) =="
start_ca_daemon && ok "CA daemon re-up with CA loaded" || bad "CA daemon restart"
sleep 2

echo "== 7. member (granite) clean + daemon up (fresh deployed binary) =="
# Wipe any leftover certmesh state + stale daemons (granite carried an old CA from a
# prior session). Use the ABSOLUTE deployed-binary path — $HOME may hold an old koi.
mssh "echo stone | sudo -S systemctl stop koi 2>/dev/null; pkill -f 'koi --daemon' 2>/dev/null; sleep 1; rm -rf /home/stone/koi-test/data; mkdir -p /home/stone/koi-test/data" 2>/dev/null
mssh "cd /home/stone/koi-test && KOI_DATA_DIR=\$PWD/data KOI_NO_CREDENTIAL_STORE=1 KOI_HTTP_BIND=0.0.0.0 nohup /home/stone/koi-test/koi --daemon --no-runtime --no-proxy --no-udp --no-mcp-http --no-acme </dev/null >/home/stone/koi-test/daemon.log 2>&1 & sleep 5" 2>/dev/null
if mssh "curl -s localhost:5641/healthz 2>/dev/null" | grep -q OK; then ok "member daemon up"; else bad "member daemon"; fi

echo "== 8. member joins the CA over the real LAN =="
JOINOUT=$(mssh "cd /home/stone/koi-test; KOI_DATA_DIR=\$PWD/data KOI_NO_CREDENTIAL_STORE=1 timeout 40 /home/stone/koi-test/koi certmesh join $CA_IP:5641 --invite '$INVITE' 2>&1")
echo "$JOINOUT" | tail -10 | sed 's/^/    /'
if echo "$JOINOUT" | grep -qiE 'joined|enrolled|installed|success'; then ok "member join"; else bad "member join (see output)"; fi

echo "== 9. CA roster shows the member =="
curl -s "$CA/v1/certmesh/status" -H "x-koi-token: $TOKEN" 2>/dev/null | jq -r '.members[]?.hostname' 2>/dev/null | sed 's/^/    roster: /'
if curl -s "$CA/v1/certmesh/status" -H "x-koi-token: $TOKEN" 2>/dev/null | jq -e ".members[]? | select(.hostname==\"$MEMBER_HOST\")" >/dev/null 2>&1; then ok "roster has $MEMBER_HOST"; else bad "roster missing member"; fi

echo "== 10. P3: member discovers the CA's posture TXT over real mDNS =="
DISC=$(mssh "KOI_DATA_DIR=/home/stone/koi-test/data timeout 10 /home/stone/koi-test/koi mdns discover _certmesh._tcp 2>&1" || true)
echo "$DISC" | head -20 | sed 's/^/    /'
if echo "$DISC" | grep -qiE 'fp=|posture=|fp:|posture'; then ok "discover sees posture/fp TXT"; else bad "no posture TXT seen"; fi

echo "== 11. P6: koi trust diagnose on the member =="
mssh "KOI_DATA_DIR=/home/stone/koi-test/data KOI_NO_CREDENTIAL_STORE=1 /home/stone/koi-test/koi trust diagnose 2>&1" | sed 's/^/    /'

echo
echo "==================== RESULT: $PASS passed, $FAIL failed ===================="
[ "$FAIL" -eq 0 ]
