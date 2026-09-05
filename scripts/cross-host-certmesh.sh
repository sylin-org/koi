#!/usr/bin/env bash
# ADR-018 Tier 3 — cross-HOST certmesh exchange.
#
# Two `koi` daemons run in SEPARATE containers (distinct hostnames/IPs on a user-defined
# bridge network) and drive the whole story over the real container network, via the real
# `koi certmesh` CLI in client mode: create → mint invite → node-b JOINS node-a over the
# bridge → assert enrolled → revoke → a fresh re-join of the revoked host is REFUSED.
#
# This is the genuine cross-host coverage the single-process Tiers 1–2 cannot give, and it
# additionally exercises the CLI client-mode path (breadcrumb discovery + DAT token +
# member-csr/member-cert custody) end to end. Runnable locally (Docker + `cross`) and in CI.
#
# Build the Linux binary with `cross` (the same musl toolchain the release uses); set
# KOI_BIN=/path/to/linux/koi to reuse a prebuilt one and skip the build.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
# On Git Bash / MSYS, hand cargo/cross a Windows-style path it can resolve.
if command -v cygpath >/dev/null 2>&1; then REPO="$(cygpath -m "$REPO")"; fi
CTX="$REPO/docker/cross-host"
TARGET="x86_64-unknown-linux-musl"
COMPOSE="docker compose -p koi-tier3"

# ── 1. Build (or reuse) the Linux koi binary and stage it for the image ──
BIN="${KOI_BIN:-}"
if [ -z "$BIN" ]; then
  echo ">> building koi for $TARGET via cross"
  ( cd "$REPO" && cross build --locked --target "$TARGET" -p koi-net )
  BIN="$REPO/target/$TARGET/debug/koi"
fi
[ -f "$BIN" ] || { echo "FAIL: koi binary not found at $BIN"; exit 1; }
cp "$BIN" "$CTX/koi"

cd "$CTX"

cleanup() {
  $COMPOSE down -v --remove-orphans >/dev/null 2>&1 || true
  rm -f "$CTX/koi" || true
}
trap cleanup EXIT

# ── 2. Bring the two daemons up on the bridge network ──
echo ">> docker compose up"
$COMPOSE up -d --build

# Each daemon answers `koi status` (client mode via its own in-container breadcrumb) once
# its HTTP adapter is bound.
ready() {
  local svc="$1"
  for _ in $(seq 1 60); do
    if $COMPOSE exec -T "$svc" koi status >/dev/null 2>&1; then return 0; fi
    sleep 1
  done
  echo "FAIL: $svc daemon did not become ready"; $COMPOSE logs "$svc" || true; return 1
}
ready node-a
ready node-b

# This image has no OS keychain, so its vault is bound to /etc/machine-id.
# Assert the actual container identities before enrollment; a shared or missing
# ID would invalidate the two-host fixture even if its network exchange passed.
MACHINE_A="$($COMPOSE exec -T node-a cat /etc/machine-id)"
MACHINE_B="$($COMPOSE exec -T node-b cat /etc/machine-id)"
if [[ ! "$MACHINE_A" =~ ^[0-9a-f]{32}$ || ! "$MACHINE_B" =~ ^[0-9a-f]{32}$ || "$MACHINE_A" == "$MACHINE_B" ]]; then
  echo "FAIL: cross-host fixtures require distinct valid machine IDs"
  exit 1
fi

# Extract the `token` field from a `--json` invite response (no jq dependency).
invite_token() {
  $COMPOSE exec -T node-a koi certmesh invite "$1" --ttl 60 --json 2>/dev/null \
    | grep -o '"token"[[:space:]]*:[[:space:]]*"[^"]*"' | head -1 \
    | sed 's/.*:[[:space:]]*"\([^"]*\)".*/\1/'
}

# ── 3. node-a: create the CA (non-interactive: --json + profile + passphrase) ──
echo ">> node-a: certmesh create"
$COMPOSE exec -T node-a koi certmesh create --json --profile just-me --passphrase 'tier3-pass' >/dev/null

# ── 4. node-a: mint an invite bound to node-b's hostname ──
echo ">> node-a: mint invite for node-b"
INVITE="$(invite_token node-b)"
[ -n "$INVITE" ] || { echo "FAIL: empty invite token"; exit 1; }

# ── 5. node-b: JOIN node-a over the container network (cross-host HTTP) ──
echo ">> node-b: join node-a"
$COMPOSE exec -T node-b koi certmesh join http://node-a:5641 --invite "$INVITE" --json >/dev/null

# ── 6. assert node-b is enrolled in node-a's roster ──
echo ">> node-a: assert node-b enrolled"
STATUS="$($COMPOSE exec -T node-a koi certmesh status --json 2>/dev/null)"
echo "$STATUS" | grep -q 'node-b' || { echo "FAIL: node-b not in node-a roster:"; echo "$STATUS"; exit 1; }

# ── 7. node-a: revoke node-b ──
echo ">> node-a: revoke node-b"
$COMPOSE exec -T node-a koi certmesh revoke node-b --json >/dev/null

# ── 8. boundary: a fresh re-join of the revoked host must FAIL ──
echo ">> node-b: re-join (must be refused)"
INVITE2="$(invite_token node-b)"
[ -n "$INVITE2" ] || { echo "FAIL: empty re-invite token"; exit 1; }
if $COMPOSE exec -T node-b koi certmesh join http://node-a:5641 --invite "$INVITE2" --json >/dev/null 2>&1; then
  echo "FAIL: a revoked host's re-join succeeded (revocation not enforced cross-host)"
  exit 1
fi

echo "OK: cross-host certmesh exchange (create -> invite -> join -> revoke -> revoked-rejoin) passed."
