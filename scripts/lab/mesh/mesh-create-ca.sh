#!/bin/sh
# Create the dogfood mesh CA on this host (idempotent-guarded).
set -eu
ENTROPY="$(sha256sum "$HOME/koi-dogfood/koi" | cut -c1-64)"
ROOT="${2:-$HOME/koi-dogfood}"
systemctl is-active koi-dogfood
curl -sf http://127.0.0.1:5641/healthz > /dev/null && echo HEALTH_OK
# create is DAT-gated; the root-owned daemon persists its token in the
# runtime breadcrumb - read it back with sudo.
DAT="$(sudo sed -n 's/^dat://p' "$ROOT/runtime/koi.endpoint" | tr -d '[:space:]')"
if curl -sf http://127.0.0.1:5641/v1/certmesh/status | grep -q '"ca_initialized":true'; then
  echo CA_ALREADY_INITIALIZED
else
  printf '{"passphrase":"lab-dogfood-pass","entropy_hex":"%s","operator":"dogfood","enrollment_open":true,"requires_approval":false,"auto_unlock":true}' "$ENTROPY" \
    | curl -s -X POST http://127.0.0.1:5641/v1/certmesh/create -H 'content-type: application/json' -H "x-koi-token: $DAT" -d @- | head -c 200
  echo ""
fi
curl -sf http://127.0.0.1:5641/v1/certmesh/status | grep -o '"ca_initialized":[a-z]*'
