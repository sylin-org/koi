#!/bin/sh
# Initialize (or confirm) the certmesh CA on the REAL koi.service install.
# Default paths only: breadcrumb /var/run/koi.endpoint, data /var/lib/koi.
# Run under sudo: the root-owned daemon's DAT is 0600 root.
set -eu
ENTROPY="$(sha256sum /usr/local/bin/koi | cut -c1-64)"
systemctl is-active koi.service
DAT="$(sed -n 's/^dat://p' /var/run/koi.endpoint | tr -d '[:space:]')"
if curl -sf http://127.0.0.1:5641/v1/certmesh/status | grep -q '"ca_initialized":true'; then
  echo CA_ALREADY_INITIALIZED
else
  printf '{"passphrase":"lab-dogfood-pass","entropy_hex":"%s","operator":"dogfood","enrollment_open":true,"requires_approval":false,"auto_unlock":true}' "$ENTROPY" \
    | curl -s -X POST http://127.0.0.1:5641/v1/certmesh/create -H 'content-type: application/json' -H "x-koi-token: $DAT" -d @- | head -c 200
  echo ""
fi
curl -sf http://127.0.0.1:5641/v1/certmesh/status | grep -o '"ca_initialized":[a-z]*'
