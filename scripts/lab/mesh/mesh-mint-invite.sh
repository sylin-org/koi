#!/bin/sh
# Mint a single-use enrollment invite for $1 on this host's dogfood CA.
set -eu
ROOT="${2:-$HOME/koi-dogfood}"
DAT="$(sudo sed -n 's/^dat://p' "$ROOT/runtime/koi.endpoint" | tr -d '[:space:]')"
printf '{"hostname":"%s","ttl_mins":120}' "$1" \
  | curl -s -X POST http://127.0.0.1:5641/v1/certmesh/invite \
      -H 'content-type: application/json' -H "x-koi-token: $DAT" -d @-
