#!/bin/sh
# Mint a single-use enrollment invite for $1 on the REAL service's mesh CA.
# Run under sudo (root-owned breadcrumb). Prints the invite code to stdout;
# redirect it into a file and ship the FILE (RL-5).
set -eu
DAT="$(sed -n 's/^dat://p' /var/run/koi.endpoint | tr -d '[:space:]')"
printf '{"hostname":"%s","ttl_mins":120}' "$1" \
  | curl -s -X POST http://127.0.0.1:5641/v1/certmesh/invite \
      -H 'content-type: application/json' -H "x-koi-token: $DAT" -d @-
