#!/bin/sh
# Post-join verification on the member: custody, diagnosis, roster presence.
set -eu
ROOT="${1:-$HOME/koi-dogfood}"
HOST="${2:-$(hostname)}"
env KOI_DATA_DIR="$ROOT/data" KOI_DNS_ZONE=internal KOI_NO_CREDENTIAL_STORE=1 \
  "$ROOT/koi" trust diagnose --json | python3 -c '
import json,sys
d = json.load(sys.stdin)
print("overall:", d["overall"])
for c in d["checks"]:
    print(" ", c["name"], "=", c["status"])
'
test -f "$ROOT/data/certs/$HOST/key.pem" && echo KEY_CUSTODY_OK
stat -c "%a" "$ROOT/data/certs/$HOST/key.pem"
