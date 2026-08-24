#!/bin/sh
# Join this host's REAL daemon to the mesh CA with local CSR custody.
# Usage: sudo sh mesh-join-real.sh <ca-endpoint> <invite-file>
# No KOI_DATA_DIR, no XDG_RUNTIME_DIR overrides — default machine paths only,
# because everything on the test machines must be real (operator, 2026-08-24).
set -eu
CA="$1"
INVITE_FILE="$2"
# Accept either the raw JSON mint response or the bare dotted code
# (<secret>.<ca_fingerprint>); --invite wants the code only.
CODE=$(python3 -c '
import json, sys
raw = open(sys.argv[1]).read().strip()
try:
    print(json.loads(raw)["token"])
except Exception:
    print(raw)
' "$INVITE_FILE")
/usr/local/bin/koi certmesh join "$CA" --invite "$CODE" --json
echo JOIN_EXIT_OK
/usr/local/bin/koi trust diagnose --json | python3 -c '
import json, sys
d = json.load(sys.stdin)
print("overall:", d["overall"])
for c in d["checks"]:
    print(" ", c["name"], "=", c["status"])
'
HOST=$(hostname)
test -f "/var/lib/koi/certs/$HOST/key.pem" && echo KEY_CUSTODY_OK
stat -c "%a" "/var/lib/koi/certs/$HOST/key.pem"
