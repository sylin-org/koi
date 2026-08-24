#!/bin/sh
# Print the dogfood CA's roster as "hostname role status" lines.
set -eu
ROOT="${1:-$HOME/koi-dogfood}"
DAT="$(sudo sed -n 's/^dat://p' "$ROOT/runtime/koi.endpoint" | tr -d '[:space:]')"
curl -s http://127.0.0.1:5641/v1/certmesh/status \
  -H "x-koi-token: $DAT" \
| python3 -c '
import json,sys
d = json.load(sys.stdin)
for m in d["members"]:
    print(m["hostname"], m["role"], m["status"])
'
