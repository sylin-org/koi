#!/bin/sh
# Join this host's dogfood daemon to the mesh CA (local key custody).
# Usage: sudo sh mesh-join.sh <ca-endpoint> <invite-file> <ca-mtls-port> [root]
# The invite FILE sidesteps cross-shell quoting of the dotted code. Runs under
# sudo because the daemon's breadcrumb is root-owned.
set -eu
CA="$1"; INVITE_FILE="$2"; MTLS="${3:-5642}"
ROOT="${4:-$HOME/koi-dogfood}"
CODE="$(cat "$INVITE_FILE")"
env KOI_DATA_DIR="$ROOT/data" \
    XDG_RUNTIME_DIR="$ROOT/runtime" \
    KOI_NO_CREDENTIAL_STORE=1 \
    "$ROOT/koi" --endpoint http://127.0.0.1:5641 certmesh join "$CA" --invite "$CODE" --ca-mtls-port "$MTLS" --json
