#!/bin/sh
# Fetch + verify + install the published Koi candidate into a persistent
# dogfood root. Usage: sh mesh-fetch.sh <version> <asset-suffix>
# Example: sh mesh-fetch.sh 1.0.0-rc.2 x86_64-unknown-linux-musl
set -eu
VERSION="$1"
SUFFIX="$2"
BASE="https://github.com/sylin-org/koi/releases/download/v${VERSION}"
ROOT="$HOME/koi-dogfood"
mkdir -p "$ROOT/bin" "$ROOT/data" "$ROOT/runtime" "$ROOT/downloads"
cd "$ROOT/downloads"
curl -fsSLO "$BASE/koi-v$VERSION-$SUFFIX.tar.gz"
curl -fsSLO "$BASE/koi-v$VERSION-$SUFFIX.tar.gz.sha256"
# The sidecar may be "<hash>", "<hash> <name>", or multi-line; take the first
# token and check our downloaded archive against it.
expected=$(head -n 1 "koi-v$VERSION-$SUFFIX.tar.gz.sha256" | awk '{print $1}')
echo "$expected  koi-v$VERSION-$SUFFIX.tar.gz" | sha256sum -c -
tar xzf "koi-v$VERSION-$SUFFIX.tar.gz"
find . -maxdepth 2 -name koi -type f -exec cp {} "$ROOT/koi" \;
chmod 0755 "$ROOT/koi"
"$ROOT/koi" --version
echo "INSTALLED_AT=$ROOT/koi"
