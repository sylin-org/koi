#!/usr/bin/env bash
# Guard: every publishable workspace crate must appear in publish.yml's CRATES list.
#
# publish.yml hardcodes the ordered publish set. If a new crate is added to the
# workspace but not to that list, a release publishes a PARTIAL set: any already-listed
# crate that depends on the missing one fails to publish (its dep isn't on crates.io),
# and everything after it never publishes. This is exactly the koi-dashboard / 0.4.0
# incident — koi-dashboard was added in P06 but not to the list, so koi-embedded and
# koi-net could not publish.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
PUB="$REPO/.github/workflows/publish.yml"

# Publishable workspace members (publish != false). cargo metadata reports publish as
# `null` (any registry), a non-empty list (specific registries), or `[]` for
# publish = false.
mapfile -t members < <(
  cargo metadata --no-deps --format-version 1 --manifest-path "$REPO/Cargo.toml" \
    | python -c "import sys,json; [print(p['name']) for p in json.load(sys.stdin)['packages'] if p.get('publish') != []]" \
    | tr -d '\r' \
    | sort
)

missing=0
for m in "${members[@]}"; do
  # CRATES entries are an indented package name followed by whitespace/comment.
  if ! grep -qE "^[[:space:]]*${m}([[:space:]]|\$)" "$PUB"; then
    echo "MISSING from publish.yml CRATES list: $m"
    missing=1
  fi
done

if [ "$missing" -ne 0 ]; then
  echo "FAIL: publishable crate(s) absent from publish.yml — a release would publish a partial set."
  echo "      Add them (in dependency order, before any dependent) to the CRATES array."
  exit 1
fi
echo "OK: all ${#members[@]} publishable workspace crates are present in publish.yml's CRATES list."
