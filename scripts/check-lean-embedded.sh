#!/usr/bin/env bash
# Tripwire: a lean `koi-embedded` consumer (default-features = false) must pull NONE of
# the optional, heavy, version-locked backends — bollard (Docker), the OS-keychain /
# Secret-Service / D-Bus stack (keyring), or the image PNG codec (qr).
#
# This is checked from an EXTERNAL probe crate, NOT from within the workspace: a
# `cargo tree -p koi-embedded --no-default-features` run inside the repo is poisoned by
# Cargo feature unification with the `koi-net` binary (which enables every backend), so
# it would mask a propagation regression. The probe has its own workspace, so it sees the
# true lean closure a downstream consumer would get.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
# On Git Bash / MSYS, hand Cargo a Windows-style path it can resolve.
if command -v cygpath >/dev/null 2>&1; then REPO="$(cygpath -m "$REPO")"; fi
PROBE="$(mktemp -d)"
trap 'rm -rf "$PROBE"' EXIT

mkdir -p "$PROBE/src"
echo 'fn main() {}' > "$PROBE/src/main.rs"
cat > "$PROBE/Cargo.toml" <<EOF
[package]
name = "koi-lean-probe"
version = "0.0.0"
edition = "2021"

[dependencies]
koi-embedded = { path = "$REPO/crates/koi-embedded", default-features = false }

[workspace]
EOF

cd "$PROBE"
tree="$(cargo tree -e normal)"

fail=0
for dep in bollard bollard-stubs keyring secret-service zbus image qrcode; do
  n="$(printf '%s\n' "$tree" | grep -c " ${dep} " || true)"
  if [ "$n" -ne 0 ]; then
    echo "LEAK: lean koi-embedded pulls '${dep}' (${n} occurrence(s))"
    fail=1
  fi
done

if [ "$fail" -ne 0 ]; then
  echo "FAIL: a lean koi-embedded (default-features = false) must shed every optional heavy backend."
  echo "      Check the default-features=false edges + feature pass-throughs (see ADR-014)."
  exit 1
fi
echo "OK: lean koi-embedded sheds bollard / keyring (Secret Service/D-Bus) / image / qrcode."
