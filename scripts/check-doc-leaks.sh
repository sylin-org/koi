#!/usr/bin/env bash
# Consumer-name tripwire (STACK-0001 D1/K2).
#
# Koi is the base layer of the Sylin stack and must NOT name or special-case its
# downstream consumers in user-facing docs. This greps the user-facing
# documentation for known consumer names and fails the build if any appears, so a
# leak (like the "Garden mesh" mention once in docs/guides/udp.md) cannot return.
#
# Internal/working docs (docs/prompts, docs/assessment, docs/plans, docs/research,
# docs/proposals, docs/qa, docs/prior-art, docs/archive) are NOT scanned — they are
# dev artifacts, not shipped documentation.
#
# Usage: scripts/check-doc-leaks.sh
set -euo pipefail

# User-facing documentation only.
PATHS=(
  README.md
  GUIDE.md
  CONTAINERS.md
  CONTRIBUTING.md
  docs/guides
  docs/reference
)

# Forbidden downstream-consumer identifiers (case-insensitive, word-ish).
# Keep this list in sync with STACK-0001's named consumers.
PATTERN='Zen Garden|Garden mesh|\bKoan\b'

hits="$(grep -rniE "$PATTERN" "${PATHS[@]}" 2>/dev/null || true)"

if [ -n "$hits" ]; then
  echo "FAIL: downstream-consumer name(s) found in user-facing docs (STACK-0001 D1):"
  echo "$hits"
  echo
  echo "Koi may not name or special-case its consumers. Rewrite in generic terms."
  exit 1
fi

echo "OK: no downstream-consumer names in user-facing docs."
