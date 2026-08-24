#!/bin/sh
# Replace the transient/user-process dogfood bootstrap with the REAL product
# install path: `sudo koi install` -> /usr/local/bin/koi + enabled koi.service
# (Type=notify, Restart=on-failure 5s, multi-user.target). Operator decision
# 2026-08-24: "there should be no transient install. Everything on the TEST
# machines must be real."
#
# Mutation boundary: stops only the legacy dogfood shapes (transient
# koi-dogfood unit / this-tree pidfile daemon), copies any pre-existing
# /usr/local/bin/koi aside for preservation, installs, verifies. Never deletes
# the old tree. Reverse: sudo koi uninstall; restart the old shape by hand.
#
# Usage (RL-6: one ownership domain, root throughout):
#   sudo sh mesh-real-install.sh            # infers tree from SUDO_USER
#   sudo sh mesh-real-install.sh /home/x/koi-dogfood /path/to/rc2-koi
set -eu
SUDO_USER_NAME="${SUDO_USER:-$(logname 2>/dev/null || echo)}"
OLD_ROOT="${1:-/home/$SUDO_USER_NAME/koi-dogfood}"
BIN="${2:-$OLD_ROOT/koi}"
# Published v1.0.0-rc.2 musl binary, derived 2026-08-24 by extracting the
# GitHub release asset and hashing the inner koi (NOT the tarball). Verified
# identical to the deployed dogfood binaries on brook/granite/test-01.
# (Ledger's 94e7d652... was the earlier pre-release evidence-series build.)
RC2_MUSL_SHA="006ef30d793fe70c0a7b69c5a71fffcf3b38092f3663508bdaf20a34a27658b8"

# 1. Stop legacy shapes — this exact install only.
systemctl stop koi-dogfood.service 2>/dev/null || true
systemctl reset-failed koi-dogfood.service 2>/dev/null || true
PIDFILE="$OLD_ROOT/runtime/daemon.pid"
if [ -f "$PIDFILE" ]; then
  pid=$(cat "$PIDFILE" 2>/dev/null || true)
  case "$pid" in ''|*[!0-9]*) pid="";; esac
  if [ -n "$pid" ]; then
    exe=$(readlink -f "/proc/$pid/exe" 2>/dev/null || true)
    case "$exe" in
      "") ;;
      "$OLD_ROOT"/koi) kill "$pid" 2>/dev/null || true; sleep 1;;
      *) echo "REFUSED_WRONG_EXE: $exe"; exit 75;;
    esac
  fi
fi

# 2. Preserve any historical /usr/local/bin/koi (granite's 0.7.0 artifact).
if [ -f /usr/local/bin/koi ]; then
  PRESERVED="$OLD_ROOT/usr-local-bin-koi.$(sha256sum /usr/local/bin/koi | cut -c1-12).preserved"
  [ -f "$PRESERVED" ] || cp -p /usr/local/bin/koi "$PRESERVED"
  echo "PRESERVED_EXISTING_BIN -> $PRESERVED"
fi

# 3. Artifact provenance: install only the exact published rc.2 musl build.
[ -x "$BIN" ] || { echo "MISSING_BINARY: $BIN"; exit 70; }
ACTUAL=$(sha256sum "$BIN" | cut -d' ' -f1)
if [ "$ACTUAL" != "$RC2_MUSL_SHA" ]; then
  echo "REFUSED_UNEXPECTED_ARTIFACT: $ACTUAL"
  exit 71
fi

# 4. The real thing.
"$BIN" install

# 5. Post-conditions: active, healthy, byte-identical installed binary.
systemctl is-active koi.service
curl -sf http://127.0.0.1:5641/healthz >/dev/null && echo HEALTHZ_OK
INSTALLED=$(sha256sum /usr/local/bin/koi | cut -d' ' -f1)
if [ "$INSTALLED" != "$RC2_MUSL_SHA" ]; then
  echo "HASH_MISMATCH_AFTER_INSTALL: $INSTALLED"
  exit 72
fi
echo "REAL_INSTALL_OK sha=$INSTALLED unit=/etc/systemd/system/koi.service data_root=/var/lib/koi"
