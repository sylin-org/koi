#!/bin/sh
# Enable Koi's mDNS on a Debian 12/13 server where systemd-resolved holds
# UDP 5353 (the ADR-030 coexistence skip made koi silent by design). The
# operator elected servers to announce: disable resolved's mDNS via a drop-in,
# restart resolved, then restart koi so its exclusive-bind probe finds 5353
# free and the capability starts.
#
# CONFLICT WARNING (measured 2026-08-25 on brook+granite): both lab servers
# carry /etc/systemd/resolved.conf.d/zen-garden.conf with MulticastDNS=resolve
# — the ZenGarden/Moss deployment deliberately owns resolved's mDNS there.
# Drop-ins merge alphabetically and "z" beats "9", so zen-garden.conf wins and
# this script's 90-* file is inert. Do NOT raise the priority or delete the
# garden's file without an explicit operator decision: one host, one mDNS
# responder — koi-announcing and garden-resolving are mutually exclusive.
#
# Mutation boundary: one drop-in file + two service restarts. Reversible:
#   rm /etc/systemd/resolved.conf.d/90-koi-mdns.conf
#   systemctl restart systemd-resolved koi
# Side effect (documented): resolved stops resolving .local via mDNS on this
# host; upstream DNS/caching is unaffected after the restart blip.
#
# Usage: sudo sh mesh-mdns-enable.sh
set -eu
DROP=/etc/systemd/resolved.conf.d/90-koi-mdns.conf

if ! systemctl is-active --quiet systemd-resolved; then
  echo "RESOLVED_NOT_ACTIVE — 5353 is koi's to take; restarting koi only."
  systemctl restart koi
else
  mkdir -p /etc/systemd/resolved.conf.d
  printf '[Resolve]\nMulticastDNS=no\n' > "$DROP"
  systemctl restart systemd-resolved
  sleep 1
  systemctl restart koi
fi

sleep 2
for i in $(seq 1 25); do
  curl -sf http://127.0.0.1:5641/healthz >/dev/null 2>&1 && break
  sleep 0.4
done
curl -sf http://127.0.0.1:5641/healthz >/dev/null && echo HEALTHZ_OK

echo "=== 5353 owner now ==="
ss -lnup | grep 5353 || echo "none"
echo "=== mdns capability ==="
curl -sf http://127.0.0.1:5641/v1/status | python3 -c '
import json, sys
d = json.load(sys.stdin)
for c in d["capabilities"]:
    if c["name"] == "mdns":
        print("mdns =>", c["summary"])
'
