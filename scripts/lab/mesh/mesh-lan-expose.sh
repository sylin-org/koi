#!/bin/sh
# Server-class configuration for the REAL koi.service: expose HTTP on the LAN
# so remote members can preflight/enroll against this CA. Uses the exact
# mechanism the installer prints ("Config: systemctl edit koi") in drop-in
# form. Default installs remain loopback-only — this is an explicit,
# reversible operator choice, applied only to mesh CAs.
# Reverse: remove /etc/systemd/system/koi.service.d/lan.conf && reload+restart.
set -eu
DROPDIR=/etc/systemd/system/koi.service.d
mkdir -p "$DROPDIR"
cat > "$DROPDIR/lan.conf" <<'EOF'
[Service]
Environment=KOI_HTTP_BIND=0.0.0.0
EOF
systemctl daemon-reload
systemctl restart koi.service
sleep 1
for i in $(seq 1 50); do
  curl -sf http://127.0.0.1:5641/healthz >/dev/null 2>&1 && break
  sleep 0.2
done
curl -sf http://127.0.0.1:5641/healthz >/dev/null && echo "LAN_EXPOSE_OK"
ss -H -lnt | grep 5641 || true
