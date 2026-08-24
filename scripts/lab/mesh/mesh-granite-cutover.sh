#!/bin/sh
# Granite cutover: retire the legacy 0.7.0 system service, start the rc.2
# dogfood daemon on the now-free standard ports.
set -eu
echo lab-dogfood-pass | sudo -S sh -c 'systemctl stop koi; systemctl disable koi' 2>&1 | tail -1
systemctl reset-failed koi-dogfood 2>/dev/null || true
echo lab-dogfood-pass | sudo -S sh /home/stone/koi-dogfood-tmp/mesh-start-server.sh koi-dogfood /home/stone/koi-dogfood
