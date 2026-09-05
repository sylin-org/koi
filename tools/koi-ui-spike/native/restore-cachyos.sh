#!/usr/bin/env bash
# R06 test-01 emergency rollback. Copy into the root-private checkpoint before
# arming a transient system timer. Never execute the working-tree copy as root.
set -euo pipefail
checkpoint=${1:?root-private checkpoint required}
[[ $(id -u) == 0 && $(hostname) == test-01 ]]
[[ $checkpoint =~ ^/var/tmp/koi-r06-native\.[[:alnum:]]+$ ]]
[[ -d $checkpoint && ! -L $checkpoint ]]
[[ $(stat -c '%u:%a' "$checkpoint") == 0:700 ]]
cd "$checkpoint"
exec 9>restore.lock
flock -n 9 || exit 1
[[ ! -f accepted && ! -f restored ]] || exit 0
sha256sum --check checkpoint.sha256
[[ $(readlink -f /usr/local/bin/koi) == /usr/local/bin/koi ]]
[[ $(readlink -f /var/lib/koi) == /var/lib/koi ]]

# Only the known package-owned workbench may be retired, never another program.
mapfile -t workbenches < <(pgrep -u test -x koi-desktop || true)
[[ ${#workbenches[@]} -le 1 ]]
for process in "${workbenches[@]}"; do
    executable=$(readlink "/proc/$process/exe")
    [[ $executable == /usr/bin/koi-desktop || $executable == '/usr/bin/koi-desktop (deleted)' ]]
    kill -TERM "$process"
    for attempt in {1..50}; do
        kill -0 "$process" 2>/dev/null || break
        sleep 0.1
    done
    ! kill -0 "$process" 2>/dev/null
done

systemctl stop koi
! pgrep -x koi
# Preserve post-upgrade data for recovery/inspection, rather than deleting it.
[[ ! -e post-data && ! -e post-etc-koi ]]
mv /var/lib/koi post-data
if [[ -e /etc/koi ]]; then
    [[ ! -L /etc/koi ]]
    mv /etc/koi post-etc-koi
fi
tar --extract --file baseline.tar --directory / --same-owner --same-permissions
systemctl daemon-reload
systemctl enable koi
systemctl start koi
pacman --noconfirm -U prior.pkg.tar.zst
for attempt in {1..30}; do
    if curl --fail --silent --max-time 2 http://127.0.0.1:5641/healthz >/dev/null; then
        break
    fi
    sleep 1
done
curl --fail --silent --max-time 2 http://127.0.0.1:5641/healthz >/dev/null
[[ $(pgrep -xc koi) == 1 ]]
[[ $(sha256sum /usr/local/bin/koi | cut -d ' ' -f1) == b2079cd3bb2e35a46f0344b8181b92e302b33681c12104124dadf4026d54cdc3 ]]
[[ $(sha256sum /usr/bin/koi-desktop | cut -d ' ' -f1) == cf6f256aef2254cc3ef8f19fcf8892c60d8b32463748ed6de6149f0fbac70f74 ]]
runuser -u test -- env XDG_RUNTIME_DIR=/run/user/1000 DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus \
    systemd-run --user --collect --unit=koi-r06-restored-window \
    --setenv=DISPLAY=:0 --setenv=WAYLAND_DISPLAY=wayland-0 \
    /usr/bin/koi-desktop
touch restored
