#!/usr/bin/env bash
# R07 browser deployment rollback for the measured test-01 daemon17fb591/desktop24d619f.
set -euo pipefail
checkpoint=${1:?root-private checkpoint required}
[[ $(id -u) == 0 && $(hostname) == test-01 ]]
[[ $checkpoint =~ ^/var/tmp/koi-browser-native\.[[:alnum:]]+$ ]]
[[ -d $checkpoint && ! -L $checkpoint && $(stat -c '%u:%a' "$checkpoint") == 0:700 ]]
cd "$checkpoint"
exec 9>restore.lock
flock -w 30 9
[[ ! -f accepted && ! -f restored ]] || exit 0
sha256sum --check checkpoint.sha256
trap 'systemctl start koi || true' ERR
user_session() {
    runuser -u test -- env XDG_RUNTIME_DIR=/run/user/1000 DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus "$@"
}
for unit in app-koi-browser-notes-20260907 app-koi-browser-announce-20260907; do
    if user_session systemctl --user is-active --quiet "$unit"; then
        user_session systemctl --user stop "$unit"
    fi
done
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
# A newly created grant repository is retained privately, never silently discarded.
if [[ -f browser-access-absent && -e /var/lib/koi/state/browser-access.json ]]; then
    [[ -f /var/lib/koi/state/browser-access.json && ! -L /var/lib/koi/state/browser-access.json ]]
    [[ ! -e rollback-browser-access.json ]]
    mv /var/lib/koi/state/browser-access.json rollback-browser-access.json
fi
fault=/run/systemd/system/koi.service.d/90-r07-browser-no-certmesh.conf
if [[ -e $fault ]]; then
    cmp "$fault" no-certmesh.conf
    rm "$fault"
    rmdir /run/systemd/system/koi.service.d || true
fi
# Any run firewall mutation must provide a byte-exact guarded restoration command.
if [[ -f firewall-changed ]]; then
    sha256sum --check firewall-before.sha256
    cp -a firewall/user.rules /etc/ufw/user.rules
    cp -a firewall/user6.rules /etc/ufw/user6.rules
    ufw reload
fi
tar -C / -xpf baseline.tar
systemctl daemon-reload
chmod 700 prior-koi
./prior-koi install --operator test
[[ $(sha256sum /usr/local/bin/koi | cut -d ' ' -f1) == fc5db34667429bf1c814f01b1baf5956dbe0ce76b30dc7f156cc9f68b4a8714e ]]
pacman --noconfirm --color never -U prior.pkg.tar.zst
[[ $(sha256sum /usr/bin/koi-desktop | cut -d ' ' -f1) == 2db016d9122678b655fc887738c82908bf3ddbbfd3896f9a5b56a7f849fb3d2d ]]
systemctl start koi
curl --fail --silent --retry 5 --retry-connrefused --max-time 5 http://127.0.0.1:5641/healthz >/dev/null
sha256sum --check --quiet state.sha256 policy.sha256
user_session systemd-run --user --collect --unit=app-koi-browser-restored --working-directory=/ /usr/bin/koi-desktop
touch restored
