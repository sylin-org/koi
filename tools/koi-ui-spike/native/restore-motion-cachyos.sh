#!/usr/bin/env bash
# Desktop-only rollback to the accepted c497b3b package. Never touches the daemon.
# Execute only the root-owned copy in the fresh private checkpoint.
set -euo pipefail
checkpoint=${1:?root-private checkpoint required}
[[ $(id -u) == 0 && $(hostname) == test-01 ]]
[[ $checkpoint =~ ^/var/tmp/koi-r06-motion\.[[:alnum:]]+$ ]]
[[ -d $checkpoint && ! -L $checkpoint ]]
[[ $(stat -c '%u:%a' "$checkpoint") == 0:700 ]]
cd "$checkpoint"
exec 9>restore.lock
flock -n 9 || exit 1
[[ ! -f accepted && ! -f restored ]] || exit 0
sha256sum --check checkpoint.sha256
user_session() {
    runuser -u test -- env XDG_RUNTIME_DIR=/run/user/1000 \
        DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus "$@"
}
user_session gsettings set org.gnome.desktop.interface enable-animations true
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
pacman --noconfirm -U prior.pkg.tar.zst
[[ $(sha256sum /usr/bin/koi-desktop | cut -d ' ' -f1) == 316fc8fa06a2474fe4de75c445cd5f3ee77d1a2fe91ccb23a9b188033065843e ]]
user_session systemd-run --user --collect --unit=app-koi-r06-normal \
    --working-directory=/ /usr/bin/koi-desktop
touch restored
