#!/usr/bin/env bash
# Exact desktop-only emergency rollback for the R06 shared-shell verification.
# Execute the integrity-checked root-owned checkpoint copy, not the worktree.
set -euo pipefail
checkpoint=${1:?root-private checkpoint required}
[[ $(id -u) == 0 && $(hostname) == test-01 ]]
[[ $checkpoint =~ ^/var/tmp/koi-r06-shell\.[[:alnum:]]+$ ]]
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
if systemctl is-active --quiet koi-r06-shared-offline.service; then
    systemctl stop koi-r06-shared-offline.service
fi
if [[ $(user_session qdbus6 org.kde.KWin /Scripting org.kde.kwin.Scripting.isScriptLoaded koi-r06-shared-narrow) == true ]]; then
    user_session qdbus6 org.kde.KWin /Scripting org.kde.kwin.Scripting.unloadScript koi-r06-shared-narrow
fi
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
[[ $(sha256sum /usr/bin/koi-desktop | cut -d ' ' -f1) == 29de5306d31362a766498678803edc769595116bc19b08f52ed69fbb2317438e ]]
# Restore availability after a service-loss check, without replacing daemon/data.
[[ $(sha256sum /usr/local/bin/koi | cut -d ' ' -f1) == dc1ebd15b8d1bf2d725c212912d78a5dd9581aa897c505596e8b0a268d9b3975 ]]
systemctl start koi
curl --fail --silent --max-time 5 http://127.0.0.1:5641/healthz >/dev/null
user_session systemd-run --user --collect --unit=app-koi-r06-normal \
    --working-directory=/ /usr/bin/koi-desktop
touch restored
