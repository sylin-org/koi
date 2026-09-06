#!/usr/bin/env bash
# Desktop-only R07 rollback for the measured e010086 baseline on test-01.
set -euo pipefail
checkpoint=${1:?root-private checkpoint required}
[[ $(id -u) == 0 && $(hostname) == test-01 ]]
[[ $checkpoint =~ ^/var/tmp/koi-r07\.[[:alnum:]]+$ ]]
[[ -d $checkpoint && ! -L $checkpoint ]]
[[ $(stat -c '%u:%a' "$checkpoint") == 0:700 ]]
cd "$checkpoint"
exec 9>restore.lock
flock -w 30 9
[[ ! -f accepted && ! -f restored ]] || exit 0
sha256sum --check checkpoint.sha256
user_session() {
    runuser -u test -- env XDG_RUNTIME_DIR=/run/user/1000 \
        DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus "$@"
}
# Restore service availability even if a later package operation fails.
[[ $(sha256sum /usr/local/bin/koi | cut -d ' ' -f1) == dc1ebd15b8d1bf2d725c212912d78a5dd9581aa897c505596e8b0a268d9b3975 ]]
systemctl start koi
curl --fail --silent --retry 5 --retry-connrefused --max-time 5 http://127.0.0.1:5641/healthz >/dev/null
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
[[ $(sha256sum /usr/bin/koi-desktop | cut -d ' ' -f1) == c874a638d31b48dfba0ec45c6a110799dbf6fdd31f604aad66605fc59a2d407a ]]
user_session systemd-run --user --collect --unit=app-koi-r07-restored \
    --working-directory=/ /usr/bin/koi-desktop
touch restored
