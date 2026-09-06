#!/usr/bin/env bash
# Measured test-01 R07 daemon + desktop rollback, executed from a private copy.
set -euo pipefail
checkpoint=${1:?root-private checkpoint required}
[[ $(id -u) == 0 && $(hostname) == test-01 ]]
[[ $checkpoint =~ ^/var/tmp/koi-r07-full\.[[:alnum:]]+$ ]]
[[ -d $checkpoint && ! -L $checkpoint && $(stat -c '%u:%a' "$checkpoint") == 0:700 ]]
cd "$checkpoint"
exec 9>restore.lock
flock -w 30 9
[[ ! -f accepted && ! -f restored ]] || exit 0
sha256sum --check checkpoint.sha256
trap 'systemctl start koi || true' ERR
user_session() {
    runuser -u test -- env XDG_RUNTIME_DIR=/run/user/1000 \
        DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus "$@"
}
for unit in app-koi-r07-announce-20260906 app-koi-r07-notes-20260906; do
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
# Only the run-owned preference may have been added to an initially absent file.
if [[ -f preferences-absent && -f /var/lib/koi/state/preferences.json ]]; then
    jq -e '.schema == 1 and (.candidates | length == 0) and
        all(.services[]; .service_key.id == "svc_r07_notes_20260906")' \
        /var/lib/koi/state/preferences.json >/dev/null
    rm /var/lib/koi/state/preferences.json
fi
tar -C / -xpf baseline.tar
./prior-koi install --operator test
[[ $(sha256sum /usr/local/bin/koi | cut -d ' ' -f1) == dc1ebd15b8d1bf2d725c212912d78a5dd9581aa897c505596e8b0a268d9b3975 ]]
pacman --noconfirm --color never -U prior.pkg.tar.zst
[[ $(sha256sum /usr/bin/koi-desktop | cut -d ' ' -f1) == 0e8a88c3f7eb67ae8237b981981fc3fd7e4e73b0a52384085d1f9e6776b46ad0 ]]
systemctl start koi
curl --fail --silent --retry 5 --retry-connrefused --max-time 5 http://127.0.0.1:5641/healthz >/dev/null
sha256sum --check --quiet state.sha256 policy.sha256
user_session systemd-run --user --collect --unit=app-koi-r07-full-restored \
    --working-directory=/ /usr/bin/koi-desktop
touch restored
