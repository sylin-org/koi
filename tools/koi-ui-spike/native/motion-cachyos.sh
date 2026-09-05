#!/usr/bin/env bash
# Bound to the accepted test-01 package and explicit true GSettings baseline.
# No daemon/package/network mutation. Run as the existing desktop user.
set -euo pipefail
[[ $(hostname) == test-01 && $(id -u) == 1000 ]]
[[ $(sha256sum /usr/bin/koi-desktop | cut -d ' ' -f1) == 316fc8fa06a2474fe4de75c445cd5f3ee77d1a2fe91ccb23a9b188033065843e ]]

restore() {
    gsettings set org.gnome.desktop.interface enable-animations true
    if [[ $(qdbus6 org.kde.KWin /Scripting org.kde.kwin.Scripting.isScriptLoaded koi-r06-motion-narrow) == true ]]; then
        qdbus6 org.kde.KWin /Scripting org.kde.kwin.Scripting.unloadScript koi-r06-motion-narrow
    fi
    if systemctl --user is-active --quiet koi-r06-motion-probe.service; then
        systemctl --user stop koi-r06-motion-probe.service
    fi
    if ! pgrep -u test -x koi-desktop >/dev/null; then
        systemd-run --user --collect --unit=app-koi-r06-normal \
            --working-directory=/ /usr/bin/koi-desktop
    fi
}
if [[ ${1:-} == restore ]]; then
    restore
    exit
fi
[[ $# == 1 ]]
evidence=$(realpath "$1")
[[ $evidence == */tools/koi-ui-spike/target/native/motion-cachyos-* ]]
native=$(cd -- "$(dirname -- "$0")" && pwd)
[[ $(dconf read /org/gnome/desktop/interface/enable-animations) == true ]]
[[ $(pgrep -u test -xc koi-desktop) == 1 ]]
systemctl --user is-active --quiet app-koi-r06-normal.service
systemd-run --user --unit=koi-r06-motion-restore --on-active=3min --collect \
    /usr/bin/bash "$native/motion-cachyos.sh" restore
cleanup() {
    restore
    systemctl --user stop koi-r06-motion-restore.timer
}
trap cleanup EXIT
trap 'exit 130' INT TERM
systemctl --user stop app-koi-r06-normal.service
systemd-run --user --collect --unit=koi-r06-motion-probe --working-directory=/ \
    --setenv="GTK_MODULES=$native/../target/gtk-motion-observer.so" \
    /usr/bin/koi-desktop --renderer-probe
sleep 2
script_id=$(qdbus6 org.kde.KWin /Scripting org.kde.kwin.Scripting.loadScript \
    "$native/kwin-narrow.js" koi-r06-motion-narrow)
qdbus6 org.kde.KWin "/Scripting/Script$script_id" org.kde.kwin.Script.run
sleep 1
qdbus6 org.kde.KWin /Scripting org.kde.kwin.Scripting.unloadScript koi-r06-motion-narrow
"$native/../target/tab-once" --page-down
sleep 3
for phase in enabled reduced resumed; do
    if [[ $phase == reduced ]]; then animations=false; else animations=true; fi
    gsettings set org.gnome.desktop.interface enable-animations "$animations"
    sleep 1
    "$native/../target/gtk-motion-observer"
    dump_xsettings | rg EnableAnimations
    for sample in a b; do
        spectacle --background --activewindow --nonotify --no-shadow \
            --output "$evidence/$phase-$sample.png"
        sleep 1
    done
    # AE is an observation, not a success predicate: unchanged pixels are required
    # only in reduced mode. Compare never modifies either capture.
    comparison=0
    magick compare -metric AE "$evidence/$phase-a.png" "$evidence/$phase-b.png" null: \
        2>"$evidence/$phase-ae.txt" || comparison=$?
    [[ $comparison -le 1 ]]
    metric=$(<"$evidence/$phase-ae.txt")
    echo "$phase changed_pixels=$metric"
    # A diagnostic run continues through all phases, then fails if reduction did
    # not settle. This preserves evidence of restoring the animation preference.
done
[[ $(<"$evidence/reduced-ae.txt") == 0* ]]
[[ $(<"$evidence/enabled-ae.txt") != 0* && $(<"$evidence/resumed-ae.txt") != 0* ]]
