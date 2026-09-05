// Load only during the explicit R06 evaluation, then unload this script.
// KWin API: https://develop.kde.org/docs/plasma/kwin/api/
const candidates = workspace.windowList().filter(window =>
    ['Koi renderer experiment', 'Koi — R06 renderer evaluation'].includes(window.caption)
        && window.normalWindow);
if (candidates.length !== 1) {
    throw new Error('Expected exactly one R06 evaluation window');
}
const window = candidates[0];
window.setMaximize(false, false);
window.minimized = false;
workspace.activeWindow = window;
function settled() {
    if (window.clientGeometry.width !== 320) return;
    print('KOI_R06_NARROW_SETTLED ' + JSON.stringify({pid: window.pid,
        frame: window.frameGeometry, client: window.clientGeometry}));
    window.frameGeometryChanged.disconnect(settled);
}
window.frameGeometryChanged.connect(settled);
window.frameGeometry = {x: 80, y: 80, width: 320, height: 900};
if (window.clientGeometry.width === 320) settled();
