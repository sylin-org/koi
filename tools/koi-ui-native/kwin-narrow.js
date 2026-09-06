// Activate/resize only the sole normal package-owned Koi window. Unload after use.
const candidates = workspace.windowList().filter(window =>
    String(window.resourceClass) === 'koi-desktop' && window.normalWindow && window.caption === 'Koi');
if (candidates.length !== 1) throw new Error('Expected exactly one Koi workbench');
const window = candidates[0];
window.setMaximize(false, false);
window.minimized = false;
workspace.activeWindow = window;
window.frameGeometry = {x: 80, y: 80, width: 320, height: 900};
print('KOI_SHARED_WINDOW ' + JSON.stringify({pid: window.pid, client: window.clientGeometry}));
