// Deliver a real compositor close request; Tauri must hide into its existing tray.
const candidates = workspace.windowList().filter(window =>
    ['Koi renderer experiment', 'Koi — R06 renderer evaluation'].includes(window.caption)
        && window.normalWindow);
if (candidates.length !== 1) {
    throw new Error('Expected exactly one R06 evaluation window');
}
print('KOI_R06_CLOSE ' + candidates[0].pid);
candidates[0].closeWindow();
