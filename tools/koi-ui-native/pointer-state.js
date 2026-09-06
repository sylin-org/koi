// Read-only: no focus, geometry, pointer or browser changes. Unload after use.
const candidates = workspace.windowList().filter(w =>
    String(w.resourceClass) === 'koi-desktop' && w.normalWindow && w.caption === 'Koi');
if (candidates.length !== 1) throw new Error('Expected exactly one Koi workbench');
const w = candidates[0];
print('KOI_POINTER_STATE ' + JSON.stringify({observedAt:Date.now(), pid:w.pid, active:workspace.activeWindow === w,
    frame:w.frameGeometry, client:w.clientGeometry, minimized:w.minimized,
    cursor:workspace.cursorPos, overKoi:workspace.windowAt(workspace.cursorPos, 1)[0] === w}));
