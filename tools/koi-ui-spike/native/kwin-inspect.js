// Read-only Koi window facts; no unrelated window titles or geometry emitted.
for (const window of workspace.windowList()) {
    if (String(window.resourceClass) !== 'koi-desktop') continue;
    print('KOI_R06_WINDOW ' + JSON.stringify({pid: window.pid,
        caption: window.caption, normal: window.normalWindow,
        hidden: window.hidden, minimized: window.minimized,
        frame: window.frameGeometry, client: window.clientGeometry}));
}
