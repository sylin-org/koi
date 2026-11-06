# Native npm launcher packaging

This directory implements the JavaScript launcher and metadata for Koi's native platform carriers. It is packaging source, not evidence that an npm package is available. Use the verified installation channels in [launch readiness](../../docs/launch/README.md).

The entry package pins six optional carriers for macOS, Linux and Windows on x64/arm64. npm selects the matching carrier; the launcher resolves its executable and passes arguments through. There is no postinstall downloader.

For `koi install`, the launcher first copies the executable to a stable user location so a registered service does not depend on npm's cache or package directory. Other commands run the carrier directly.

```sh
node --test packages/npm/test/launcher.test.js
```

Before advertising an npm installation command, publish the matching carriers and entry package, verify registry availability, then perform a clean install and the actual container/LAN journey. Record the exact versions and artifacts in the launch ledger. Launcher unit tests establish argument/path behavior, not publication or native service acceptance.
