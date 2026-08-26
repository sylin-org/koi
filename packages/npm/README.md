# Koi for `npx`

Let everything local find, trust, and talk.

```console
npx @sylin-org/koi@1.0.0-rc.2 -- mdns discover
```

This package carries Koi's native binary for your platform. npm downloads
exactly one of the six platform carriers (`@sylin-org/koi-darwin-arm64`,
`-darwin-x64`, `-linux-arm64`, `-linux-x64`, `-win32-arm64`, `-win32-x64`) as an
exact-version optional dependency; the launcher resolves it and runs it. There
is no download step, no `postinstall` script, and no runtime JavaScript
dependencies.

One deliberate exception keeps npm's hands off system state: `koi install`
first copies the carried binary to Koi's stable per-user location and runs the
installation from there, so a registered service never points at an
npm-managed path. Everything else (`mdns discover`, `status`, `dns`, …) runs
the carried binary directly.

After a real install, use Koi normally:

```console
koi mdns discover
koi status
```

Koi is open source under Apache-2.0 OR MIT. Source, native release artifacts,
checksums, and verification instructions live at <https://github.com/sylin-org/koi>.
