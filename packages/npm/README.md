# Koi for `npx`

Let everything local find, trust, and talk.

```console
npx @sylin/koi
npx @sylin/koi -- mdns discover
```

This package is a small, dependency-free bootstrapper for Koi's native binary. It
downloads the installer from the matching Koi Git tag, verifies it against the
release manifest carried inside this npm package, and installs `koi` in its stable
per-user location. It does not run Koi from npm's cache and has no `postinstall`
script.

After the first command, use Koi normally:

```console
koi mdns discover
koi install
```

Koi is open source under Apache-2.0 OR MIT. Source, native release artifacts, and
verification instructions live at <https://github.com/sylin-org/koi>.
