# Dependency Study: `netdev` and the `paste` Advisory

> **Status:** Resolved — netdev removed (Option 1). 2026-06-13.
> **Trigger:** `cargo audit` flagged `paste 1.0.15` as unmaintained (RUSTSEC-2024-0436).
> The question was whether bumping `netdev` 0.31 → latest would clear it.

## TL;DR

Bumping `netdev` does **not** clear `paste` and adds bloat. The right fix was to
**remove `netdev` entirely** — koi used a single function from it, replaceable with a
~15-line stdlib default-route probe plus the `if_addrs` crate koi already depends on.
This dropped the whole `netdev → netlink-* → paste` subtree (8 crates), so `cargo audit`
is clean with **no `--ignore`** needed.

## How koi used netdev

A single capability, in two parallel `/v1/host` handlers
([koi/src/adapters/http.rs](../../crates/koi/src/adapters/http.rs),
[koi-embedded/src/http.rs](../../crates/koi-embedded/src/http.rs)):
`netdev::get_default_interface()` → the interface owning the default route, emitted as
`{name, ip}`. Both already had an `if_addrs` enumerate-all fallback. netdev's only value
was *default-route disambiguation* (notably on Windows, where vEthernet virtual switches
share the physical Ethernet `IfType`).

## Why `paste` was present (and why bumping netdev can't remove it)

`paste` is a **compile-time proc-macro** used by the `rust-netlink` crates
(`buffer!`/`getter!`/`setter!` macros) to synthesize `set_$name` / `$name_mut`
identifiers. netdev pulls the netlink stack **only under `cfg(target_os = "android")`**;
on Linux/macOS/Windows it uses `libc` / `system-configuration` / `windows-sys`. So
`paste` was **never compiled for any platform koi ships** — a phantom entry in the
all-targets `Cargo.lock` that `cargo audit` scans.

Empirical bump test (0.31 → 0.44, since reverted):

| Property | Result |
|---|---|
| koi code changes | none (builds clean) |
| Removes `paste`? | **No** — `netlink-packet-utils` dropped, but `paste` then pulled by `netlink-packet-core 0.8.1` |
| New deps | 8 `objc2-*` (macOS WLAN), `jni`/`cesu8` (Android), `plist`, `quick-xml`, `mac-addr`, a 6th `windows-sys` |

Every selectable netlink version pulls `paste`: upstream **deliberately reverted
`pastey` → `paste`** (rust-netlink issue #19, 2025-09-17), and the paste-free inlining
(issue #41) is unreleased. No netdev version reaches a paste-free state.

## Risk of RUSTSEC-2024-0436 — negligible

`unmaintained`, not a vulnerability (no CVE, no `[affected]` section); a compile-time
proc-macro (zero bytes in the shipped binary); Android-gated (never built for koi); and
unpatchable in place (`pastey` ≠ `paste`, so `[patch.crates-io]` can't override a
transitive `paste`). Leaving it would have been defensible — but removing the root cause
is cleaner.

## Options considered

| Option | Verdict |
|---|---|
| Bump netdev → 0.44 | **Reject** — keeps `paste`, adds bloat |
| Bump netdev → 0.41 (leaner than 0.44) | Reject — still keeps `paste` |
| **Remove netdev → stdlib default-route + `if_addrs`** | **Chosen** — removes the subtree and the advisory; 0 new deps |
| Keep netdev, swap `cargo audit` → `cargo-deny` with `[graph] targets` | Viable alt — `cargo-deny` evaluates `cfg()` and prunes Android-only deps, so `paste` never reaches the check. Not needed once netdev is gone. |
| Keep `--ignore RUSTSEC-2024-0436` | Defensible but leaves a phantom dep and an ignore to maintain |

Surveyed netdev replacements all lost: `local-ip-address` → `neli` (another netlink lib);
`getifs` → declares `paste` **unconditionally for all targets** (worse); `if-addrs` /
`network-interface` → enumerate only, no default-route API; `default-net` → dead.

## What was implemented (Option 1)

`get_default_interface()` replaced with the kernel's own route selection: a UDP socket
"connected" to a public IP (no traffic sent) reports the default-route **source IP** via
`local_addr()`; that IP is matched back to an interface **name** through `if_addrs`. The
prior enumerate-all-IPv4 fallback is preserved. Identical `default_lan_interfaces()` /
`default_route_ipv4()` helpers live in both `/v1/host` handlers (mirroring the existing
duplication of those handlers).

- Removed `netdev` from the workspace + both crates' `Cargo.toml`.
- `Cargo.lock`: 8 crates dropped (`netdev`, `netlink-packet-{core,route,utils}`,
  `netlink-sys`, `dlopen2`, `paste`, `system-configuration`); 462 → 454 deps.
- `.github/workflows/ci.yml`: dropped `--ignore RUSTSEC-2024-0436` (and its
  now-incorrect "on Linux" justification — `paste` was Android-only).

**Verified:** `cargo audit` (no ignore) exit 0, 0 findings; `build --all-targets`,
`clippy -D warnings`, `fmt --check` clean; workspace test suite green; koi-proxy TLS and
host-handler paths unaffected.
