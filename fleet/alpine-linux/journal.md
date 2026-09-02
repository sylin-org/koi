# alpine-linux — journal

## 2026-08-31 12:40 UTC — canary v2 (orchestrator-driven)
commit: da6032b | gates: cargo check -p koi-net →     Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.39s
koi state now: standing daemon on port 5641 (untouched by the canary)
stack: kwin_wayland kwin_wayland_wr plasma_session plasmashell startplasma-way 
ladder (head): {"capabilities":[{"healthy":false,"name":"mdns","summary":"1 registered (1 alive, 0 draining); browse active 27324s on a live LAN but last mDNS was 832s ago — inbound multicast is not reaching this daemon (confirm with `koi mdns discover`)"},{"healthy":true,"name":"certmesh","summary":"ready — r
findings: none (canary run)

## 2026-09-02 01:00 UTC — native musl deployment, workbench, and ADR-042 acceptance

commit: koi product `dbd2466`, portable gate follow-ups through `739b902`; koi-desktop `4c05ed2` | gates: full locked musl workspace all-target/all-feature suite; strict clippy; release build/install; OpenRC lifecycle; desktop Rust/UI/strict-clippy/release gates; real Plasma/AT-SPI; physical Pond
koi state now: exactly one OpenRC-managed `/usr/local/bin/koi --daemon`, PID `14321`, SHA-256 `7ea773c5ce936fe85853ad3d3e81e49f4645674b67ae52f51d50b9e4141ccae7`; it honors the standing shifted configuration at `127.0.0.1:5651` with derived Pond port 5654. Pond is deliberately disabled and 5654 is closed. mDNS is Ready through native Koi (`publish native, browse native, resolve browse fallback`); certmesh reports `authenticated member`. No checkout desktop or second Koi remains.
findings:

1. The former unmanaged dogfood process was retired in favor of the one default-runlevel OpenRC service. The real standing member identity was copied into the empty `/var/lib/koi` slot with root ownership; source and destination `member.json` both hash to `5ecf787095e170708b9db9d705db44c4386c1732332f87864fbd7196f357d3eb`, and the source remains untouched.
2. Physical Pond run `20260902T003409Z-14183` used the installed musl artifact and independent test-01. It passed the complete public allowlist/negative mutation matrix, explicit stop, and serial restart recovery (`14030→14321`) before restoring the original disabled desire. With neither firewalld nor UFW present, Koi reports the host-policy assessment as unknown instead of claiming an open firewall.
3. The full native command `cargo test --workspace --all-targets --all-features --locked` passed after 5m36s, including 170 koi tests, three two-daemon tests, and 66 koi-serve tests; only explicit Docker/real-provider environment gates remained ignored. This is the fleet's complete musl proof, not merely the canary's `cargo check -p koi-net`.
4. koi-desktop now disables Rust's static CRT only for musl targets and links Alpine's shared GTK/WebKitGTK/app-indicator stack. Native Rust tests (9 pass/1 environment-gated), 37 UI tests, strict clippy, and release all passed without an ad-hoc environment override. A real Plasma/Wayland release process exposed the full AT-SPI workbench, discovered the shifted daemon, armed exact URL `http://192.168.1.221:5654/`, passed second-host access, stopped sharing, and exited cleanly.
5. The temporary SDDM autologin file used to establish the physical Plasma seat was deleted immediately after the session began; no validation SDDM configuration remains. Both repositories are clean at shared heads (`739b902` and `4c05ed2`).
