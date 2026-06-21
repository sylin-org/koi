# Real-world integration hosts

> **Directive (operator, 2026-06-20):** local Windows `cargo test`/clippy/fmt and
> single-host cross-process tests (`two_daemon_certmesh`) are fine *during*
> development, but **closing any major phase requires a full two-box Linux
> integration test** exercising the real capability surfaces (real binary, real
> LAN, real mDNS/multicast, cross-host mTLS, the actual CLI). CI-green ≠
> works-on-hardware — networking code (multicast/mDNS, interface selection, TLS on
> non-loopback, clock skew) routinely passes loopback/unit tests and fails on real
> infrastructure. Deploying to these hosts is part of the integration test suite.

Two dedicated Debian boxes on the LAN. Both: user `stone` / password `stone`,
passwordless `sudo`, in the `docker` group. Access from the Windows dev machine via
PuTTY `plink`/`pscp` (`plink -batch -ssh -pw stone stone@<ip> "<cmd>"`). The
`.internal` names resolve via the LAN.

| Host | IP | Role | Notes |
|------|-----|------|-------|
| `stone-platinum-brook` | 192.168.1.44 | primary test target (this session's box) | Debian 13 (trixie), kernel 6.12, x86_64, 4 cores, ~49 GB free, Docker 26.1.5. **No native C toolchain** (no gcc/cmake/make) — build in a Rust container or `apt install build-essential cmake pkg-config`. |
| `stone-granite-spring` | 192.168.1.55 | second box (cross-host peer) | Debian; sudo + docker. Used by the ADR-018 cross-host suite. Apply the same conflict-service teardown before a run. |

## Per-host setup (run before an integration session)

Both boxes ship with services that conflict with exercising Koi's surfaces;
disable them so Koi owns its ports and mDNS cleanly:

```sh
# garden-moss = the Zen Garden consumer (embeds koi-embedded; holds port 5641).
sudo systemctl disable --now garden-moss.service
# avahi = a competing mDNS responder on 5353 (pollutes Koi's discover).
sudo systemctl disable --now avahi-daemon.service avahi-daemon.socket
```

`systemd-resolved` also binds UDP 5353 but with LAN-interface mDNS **off**
(`resolvectl mdns` → the physical link shows `no`), so it does not respond as a
competing mDNS stack and `koi-mdns` (mdns-sd) binds 5353 alongside it via socket
reuse — the standard Debian coexistence. Leave it as-is.

Verify the control ports are free afterward:

```sh
ss -tulpn | grep -E ':5641|:5642|:5643'   # expect empty (5641 freed by stopping garden-moss)
```

Workspace on each box: `/home/stone/koi-test/` (binary + `data/` for `KOI_DATA_DIR`).

## Build & deploy

**Build on the dev machine, never on the boxes.** The dev machine is far more
powerful and already has the `cross` + Docker toolchain. Build a **static musl**
binary (the same toolchain the release workflow + `scripts/cross-host-certmesh.sh`
use) and copy it to the boxes — they then need **no Rust/C toolchain at all** (the
binary is static, no glibc dependency):

```sh
# dev machine, repo root:
cross build --locked --target x86_64-unknown-linux-musl -p koi-net
#   → target/x86_64-unknown-linux-musl/debug/koi   (static x86_64 binary; add --release for release)

# copy to both boxes (PuTTY pscp from Windows; or scp elsewhere):
pscp -pw stone target/x86_64-unknown-linux-musl/debug/koi stone@192.168.1.44:/home/stone/koi-test/koi
pscp -pw stone target/x86_64-unknown-linux-musl/debug/koi stone@192.168.1.55:/home/stone/koi-test/koi
plink -batch -ssh -pw stone stone@192.168.1.44 "chmod +x /home/stone/koi-test/koi"
plink -batch -ssh -pw stone stone@192.168.1.55 "chmod +x /home/stone/koi-test/koi"
```

Box-side test instrumentation (install once): `curl` (HTTP probes — not present by
default on a minimal Debian), `jq` (parse `koi … --json`), `dnsutils` (`dig`),
`netcat-openbsd` (`nc`, port checks).

## Cross-host integration scenario (the gate)

With box A (e.g. brook) as the CA and box B (e.g. granite) as a member, over the
real LAN:

1. **A:** `koi certmesh create` → CA initialized + self-enrolled (posture flips
   Open→Authenticated; the same-port mTLS/ACME listeners come up reactively).
2. **A:** mint an invite; **B:** `koi certmesh join <A>` over real HTTP → B holds a
   CA-signed leaf.
3. **discover** over real mDNS: each box sees the other's `_certmesh._tcp` /
   `_http._tcp` with `fp=`/`posture=`/`expires=` TXT.
4. **`koi trust diagnose`** on both → Healthy (and a deliberate RED case: revoke B,
   confirm B diagnoses self-revoked + exits non-zero).
5. **seal/open** + **sign/verify** of an Envelope produced on A, verified on B
   (cross-host carry-cert).
6. Tear down (`koi certmesh destroy`, re-enable nothing — the box stays set up).

Automated by `scripts/integration/cross-host-test.sh` (runs on the CA box, drives
the member via `sshpass`). See also the container-based ADR-018 harness:
`scripts/cross-host-certmesh.sh`.

## Findings (real-hardware runs, 2026-06-20/21)

**Full cross-host flow VALIDATED (12/12 green).** `cross-host-test.sh` exercises, on
real hardware over the real LAN: CA box reset → Open; **P4** mTLS listener DOWN while
Open, then reactive-UP after `certmesh create` (no restart); **P6** `koi trust
diagnose` Healthy on the CA; invite mint; **member join over the LAN** (pinned-
fingerprint preflight + invite enrollment + member-side key custody); CA roster shows
both nodes; **P3** the member discovers the CA's `_certmesh._tcp` with
`posture=`/`fp=`/`expires=` TXT over real multicast; member `diagnose` Healthy.

**RESOLVED — reactive `_certmesh._tcp` announce.** The CA discovery announce was
**startup-gated** (ran once at boot, gated on a CA already existing): a node that
booted Open and later ran `certmesh create` did not advertise until a restart. Now
the posture-reactive trust-plane supervisor (`crates/koi/src/adapters/trust_plane.rs`)
publishes it the moment the CA appears and withdraws it when the CA is destroyed —
the same `watch_posture` mechanism that drives the mTLS/ACME listeners. The harness
no longer restarts the CA after create (step 6 now asserts the record is present
reactively).

**KNOWN LIMITATION — the long-running daemon's mdns-sd drops ALL inbound mDNS
in-process (an `mdns-sd` interface-index bug, NOT systemd-resolved).** A long-running
koi daemon receives zero inbound mDNS: its browse + LAN meta-browse cache stay empty
for every remote service, while a **standalone** `koi mdns discover` (same binary,
same NIC, daemon stopped) receives everything — which is how the test validates P3.
The *send/announce* side works regardless (peers discover the daemon's records).

Root cause (source-verified + observed on hardware, 2026-06-21):
- **systemd-resolved is NOT the cause.** 2×2 bisection: daemon = 0 with resolved both
  UP and DOWN; standalone = 2 with resolved both UP and DOWN. With resolved stopped
  koi is the *sole* 5353 binder and still gets 0 — there is no other socket to "steal"
  the packets, and on Linux inbound multicast is copied to *every* `SO_REUSEPORT`
  member anyway (only unicast is hash-balanced). So the earlier "resolved/kernel
  steering" attribution here was wrong.
- **The loss is in-process, observed:** during a 9 s window `tcpdump` on the daemon
  box captured **266** mDNS frames at the NIC while the daemon's meta-browse snapshot
  read `total_instances:0`; a standalone process on the same NIC saw **16** service
  types. Packets reach the host; the daemon's mdns-sd discards them.
- **Mechanism (`mdns-sd` 0.20.0):** `handle_read` (service_daemon.rs:2459-2467)
  silently drops every datagram whose kernel `IP_PKTINFO` `ipi_ifindex` is absent
  from `my_intfs`; but `my_intfs` is keyed by the **if-addrs** index
  (`intf.index.unwrap_or(0)`). When those two index sources disagree (e.g. if-addrs
  yields `None`→0 vs the kernel's real index), **all** inbound multicast is dropped.
  *Send* is unaffected because the send path selects the egress interface by **IP
  address**, not index — exactly the observed send-OK / receive-0 split. The
  daemon-vs-standalone difference is lifecycle: the short-lived standalone process
  keeps the consistent snapshot it took at start; the long-lived daemon's `my_intfs`
  ends up desynced (the precise trigger — boot-snapshot vs a `check_ip_changes`
  re-key — was not byte-captured because koi has no `log`→`tracing` bridge for
  mdns-sd's debug line; capturing it needs a small mdns-sd repro with the `logging`
  feature).

**Separate from ADR-020.** It affects the dashboard LAN browser on these hosts.
Candidate fixes: (a) the durable one is upstream — `mdns-sd` should key `my_intfs` by
the same index source the recv path uses (file an issue); (b) koi-side, pin the NIC
via `ServiceDaemon::enable_interface` in `crates/koi-mdns/src/daemon.rs` (the sole
mdns-sd importer) behind a `--mdns-interface`/`KOI_MDNS_INTERFACE` config; (c) add a
browse-reachability check to `koi status`/`koi trust diagnose` so an empty cache on a
live interface is a loud RED, not silent (matches ADR-020's anti-silence ethos).

**Harness lessons (all fixed in `cross-host-test.sh`):**
- The daemon token is breadcrumb line 2 with the `dat:` prefix stripped.
- The invite HTTP response field is `.token` (format `<secret>.<ca_fp>`); `join`
  needs the CA endpoint **with a scheme** (`http://host:5641`).
- Both boxes must start from a wiped data dir; the CLI `koi certmesh create` runs an
  interactive entropy ceremony (hangs headless) → create the CA via the HTTP API
  (non-interactive), as the `two_daemon_certmesh` test does.
- Start a remote daemon over ssh with `setsid -f … </dev/null >log 2>&1` (a plain
  `nohup … &` over the brook→granite hop does not detach and hangs the test).
- Kill koi with `pkill -x koi` (by name): `pkill -f 'koi --daemon'` self-matches the
  remote `bash -c` whose own argv contains that string (ssh rc=255, data not wiped).
- `curl` must be present on every box (granite lacked it; `apt-get install -y curl`).
