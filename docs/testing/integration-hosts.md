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

## Controller and safety model

The v1 path is the non-published `koi-lab` workspace tool. It is the single evaluation
point for node identity, SSH host-key pins, clocks, prerequisites, service/port baseline,
artifact identity, distributed locks, allowed remote roots, and cleanup ownership.

```powershell
$env:KOI_LAB_PASSWORD = '<dedicated-lab-password>'

# Read-only: writes a redacted report under .lab-runs/ locally.
cargo run -p koi-lab --locked -- preflight

# Build only on this Windows workstation through cross + Docker.
cargo run -p koi-lab --locked -- build

# Lock both nodes and stage one hash-identical binary under runs/<run-id>/.
cargo run -p koi-lab --locked -- deploy

# Non-privileged first vertical: brook CA → granite member, driven from Windows.
cargo run -p koi-lab --locked -- certmesh-smoke --run-id <run-id>

# Privileged Linux trust rotation. Refuses without the explicit acknowledgement.
cargo run -p koi-lab --locked -- certmesh-native-trust --run-id <run-id> `
  --allow-system-mutation

# Read-only cleanup preview, then owner-checked exact cleanup.
cargo run -p koi-lab --locked -- plan-cleanup --run-id <run-id>
cargo run -p koi-lab --locked -- cleanup --run-id <run-id>
```

Deployment does **not** stop a service, overwrite `/home/stone/koi-test/koi`, erase data,
or use `sudo`. It stages only these run-owned files:

```text
/home/stone/koi-test/runs/<run-id>/owner
/home/stone/koi-test/runs/<run-id>/artifact.sha256
/home/stone/koi-test/runs/<run-id>/koi
```

The atomic `.koi-lab-lock` directory refuses a concurrent run. Cleanup checks both the
lock owner and run-directory owner, removes an exact file allowlist, permits recursive
deletion only for resolved run-owned data/runtime roots, and verifies the run directory
and lock are absent afterward.

`certmesh-smoke` uses dedicated high ports from `tools/koi-lab/lab.json`, so it can run
beside a captured system Koi service. It starts only run-owned PIDs, creates certmesh data
only below the run directory, drives create→pinned invite→join from Windows, asserts the
member's trust diagnosis is Healthy, hashes the Linux system trust stores before/after to
prove the non-privileged slice changed no roots, and records a secret-redacted report.

`certmesh-native-trust` is the one privileged mutation boundary. It refuses without
`--allow-system-mutation`, rechecks run/lock ownership and passwordless sudo, and uses
only the run CA PEM and a separate run-owned trust-state root. It configures granite's
real Koi TLS proxy with the certmesh member leaf, then proves from brook that native
`curl` fails before installation, native `curl` and OpenSSL succeed after installation
without a custom CA, and a wrong hostname still fails. It removes the exact tracked
fingerprint, proves native TLS fails again, and requires the complete trust-store hash
to match its captured baseline before reporting success.

Debian testing exposed an `os-truststore 0.0.2` cleanup defect: uninstall removes the
anchor, but `update-ca-certificates` can leave two dangling symlinks for that anchor.
The controller's compatibility cleanup checks the missing exact anchor, full symlink
target, and fingerprint marker before pruning only those links. This is recorded as
upstream integration debt; a future `os-truststore` release should own the fix, after
which the guarded compatibility branch becomes a no-op and can be removed.

Services that conflict with a scenario are captured as baseline and make
`scenario_ready=false`; preflight never changes them. A future privileged lane must stop
only the captured service and restore its exact active/enabled state. `systemd-resolved`
on UDP 5353/53 is recorded but left alone—the previous hardware runs proved Koi's mDNS
socket reuse can coexist with it.

## Build and artifact identity

`koi-lab build` always uses the release-musl command below on the workstation. There is
no remote build fallback:

```text
cross build --release --locked --target x86_64-unknown-linux-musl -p koi-net
```

The controller records the Git commit, byte length, and SHA-256, copies the same file to
both run directories, and accepts a node only after its native `sha256sum` matches and
the staged binary reports a version. The nodes need no Rust or C toolchain. Preflight
checks the existing `curl`, `jq`, `dig`, `nc`, Docker, OpenSSL, `systemctl`, `ss`, and
`sha256sum` installations without installing packages.

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

The historical scenario is automated by `scripts/integration/cross-host-test.sh` (runs
on the CA box and drives the member via `sshpass`). It predates `koi-lab`, resets fixed
data paths, and disables SSH host-key checking; treat it as legacy evidence, not the v1
controller. Its assertions will move behind the run-scoped controller before this lane is
called release-grade. The container-based ADR-018 harness remains
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

**RESOLVED (2026-06-21) — the long-lived daemon's `discover` now surfaces cached
services.** A long-running koi daemon's `discover` used to return nothing, while a
**standalone** `koi mdns discover` (cold cache, same NIC) resolved fine — and crucially
`koi mdns resolve` worked on the *same* daemon. The split was never in mdns-sd.

Root cause (confirmed on hardware by strace + tcpdump + the daemon's own `resolve`):
**the koi mDNS hub did not replay its warm record cache to a *new* browse subscriber.**
The hub multiplexes one real mdns-sd browse per type across N subscribers via a
future-only `broadcast` channel. mdns-sd replays its cache synchronously only to the
FIRST listener; every koi subscriber after that — and any direct `discover` once the lazy
LAN-wide meta-browse already holds the type — received future events only. Because the
service was already resolved and cached, no new `ServiceResolved` ever fired, so the
subscriber saw nothing. A standalone worked only because its cache was cold, so the
browse triggered a live resolve.

What disproved the earlier mdns-sd theories: an instrumented mdns-sd build showed
`sendto(224.0.0.251)` succeeds, frames egress the LAN NIC, and the daemon's `resolve`
returns the CA in full — the cache is healthy; only `discover` was blind. The earlier
index-drop, "query never emitted", and Known-Answer-Suppression theories were all the
wrong layer (instructive dead ends, kept here only as a caution).

Fix: `crates/koi-mdns/src/daemon.rs` — `subscribe_type` replays the per-type warm
`records` cache to the joining subscriber (to that subscriber only; no peer
re-broadcast). **Stock mdns-sd, no fork.** Unit-tested (`new_subscriber_replays_warm_cache`)
and hardware causal-flip confirmed (daemon `discover _certmesh` returns the CA; it
returned nothing before). Step 10 of this suite exercises the real client-mode daemon
path again.

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
