# ADR-032: Windows First-Class Parity Program

**Status:** Accepted (operator-approved 2026-08-24). **Gates stable 1.0.**
**Date:** 2026-08-24
**Builds on:** ADR-018 (integration tiers), ADR-029 (role-matrix testbed + host classes), the July elevated Windows lifecycle evidence (historical, pre-rc.1 tree)
**Constrained by:** workstation-class safety rules; no broad system mutation without flags and exact restoration

---

## Context

Windows is a mandatory first-class citizen with 1:1 capabilities: every capability
provable on Linux must have an equally proven Windows lane. Today Windows has proven
trust-plane evidence (exact `LocalMachine\Root` install/remove, Schannel verification,
hosts restoration — re-proven on the rc.2-era tree) plus July-era member-lifecycle
evidence that predates V1-08..V1-11 and must be redone. Unclaimed: service
supervision via SCM, named-pipe IPC, whole-story breadth (proxy/DNS/health/webhooks/
mDNS serving *from* Windows), backup/cold recovery, and installer distribution.

The operator decision: **Windows parity gates stable 1.0.** The rc.2 soak continues in
parallel; stable ships only when this program's matrix is green.

## Decision

### Parity definition

A capability is *Windows-parity-proven* when its Linux lane's assertions pass on
Windows with OS-native verification adapters (Schannel vs OpenSSL, SCM vs systemd,
named pipes vs Unix sockets, Resolve-DnsName vs dig) in both rotations where the
capability involves a peer, through the same evidence pipeline (redaction-attested
reports, baseline restoration).

### Acceptance matrix

| # | Capability lane | Linux proof | Windows lane | Adapter notes | Status |
|---|---|---|---|---|---|
| W1 | Service supervision | systemd transient unit (`Type=notify`, restart-on-failure) | **SCM service**: install/start/restart/recovery/stop via `platform/windows.rs` service support; run as SYSTEM so privileged ports work | koi-lab SCM driver; exact unit identity checks | not started |
| W2 | Named-pipe IPC | Unix socket NDJSON protocol | Same protocol over `\\.\pipe\koi-*` | pipe path adapter; same request corpus | not started |
| W3 | Trust install/remove | `update-ca-certificates` + fingerprint scan | `LocalMachine\Root` via .NET X509Store | existing lanes; redo on current tree both directions | ✅ trust plane re-proven rc.2 era |
| W4 | Enrollment/join/renew/revoke | CLI custody flow over HTTP+mTLS | Same CLI against a Linux CA (July-era shape), plus **Windows-hosted CA** rotation | invite pin + CSR custody identical | ✅ Windows-member half re-proven 2026-08-24 (`certmesh-native-trust-windows-client`); **Windows-hosted CA half green 2026-08-25** run `v1-20260825T145514Z-c2be3c52` (`certmesh-lifecycle-windows-ca`, brook member, artifact `b47f1fe0…`, 7/7 checks incl. wrong-pin refusal, 0600 custody join, roster, rotation+convergence, RED self-revocation, immutable identity on refusal, exact cleanup) |
| W5 | mDNS announce/browse | mdns-sd multicast | ✅ Both directions over the real LAN: Windows announce API → avahi-browse on test01 discovers it (standards conformance; Koi is the lab's only koi-side mDNS participant — Linux daemons deliberately skip per ADR-030); avahi-publish on test01 → Windows browser snapshot discovers it. Verified against the OS stacks themselves (avahi), not just koi peers. Found+fixed a real product defect en route: the mDNS hub never cached meta-query Found events, so a late browser subscriber on a quiet LAN replayed nothing (chatty LANs masked it with live events); meta Found events are now cached and replayed as Found (koi-mdns `cache_update`/`replay_events` + regression tests). | green 2026-08-26, run `v1-20260826T215040Z-c21a6aac` (`windows-mdns`) |
| W6 | DNS serve + resolve | UDP/TCP 53 + cross-host `dig` | ✅ Daemon serves its authoritative `.internal` zone on a lane-scoped port picked exclusively-free at run time (18653+), verified cross-host by `dig` from the Linux member and locally by a PowerShell loopback wire probe — same zone-contributor contract as the Linux lanes. Measured limitations recorded: workstation 53 is held by system services (ICS) with reuse semantics; `Resolve-DnsName` has no `-Port`; `nslookup` sends zero packets for non-53 ports (system-client only). | green 2026-08-26, run `v1-20260826T191612Z-b559ca5d` (`windows-breadth`) |
| W7 | TLS proxy serve/verify | openssl client → Linux proxy | ✅ Proxy serving ON Windows with a certmesh-sourced leaf (member joined a brook-hosted CA with local custody), LAN-reachable (`allow_remote`), verified by **openssl from brook** (chain + hostname, wrong-host rejected) **and Schannel from Windows** — the true inter-OS pairing; tracked native-trust install/exact-remove on both sides. | green 2026-08-26, run `v1-20260826T221922Z-0fe825ee` (`windows-proxy`) |
| W8 | Webhooks origin/sink | python fixture on Linux | ✅ Origin ON Windows (manifest-driven fan-out enabled), sink on brook (python fixture, HMAC secret via env only); two real DNS-record domain events fired through the Windows daemon's API; both deliveries HMAC- and body-verified at the sink. Built on the WindowsLabDaemon owner. | green 2026-08-27, run `v1-20260827T002150Z-5f463890` (`windows-webhook`) |
| W9 | Health checks | HTTP Up→Down→Up cross-host | ✅ Cross-host TCP health in both directions: Windows daemon drove a LAN fixture on brook through up→down→up (new `start_cross_host_fixture` binds 0.0.0.0; the story fixture is loopback-scoped by design); brook daemon watched the Windows HTTP surface up. | green 2026-08-26, run `v1-20260826T191612Z-b559ca5d` (`windows-breadth`) |
| W10 | Backup/cold recovery | recovery profile | ✅ Encrypted backup → exact data loss → restore → identity continuity with the CA hosted on the workstation (WindowsLabDaemon staging, HTTP+mTLS behind scenario-scoped firewall rules) and a physical Linux member holding custody: v2 encrypted backup; wrong-backup-passphrase restore rejected without disturbing the live CA; the owned data root erased and the restarted daemon uninitialized; restore under a NEW passphrase with fingerprint + roster + machine-binding continuity; member renewal over restored mTLS; restart comes back LOCKED, renewal refused with byte-identical member identity; old passphrase rejected, restored passphrase unlocks; second key-rotating renewal converges the roster; `backup_restored` in the CA audit log; exact cleanup. | green 2026-08-27, run `v1-20260827T205903Z-e6881df9` (`certmesh-recovery-windows`, 8/8 checks incl. run_owned_cleanup; first physical run passed all assertions, failed only on a cleanup path-identity guard, fixed in `1e75a19`) |
| W11 | Runtime auto-wire | Docker label derivation | **Capability-tagged exclusion**: Docker Desktop presence optional, not required for parity | honest scope line | excluded-by-tag |
| W12 | ACME dns-01 | instant-acme cross-host | ✅ Same flow with the Windows-side daemon serving TXT: instant-acme issued `acme-w12-2c5a7de8.internal` through the Windows RFC 8555 server (directory dialed on the workstation hostname, leaf-SAN-covered); the dns-01 TXT was published through the daemon's authenticated API, served by the Windows DNS lane port (18653), and observed cross-host by `dig` from brook; the chain verified to the run CA and the identity landed in the certmesh roster; exact cleanup. Three first-run defects fixed en route (bfab513, 8315d40, fd2f7e5): the directory URL lacked its `/acme/directory` path so the client parsed an empty body; the cross-host dig targeted the member's catalog dns_port instead of the Windows lane port (dig exit 9); and daemon-launch guards now fail loud (exit 71, self-describing stderr) instead of a bare `test` silently killing the script. | green 2026-08-27, run `v1-20260827T203030Z-2c5a7de8` (`windows-acme`) |

Non-goals: Windows containers, Hyper-V-specific isolation, MSI/winget submission
timing (external authority; P4 below covers the local installer groundwork).

### Program phases

- **P1 — Foundations:** W1 (SCM) + W2 (named pipe). Everything desktop/install-and-done
  stands on these. Includes koi-lab drivers for both.
- **P2 — Breadth acts:** W4–W9, W12 as scenario extensions driven by the catalog
  planner (Windows already declares caller roles; extend to serving roles).
- **P3 — Recovery:** W10.
- **P4 — Installer groundwork:** signed archive layout + silent-install script;
  winget submission remains externally gated.

### Stable-gate redefinition

Stable `1.0.0` requires, in addition to the existing gates:

- Every matrix row green in its stated rotations, executed by `run-profile full`
  extended with the Windows breadth cases. **DONE — the extended profile
  (25 cases: 16 Linux + 9 Windows workstation lanes) went fully green
  2026-08-28, run `v1-20260828T165112Z-f6a23b30`, git 359337a, after the
  ADR-035 shakedown. One recorded deviation: the W1 SCM lane runs standalone
  (green 2026-08-24) rather than in-profile — it installs the product service
  under the operator name and correctly refuses to clobber the operator's
  `koi install`, which exists on this workstation.**
- Elevated scheduled-task profile green including all W-cases.
- Soak of the final candidate clean, with Windows participants included per ADR-029
  host classes. **This is the only remaining 1.0 gate.**

## Consequences

- The role-matrix planner earns its keep immediately: W7/W9 pairings are generated,
  not hand-wired.
- OS-native verification adapters become first-class lab components with their own
  tests — the cross-compatible testbed's core mechanism.
- Honest scope line: Docker Desktop automation and winget are explicitly outside
  parity; they are tagged, not silently missing.

## Alternatives considered

- Ship stable on Linux evidence, treat Windows as 1.x — rejected by operator decision:
  Windows users hitting an unsupported-service experience at "stable" would contradict
  the honesty doctrine at its most visible moment.
- Cross-platform service abstraction crate — deferred: two implementations behind one
  trait is cheaper than adapting a generic crate to SCM's recovery semantics.
