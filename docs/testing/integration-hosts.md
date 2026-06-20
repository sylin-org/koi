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

The boxes are x86_64 Linux; build **once** and copy the binary to the second box.
Source is shipped from the dev machine via `git archive` (tracked files only — no
`target/`, no `.git`), because the `dev` branch is local/unpushed and the boxes
cannot `git pull` it:

```sh
# from the repo root on the dev machine (Git Bash):
git archive --format=tar.gz -o /tmp/koi-src.tgz HEAD
pscp -pw stone /tmp/koi-src.tgz stone@192.168.1.44:/home/stone/koi-test/
# on brook: extract + build the binary (toolchain via apt or a rust container)
plink -batch -ssh -pw stone stone@192.168.1.44 \
  "cd /home/stone/koi-test && tar xzf koi-src.tgz && cargo build --release -p koi"
# distribute the binary to the second box:
#   pscp brook:/home/stone/koi-test/target/release/koi  →  granite:/home/stone/koi-test/koi
```

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

Automated by `scripts/integration/` (added once the procedure is proven on
hardware). See also the container-based ADR-018 harness:
`scripts/cross-host-certmesh.sh`.
