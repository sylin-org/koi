# Koi Epic to v1 — canonical continuation ledger

**Status:** active — V1-00 and V1-01 complete; V1-02 in progress; V1-07 identity and publication-foundation slices complete
**Last updated:** 2026-07-19 13:45 EDT
**Resume phrase:** `continue the epic to v1`

This is the repository's canonical handoff and progress ledger for the v1 epic. The plan is a
working hypothesis, not a frozen specification. Every session must verify it against code, tests,
Git, and the live lab; adjust it when evidence changes the best route, and record the reason.

## Objective

Bring Koi to an evidence-backed v1 by establishing a repeatable three-machine hardware lab across:

- **W:** this Windows workstation (`192.168.1.138` at the last check);
- **L1:** `stone-platinum-brook.internal` (`192.168.1.44`); and
- **L2:** `stone-granite-spring.internal` (`192.168.1.55`).

The lab must exercise Koi's complete public capability surface and its composed whole story, with
certmesh and native OS trust as the first high-value slice. It must prove real Windows↔Linux and
Linux↔Linux behavior, native certificate installation/removal, cross-machine verification,
service lifecycle, clean teardown, and honest failure behavior. Its results become v1 release
evidence rather than a one-off demo.

## User decisions and boundaries

- The user approved this epic and the three-node lab proposal on 2026-07-19.
- The user ratified **"Let everything local find, trust, and talk"** as Koi's banner and
  authorized a full public-documentation realignment around **Find. Trust. Connect.** on
  2026-07-19. ADR-024 is the canonical product-identity decision.
- The user approved an artifact-first release-channel implementation on 2026-07-19.
  ADR-025 is the canonical distribution decision. Preparation and tests are authorized;
  first npm publication, registry/repository creation, package-visibility changes, and
  external WinGet/Homebrew submissions remain separate external actions.
- The user explicitly expects the plan to be naive in places and wants it adjusted as evidence
  accumulates. Do not preserve a bad plan for consistency; preserve the decision trail.
- The privileged lane is approved in principle: it may temporarily modify the Windows
  `LocalMachine\Root` certificate store and Koi service state, and may deploy to/mutate the two
  documented dedicated Linux test boxes. Implement explicit safety gates before exercising that
  authority.
- Every system mutation must be run-scoped, fingerprint/path-specific, preflighted, and reversed.
  Never broadly clear a certificate store, service collection, data directory, or unrelated
  process. A cleanup failure is a failed run with an exact manual remedy.
- The Windows workstation is not a disposable test box. Privileged Windows mutations require an
  explicit runner flag such as `--allow-system-mutation`, an elevated process, pre-state capture,
  and exact restoration.
- External publication remains unauthorized. Do not post, contact communities, open external PRs,
  or publish packages. Commit and push also require a separate user request.
- Preserve pre-existing user work. `docs/animations/` was already untracked before this epic.

## Outcome so far

- Koi's objectives, architecture, capability surfaces, market/ecosystem niche, readiness risks,
  and public claims were mapped. The generated adoption workspace is under `.oss-adoption/` and
  its validator reports `VALID`.
- ADR-024 now defines Koi as an open-source local connectivity substrate that makes containers,
  applications, and devices delightfully discoverable, secure, and interconnected. The README,
  documentation hub and overview, user/container/getting-started guides, `.internal` capability
  card, primary crates.io copy, and generic crate READMEs now use the Find/Trust/Connect model.
  ADR-016 remains the technical strategy and maturity-ordering source, with its public positioning
  explicitly refined by ADR-024. Historical ADRs, changelog/assessment artifacts, and the
  user-owned `docs/animations/` tree were deliberately preserved.
- ADR-025 defines one native build and one deterministic release manifest as the publication
  chokepoint. The release workflow now validates all six archives and checksum sidecars, attests
  and publishes the manifest, and exercises the dependency-free npm bootstrap during dry runs.
  `cargo-binstall` metadata consumes only official Koi archives with unofficial-binary and compile
  fallbacks disabled. `@sylin/koi` is implemented as a version-pinned installer dispatcher, never
  a cache-hosted runtime; npm publication is inert until trusted publishing and the explicit
  `NPM_PUBLISH_ENABLED` repository variable are configured. Release prep now stages only known
  release files, and tagging defaults to the exact remote `main` tip. Validation is green:
  manifest/bootstrap tests (7/7), zero-dependency npm audit and real-v0.9.0 pack smoke, actual
  six-archive manifest generation, Cargo package/metadata validation, POSIX and Windows PowerShell
  parsing, actionlint, formatting, and the complete locked workspace test/doc-test suite.
- The existing whole-story design, ADR-018 tiers, surface ledger, QA workflow, physical-host
  runbook, deployment script, Linux↔Linux hardware harness, Windows↔Linux-container harness,
  certmesh/trust implementation, and external `os-truststore` behavior were inspected.
- Both physical lab hosts were verified live through read-only SSH on 2026-07-19:
  - brook reported `stone-platinum-brook`, Linux `6.12.69+deb13-amd64`;
  - granite reported `stone-granite-spring`, Linux `6.12.90+deb13.1-amd64`.
- Local prerequisites exist: PuTTY `plink`/`pscp`, OpenSSH, `cross 0.2.5`, and Docker client/server
  `29.5.3`.
- V1-00 exploration was completed on 2026-07-19 under the repository's mandatory `explore`
  workflow. A fresh `cargo build --release --locked` passed, the unchanged Windows integration
  harness reproduced **123/131 passed, 8 failed, 2 skipped**, and the unchanged concurrency
  harness passed 50 registrations / heartbeats / removals. The integration run cleaned up its
  process and temp directory; only a normal `TIME_WAIT` socket remained.
- Both lab hosts were re-verified with the operator-authorized `stone / stone` credentials and
  pinned PuTTY host keys. Their fixed Koi binaries and pre-existing service state were captured as
  baseline and left unchanged by every completed run.
- V1-00 was implemented and validated on 2026-07-19. The repaired Windows QA harness passed
  **128/128 assertions with 2 environmental skips**; concurrency passed 50 registrations,
  heartbeats, and removals. The full locked Rust suite, all-feature clippy with warnings denied,
  formatting, audit, and native release build passed.
- A static `x86_64-unknown-linux-musl` release was cross-built **on the Windows workstation via
  Docker**, never on a test server. Artifact SHA-256:
  `7C54C0296128ADEB0E009CA460149F32D97154A90E97F2B37948E6987875202A` (40,944,656 bytes).
  That artifact passed the local two-container bridge-network certmesh scenario
  (create→invite→join→roster→revoke→rejoin refused). The script removed its containers/network
  and staged file afterward.
- V1-01 was implemented as the non-published `tools/koi-lab` workspace tool. It centralizes the
  declarative node inventory, pinned SSH identities, preflight, local cross-build, artifact
  identity, distributed lock, run-owned deployment, exact cleanup plan, cleanup execution, and
  redacted JSON evidence. `scripts/integration/deploy.ps1` is now only a compatibility wrapper;
  it refuses the old persistent setup behavior.
- The controller deployed the same Koi 0.9.0 musl artifact to isolated run directories on brook
  and granite, verified the native SHA/version, and refused a concurrent deployment with the
  recorded lock owner. Cleanup removed only its allowlisted run-owned files and locks.
- The first three-machine vertical slice passed on run
  `v1-20260719T055642Z-eb8eadcb`: brook created the CA, granite joined as a member, Windows drove
  both high-port health checks, the invite pin matched the CA, the roster contained granite, and
  granite diagnosed `Healthy / Authenticated`. Linux system trust-store fingerprints were
  unchanged before/after. Exact cleanup stopped only run-owned binaries and removed both run
  roots and locks.
- Post-cleanup preflight proved the original fixed binaries still have SHA-256
  `8b6de1ac7f478a376021906b662f5809fa4f4e67ebdeb58394cec5b90a1dc263`; brook remains without an
  active Koi service, while granite's pre-existing `/usr/local/bin/koi --daemon` service remains
  active on port 5641. The current Windows process is not elevated, so no Windows trust-store
  mutation has been attempted.
- Full workspace validation after V1-01 passed: formatting, all-target/all-feature clippy with
  warnings denied, the complete locked test suite, audit, native release build, publish-list
  coverage, the surface-ledger linter, and diff hygiene are green. The validation run exposed and
  fixed a real TOTP isolation defect: all slot tables had shared one machine-global credential
  label. Slot-table v2 now derives stable per-slot labels at the crypto boundary, retains the v1
  legacy read path, and has a two-slot isolation tripwire. The surface linter was also made CRLF
  safe for Git Bash without changing its ledger contract.
- V1-02 now has one privileged Linux mutation boundary. The controller refuses without
  `--allow-system-mutation`, requires run/lock ownership and passwordless sudo, uses exact
  run-owned CA/state paths, and compensates post-install failures through the same removal path.
  Windows remains the control-plane driver; its LocalMachine store has not been touched.
- A current static musl artifact was rebuilt locally through Docker/cross (never remotely):
  40,944,480 bytes, SHA-256
  `c3de84f63e43f9bb9277755395319952ad2c434794dfc4b945c00705341d956e`.
- Privileged run `v1-20260719T063001Z-0d96f847` passed the first native trust rotation. Brook
  rejected granite's real Koi TLS proxy before root installation; after exact root installation,
  native `curl` and OpenSSL verified it without a custom CA; wrong-host verification failed; Koi's
  tracked fingerprint matched; exact removal made TLS fail again; and brook's complete trust-store
  fingerprint returned to its captured baseline. The report is secret-redacted.
- The run exposed an `os-truststore 0.0.2` Debian cleanup defect: uninstall removed the anchor but
  left two dangling `update-ca-certificates` symlinks. The lab boundary now prunes them only after
  verifying the missing exact anchor, full symlink target, and fingerprint marker. This is an
  explicit compatibility workaround and upstream debt, not hidden success.
- Final cleanup removed both run roots and distributed locks. Post-cleanup preflight again shows
  the fixed 0.7.0 binaries at their original hash, brook's Koi service inactive/not-found, and
  granite's pre-existing PID 803 service active/enabled on 5641.
- Post-V1-02 validation is green: formatting, all-target/all-feature clippy with warnings denied,
  the complete locked workspace and doc-test suite, native release build, and audit all pass. Audit
  retains only the already-dispositioned `anyhow 1.0.102` advisory and yanked transitive
  `spin 0.9.8` warnings.

## Current repository state

- Workspace: `F:\Files\repo\github\sylin-org\koi`
- Branch/upstream: `dev` tracking `origin/dev`, ahead 0 / behind 0 at handoff time.
- HEAD: `04cdfb4cecd9498f2154fdee70dd7464c83cc20b`
  (`feat(certmesh): membership-intrinsic self-managing trust (ADR-023)`).
- Tracked changes implement V1-00 plus the V1-01 lab controller, safe deployment wrapper, physical
  host runbook, ignore rule for generated `.lab-runs/` evidence, and workspace/lockfile wiring.
  `.agentic/CONTEXT.md` and `SESSION-HANDOFF.md` carry continuation state. All remain uncommitted.
- Other untracked state:
  - `.oss-adoption/` — generated by this session's approved adoption analysis;
  - `docs/animations/` — user-owned and pre-existing; do not alter without scope.
- No commit, push, PR, release, or package publication was made. Run-scoped test deployments were
  made to both dedicated Linux hosts and were cleaned up exactly; no deployed run remains.

## Evidence that changes the plan

### Facts

- [`docs/testing/whole-story-e2e-surface.md`](docs/testing/whole-story-e2e-surface.md) already
  defines Acts 0–11 for the composed lifecycle. Reuse its public-surface assertions rather than
  inventing another capability inventory.
- [`docs/adr/018-certmesh-integration-test-suite.md`](docs/adr/018-certmesh-integration-test-suite.md)
  records four certmesh tiers. Tier 4 is native Windows plus a Linux container on the same host;
  it is not physical Windows↔Linux validation.
- [`scripts/integration/cross-host-test.sh`](scripts/integration/cross-host-test.sh) drives real
  Linux↔Linux hardware, but it is a state-resetting bespoke script rather than a reusable
  three-node scenario engine.
- [`docs/SURFACES.md`](docs/SURFACES.md) says Koi delegates trust-store implementation tests to
  `os-truststore`; Koi's own CI does not prove the composed native
  install→serve→verify→remove journey.
- Certmesh create/join calls OS root installation **best-effort** and logs failure while allowing
  the protocol operation to succeed (`core_lifecycle.rs` and `core_member.rs`). Therefore join
  success is not trust-install evidence; the hardware harness must query the native store and run
  native TLS clients.
- `koi trust install` targets the system scope. Windows `LocalMachine\Root` requires an already
  elevated process. `koi trust remove` rereads the original PEM path, so the run must retain that
  exact PEM until cleanup finishes.
- The lockfile now resolves `quinn-proto 0.11.15` and `crossbeam-epoch 0.9.20`, clearing
  RUSTSEC-2026-0185 and RUSTSEC-2026-0204. `cargo audit` exits green with two explicitly
  dispositioned upstream warnings: `anyhow 1.0.102` is the newest compatible published release
  but carries RUSTSEC-2026-0190, and `spin 0.9.8` is yanked transitively through
  `mdns-sd -> flume`; neither currently has an available compatible lock-only replacement.
- The latest three scheduled QA runs inspected on 2026-07-19 were red. On the latest run,
  Windows completed 119/129 checks with ten DNS/certmesh/client contract mismatches; Linux/macOS
  startup was masked by `$env:TEMP` use before `Cleanup` exists. The local QA suite has not been
  rerun in this handoff session.
- The whole-story design still describes the proxy data plane as deferred, while `SURFACES.md`
  says the proxy was rebuilt and now has TLS round-trip tests. Reconcile this documentation before
  using it as the physical acceptance contract.
- The local reproduction classified the Windows failures. Eight are deterministic: two `.lan`
  expectations contradict the intentional `.internal` default; `CertmeshStatus.profile`,
  deadline enrollment, `set-policy` (two assertions), and `/certmesh/roster` were deliberately
  removed by P08; and `certmesh log --endpoint` correctly refuses to leak the local breadcrumb DAT
  to an explicit endpoint, so the harness must pass the token explicitly. The other two CI
  failures (`discover`/`subscribe` `.Count`) are PowerShell scalar-vs-array flakes and happened to
  pass locally because events were present.
- Two real public-dashboard drifts were found: it reads removed `certmesh.profile`, and it reads
  removed `listener.running` although the snapshot now carries `listener.state`. Current help and
  several active examples also still present `.lan` despite the intentional `.internal` default.
- The `crates/koi-udp/Cargo.toml` cache warning is caused by an actual UTF-8 BOM (`EF BB BF`), not
  malformed TOML content.
- The former TOTP test retry was masking a credential-ownership problem rather than a 30-second
  clock rollover: all TOTP slots used the same platform label. Versioned per-slot labels are the
  single evaluation point now; isolated data roots no longer overwrite one another, while v1
  tables continue to resolve their legacy labels.

### Working design choices — revise when evidence warrants

- Build a non-published structured lab controller (`tools/koi-lab`) and keep PowerShell limited to
  provisioning, Windows elevation, and native service operations. Product assertions should use
  typed HTTP/JSON, protocol clients, IPC, and native OS tools, not formatted CLI text.
- Use one node abstraction with local-Windows and SSH-Linux drivers, one run inventory, one
  distributed lab lock, one artifact/report format, and reusable scenarios.
- Separate non-privileged protocol tests from privileged native service/trust/resolver tests.
- Build once per run, record commit and SHA-256 hashes, and deploy the same musl artifact to both
  Linux nodes.
- Produce JSON + JUnit + readable summaries. Redact DATs, invites, private keys, and sensitive
  environment data. Preserve diagnostic artifacts on failure without retaining secrets.
- Never change host clocks for expiry tests. Cover deterministic time boundaries below the
  hardware tier; use hardware for real transport, native stores, lifecycle, and integration.

## Epic ledger

| ID | Workstream | Status | Acceptance evidence |
| --- | --- | --- | --- |
| V1-00 | Reconcile the acceptance contract and restore a trustworthy baseline | **complete — 2026-07-19** | Windows QA 128/128 + 2 skips; concurrency 50/50; fmt, all-feature clippy, full locked tests, audit and release build green; local Docker Linux certmesh exchange green; public contract/docs/dashboard aligned |
| V1-01 | Lab inventory, preflight, locking, artifact identity, deployment and exact cleanup | **complete — 2026-07-19** | All three nodes identified; host keys pinned; prerequisites/time/ports checked; concurrent run refused with owner; identical binaries verified; dry-run and exact cleanup removed only run-owned state; original service/binaries preserved |
| V1-02 | Certmesh protocol and native trust role rotations | **in progress — first privileged Linux rotation green** | brook CA→granite member/proxy→brook native client passed fail-before/install/curl+OpenSSL success/wrong-host/remove/fail-after/full-store restoration; Windows drove APIs; Windows trust and remaining role rotations pending |
| V1-03 | Certificate lifecycle and adversarial trust cases | planned | Local key custody/ACLs, chain/SANs, renewal/key rotation, restart, backup/restore, pin mismatch, revocation boundary, wrong-host rejection, exact root removal and post-removal TLS failure proven |
| V1-04 | Real whole-story capability surface | planned | Acts 0–11 pass on hardware: mDNS, DNS, runtime/orchestrator, health, proxy data plane/reload, UDP, ACME, status, dashboard, OpenAPI, Prometheus, MCP, IPC, service lifecycle and reverse cleanup |
| V1-05 | Resilience, reconnect, fault and soak lanes | planned | Startup reconciliation, Docker event reconnect, daemon/service restart, capability loss/recovery and bounded long-run stability produce repeatable reports without leaked state |
| V1-06 | Automation, evidence ledger and v1 release gate | planned | Smoke/certmesh/full/soak profiles documented; scheduled hardware execution reliable; three consecutive full green runs; release evidence and `SURFACES.md` updated honestly |
| V1-07 | Adoption/public-surface polish backed by proved behavior | **in progress — identity + publication foundation complete 2026-07-19** | ADR-024 canonizes “Let everything local find, trust, and talk” plus Find/Trust/Connect; ADR-025 establishes one attested artifact contract, no-build cargo-binstall metadata, tested npx bootstrap, gated OIDC publication, and safer release operation; registry activation, native-manager channels, evidence-gated compatibility claims and golden demo remain |

## Certmesh/native-trust acceptance matrix

Each of the three V1-02 role rotations must prove:

1. Native TLS verification fails before root installation.
2. Invite fingerprint pins the intended CA; member key/CSR originate locally; no private key crosses
   enrollment; Linux mode and Windows ACL checks pass.
3. `koi trust install` installs the exact CA fingerprint; native store inspection and
   `koi trust list` agree.
4. A real service behind Koi's TLS proxy is accepted cross-machine without `-k` or a custom CA
   override by Windows Schannel (`curl.exe` and `Invoke-WebRequest`) and Linux native clients
   (`curl`, `openssl s_client -verify_return_error`). Wrong hostname still fails.
5. TLS-only tests use an explicit address mapping first so DNS failures cannot masquerade as trust
   failures. A separate privileged lane proves real `.internal` system resolver configuration and
   restores it exactly.
6. Renewal rotates the member key; restart preserves state; revocation blocks Koi renewal/rejoin
   and makes diagnosis red. Generic TLS acceptance of an unexpired revoked leaf is recorded as the
   documented non-CRL/OCSP limitation, not misreported as a test failure.
7. `koi trust remove` removes only the recorded fingerprint; a fresh native client fails afterward;
   service, resolver, files and processes return to their captured baseline.

## Execution profiles

- **smoke:** connectivity, artifact identity, deploy, health, mDNS and one join; target ~5 minutes.
- **certmesh:** all role rotations and native trust lifecycle; target ~20–30 minutes.
- **full:** every capability and composed whole story; target ~45–60 minutes.
- **soak:** repeated events, restarts, renewals and controlled faults; 6–24 hours.

Hardware execution is not a PR gate initially because the lab is shared and finite. Local/unit and
container tiers remain PR gates; hardware smoke runs frequently; certmesh/full gate major phases and
releases; soak is scheduled or explicitly invoked.

## Resume here

1. Generalize the proven Linux trust transaction by declarative CA/service/client roles rather
   than copying a second scenario. Exercise the reverse dedicated-host direction and keep the
   pre-existing granite service untouched on its fixed binary/port.
2. Add the Windows LocalMachine implementation behind the same permit semantics plus an elevation
   proof. It must refuse before setup when unelevated. Execute it only from an elevated session,
   with exact certificate thumbprint capture/removal and Schannel failure-before/success/
   wrong-host/failure-after assertions.
3. Resolve the certmesh SAN drift discovered during exploration: CLI enrollment still requests
   `<hostname>.local` while Koi's intentional DNS default and public contract are `.internal`.
   Centralize the configured zone at the enrollment boundary before using system DNS in hardware.
4. Upstream the Debian dangling-symlink fix to `os-truststore` when separate repository/publication
   authority exists; then remove Koi lab's guarded compatibility branch.

## Implementation map

- `tests/integration.ps1`, `tests/concurrency.ps1`: current scheduled QA harness and immediate V1-00 repair surface.
- `.github/workflows/qa.yml`, `.github/workflows/ci.yml`: existing gates and eventual profile wiring.
- `docs/testing/whole-story-e2e-surface.md`: canonical Acts 0–11; reconcile stale constraints.
- `docs/adr/018-certmesh-integration-test-suite.md`: existing certmesh tiers and cross-platform history.
- `docs/SURFACES.md`: honesty/rotation ledger; update only with real evidence.
- `docs/testing/integration-hosts.md`: physical-host runbook and last hardware findings.
- `scripts/integration/deploy.ps1`, `scripts/integration/cross-host-test.sh`,
  `scripts/cross-platform-certmesh.ps1`: reuse lessons, then retire duplication deliberately.
- `crates/koi-embedded/tests/whole_story.rs`, `crates/koi/tests/two_daemon_certmesh.rs`:
  existing reusable scenario behavior and assertions.
- `crates/koi-certmesh/src/core_lifecycle.rs`, `core_member.rs`, `diagnosis.rs`: best-effort trust installation and diagnostic semantics the hardware lane must prove.
- `crates/koi/src/commands/trust.rs`: explicit root install/list/remove/export; source PEM must survive through removal.
- `.github/workflows/release.yml`, `scripts/release-manifest.mjs`, `packages/npm/`,
  `crates/koi/Cargo.toml`: artifact-first publication contract and thin channel consumers.
- Proposed `tools/koi-lab/` and `tests/lab/`: controller, inventory, node drivers, scenarios, fixtures and reports. Confirm placement during exploration before creating them.
- Sibling `F:\Files\repo\github\sylin-org\os-tools\crates\os-truststore`: native trust-store implementation and lower-tier tests; do not duplicate it inside Koi.

## Do not redo

- Do not repeat broad repository/market/ecosystem discovery; use `.oss-adoption/current/` for that evidence.
- Do not treat ping failure or a sandbox-denied socket as proof a lab host is down. Both hosts were
  authenticated successfully over SSH after using the permitted network context.
- Do not extend the current bash script into a second monolithic source of truth. Reuse its proven
  operational lessons in the structured lab runner.
- Do not parse human CLI tables for contract assertions when JSON/HTTP/protocol output exists.
- Do not infer OS trust from a successful certmesh create/join; query the native store and execute a
  native TLS verifier.
- Do not use `-k`, broad certificate deletion, unpinned SSH, hard-coded credentials in new work, or
  host clock changes to manufacture green results.
- Do not claim the epic or a capability complete because a lower tier passes. Record the tier and
  the exact evidence.

## Validation still owed

- V1-00 is locally complete. Hosted Linux/macOS scheduled-QA evidence remains unavailable until
  changes are intentionally published to CI; do not conflate the local Linux container certmesh
  gate with the full cross-platform PowerShell QA lane.
- No trust root has been installed/removed and no Koi service lifecycle has been exercised on the
  Windows workstation. The current process is not elevated, so its LocalMachine lane remains
  gated/refused.
- One Linux native trust install/remove rotation is proven; the reverse role direction and the
  three-node Windows-client role matrix are still outstanding.
- The full three-node role matrix, whole-story surface, privileged service lifecycle, fault lanes,
  soak, scheduled execution and three-consecutive-green v1 gate are outstanding.
## Open basket

- **Now:** finish full workspace validation, generalize the proven trust transaction for role
  rotation, and implement the elevation-refusing Windows boundary without mutating its store.
- **Later in epic:** complete V1-02, then V1-03 through V1-06 in evidence-driven order.
- **Deferred:** remaining V1-07 evidence-backed adoption/golden-demo work; first npm publication
  and trusted-publisher activation; GHCR public-visibility verification/fix; WinGet/Homebrew
  channel creation; and any other external publication.
- **Related readiness debt:** runtime list/watch reliability, off-loopback management transport,
  embedded data-root isolation, partner label semantics, ACME/Prometheus/Tailscale contract proof,
  and claim/documentation drift remain relevant to the v1 full-surface gate.
