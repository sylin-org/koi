Status: complete
Run ID: 20260719T034411Z
Project: koi
Created: 2026-07-19T03:44:11Z

# Readiness audit

Use `blocker`, `important`, `helpful`, or `not applicable` for each finding.

Evidence was checked at three distinct points and is not interchangeable: the local `dev`
checkout at `04cdfb4cecd9498f2154fdee70dd7464c83cc20b`, public `main` at
`021b9c7745a0c67d5f0e9f9b891b49804c5e04d1`, and release `v0.9.0` published
2026-06-25.

## Executive finding

**Recommendation: repair before broad promotion; use only for a narrow, technically
informed evaluation cohort.** Koi is a substantial pre-1.0 feasibility product with an
unusually strong release supply chain and broad automated tests. It is not ready to be
described as load-bearing. A known vulnerable dependency remains in both public `main` and
the current local lockfile, the latest three scheduled QA runs are red, and several
headline collaboration and isolation paths are stronger in documentation than in the
implementation.

The positive evidence is real: the latest public-main CI run built and tested on Linux,
Windows, and macOS; passed formatting, clippy, the Rust 1.92 check, lean-feature and surface
tripwires, and the cross-host certmesh exchange. The workflow as a whole was nevertheless
red because `cargo audit` correctly rejected the dependency graph. That distinction must
remain explicit in every public claim.

## Legal and ownership

- **helpful — licensing is explicit.** `Cargo.toml` declares `Apache-2.0 OR MIT`, the root
  contains `LICENSE-APACHE` and `LICENSE-MIT`, release packaging copies both, and
  `CONTRIBUTING.md` applies the same dual license to contributions.
- **important — community governance is thinner than the product surface.** The repository
  has a contribution guide and a private vulnerability route, but no Code of Conduct,
  governance document, general support policy, or issue/PR templates in the adoption
  inventory. This is acceptable for a small evaluation cohort, but expectations should be
  made explicit before inviting broad participation.
- **not applicable — Koi has no buyer or sales path.** It is an Apache-2.0 OR MIT
  open-source project with no hosted tier or paid feature boundary. Adoption should be
  evaluated through successful use, contribution quality, ecosystem compatibility, and
  sustainable maintenance rather than commercial conversion.

## First success and installation

- **helpful — the first-use path is unusually concrete.** `README.md` leads from the
  practitioner problem to platform installers, daemon startup, status, discovery, and a
  visible HTTP example. `GUIDE.md` documents `koi uninstall` and the platform service
  managers.
- **important — installer evidence is release/workflow evidence, not an independent clean
  install.** `install.sh` and `install.ps1` select a platform archive and verify its SHA-256
  sidecar before installation. This run did not execute the remote installers on clean
  machines, and the red scheduled QA means the install-to-first-result story must not be
  called validated on all supported platforms.
- **important — supported-platform wording needs the QA qualifier.** Six native v0.9.0
  archives exist for x86-64/AArch64 Linux, macOS, and Windows, but the most recent weekly
  integration evidence is not green. Safe wording is “prebuilt for,” not “operationally
  validated on,” all six targets.

## Product evidence and limitations

- **helpful — broad evidence exists.** The public-main CI run
  [28137185932](https://github.com/sylin-org/koi/actions/runs/28137185932) passed the three-OS
  build/test matrix, formatting, clippy with warnings denied, Rust 1.92, lean dependency
  closure, publish-list completeness, surface-ledger checks, and a genuine cross-host
  certmesh exchange. The repository also carries domain, protocol, integration,
  property/conformance, security, XSS, embedded, UDP, MCP, runtime, and two-daemon tests.
- **blocker — scheduled acceptance evidence is red.** The latest three QA runs failed on
  [2026-07-13](https://github.com/sylin-org/koi/actions/runs/29223317029),
  [2026-07-06](https://github.com/sylin-org/koi/actions/runs/28767718155), and
  [2026-06-29](https://github.com/sylin-org/koi/actions/runs/28348655641). On July 13 the
  Windows integration job ran 129 checks: 119 passed and 10 failed because asserted DNS
  output, certmesh fields/routes, and CLI discover/subscribe counts no longer match the
  product. The Windows service job added four passing lifecycle checks but hit the same 10
  failures. Linux/macOS integration and Linux concurrency fail before the checks because
  `$env:TEMP` is used before `Cleanup` is defined; the trap then masks the startup failure
  with `Cleanup not recognized`. This is both product-contract drift and a broken
  diagnostic path.
- **blocker — container list/watch is not durable enough for the headline automation
  promise.** `RuntimeCore::start_watching` broadcasts initial `Started` events before the
  compose orchestrator necessarily subscribes (`crates/koi-runtime/src/lib.rs` and
  `crates/koi-compose/src/orchestrator.rs`). The Docker event loop exits when the stream
  errors or ends and does not reconnect (`crates/koi-runtime/src/docker.rs`). Existing
  containers or events can therefore be missed at startup or after a disconnect.
- **blocker — Traefik/Caddy label cooperation currently crosses the ownership boundary.**
  `crates/koi-runtime/src/instance.rs` converts Traefik
  `loadbalancer.server.port` and caddy-docker-proxy `{{upstreams PORT}}` backend ports into
  Koi `proxy_port`; `crates/koi-compose/src/orchestrator.rs` treats that value as a Koi
  listener port. Partner-managed routes should be inventory/DNS facts, not an instruction
  for Koi to bind a potentially occupied frontend port.
- **important — the ACME workflow is not yet demonstrated with standard clients.** Koi
  advertises DNS-01 interoperability, but the challenge handler validates and clears a TXT
  value while no production caller or public DNS mutation interface sets that value. The
  current Caddy/Traefik recipes therefore exceed the demonstrated workflow. Keep the claim
  at “experimental ACME facade” until a real client conformance test passes, preferably
  through HTTP-01/TLS-ALPN-01 and/or RFC 2136 with TSIG.
- **important — Prometheus compatibility is wire-level, not scrape-level.**
  `crates/koi-serve/src/prometheus_sd.rs` emits health targets and arbitrary first-published
  runtime ports in the Prometheus HTTP-SD JSON shape. Those are not necessarily metrics
  endpoints and will create failed/noisy scrapes. Require explicit metrics annotations or
  provide a separate blackbox-exporter view before claiming automatic Prometheus scraping.
- **important — direct Tailscale/Headscale addressing is outside the default safety
  model.** `crates/koi-dns/src/safety.rs` accepts RFC1918/loopback/link-local IPv4 but not
  `100.64.0.0/10`. Split-DNS documentation can be claimed; direct tailnet client/record
  support cannot be claimed until operator-scoped CIDR allowances and end-to-end tests
  exist.
- **important — embedded data-root isolation is incomplete.** The composition layer accepts
  an injected data directory, but proxy TLS loading and trust-plane leaf persistence still
  call process-global `koi_common::paths::koi_certs_dir()`
  (`crates/koi-proxy/src/tls.rs` and `crates/koi-serve/src/trust_plane.rs`). An embedded host
  can therefore read or write outside its configured root.
- **important — “sealed” must not imply encrypted.** Sealed v0 is an authenticated,
  signed passthrough whose payload remains cleartext. The code exposes
  `Confidentiality::None` and logs a warning, which is good evidence of an intentional
  limitation; marketing and examples must say “signed, not encrypted” until group-key v1
  exists.
- **important — maturity is stated honestly and must remain so.** `README.md` says
  “pre-1.0, feasibility-validated, and consolidating,” and `SECURITY.md` supports only the
  latest release and current `main`. Nothing audited supports a production-ready,
  enterprise-ready, or load-bearing claim.

## Repository and community health

- **helpful — an owned product surface already tells the bounded story well.**
  [sylin.org/koi](https://sylin.org/koi) is indexed and presents current v0.9 positioning,
  a first command, explicit “reach for Koi”/“choose something else” boundaries, and the
  pre-1.0 caveat. It is a credible canonical landing page rather than a speculative launch
  asset. Its “Released today” wording is date-sensitive and should be replaced with the
  actual release date or “current release.”
- **important — GitHub metadata does not connect visitors to that owned surface.** The
  repository homepage field was empty when inspected, so GitHub discovery fails to hand a
  reader to the stronger maintained narrative. Add `https://sylin.org/koi` as the repository
  homepage and keep its version/maturity wording synchronized with releases.
- **helpful — release hygiene is strong.** Release
  [v0.9.0](https://github.com/sylin-org/koi/releases/tag/v0.9.0) publishes six native
  archives plus SHA-256 sidecars. `.github/workflows/release.yml` gates release creation on
  tests/builds, creates keyless build-provenance attestations for archives, builds a
  multi-architecture GHCR image with provenance and SBOM, and attests the image digest.
  `CHANGELOG.md`, tags, workspace versions, release assets, and the release workflow tell a
  coherent v0.9.0 story.
- **blocker — current public CI is red even though most jobs pass.** The latest public-main
  CI run failed in `audit`; a badge or summary that says “CI passing” would be false.
- **important — executable documentation has drifted.** The QA failures show stale output
  and route expectations. Separately, ACME, Prometheus, and partner-label documentation
  describes workflows that are not yet end-to-end true. Treat the live tests and code as
  the repair source, then update guides, reference pages, examples, and claim cards in one
  change.
- **helpful — remove the UTF-8 BOM in `crates/koi-udp/Cargo.toml`.** Its leading
  `EF-BB-BF` bytes cause a TOML parse warning in `rust-cache`. Cargo still builds the
  workspace, but clean manifests reduce avoidable CI ambiguity.
- **important — issue intake is not launch-shaped.** Add focused bug/feature forms and a
  support route only when the maintainer is ready to service the resulting demand; do not
  add channels that imply response capacity first.

## Security and operational trust

- **blocker — known vulnerable dependency.** `Cargo.lock` pins `quinn-proto 0.11.14` at
  both public `main` and current local `dev`. `cargo audit` reports
  [RUSTSEC-2026-0185](https://rustsec.org/advisories/RUSTSEC-2026-0185.html); the fixed range
  begins at `0.11.15`. Upgrade the resolved dependency, rerun the complete locked test
  matrix and audit, and issue a patched release before inviting adoption.
- **blocker for off-loopback management — bearer credentials travel over plaintext HTTP.**
  Loopback is the safe default. When `--http-bind` exposes the management API, DAT-protected
  requests still use plaintext HTTP with `x-koi-token`; a network observer can replay the
  bearer token. Some GET/SSE surfaces are intentionally unauthenticated, while selected
  topology/live-channel reads are gated. Do not describe off-loopback management as
  confidential or secure against a hostile LAN. Add TLS/mTLS or require placement behind a
  secure transport before promoting this mode.
- **important — sealed-message confidentiality is absent.** Sealed v0 protects origin and
  integrity, not payload secrecy. This is distinct from CA-private-key encryption at rest;
  the two claims must never be collapsed.
- **important — embedded root escapes violate host isolation expectations.** Global
  certificate paths are an operational and test-contamination risk for applications that
  supply a private data root. Thread the injected root through every cert/proxy/trust path
  and prove that no file access escapes it.
- **helpful — the supply-chain controls are materially stronger than average.** Checksums,
  archive and image attestations, image provenance, and an SBOM are strong positive trust
  signals. They do not compensate for a known vulnerable dependency or red acceptance
  checks.
- **helpful — vulnerability reporting is discoverable.** `SECURITY.md` directs private
  reports to GitHub Security Advisories or `hello@sylin.org`, names supported versions, and
  documents important trust boundaries.

## Maintainer capacity

- **important — choose a small asynchronous cohort.** A product spanning DNS, mDNS, PKI,
  HTTP, containers, OS services, trust stores, MCP, and embedded Rust creates high-cost,
  platform-specific support. The red scheduled runs already represent maintenance work
  that must be completed before adding launch-driven issue volume.
- **important — publish a narrow support contract.** The security policy promises
  acknowledgement “within a few days,” but there is no equivalent general-support route or
  response expectation. For pre-1.0, a sustainable contract is best-effort GitHub issues,
  current release only, no uptime promise, and no production incident response.
- **helpful — delay high-volume channels.** Start with 5–10 technically capable homelab/Rust
  evaluators who accept pre-1.0 breakage. Expand only after dependency audit and scheduled
  QA remain green and the first cohort completes install-to-first-value without maintainer
  intervention.

## Ordered repairs

1. **Blocker:** resolve `RUSTSEC-2026-0185` by moving `quinn-proto` to at least `0.11.15`,
   run the full locked matrix plus `cargo audit`, and publish a patched release.
2. **Blocker:** repair `tests/integration.ps1` initialization/cleanup ordering, preserve the
   original failure in traps, update stale DNS/certmesh/client assertions against the
   intended contract, and obtain three consecutive green scheduled QA runs.
3. **Blocker:** give off-loopback management authenticated encryption (native TLS/mTLS or an
   explicit secure-fronting requirement) and test token non-disclosure/replay boundaries.
4. **Blocker:** implement runtime subscribe/reconcile without a startup gap, reconnect with
   backoff and full reconciliation, and test restart, disconnect, lag, and pre-existing
   containers.
5. **Blocker for integration claims:** stop translating Traefik/Caddy backend ports into Koi
   listeners; add real-container ownership-boundary tests.
6. **Important:** make ACME usable by unmodified standard clients and make Prometheus export
   only explicit metrics endpoints or a separately documented blackbox target set.
7. **Important:** thread the embedded data root through proxy TLS and trust-plane storage;
   add a test that fails on any read/write outside a temporary root.
8. **Important:** rewrite every “sealed,” ACME, Prometheus, Tailscale/Headscale, and
   cross-platform validation claim to match the claim ledger; repair executable QA
   expectations in the same change.
9. **Helpful:** remove the `koi-udp` manifest BOM, add intentionally scoped issue/support
   surfaces, link the existing owned page from GitHub metadata, and run a clean-machine
   installer/uninstaller study with the initial cohort.
