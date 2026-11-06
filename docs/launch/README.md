# Release readiness

Koi's release target is a container application that another computer on the LAN
can find and open, with correct naming and state through restart, recreation and
removal. Trusted service-name HTTPS is the next milestone.

[ADR-046](../adr/046-container-lan-adoption.md) sets scope.
[Epic 004](../../fleet/epics/004-container-lan-adoption.md) defines work.
[The ledger](../../fleet/launch/LEDGER.md) records progress.
[The UX contract](../ux/README.md) defines the coherent operator experience and
links an interactive design concept; it is not a shipped UI claim.

## Artifacts and channels

Observed baseline: 2026-09-12. Recheck public endpoints before preparing a release.

| Surface | Current fact | What an operator should infer |
| --- | --- | --- |
| Repository source | 1.0.0-dev.0 | Development instructions describe this source; it is not an accepted launch candidate |
| Latest published stable | 0.9.0 | Unqualified stable installers may select this version; use its tagged documentation |
| Latest published prerelease | 1.0.0-rc.2 | Available pinned artifact, with its own tagged behavior and evidence |
| New operator preview | No accepted artifact | The focused journey remains a target until a receipt and published version appear here |
| Trusted-service extension | No accepted artifact | Automatic exact service-name setup is not currently a completed public workflow |
| npm @sylin-org/koi | Public registry returned not found | Packaging source is not an available installation channel |
| Homebrew, winget, AUR and Scoop | Repository scaffolds | Do not advertise an install command until the actual channel is verified |

The [public snapshot](../assessment/findings/2026-09-12-public-adoption-snapshot.json)
records the baseline. It is not a live monitor. A later accepted receipt replaces
a channel fact only after an independent download/install check.

## Supported scenario claims

The initial acceptance target is Windows x64/Docker Desktop paired with Linux
glibc x64/Docker Engine, in both host/client directions on a normal LAN with
multicast permitted. Neither row is accepted for the new preview yet.

Existing builds for other operating systems/architectures remain available
according to their release. Build availability does not establish a specific
container/client workflow. Podman, macOS, musl, routed networks and non-desktop
clients need their own scenario evidence before the quickstart promises them.

## What is implemented, and what remains

Runtime inventory is composed into mDNS, DNS, health and proxy state. CLI/HTTP
discovery and control, provider selection and lifecycle reconciliation exist.

Certmesh is the private-space identity and trust pillar. It already provides
CA ownership, member enrollment and renewal, signed membership/revocation
information, and recovery primitives. Participating applications can consume
those identities and apply their own access rules. See [Certmesh](../guides/certmesh.md).
This capability is distinct from the unfinished service-name HTTPS composition.

The container certmesh label records a request; it does not automatically issue
or inject workload certificates. Current grant-based ACME requires an exact
service-name/account authorization whose public operator workflow remains
unfinished. The trusted-extension tasks close that gap.

A name returned by Koi's own DNS lookup is not proof of the client's normal DNS.
A published port is not proof of an application response. OS-root installation
is not proof that a particular browser or runtime trusts a certificate.

## Preview release gate

1. A unique candidate source/version, lockfile and complete artifact identity.
2. Clean-checkout hosted dry run and required repository/regression checks.
3. Installed Windows/Linux evidence for the actual second-device application,
   container lifecycle, restart, collision, failure diagnosis and recovery.
4. Upgrade/uninstall/interrupted-install evidence with protected durable state.
5. At least five formative operator attempts with failures and interventions
   included; no unresolved advertised-task, security or data-loss blocker.
6. A core U06 receipt for the explicitly selected preview UI: useful service
   actions, truthful evidence and recovery, coherent Private space orientation,
   accessibility and the actual delivered entry. Record at least five L05
   attempts on this surface; earlier CLI trials remain valuable formative evidence.
7. Versioned instructions, known limits, checksums/provenance, rollback and a
   verified public install after publication.

The preview may ship without the trusted extension, new Certmesh wizards or
whole-desktop migration. The core experience on its advertised UI is required.
Early CLI/HTTP trials may begin before that gate; they do not accept the UI.

## Trusted-extension gate

Add exact service-name grant/issuance/listener wiring, normal second-client
resolution and TLS validation, renewal and failure recovery, and one complete
proxy/resolver integration. Revalidate affected source and artifacts. Record
a separate explicit stable-readiness decision if a stable release is intended.

## Evidence and adoption

Use [proof receipts](proof.md) for technical claims and the [cohort protocol](cohort.md)
for independent usage. The ledger owns completion. Neither downloads nor a green
development build establishes user retention or full release acceptance.

The [L03 lifecycle-fixture evidence](lifecycle-fixture-proof.md) records the
copyable fixture's local dry run and the exact physical proof still required.
