# Proof for a release claim

A proof establishes one user-visible result on named artifacts and environments.
It is not a general declaration that Koi works everywhere.

## Required receipt

Record:
- task and case IDs, recorder, date and result: pass, fail, blocked or not run;
- source SHA, version, dependency lock, recipe/installer revisions and artifact hashes;
- host OS/architecture, runtime/version and service identity/PID;
- independent client's OS, application/browser/runtime and version;
- network prerequisites, configured DNS path and published application endpoint;
- exact setup, observed output, elapsed times and expected behavior;
- cleanup/restoration result, residual changes and protected durable state;
- links to redacted logs, commands, fixture and reproduction instructions.

Do not publish tokens, private keys, personal hostnames, real user network
addresses or other identifying configuration in public proof. Use consented
redacted records and synthetic examples.

## Container case matrix

| Case | Required observation |
| --- | --- |
| Clean install | Documented command reaches the intended daemon; no accidental second daemon |
| Existing container | A container started before Koi is discovered and usable |
| Initial publication | Independent peer sees the record and opens the real application |
| Client DNS | The ordinary client resolver resolves the intended name |
| Restart/recreate | New endpoint/state converges; stale endpoint is not called usable |
| Changed port/name collision | Correct endpoint or explicit conflict; no silent reassignment |
| Runtime restart | Observation reconnects and current inventory reconciles |
| Host reboot | The documented install restores intended service behavior |
| Stop/removal | Record and derived state retire under the measured lifecycle contract |
| Failure/recovery | DNS, discovery, bind/firewall and application failures are distinguished |
| Upgrade/uninstall | Configuration and identity are preserved or deliberately removed as documented |

Run Windows host/Linux client and Linux host/Windows client separately.
Use pinned application fixtures. Mocks belong in tests, not native acceptance.

## Trusted-service cases

Verify the exact SAN and application URL, the intended client's normal DNS and
certificate validation, grant/account isolation, key permissions, renewal,
CA lock/unavailability, wrong name/account, service removal and restart recovery.

Never use curl -k, a certificate-warning bypass or a direct DNS query as the
passing substitute. State ordinary-TLS revocation limits accurately; a Koi roster
change is not instant CRL/OCSP revocation for every client.

## Revalidation and publication

Source, dependency, installer, package recipe and shipped-asset changes create a
new candidate identity. Re-run affected cases and required regression checks;
record why unaffected evidence still applies.

A publication receipt includes actual URLs, immutable version, post-publication
hash checks and an independent quickstart. Preparing files is not publication.
An accepted technical receipt is not an independent user observation.
