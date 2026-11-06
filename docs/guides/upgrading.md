# Upgrade and migration

Upgrade a known artifact while preserving the installed service, application
access and any certificate identity. The [release-readiness page](../launch/README.md)
names the supported destination and its migration evidence.

Stable 0.9.0 and prerelease 1.0.0-rc.2 are published. Source 1.0.0-dev.0 is
development, not a replacement release candidate. A new source commit or passing
CI is not an instruction to replace an installed service.

## Establish the starting point

Record the CLI version and the installed service's executable/version separately:

```sh
koi version
koi status
curl -fsS http://127.0.0.1:5641/v1/runtime/status
```

Record the data root, durable configuration, native service definition, runtime
account/socket, Koi-owned firewall policy and a known application's second-client
result. Preserve the current artifact and checksum for restoration.

Read the destination's release notes and migration instructions. In their
absence, a development installation is an explicit evaluation with its own
rollback plan, not a routine upgrade.

## Back up before changing state

If operating a CA, make an encrypted backup with the matching supported command:

```sh
koi certmesh backup mesh-pre-upgrade.koi
```

Keep the backup and its passphrase available independently of the host.
[CA recovery](certmesh-ha-recovery.md) explains its contents and exclusions;
the CA bundle is not a full service/configuration backup.

For a consistent whole-state copy, stop the daemon through its native manager
and preserve the actual data directory and relevant service/configuration/policy.
Default roots are /var/lib/koi on Linux, /Library/Application Support/koi on macOS
and %ProgramData%\koi on Windows. KOI_DATA_DIR may override them.
Protect member private keys and backups with appropriate permissions.

## Replace through the owning installer

Download the chosen release archive and verify its checksum/provenance.
Bootstrap scripts default to stable unless KOI_VERSION is supplied. npm is not
an available installation path.

For installed services, run the selected binary's supported koi install recipe
with required platform elevation. Preserve explicit local-operator and runtime
settings. Current transactional recipes verify replacement and restore the
previous state on a failed operation; interrupted operations recover through the
installer. Inspect the result instead of deleting recovery files by hand.

For a foreground process, stop it, preserve state and the old binary, then launch
the chosen replacement with the intended configuration. Do not run both against
the same state or LAN identity.

## Compatibility checks for current source

| Area | Required review |
| --- | --- |
| Standalone/client behavior | Normal commands use the installed service; standalone operation is explicit and refuses an existing local owner |
| Status/catalog/UI | Rebuild consumers against current schemas and observed-state semantics; stale/unavailable is not empty success |
| Proxy certificates | Explicit overrides belong under proxy-certs/<entry-name>; Proxy consumes member identity through composition |
| Exact-name ACME | An in-zone name alone no longer authorizes issuance; current source requires one account-bound service grant |
| Public setup | The exact service-name grant/listener operation is incomplete; do not migrate a working proxy integration by assuming a replacement public path exists |
| Certificate SANs | Inspect actual issued names; older .local, hostname and persisted certificates can differ from current configured-zone issuance |
| Embedded serving | KoiHandle::serve is async and returns the bound SocketAddr; try_serve and public serve_adaptive are removed |
| Participation | participate returns its actual address after listener bind and initial publication succeed |

Existing service grants are not created by hand-editing the roster. A missing
public operation is a limit to plan around.

## Published-prerelease behavior to preserve

When moving from rc.1 to rc.2, stored mesh policy is retained. Newly created meshes
use seven-day leaves renewed with three days remaining. A healthy certificate
inside its normal renewal window is not itself a warning.

The certificate-authenticated management listener can expose /v1/mcp; inspect
the configured authority and use --no-mgmt-mcp where appropriate.
These published behavior notes do not certify later development source.

## Older installations and consumers

The following are migration facts for installations that still depend on older
contracts, not an implementation campaign or a claim of current acceptance.

- **Very old rosters:** pre-0.4.2 state may need an explicit compatibility/recovery
  plan. Do not re-run CA creation as generic repair: creating a new root can break
  every member and client. Preserve an encrypted backup and inspect the roster
  error before choosing restore or deliberate replacement.
- **Removed interfaces:** FIDO2 enrollment, automatic CA failover, enrollment
  deadline/CIDR scope, compliance endpoints and stub runtime backend names are
  not current supported interfaces. Promotion is an explicit operation; supported
  backend names are auto, docker and podman.
- **Remote reads:** current authorization distinguishes loopback from remote or
  unknown peers. Full certmesh status and DNS inventory need appropriate remote
  credentials; enrollment preflight uses /v1/certmesh/bootstrap. The signed trust
  bundle remains public. Audit and UDP reads require authentication.
- **UDP exposure:** loopback is the default. Non-loopback binding or destinations
  require the explicit remote option. Recheck existing consumers' lease and token
  handling.
- **Embedded exposure:** an announced HTTP endpoint requires the configured token;
  do not preserve an older insecure exposure pattern.
- **Embedded management:** replace certmesh_background with certmesh_managed.
  Management is on by default for a member; use false only when the application
  deliberately owns trust refresh and renewal itself.
- **Embedded trust shapes:** CertmeshHandle::posture is async. Assurance::Rejected
  includes optional signer_cn; exhaustive matches need the current fields.
  Removed RejectReason values include no_signature, clock_skew and name_mismatch.
  Unsigned/stale envelopes use the current assurance model.
- **Request authorization:** use the request-bound identity/verification APIs when
  authorizing an envelope. Presence of an identity alone is not sufficient binding
  to the request being authorized.

For Rust or cross-language consumers, compile/run meaningful integration tests
against the selected version. [Embedding](embedded.md) and the
[trust protocol](../reference/trust-protocol.md) define current interfaces.

## Verify the result or restore

After replacement:

```sh
koi status
curl -fsS http://127.0.0.1:5641/v1/runtime/status
koi mdns discover _http._tcp
koi health status
```

Verify the installed executable identity, not just the CLI on PATH.
Repeat the [second-client application and lifecycle checks](../../CONTAINERS.md)
for the actual workload. If using TLS, verify the intended browser/runtime,
certificate SAN/chain/expiry and renewal/recovery.

A passing healthz response does not prove these outcomes. If a required result
fails, follow the destination's documented restoration procedure using the
preserved artifact and state; record both the failure and restoration result.

Uninstall is not required for routine upgrades. Factory reset and CA destruction
are destructive operations, not rollback tools.
