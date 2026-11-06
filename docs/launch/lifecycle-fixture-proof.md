# L03 lifecycle-fixture evidence

Task: [L03 in Epic 004](../../fleet/epics/004-container-lan-adoption.md#l03--complete-the-real-container-to-second-device-task).
Last verified: 2026-09-13.
Source baseline: `791f87ebe0a8ba93246f60ce0b283c13fb86595b` plus the preserved working tree.
Verdict: the copyable fixture and its local container lifecycle are verified;
L03 remains in progress. This is not Koi discovery, installed-host, physical
client or release proof.

## Fixture contract

The [operator-preview Compose fixture](../../docker/operator-preview/README.md)
used the pinned image
`node:24-bookworm-slim@sha256:ba849c60be29959425b8734d57b8b4b7d56f98edd9504c9af091d5281095a71e`
for the dry run below. A later dependency refresh (2026-11-05) moved the pin to
`node:26-bookworm-slim@sha256:add5c17c14752c54d2f3d519ec46a3815684d41c33f198bcb09fb998f7dcbf68`;
the dry run has not been repeated on that image.
It publishes a configurable TCP port on `0.0.0.0`, opts in with the implemented
`koi.announce` shorthand, and requests HTTP health checks at `/health` every
five seconds with a two-second timeout. Its response includes the operator's
run ID, current container hostname and request path.

Each installed-host run has a 60-second observation deadline for every catalog,
resolver and physical-client transition. The recorder captures actual elapsed
time and the last observed state; exceeding the deadline fails that case. The
deadline is a preview acceptance budget rather than a general latency promise.
Current source caps Docker observation reconnect backoff at five seconds and
composition retries every five seconds, but the physical run must measure the
complete mDNS, resolver and application path.

## Local fixture dry run

Environment: Windows amd64 Docker client 29.7.2, Docker Desktop 4.89.0 with
Linux Engine 29.7.2, Compose v5.5.0, context `desktop-linux`. Docker resolved the
image to the exact digest above. Run ID: `local-measure-20260913b`.

| Transition | Local observation | Elapsed |
| --- | --- | ---: |
| Initial start | Container `cc1642212f6c4094d95a5bf78aa0ad5536680294f23c6d803643e0ea346d5053` became healthy on `0.0.0.0:18080`; `/` returned the exact run ID and hostname | 7.249 s |
| Container restart | Same full container ID returned healthy and served the same run ID | 7.090 s |
| Recreate with changed port | New container `eff1fb5ef00ebf0cac33a5167cf66ea2ee587cefe374a2bdeaf532386a7f79e2` became healthy on `0.0.0.0:18081`; the old port was closed and the response retained the run ID | 7.752 s |
| Stop | Container reached `exited` and port 18081 stopped responding | 2.844 s |
| Cleanup | Compose reported zero rows, zero project-labeled containers and zero project-labeled networks; ports 18080 and 18081 were closed | complete |

`docker compose config` also resolved the intended digest, port binding, health
metadata and Koi labels. This run deliberately did not start or modify Koi, use
a resolver, cross a LAN, or act as a physical client. Its timings describe only
the local fixture lifecycle and cannot accept the 60-second end-to-end budget.

## Remaining acceptance

Run the fixture against one identified candidate and installed service for each
Windows-host/Linux-client and Linux-host/Windows-client direction. Record Koi
artifact, configuration, process and provider identity; catalog service ID and
singularity; ordinary resolver result; exact client URL and JSON; restart,
recreation, runtime restart, daemon restart, host reboot, collision, stop and
removal timings; and complete restoration. No stale endpoint may remain usable.

## Current Windows development deployment

On 2026-09-13 the current source was built as release-mode Koi
`1.0.0-dev.0` and installed through Koi's elevated transactional SCM recipe.
The source and staged `C:\Program Files\Koi\koi.exe` both had SHA-256
`E2267E0D04FFEA16792C3C1805BFAC7CAB2B38A441A194263B6A30CB3084567C`.
SCM reported the automatic service running as PID 32392 at observation time;
the installer verified `/healthz` on 5641. The service reported Docker healthy
and observed the real fixture.

The deployed fixture used run ID `deployed-20260913`, container
`bdfd39f763c9939cfee217e249eaaf4da7746f654769dbe95445cd4fb4897012`,
and `0.0.0.0:18080`. Koi's catalog projected
`runtime:koi-operator-preview` as `responding` at
`http://127.0.0.1:18080`, with Open, Copy, details, Favorite, alias and
diagnosis eligibility. The application returned the exact run ID through both
loopback and host LAN address `192.168.1.137:18080`.

The paired native development workbench was built from the sibling desktop base
plus the U02/U03 changes, directly against this Koi working tree. The Windows
package was generated with `npx @tauri-apps/cli@2.11.4 build --bundles nsis`.
The resulting unsigned `Koi_0.1.3_x64-setup.exe` had SHA-256
`3F381903C791C2E0948082F91485EE6066AD07EAD849893FDD48A8D4E1E9AF1A`
and installed successfully as the current-user Koi 0.1.3 application. The
installed executable at `C:\Users\Leo\AppData\Local\Koi\koi-desktop.exe` had
SHA-256 `DAB0A31A0EF7A0F3273A6EF0247FBDD8F9123255BE07A3D479C14E4182BE384E`;
PID 41304 was connected and running at observation time. Tauri patches/stages
the application for its NSIS bundle, so the installer hash is the package
provenance boundary rather than equality with the post-bundle build output.

The invented port-8766 preview was stopped. The shared native pane still
withholds endpoint actions pending its typed command bridge. No independent
physical client participated, so L02, L03, U02, U03 and the 60-second end-to-end
budget remain unaccepted.
