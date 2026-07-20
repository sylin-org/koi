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

# Build Windows natively and Linux through cross + Docker on this workstation.
cargo run -p koi-lab --locked -- build

# Lock both nodes and stage one hash-identical binary under runs/<run-id>/.
cargo run -p koi-lab --locked -- deploy

# Non-privileged role vertical, driven from Windows.
cargo run -p koi-lab --locked -- certmesh-smoke --run-id <run-id> `
  --rotation linux-forward

# Non-privileged lifecycle/adversarial transaction. Use a fresh run ID.
cargo run -p koi-lab --locked -- certmesh-lifecycle --run-id <run-id> `
  --rotation linux-forward

# Encrypted disaster recovery. This erases only the run-owned CA data/runtime roots.
cargo run -p koi-lab --locked -- certmesh-recovery --run-id <run-id> `
  --rotation linux-forward

# Physical whole story including native-trusted Act 7. Use a fresh deploy/run ID.
cargo run -p koi-lab --locked -- capability-story --run-id <run-id> `
  --allow-system-mutation --rotation linux-forward

# Docker event-stream fault/reconciliation. This faults only Koi's run-owned relay.
cargo run -p koi-lab --locked -- runtime-reconnect --run-id <run-id> `
  --rotation linux-forward

# Brook-only transient systemd readiness/restart/reconstruction transaction.
cargo run -p koi-lab --locked -- service-lifecycle --run-id <run-id> `
  --allow-system-mutation

# Bounded churn/reconstruction soak. Defaults: 20 iterations, 15 minutes, restart every 5.
cargo run -p koi-lab --locked -- bounded-soak --run-id <run-id>

# Unattended policies own fresh deployment + scenario + exact cleanup per case.
cargo run -p koi-lab --locked -- run-profile smoke
cargo run -p koi-lab --locked -- run-profile certmesh --allow-system-mutation
cargo run -p koi-lab --locked -- run-profile full --allow-system-mutation
cargo run -p koi-lab --locked -- run-profile soak `
  --iterations 20 --max-minutes 15 --restart-every 5

# Privileged trust rotation. Use a fresh deploy/run ID for each rotation.
cargo run -p koi-lab --locked -- certmesh-native-trust --run-id <run-id> `
  --allow-system-mutation --rotation linux-forward

# Other assignments use the same scenario engine:
#   linux-reverse: granite CA → brook service → granite native client
#   windows-client: brook CA → granite service → Windows Schannel client

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
and lock are absent afterward. Story cleanup additionally verifies the exact run label,
container ID, container name, image ID, and image tag before removing Docker objects.

`certmesh-smoke` consumes declarative CA/service/client roles and uses dedicated high
ports from `tools/koi-lab/lab.json`, so it can run
beside a captured system Koi service. It starts only run-owned PIDs, creates certmesh data
only below the run directory, explicitly injects the `.internal` issuance zone, drives
create→pinned invite→join from Windows, asserts the
member's trust diagnosis is Healthy, hashes the Linux system trust stores before/after to
prove the non-privileged slice changed no roots, and records a secret-redacted report.

Completed check-bearing scenarios publish evidence through one controller chokepoint. Each report
exposes its checks plus an explicit secret-redaction verdict; the publisher renders every format
before writing any file and refuses reports that have not attested redaction. The canonical `.json`
path is accompanied by a CI-readable `.junit.xml` and an operator-readable `.txt` summary with the
same filename stem. Preflight, deployment manifests, and diagnostic snapshots remain JSON-only
because they are not scenario verdicts. Physical certmesh-smoke run
`v1-20260720T202701Z-5db023d1` at clean commit `f435382` emitted:

```text
certmesh-smoke-linux-forward.json
certmesh-smoke-linux-forward.junit.xml
certmesh-smoke-linux-forward.txt
```

The parsed JUnit suite reported 6 tests and 0 failures, matching the text summary's 6/6 verdict.
The locally built Linux musl artifact was 41,511,128 bytes with SHA-256
`199a4b46faa3ef5777b949ffd46684f468e279324f4f98c9e9f1369a856f3287`; nothing was built on either
Linux host. Exact cleanup removed both run roots and locks. Final preflight
`preflight-20260720T202852Z.json` left Brook inactive and preserved Granite's original active,
enabled Koi 0.7.0 service at PID 803.

`run-profile` is the V1-06 unattended policy boundary. It never reimplements a scenario verdict:
smoke owns the two Linux certmesh-smoke rotations; certmesh owns the existing lifecycle, recovery,
and all three native-trust rotations; full extends that same certmesh list with both reconnect and
capability-story rotations plus Brook's service-lifecycle transaction; soak delegates to the
existing bounded-soak evaluator. Every case gets a fresh deployment and always attempts exact
cleanup before the policy continues or fails fast. One execution-scoped directory retains the
before/after preflights and aggregate redacted JSON/JUnit/text verdict. Stable baseline comparison
includes host identity, fixed Koi service state/executable, fixed artifact identity, and listening
sockets while intentionally excluding clocks.

Physical smoke execution `v1-20260720T205716Z-41637b4e` at clean commit `c37fdb6` passed 8/8 in
63 seconds. Child runs `v1-20260720T205733Z-2a4cc973` and
`v1-20260720T205756Z-939cba58` independently passed forward/reverse deployment, existing scenario,
and exact cleanup. Parsed `profile-smoke.junit.xml` reported 8 tests / 0 failures and matched the
readable summary. The locally built Linux musl artifact was 41,510,952 bytes with SHA-256
`020f9e86694a272e5c066b9d359fa6578e1b4ee0fef3682e629327e0d602497f`. Final recorded preflight
left Brook inactive and Granite's original active/enabled Koi 0.7.0 service at PID 803 with the
same executable and start time.

The elevated certmesh policy then passed execution `v1-20260720T211240Z-df893184` at controller
commit `3cfb205`. All seven child transactions passed deploy/scenario/cleanup and parsed aggregate
JUnit reported 23 tests / 0 failures. It covered lifecycle and recovery in both Linux directions,
native trust in both Linux directions, and the elevated Windows-client trust/lifecycle rotation.
Independent post-run inspection found zero copies of the Windows run CA's SHA-256 fingerprint in
`LocalMachine\Root`; final preflight restored the complete stable baseline.

Full execution `v1-20260720T211813Z-47d0f395` passed in 12m57s using the same locally rebuilt musl
artifact SHA-256 `020f9e86694a272e5c066b9d359fa6578e1b4ee0fef3682e629327e0d602497f`.
Every one of its 12 fresh child transactions passed deployment, the existing scenario evaluator,
and exact cleanup; parsed `profile-full.junit.xml` reported 38 tests / 0 failures. Beyond the seven
certmesh cases, it proved Docker reconnect in both directions, capability story plus ACME in both
directions, and Brook systemd supervision (`92889→93222`, `NRestarts=1`). Final preflight left
Brook inactive/not-found, preserved Granite's original active/enabled PID 803 service with the same
executable and start time, and matched the pre-run stable service/artifact/listener baseline. This
is v1 full green 1 of 3.

### Scheduled full profile

Windows Task Scheduler is only the clock and elevation adapter. The scheduled command builds the
Windows and Linux artifacts on this workstation, then calls the same `run-profile full` policy
used manually. It contains no profile membership, scenario assertions, deployment, cleanup,
baseline, or evidence logic.

```powershell
# Safe inspection; changes nothing.
pwsh scripts/lab/scheduled-profile.ps1 -Plan

# One-time setup from an elevated PowerShell process. The prompt is secure.
pwsh scripts/lab/scheduled-profile.ps1 -Install

# Optional immediate proof after installation (also run elevated).
Start-ScheduledTask -TaskName 'Koi v1 full profile'

# Exact removal from an elevated PowerShell process; retains scheduler transcripts
# and .lab-runs evidence.
pwsh scripts/lab/scheduled-profile.ps1 -Remove
```

The default trigger is Monday at 03:00 local time; `-DayOfWeek` and `-At` can override it during
installation. The dedicated lab password is stored outside the repository as a Windows
CurrentUser-DPAPI ciphertext and exists as plaintext only in the scheduled process environment
while the physical profile runs. It is absent from the task action, scheduler arguments,
transcript, and evidence; the existing PuTTY transport receives the throwaway credential through
its established `KOI_LAB_PASSWORD` boundary. The task runs at highest privilege as the installing
interactive user, so that same user must be logged on when the trigger fires. `StartWhenAvailable`
catches a missed trigger after logon. A dirty Git worktree is refused before any build, credential
decryption, or lab mutation. Scheduler transcripts live below
`%LOCALAPPDATA%\Koi\lab-scheduler\logs`; canonical redacted JSON/JUnit/text verdicts remain under
`.lab-runs/`.

The installed task passed its first complete proof at clean commit `7536417`. Parent execution
`v1-20260720T221929Z-238c05e1` completed all 12 fresh deploy/scenario/cleanup transactions and
published aggregate JSON/JUnit/text; parsed JUnit reported 38 tests / 0 failures. Independent
inspection found zero copies of the Windows rotation's run CA in `LocalMachine\Root`; final
preflight left Brook inactive and preserved Granite's original active/enabled PID 803 service.
Task Scheduler recorded result `0`, action start/completion events, a correctly refused overlapping
`StartWhenAvailable` attempt, and the next Monday 03:00 trigger. The profile took 842 seconds (887
seconds including its local build); Brook systemd supervision restarted `117035→117373` with
`NRestarts=1`. This is complete v1 full green 2 of 3.

An earlier trigger, parent `v1-20260720T220251Z-48863adc`, was interrupted with `CTRL+C` during its
eighth case and is not counted as a green. Exact inspection of interrupted child
`v1-20260720T221040Z-2f50a1df` found matching owners on both Linux nodes. Explicit owner-checked
`plan-cleanup` and `cleanup` then removed only that child's run roots and locks; a fresh preflight
confirmed the stable service/listener/artifact baseline. Forced process termination cannot run the
controller's in-process final cleanup, so centralized interrupted-profile journaling/recovery is a
remaining V1-06 hardening item; the PowerShell scheduler must not infer remote ownership.

`certmesh-lifecycle` extends that protocol vertical without mutating native trust stores. It
rejects a wrong invite fingerprint before local key creation; checks mode-`0600` key/state custody,
key/leaf correspondence, the full chain, and hostname plus configured-zone SANs; then triggers the
same CSR-only mTLS renewal path used by scheduled renewal and requires a new local key plus matching
CA-roster state. It restarts only the run-owned daemon and requires identity and proxy continuity.
Finally it pulls revocation, requires RED diagnosis and CA renewal refusal without replacing the
local identity, and records that generic TLS still accepts the unexpired leaf in the absence of
CRL/OCSP. `linux-forward` and `linux-reverse` both passed on 2026-07-19.

`certmesh-recovery` is the run-scoped destructive recovery gate. It creates a v2 encrypted
backup, rejects a wrong backup passphrase without changing live state, stops only the owned CA
daemon, verifies the exact resolved `data` and `runtime` roots, erases those two roots, and proves
the replacement daemon is uninitialized. Restore must recover the same CA fingerprint and active
roster, bind the CA to the recovery machine with mode `0600`, publish secure posture, and accept a
key-rotating member renewal over restored mTLS. A restart must lock the recovered key; the old CA
passphrase must fail, the new restore passphrase must unlock it, and another renewal must succeed.
Both Linux role directions passed on 2026-07-19. Backup bundles and passphrases are streamed to
`curl` over stdin and never written to evidence or placed in process arguments.

`capability-story` is the V1-04 physical whole-story transaction. It starts isolated
full-surface daemons on the two Linux nodes with explicit high DNS and fixture ports, then proves
Acts 0, 3, 4, 5, 6, 7, 8, 10, and 11. The transaction covers mode-`0600` breadcrumbs and Unix IPC,
HTTP plus real cross-host `dig`, multicast resolve/heartbeat/goodbye removal, a run-owned TCP
fixture driving health Up→Down→Up, protected UDP SSE round-trip/heartbeat/unbind, and the shared
status/dashboard ladder plus host metadata, OpenAPI, Prometheus discovery, authenticated MCP
resource list/read, and the public MCP server card. For Acts 5/11 it copies the exact deployed musl
binary back to the controller, assembles a `FROM scratch` image locally, loads it under a run-only
tag, and starts a labeled container without compiling or building on either Linux host. One Docker
event must derive runtime inventory, mDNS, `.internal` DNS, health, and a live self-signed TLS proxy.
The story then leaves that container running, restarts only the run-owned Koi daemon, requires a
new daemon PID, and proves runtime inventory plus every derived service is reconstructed before
container stop reverses them and the owned container and image are removed.
Act 3 also stops the live DNS resolver while retaining its record, verifies the centralized status
ladder reports `stopped`, gives the resolver port to an exact run-owned UDP process, requires
`POST /v1/dns/serve` to fail rather than claim success, removes only that blocker, retries, and
requires the same record to resolve again from the other host. The shared domain lifecycle
chokepoint accepts fallible asynchronous startup and generation-checks loop completion, so a stale
loop cannot mark its replacement stopped.
Act 7 composes pinned certmesh enrollment, `.internal` DNS, a certmesh-sourced proxy, native trust,
hostname verification, member key/certificate rotation, and hot leaf reload without a daemon restart.
Its ACME mini-act uses a real `instant-acme` client, publishes and exact-clears dns-01 proof through
Koi's authenticated TXT API, observes it from the other host with `dig`, and verifies the issued
chain and SAN. Exact root removal must restore the full native-store baseline and make native TLS
fail again. All manual and Docker-derived state is compensated before evidence is written. Both
Linux role directions passed with startup reconciliation on 2026-07-20: forward run
`v1-20260720T014815Z-96794673` restarted Brook (`38290` → `38620`) and reverse run
`v1-20260720T015153Z-558233f4` restarted Granite (`67926` → `68309`), both using locally built musl
SHA-256 `928522b3c18fce60a28310e619fbb4ff715d8b0a9f03c059842eaef6629f8d07`.
Reusable Tier 1 breadth and Windows execution remain unclaimed.
The enhanced Act 3 and complete story passed again in both directions on 2026-07-20: forward run
`v1-20260720T190754Z-fdc848da` used Brook (`57914` → `58297`) and reverse run
`v1-20260720T191154Z-adb441bc` used Granite (`111400` → `111831`). Both used clean commit
`27b268d` and locally built musl SHA-256
`199a4b46faa3ef5777b949ffd46684f468e279324f4f98c9e9f1369a856f3287` (41,511,128 bytes).
Final preflight `preflight-20260720T191606Z.json` found no run roots or locks, left Brook without an
installed service, and preserved Granite's original enabled Koi at PID 803.

`runtime-reconnect` is the V1-05 physical Docker recovery transaction. The controller stages a
small Python standard-library Unix-stream relay inside the run root and starts the run-owned Koi
daemon with a process-scoped `DOCKER_HOST` pointing at that mode-`0600` socket. Stopping the relay
therefore interrupts only Koi's Docker connection; neither host Docker daemon is restarted. While
disconnected, the transaction leaves one container unchanged, stops one, starts one, and attaches
a run-owned network to one for a material IP update. The authenticated `/v1/events` stream must
then contain exactly one disconnect, stop, start, update, and reconnect fact, with no lifecycle
event for the unchanged container and no duplicate from the inclusive Docker cursor replay.
Runtime health must become inactive and recover, the last good inventory must remain readable,
and the unchanged container must retain the same mDNS registration plus working DNS, health,
proxy configuration, cross-host mDNS, and live proxy traffic throughout. Cleanup checks the exact
relay PID/executable/arguments, socket, container/image/network labels and IDs, and run ownership.
Both directions passed on 2026-07-20: forward run `v1-20260720T181705Z-f96627ae` kept mDNS
registration `07e03545`; reverse run `v1-20260720T181902Z-165ff7be` kept `269ddfcf`. Both used the
clean locally built musl artifact SHA-256
`0d5d47d850d52c601a70941b525a80a1dabac0dd861e95dfbca6ee9c2c42f4f7` (41,566,120 bytes).
Final preflight `preflight-20260720T182050Z.json` found no run roots, locks, listeners, containers,
images, networks, or relays; Brook remained inactive and Granite's original enabled Koi remained
PID 803.

`service-lifecycle` is the V1-05 Linux supervision transaction. It is deliberately narrower than
public `koi install`: Brook must have no permanent Koi unit, binary, or data root, and the controller
creates only a run-named transient systemd unit backed by the staged artifact and high test ports.
The unit runs as the configured lab user with `Type=notify`, `Restart=on-failure`, and exact
run-owned data/runtime roots. The controller verifies the unit's transient fragment, user, MainPID
executable, and READY-derived active state; starts a labeled container; then SIGKILLs only MainPID.
The replacement process must have a new PID and DAT, increment `NRestarts`, and reconstruct runtime
inventory, DNS, cross-host mDNS, health, TLS proxy state, and live proxy traffic. Cleanup will stop
only a unit whose name, transient fragment, user, and live executable match the run marker.

Run `v1-20260720T194505Z-4b9b9788` passed on 2026-07-20 using clean controller/artifact commit
`cc3685d` and locally built musl SHA-256
`199a4b46faa3ef5777b949ffd46684f468e279324f4f98c9e9f1369a856f3287` (41,511,128 bytes).
Systemd replaced Brook PID `64274` with `64608` (`NRestarts=1`), the DAT rotated, and all derived
surfaces reconverged. Exact service cleanup restored Brook's absent permanent-service baseline;
full cleanup removed both run roots and locks. Final preflight `preflight-20260720T194652Z.json`
preserved Granite's original active/enabled PID 803 service. Public Linux install/uninstall remains
a separate unclaimed contract because its fixed paths and default port 53 require a byte-exact
reversibility design.

`bounded-soak` amplifies the already-proved orchestration lifecycle without introducing another
domain path. One run-owned image is reused while each iteration starts a uniquely named container,
requires the shared derived-service evaluator to converge runtime inventory, DNS, cross-host mDNS,
health, TLS proxy state, and live proxy traffic, then removes the container and requires every one
of those projections to disappear. Every Nth iteration restarts the primary Koi daemon while the
container remains live and requires a new PID, new DAT, and full reconstruction. `--iterations`
(1–100,000) and `--max-minutes` (1–1,440) are independent finite bounds; the duration boundary is
checked before admitting another iteration, while each admitted operation retains its own timeout.

Short physical proof `v1-20260720T195910Z-a235c0c4` completed 3/3 iterations in 29,614 ms using
clean commit `8907a15` and musl SHA-256
`199a4b46faa3ef5777b949ffd46684f468e279324f4f98c9e9f1369a856f3287`. Iteration 2 restarted
Brook `66702→67236`; its DAT rotated and all derived surfaces reconstructed. Each iteration fully
reversed, exact scenario/full cleanup succeeded, and final preflight
`preflight-20260720T200046Z.json` preserved Granite PID 803 with no run roots or locks. This proves
the profile and short churn lane; a scheduled 6–24 hour run remains release evidence work.

`certmesh-native-trust` is the one privileged mutation boundary. It refuses without
`--allow-system-mutation`. Linux clients additionally require passwordless sudo; the
Windows-client rotation proves elevation **before** checking the run or contacting either
Linux node. The shared transaction uses only the run CA PEM and a separate run-owned
trust-state root, configures the role-selected service's real Koi TLS proxy, and proves
native TLS fails before installation, succeeds afterward without a custom CA, and rejects
a wrong hostname. Linux uses `curl` plus OpenSSL. Windows uses Schannel through `curl.exe`
plus `Invoke-WebRequest`; the latter gets an explicit temporary hosts mapping whose exact
original bytes are restored in a `finally` block. Windows installation is verified by the
certificate's SHA-256 identity in `LocalMachine\Root`. The transaction removes only the
tracked fingerprint, proves TLS fails again, and requires the complete native trust-store
snapshot to match its captured baseline before reporting success.

The elevated Windows-client transaction passed on 2026-07-20 as run
`v1-20260720T030254Z-bb6572bc`. Store capture and membership checks use the
provider-independent read-only `.NET X509Store` API rather than assuming the PowerShell `Cert:`
provider exists. Its exact CA SHA-256 was
`5cb069719615e570e7590cfd30a8fe4ad5ec55559d77c7aac24928d1abb3fb86`. Schannel
`curl.exe` keeps CA and hostname verification enabled and uses `--ssl-revoke-best-effort` only
because this private CA has no CRL distribution point; `-k`, `--insecure`, and
`--ssl-no-revoke` are forbidden. `Invoke-WebRequest` succeeded and the temporary hosts mapping was
restored byte-for-byte. After exact root removal, both native rejection and the complete captured
store baseline were restored.

That same tracked trust window now includes the Windows V1-03 member lifecycle. A run-owned
Windows daemon uses the local 18541–18555 port range, a run-owned `KOI_DATA_DIR`, and an isolated
`ProgramData` breadcrumb. It must reject a wrong invite pin before creating a key, join Brook with
local key custody, diagnose Healthy, and appear Active in Brook's roster. ACL evidence resolves
identities to SIDs and permits allow ACEs only for SYSTEM (`S-1-5-18`),
BUILTIN\Administrators (`S-1-5-32-544`), and the current user; the data root and DAT breadcrumb
must have inheritance disabled. Cleanup kills and waits for the exact spawned child, verifies the
local owner marker, and deletes only `.lab-runs/<run-id>/windows-member`. Owner-checked remote
cleanup removes only that run.

Run `v1-20260720T043212Z-0b37baee` physically passed the extended transaction. The member rotated
private-key hash `6b2e19a825fc4e92…` to `15cc14f07b399e07…` and certificate hash
`242296e4a1cb2d2d…` to `f476482bb4f87205…`; production diagnosis verified correspondence and the
CA roster converged to leaf fingerprint
`76f4780218d52088ded4847b6f505057ddf5bf5e291350d8f5159477c68569c3`. The exact run-owned child
restarted from PID 41980 to 19832 with identity, Healthy diagnosis, and Schannel proxy continuity,
then restarted to PID 23936 to pull revocation. Diagnosis became RED with `self_revocation=red`;
both renewal and fresh-invite rejoin were refused, and neither changed the active key or
certificate. CA root SHA-256
`c4de1f63a0c115ab689bccbaf84505e368e158807b19cb863e54102f6cbf64d0` was removed exactly and the
complete store baseline matched. Locally built artifacts were Linux SHA-256
`8178b6cd00fe9996bc6f2be748593124e6c9f4ba5569bb9042899fcaf20ed011` (41,506,592 bytes) and Windows
SHA-256 `45036ca7adc119dbda80918a5fb212845db8b41684d048c0a1fae0bde279cc7a` (35,726,336 bytes).
Final preflight `preflight-20260720T043333Z.json` plus independent store/hosts/PID/port/path checks
found no run residue, kept Brook inactive, and preserved Granite's original enabled Koi 0.7.0 PID
803. Windows cold recovery is still not claimed.

The first two attempts were useful harness/product findings and were cleaned exactly. Run
`v1-20260720T041817Z-3c30c620` exposed Schannel rejection at the local proxy; run
`v1-20260720T042416Z-cf6a51fb` localized it to a freshly issued member leaf whose `notBefore` was a
few seconds ahead of Windows. Certmesh now backdates certificate validity by its centralized
300-second clock-skew tolerance without shortening expiry. Failed enrollment also stages its CSR
key and cannot replace an active identity before a matching signed leaf is validated. The first
failed run retains its redacted smoke report and the second its redacted
`windows-member-failure.json`; no private key or DAT is retained.

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

`koi-lab build` always builds both required binaries on the workstation. There is no
remote build fallback:

```text
cargo build --release --locked -p koi-net
cross build --release --locked --target x86_64-unknown-linux-musl -p koi-net
```

The build report records byte length and SHA-256 for both artifacts. Deployment records
the Git commit and Linux artifact identity, copies that same Linux file to both remote run
directories, and accepts a node only after its native `sha256sum` matches and the staged
binary reports a version. The nodes need no Rust or C toolchain. Preflight
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
