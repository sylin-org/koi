# Fleet execution protocol

This protocol applies to an explicitly activated assignment selected through
[the fleet task](task.md), [Epic 004](epics/004-container-lan-adoption.md), and
[the launch ledger](launch/LEDGER.md). It is not authority to start another host.

## Ownership and authorization

- CachyOS owns source implementation and integration. Other hosts supply requested
  native verification and their own evidence. A separately authorized repository
  documentation task may edit the documentation it owns without transferring the
  ongoing source role.
- Each host owns its own system mutations and evidence. Do not start another
  host's session, install there, change its provider/network/firewall/trust state,
  or borrow its credentials. Peers execute their own addressed requests.
- Production LAN machines, garden-moss on limpid-dune/topaz-butte, and anything
  outside the explicitly assigned host remain out of scope. Private local notes
  contain protected machine and credential details.
- An activated native assignment permits required build/platform dependencies and
  the named install, upgrade, restart, enrollment, uninstall, service, provider,
  firewall, trust-store and session exercises on that host. Capture baseline and
  rollback material first; mutate only the named surfaces.
- Documentation maintenance alone authorizes no remote execution, installation,
  deployment, push or service mutation.

## Repository work

Inspect the worktree before synchronization. Preserve interrupted work and edits
owned by others. Fleet source/evidence publication uses `dev` and direct authenticated
pushes when the fleet assignment is activated. On a clean checkout synchronize with
`git pull --ff-only origin dev`. Commit only owned paths, resolve ordinary publication
races with `git pull --rebase origin dev`, then push `origin HEAD:dev`. Never
force-push or discard another change. Separate repositories retain separate identities.

Source integration stays with CachyOS. Appropriate native hosts or hosted CI execute
the required checks, including locked builds/tests and lint gates specified by the
repository. A source-only task does not require installing Koi or running unrelated
native workbooks. Debian's capacity restriction applies before assigning any check.

Owner verification policy, 2026-09-06 (retained): use focused local checks while
developing, one complete product CI result per coherent milestone, and native
installation only for an affected platform behavior or user journey.
Documentation-only changes need no product build or deployment; CI's Change scope
job (`scripts/ci-scope.mjs`) lets only known documentation paths skip product jobs.
Record a claim in the launch ledger before editing; a sole source owner publishes
it with the implementation commit, and a separate claim-only push is needed only
when another writer or host must act on it. Exact identity, restoration guards for
real mutations, release gates and truthful evidence remain binding.

## Native execution

Keep one installed Koi per host. Capture the exact binary, configuration, state,
service descriptor and enablement, provider, ports, network, firewall, trust roots,
startup entries and process baseline relevant to the assignment.

Arm interruption-safe restoration before destructive steps. Upgrade serially:
stop → replace/migrate through the supported product path → start → verify.
Do not create a second service, alternate-port test Koi, isolated data root, or
checkout-only UI to obtain acceptance. A different port is justified only by an
actual non-Koi incumbent required by the intended deployment.

Use native system/package/service mechanisms. Preserve unrelated services,
application state, roots, keys and firewall rules. Where a task enrolls a replacement
shape, use its own single-use hostname-bound invitation, retire the old shape and
verify the roster and process count. A cancellation must not abandon admitted
native changes.

Use provided credentials through the platform's noninteractive standard channel
when available. Temporary askpass files, environment secrets, copied keys and
credentials are untracked, excluded from evidence and removed before passing.
Never print tokens or credential material.

Restore all run-owned temporary state and prove restoration. Leave only the intended
working Koi deployment. Capture settled state after the relevant recovery/retry
interval, rather than inferring success from command exit alone.

## Evidence

Every native claim identifies source commit, artifact/package origin, installed
path and SHA-256, process identity, OS/runtime/provider, relevant configuration,
command and result, peer identity, run ID and final restoration state. A named
candidate is built from that exact source with the locked dependency graph. Later
HEAD is not a substitute. Changes to product bytes, dependencies, recipes or shipped
assets invalidate affected candidate evidence under the epic's rules.

Discovery, resolution, local reachability, peer application response, and named-client
TLS validation are distinct facts. A generated URL, certificate file, UI screenshot,
root installation, or successful TCP connection proves only that measured step.
A `passed` result requires the task's full applicable proof; unknown, not run and
pending remain explicit.

A second-device claim uses an independent physical client, the intended name/URL,
and a real application operation. Record both sides' artifact and configuration
identities where Koi runs. Do not use `-k` or equivalent TLS bypasses for trust proof.
Unsupported/unavailable counters or providers remain explicitly unavailable.

Bounded tests may use fakes where appropriate; release and user-workflow evidence
uses the actual supported artifact and native path. Repeat proof only when an
affected artifact, behavior, configuration or declared gate changes.
