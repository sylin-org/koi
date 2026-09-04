# R13 - Complete one Linux installation recipe per execution

You are executing one work order in Koi Epic 003. You need no prior conversation.
Deliver this result: **Each supported Linux environment installs into its native lifecycle and works without terminal repair.**

- Dependencies: [R11](R11-installation-contract.md), [R09](R09-settings-about-and-surface-consolidation.md)
- Epic gate: G3
- Execution class: native acceptance through the activated fleet protocol.
- Status, fixed owner, dependency readiness and exact next slice live in [LEDGER.md](LEDGER.md).
  Its Linux readiness rule qualifies only pending Windows physical proof, never missing source or Linux evidence.

## Start here

1. Read [the epic](../../../fleet/epics/003-delight-realignment.md), [CHARTER.md](CHARTER.md),
   [LEDGER.md](LEDGER.md) and [CONTRACT.md](CONTRACT.md).
2. Verify dependency evidence against current code and preserve the worktree.
   R01 activation is required. A queued plan or missing predecessor contract does not authorize guessing its implementation.
3. Read the source set below and nearby tests. Use R01's owner map and R06's component
   map where they exist. New file names in those maps are authoritative.
4. Write the bounded plan in reports/R13.md (or reports/R13-<slice>.md), then
   execute without another routine plan-approval question. Use the charter's report format.

## Choose one slice

This task has separately tracked slices: `systemd-plasma`, `rpm-ostree-gnome`, `openrc-musl`, `systemd-headless`.
Select one applicable dependency-ready slice from LEDGER.md. Execute and report only
that slice; complete the parent task only when all required rows are accepted.
The slice table defines order, owner and narrow deliverable.

## Starting source

- `crates/koi/src/platform/recipes/mod.rs`
- `crates/koi/src/platform/recipes/systemd.rs`
- `crates/koi/src/platform/recipes/openrc.rs`
- `crates/koi/src/platform/recipes/transaction.rs`
- `packaging/alpine/APKBUILD`
- `../koi-desktop/packaging`
- `fleet/coordination.md`

Paths are relative to Koi root; ../koi-desktop is the sibling. Search moved paths
with rg, update the contract map, and inspect the current owner before creating files.

## Work

1. Resolve this host's existing fleet hat and select exactly one ledger subrow: CachyOS=systemd-plasma, Bluefin=rpm-ostree-gnome, Alpine=openrc-musl, Debian=systemd-headless. Read its brief. Do not mark other rows accepted or invent macOS evidence.

2. Implement the missing portion of R11 using that environment's service/package/session facilities. A GUI installation pairs daemon/workbench at durable paths; headless installation supplies a useful local operator entry. Keep compilers outside an immutable host's deployed image.

3. Prove install, rerun, boot/login as applicable, close/reopen, restart, upgrade, failed-upgrade rollback, uninstall/reinstall and provider coexistence. Validate real package/service operations, including OpenRC/musl and rpm-ostree reboot/rollback where applicable.

4. Exercise native discovery and a peer service using the intended deployment, restore all run-owned changes and retain one healthy Koi. Report shared bugs at the shared owner and implement only this native recipe's adapter differences.

## Acceptance cases

- [ ] The selected subrow completes installation to a usable service without manual provider commands.
- [ ] Desktop entry, tray where supported, native window decoration, notification and startup work in an actual fresh session; headless parity requires no GUI.
- [ ] No source-checkout path or build dependency becomes part of the durable installed product.
- [ ] Own receipt cleanup and rollback preserve foreign providers, DNS policy, user data and firewall rules.

## Verification

Run the selected host's locked native gates and package lifecycle tests. Use an independent physical peer; count existing rows only when their exact source/artifact remains valid. R13 is accepted only when all four subrows pass.

For code changes, finish the applicable CHARTER.md gates. Record missing native or
hosted prerequisites explicitly; a source-only check cannot close that acceptance.

## Documentation and handoff

Update only this hat's journal plus its R13 subrow/report and the relevant distro guide. Include exact artifact identities and restoration result.

Update the selected LEDGER.md row and its report with exact source changes, commands,
results, remaining work and the next concrete action. Cite owned fleet evidence for
native claims. Retest downstream contracts affected by your change.

## Scope boundary

Do not replace one Linux recipe with distribution detection inside common product logic, rebuild all four hosts in one session, or call an AppImage-only build cross-distro acceptance.

A standalone invocation ends after this work order. A fleet invocation returns to
fleet/task.md after publishing the slice and rechecks the assigned dependencies.
If this slice is too large, checkpoint coherent work and its exact next step.
Do not mark acceptance complete with pending required evidence or production placeholders.
Test fixtures prove only their stated layer; they cannot replace native or user evidence.
