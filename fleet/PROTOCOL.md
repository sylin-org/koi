# fleet/PROTOCOL.md — the agent contract (one page)

You are one **hat** of the Koi fleet: an OS agent on a real machine, making
sure Koi *simply works* there. The universal entry point is `fleet/task.md`;
it resolves this machine to `fleet/briefs/<hat>.md`. The campaign's home is
`fleet/coordination.md`.

## The loop (every session)

1. `cd` to your repo path (in your brief) and inspect the worktree. Continue an
   intentional interrupted change; never overwrite another agent's work. Otherwise
   `git switch dev` → `git pull --ff-only origin dev` → record the commit you are
   testing.
2. Build + test natively: `. ~/.cargo/env` first (rustup is per-user;
   non-login shells will not find cargo otherwise). The gates are
   `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`,
   `cargo test --locked`, `cargo build --locked --release -p koi-net`.
3. Install/run FOR REAL via the product's own path (`koi install`, or
   `--user` where your brief says so). No sandboxing, no KOI_DATA_DIR
   shelters: fidelity is the test. Uninstall is a real exercise too. You are
   authorized on your own hat machine to install required platform/build
   dependencies and to upgrade, restart, enroll, uninstall/reinstall, and
   exercise Koi and its native session integrations as the brief requires.
4. Exercise the surfaces your brief names (daemon HTTP, CLI, pond UI,
   desktop UX). Collect evidence: command + output, log tails after at least one
   periodic retry interval, and visible captures for desktop claims. A generated
   startup file counts only after its executable target is proved durable.
5. Report: append to `fleet/<hat>/journal.md` (commit under test, gates,
   what your machine's real koi state is now, findings). File defects as
   `fleet/<hat>/issues/NNN-short-slug.md` with reproduction evidence.
6. Commit to `dev`, synchronize, and publish in the same session:
   `git add <owned paths> && git commit`, then `git pull --rebase origin dev`
   and `git push origin HEAD:dev`. Every agent is authorized and expected to
   push directly. If another agent wins the race, rebase and retry; never
   force-push and never leave the completed commit local-only.

## Rules

- Your machine, your namespace (`fleet/<hat>/`), your hat only.
- One shared branch: work directly on `dev`; do not create per-agent branches.
  A session with `HEAD` ahead of `origin/dev` is unfinished. Resolve ordinary
  push races with `git pull --rebase origin dev` and retry the push.
- Real state, real lifecycle; leave your machine in a *working real*
  koi state at session end and journal exactly what that state is.
- One koi per machine, including during validation: no parallel test daemon,
  second service, alternate-port Koi, or isolated data-root copy. Capture
  rollback material, then stop → upgrade/migrate → start → verify as
  one serial transition. If your brief migrates the standing shape, enroll the
  replacement with its single-use hostname-bound invite, retire the old shape,
  and verify the roster and process count. Shift ports only for a genuine
  non-Koi incumbent the final deployment must coexist with, never to make room
  for a test instance.
- Untouchable: garden-moss on limpid-dune/topaz-butte; anything outside
  your machine; production LAN boxes (see local/NOTES.md).
- Credentials: only your brief's. Never reuse another machine's. When the lab already provides
  test credentials, pass them through the platform's noninteractive standard channel instead of
  opening an operator-facing privilege dialog. Any askpass file, environment value, copied key,
  or other credential material created for a run is volatile, untracked, excluded from evidence,
  and removed before the run can pass.
- Test latitude: on your own hat machine, install the platform/build
  dependencies and exercise the system services, responder/provider lifecycle,
  immutable deployment, firewall, trust store, and graphical-session surfaces
  necessary for the brief's real acceptance gates. Capture exact baseline and
  rollback material first, mutate only the named surface, settle-check it, and
  restore anything not intended as the final Koi deployment. This authority does
  not extend to another fleet or production machine.
- Truthful or silent: never report a state you did not observe.

## Journal format (append-only)

```
## YYYY-MM-DD HH:MM <tz> — session N
commit: <sha> | gates: fmt/clippy/test <pass|fail notes>
koi state now: <what is actually running, where, which ports>
findings: <numbered, or none>
```
