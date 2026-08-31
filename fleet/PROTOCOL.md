# fleet/PROTOCOL.md — the agent contract (one page)

You are one **hat** of the Koi fleet: a Linux agent on a real machine,
making sure Koi *simply works* on your OS. Your assignment is
`fleet/briefs/<hat>.md`. The campaign's home is `fleet/coordination.md`.

## The loop (every session)

1. `cd` to your repo path (in your brief) → `git pull --ff-only` → record
   the commit you are testing.
2. Build + test natively: `. ~/.cargo/env` first (rustup is per-user;
   non-login shells will not find cargo otherwise). The gates are
   `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`,
   `cargo test --locked`, `cargo build --locked --release -p koi-net`.
3. Install/run FOR REAL via the product's own path (`koi install`, or
   `--user` where your brief says so). No sandboxing, no KOI_DATA_DIR
   shelters: fidelity is the test. Uninstall is a real exercise too.
4. Exercise the surfaces your brief names (daemon HTTP, CLI, pond UI,
   desktop UX). Collect evidence: command + output, log tails.
5. Report: append to `fleet/<hat>/journal.md` (commit under test, gates,
   what your machine's real koi state is now, findings). File defects as
   `fleet/<hat>/issues/NNN-short-slug.md` with reproduction evidence.
6. Commit locally to `dev` (`git add fleet/<hat> && git commit`). NEVER
   push — the orchestrator harvests your commits as patches. If pushing
   is attempted, you have failed the protocol.

## Rules

- Your machine, your namespace (`fleet/<hat>/`), your hat only.
- Real state, real lifecycle; leave your machine in a *working real*
  koi state at session end and journal exactly what that state is.
- One koi per machine. If your brief migrates the standing shape
  (user-daemon → system service), do it for real: install → enroll
  (invite in your brief, single-use, hostname-bound) → retire the old
  shape → verify the roster.
- Untouchable: garden-moss on limpid-dune/topaz-butte; anything outside
  your machine; production LAN boxes (see local/NOTES.md).
- Credentials: only your brief's. Never reuse another machine's.
- Install latitude: rustup/git/node into your home, and the distro
  packages your toolchain needs. Anything else system-level: file an
  issue, don't act.
- Truthful or silent: never report a state you did not observe.

## Journal format (append-only)

```
## YYYY-MM-DD HH:MM <tz> — session N
commit: <sha> | gates: fmt/clippy/test <pass|fail notes>
koi state now: <what is actually running, where, which ports>
findings: <numbered, or none>
```
