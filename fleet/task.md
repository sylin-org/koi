# Koi fleet task — universal agent entry point

The operator invokes this campaign with one prompt on every participating machine:

```text
run fleet/task.md
```

This file is the complete dispatcher. Do not ask the operator to restate the hat,
brief, authorization, or next task. Identify this machine, load its assignment,
and execute it.

## 1. Resolve this machine's hat

Normalize the local hostname to lowercase and remove a trailing DNS suffix. Match it
exactly:

| hostname | hat | brief |
|---|---|---|
| `stone-leaded-sparkle` | `windows` | `fleet/briefs/windows.md` |
| `test-01` | `cachyos-linux` | `fleet/briefs/cachyos-linux.md` |
| `bluefin` | `bluefin-linux` | `fleet/briefs/bluefin-linux.md` |
| `test-03` | `alpine-linux` | `fleet/briefs/alpine-linux.md` |
| `stone-halcyon-savanna` | `debian-linux` | `fleet/briefs/debian-linux.md` |

The tracked address/host-key catalog in `tools/koi-lab/lab.json` may confirm an
identity, but never use an address alone to guess after a mismatch. Refuse to execute
on an unknown host, a retired `omarchy-linux` host, brook/granite, the phase-two Debian
twins, or a production machine. Report the observed hostname and OS when refusing.

## 2. Load the contract and current facts

1. Inspect the worktree first. Continue an intentional interrupted change; never
   discard or overwrite someone else's work.
2. Work on `dev`. If clean, run `git pull --ff-only origin dev`. If a prior local
   commit exists, finish the synchronization/push before starting something else.
   Re-read this file after synchronization if it changed.
3. Read, in order:
   - `fleet/PROTOCOL.md`;
   - `fleet/coordination.md`;
   - `fleet/epics/001-productization-hardening.md`;
   - this hat's brief from the table above;
   - this hat's full journal and unresolved issues;
   - the relevant ADRs, source, tests, and `docs/SURFACES.md` rows.
4. For desktop work, also inspect the sibling `koi-desktop` repository and its
   current installed artifact. Its branch and publication remain independent.

Measured machine state outranks a stale brief. Correct the brief when the machine
proves it wrong.

Within a brief, the most recent dated `next dispatch` section is the current routing
and outranks retained baseline lists. Journal and issue evidence still determine what
is already complete.

## 3. Select work without waiting for another prompt

Choose the first unfinished, dependency-ready item in this order:

1. a correctness or security defect explicitly named in the hat brief or current epic;
2. the hat's earliest open PH workstream;
3. evidence another hat needs from this OS for the next cross-host gate;
4. the hat's share of the final frozen-candidate matrix or soak.

Do not redo a green physical gate unless its relevant code/artifact changed or the
epic explicitly requires it on the frozen candidate. Research locally, in repository
history, and online using authoritative platform sources. The listed epic and protocol
are operator approval to implement and exercise the selected in-scope item. Complete
the repository's required exploration/plan step, then proceed without asking for the
same approval again. A plan or status summary alone is not a completed session.

If the newest dispatch says this hat is complete and waiting for the frozen source,
perform only the named read-only readiness or peer role. Report the dependency and
leave the deployment and repository unchanged; do not invent work, evidence, or a
commit merely to make the session look active.

If an observed defect belongs to shared architecture, fix it once at the lowest
correct shared boundary. Do not create an OS-local imitation. Breaking and rebuilding
pre-1.0 code is authorized when it yields fewer, clearer moving parts.

## 4. Execute the real product path

- Capture exact service, binary, configuration, state, provider, firewall, network,
  login/startup, and process baselines before mutation. Install interruption-safe
  restoration before the first destructive step.
- Keep exactly one installed Koi on the machine. No parallel daemon, helper backend,
  alternate-port test Koi, isolated data root, fake provider, or checkout UI may count
  as acceptance.
- All production capabilities and endpoints are real. Fakes are permitted only inside
  tests. Do not leave TODO-backed product behavior.
- Use the platform's supported install, service, package, session, firewall, and
  authorization mechanisms. Safe automatic recovery is preferable to merely describing
  a failure; when external policy makes recovery impossible, expose one precise action.
- Run risk-focused local tests, the full native gates appropriate to the change, then
  deploy that exact candidate serially and exercise it in the lived-in environment.
- Cross-host assertions use independent physical Koi peers. A peer may perform
  run-owned API publications and reads, but system/provider mutation belongs to that
  peer's own hat. Coordinate shared run IDs and retain both sides' PID/hash evidence.
- Remove test-only firewall rules, provider packages/configuration, login automation,
  credentials, keys, repositories, fixtures, and recovery tasks. Preserve only the
  intended installed Koi state.

## 5. Publish in the same session

1. Append one evidence-dense entry to `fleet/<hat>/journal.md` containing the PH ID,
   source commit, installed artifact path/hash/PID, peer identities, run ID/verdict,
   exact restoration result, and final state.
2. File an issue only for work that remains unresolved. A defect fixed and physically
   verified in the same session needs only the journal entry and tests.
3. Update the epic only when a whole gate changes state. Update `docs/SURFACES.md` only
   when physical evidence changes a public claim.
4. Commit the coherent change, `git pull --rebase origin dev`, and push directly to
   `origin/dev`. Never force-push and never leave a completed local-only commit.
5. For `koi-desktop`, commit/rebase/push its own repository too. Record both SHAs.

The session ends only when temporary state is gone, the intended real deployment is
healthy, process counts are exact, repositories are synchronized, and the agent reports
what landed plus the next dependency—not merely what it plans to try.
