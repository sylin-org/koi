# Issue 001 — SCM can wedge a service object against all starts after a failed replacement cycle; config restoration cannot repair it

**Opened:** 2026-09-02 (PH-001, brief assignment 2 exercise)
**Status:** open — recovery fallback armed against the observed signature; mechanism not reproducible on demand
**Machine:** stone-leaded-sparkle
**Updated:** 2026-09-02 (repro matrix + hardened recovery, see below)

## Observed

During the transactional-installer rollback exercise (broken daemon staged, health
gate failed, rollback restored the prior binary byte-exact), the final
`StartService` — and every later start of the `koi` service — failed with
`ERROR_ACCESS_DENIED` from the SCM itself (event 7000, "failed to start due to the
following error: Access is denied"), twice per second while a 10 s bounded retry
loop ran, and again from every manual elevated `sc start koi`.

At the same time, everything the denial could plausibly blame was verified healthy:

- the service binary ran interactively (`koi version` exited 0),
- `icacls` on `C:\Program Files\Koi` and `koi.exe` showed inherited
  SYSTEM/Administrators full control,
- `sc sdshow koi` showed the textbook default service DACL (SY/BA carry
  `RPWP` = start/stop),
- the registry key values were sane (ImagePath correctly quoted, ObjectName
  LocalSystem, Start=2, Type=16) and the key ACL was normal,
- no koi.exe processes remained, no Defender detections, no ASR rules.

**Discriminating fact:** a throwaway service created with the identical binary at
the identical path (`sc create koitest binPath= C:\Program Files\Koi\koi.exe`)
started and ran (PID observed RUNNING). Only the `koi` service *object* was
denied; the binary, path, and SCM were fine.

## Remedy (proven)

Back up the key (`reg export HKLM\SYSTEM\CurrentControlSet\Services\koi`), then
`sc delete koi`, then `koi install` — the fresh service object started and passed
the installer's health gate immediately. Final state after remedy: RUNNING,
standard ports, product-path binary, peer-resolvable self-publication.

## When it formed

Broken install run #2 (retry-loop build): prior service stopped cleanly,
`ChangeServiceConfig` + staging succeeded, and the *first* start after that was
already denied (no crash-loop events for that run — the broken binary never
launched). An earlier broken run whose binary did launch produced the same
denial at its rollback restart. A good-binary install between the two runs
started fine. The precise trigger (queued SCM recovery vs ChangeServiceConfig vs
rapid stop/start cycling vs something else) is **not** isolated; a controlled
repro is required before any automatic delete+recreate is trusted.

## Product gap

`restore_manifest` restores configuration faithfully but cannot repair a wedged
service object; it currently reports "rollback is incomplete — re-run
`koi install`". That instruction happens to work only because a *fresh* install
path recreates the object when recovery finds it missing — but the wedge leaves
the object present, so `koi install` alone would not have recreated it; the
operator had to delete it manually first. Candidate designs (need the repro):

1. Recovery path: when a restored service persistently refuses to start with
   access-denied, delete + recreate the service object (registry-backed config
   first) as an explicit, logged last-resort step.
2. Diagnose the wedge mechanism and avoid triggering it (likely in the
   stop → change_config → start sequencing).

## Evidence

- `.tmp/ph001-broken-install.log`, `.tmp/ph001-empirical.log`,
  `.tmp/ph001-recreate.log`, `.tmp/ph001-sdshow.log`, `.tmp/koi-service-key-backup.reg`
  (session-local, hashes in the 2026-09-02 (2) journal entry)
- System event log: SCM 7000 storm 12:43:46–12:46:50, crash-loop 7031/7034 at
  12:39:43–12:39:58 from the first broken run.

## Reproduction matrix (2026-09-02, controlled, raw SCM operations — no installer in the loop)

Six experiments against the live service, each with waited stops and event-log capture
(`.tmp/ph001-wedge-repro.log`, `.tmp/ph001-wedge2.log`, `.tmp/ph001-wedge3.log`):

| # | sequence | outcome |
|---|---|---|
| E1 | stop; start (raced stop) | start rc 1056 (already running) — validated the installer's `start_with_retry` tolerance; no wedge |
| E2 | waited stop; start | RUNNING |
| E3 | waited stop; broken bytes (`Copy-Item`); start; crash loop to exhaustion (7031×2+7034×3 in log); good bytes; start | RUNNING — **no wedge** |
| E4 | waited stop; broken bytes; start; good bytes swapped during the 5 s restart delay; start | RUNNING — no wedge |
| E5 | waited stop; broken bytes via **rename-replace** (`Move-Item -Force`, the installer's `MoveFileEx` shape); start | launched, crashed normally (7034) — no wedge |
| E6 | waited stop; `sc failure` actions set; rename-replace good bytes; start | RUNNING — no wedge |

**Verdict: not reproducible on demand.** Every staged variable (copy vs rename-replace
staging, crash exhaustion, mid-restart-delay swap, failure-action state, repeated
stop/start) was exercised without forming the wedge. The original incident remains a
transient SCM-internal failure (first launch denial of a just-replaced binary at
12:43:46) that was sticky for that one service object until deletion.

## Recovery fallback (armed 2026-09-02)

`koi install`'s restore path now handles the signature rather than a mechanism theory:
when a fully restored registration (byte-verified snapshots, complete semantic
descriptor) persistently refuses to start with raw `ERROR_ACCESS_DENIED` — the observed
wedge signature, and the state under which a fresh service object ran the same binary
during the original incident — recovery deletes and recreates the service object from
the manifest descriptor, then requires the same start + health gate. A partial
descriptor never backs a delete. The manifest and backups are retained until the
restored start, identity, and health all pass, so an incomplete restoration is
retried by the next `koi install` instead of being orphaned.

The destructive failed-candidate transaction re-run after this hardening rolls back
cleanly (byte-exact restore, restart, healthz, then commit) without touching the
fallback — see journal 2026-09-02 (4).
