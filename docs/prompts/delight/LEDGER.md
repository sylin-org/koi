# Launch ledger

The single current task and evidence authority is
[the launch ledger](../../../fleet/launch/LEDGER.md), under
[Epic 004](../../../fleet/epics/004-container-lan-adoption.md).
Read [launch readiness](../../launch/README.md) for current artifact and
compatibility claims.

## Retired Epic 003 status (history)

- 2026-09-06 — R06 and R06/shared-shell accepted after desktop d948015
  Windows/Alpine Home-return retries (commit 06eb206).
- 2026-09-07 — R07 Home launchpad accepted on Koi 34e0d8c / desktop be834e8, all
  14 product CI jobs passing (run 34077834757); browser access removed and its ADR
  parked ([record](../../adr/046-browser-invitations-and-sessions.md)). See
  [reports/R07.md](reports/R07.md).
- 2026-09-07 — R08 Devices and comparison implemented / linux-ready on Koi
  e3b1157 / desktop 062b0b5 (CI 34087132808); Windows WebView2 cases and the
  two-peer proof were never run. See [reports/R08.md](reports/R08.md).
- 2026-09-12 — Epic 003 retired by ADR-046; its queued rows (R09–R19, R21–R27,
  R29, R30) never started. R20 and R28 had already been accepted.
- 2026-09-13 — ADR-047 superseded the Home and Devices presentation; the
  2026-11-05 merge re-expressed their retained behaviour in Services.

The full prior ledger is at `git show cd0926f:docs/prompts/delight/LEDGER.md`.
