# Service implementation contract

The [current implementation and evidence contract](../../../fleet/CONTRACT.md)
defines module ownership, identity, freshness, authority and readiness.
[ADR-044](../../adr/044-service-experience-ownership.md) records the architectural
decision. Current work and acceptance are defined by
[Epic 004](../../../fleet/epics/004-container-lan-adoption.md) and
[the launch ledger](../../../fleet/launch/LEDGER.md).

Epic 003 contract text through 2026-09-07, including the R07 Home and R08
comparison sections, is preserved at
`git show cd0926f:docs/prompts/delight/CONTRACT.md`. Its rules that still apply
(catalog `discovery`/`local_device_id`, the comparison reader bounds) now live in
the [current contract](../../../fleet/CONTRACT.md).
