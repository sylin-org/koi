# L01 documentation evidence

Task: [L01 in Epic 004](../../fleet/epics/004-container-lan-adoption.md#l01--one-current-product-and-contributor-story).
Owner: coordinating documentation agent, under the maintainer's explicit rewrite instruction.
Date: 2026-09-12.
Source baseline: `791f87ebe0a8ba93246f60ce0b283c13fb86595b` plus the current, uncommitted documentation change.
Verdict: accepted for L01.

Positioning scope: give Certmesh a visible private-space identity and trust
pillar under the maintainer's follow-up instruction. The coordinating agent
owns README, overview/navigation, user/Certmesh guide introductions and current
launch messaging; the site agent owns `site/index.html` and `site/README.md`.
The source baseline and existing uncommitted work are retained. The positioning
refinement verifies current links, the public-document consumer-name guard,
HTML structure and links, and the new site section at desktop and 390px width.
Its final integration check refreshes the current documentation bundle.

## Change boundary

The rewrite covers public entry points and site copy, all current guides and
tutorials, architecture/protocol/security references, crate and SDK documentation,
packaging guidance, contributor/agent instructions and fleet routing. Obsolete
execution plans and journals are removed; only small navigation stubs remain at
paths needed by preserved evidence.

[ADR-046](../adr/046-container-lan-adoption.md) records the adopted focus.
[Epic 004](../../fleet/epics/004-container-lan-adoption.md),
[readiness](README.md) and [the ledger](../../fleet/launch/LEDGER.md) own scope,
artifact facts and progress respectively. The research index is current navigation;
existing ADR and research records retain their original contents.

The tooling boundary is [the generator](../../scripts/AiDocDist.ps1) and its
[focused regression test](../../scripts/ai-doc-dist.test.mjs).
The ACME module's documentation comment also replaces a removed plan link and
corrects the claim that external clients need no Koi-specific setup.
The default bundle leads with current docs and launch contracts; complete ADR
and research corpora are separately opt-in. The release template retains the
release workflow's substitution contract and uses explicit artifact versions.

## Verification

- Links checked across 150 current Markdown documents and 83 preserved records; no
  unresolved current-document links or anchors.
- Current prose scanned for obsolete task sequencing and unsupported product or
  installation claims. Command examples checked against the CLI/HTTP source.
- `scripts/lint-surfaces.sh`: passes with 21 surface rows.
- `scripts/check-doc-leaks.sh`: passes the public-document consumer-name guard.
- Release version, manifest and candidate-validation Node suites: 12 tests pass.
- Release-template synthetic expansion: all four workflow placeholders preserved;
  version selection and the PowerShell environment-variable syntax remain valid.
- Repository exploration skill passes the skill-creator validator.
- Local site inspected at the default desktop viewport and 390px width; content
  and release cards remain readable, with the sample command scrolling inside its card.
- Generated bundle navigation and corpus selection: default (23 files), research
  (27 files) and ADR (24 files) real-corpus runs pass local file/anchor validation.
  The research and ADR runs separately report the preserved exceptions below.
- `node --test scripts/ai-doc-dist.test.mjs`: two tests pass, covering all four
  corpus-flag combinations, relative paths, real/duplicate/custom heading anchors,
  directory links and code examples. Deliberately corrupted outputs are rejected.
- `git diff --check`: passes. The accepted receipt/ledger and default bundle receive
  a final link, surface and generation check at integration.

## Preserved-record exceptions

Three existing code links point to files already absent from the baseline:

- [ADR-015](../adr/015-certmesh-enrollment-hardening.md) references
  `crates/koi-certmesh/src/pond_ceremony.rs`.
- [The netdev dependency study](../assessment/netdev-dependency-study.md) references
  `crates/koi/src/adapters/http.rs` and `crates/koi-embedded/src/http.rs`.

These are dated source-location references in protected evidence. They are not
current instructions, and this rewrite does not alter those records or fabricate
replacement source files. Existing links from preserved evidence into current
documentation retain working navigation anchors.

## Claim limit

This receipt accepts documentation only. Runtime behavior, installed-platform
acceptance, public artifacts and independent-user outcomes require the subsequent
epic tasks and their own receipts. Their status remains in the launch ledger.
