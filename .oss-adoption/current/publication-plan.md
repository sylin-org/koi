Status: complete
Run ID: 20260719T034411Z
Project: koi
Created: 2026-07-19T03:44:11Z
External publication authorized: no

# Publication and adoption plan

## Strategy and sequencing rationale

Koi should be polished before it is promoted. Its credible market position is a
cross-platform, offline LAN substrate that connects discovery, naming, private trust, TLS,
health, and container lifecycle while complementing the tools operators already use. The
adoption sequence therefore optimizes for trustworthy first success and retained use, not
simultaneous attention.

The order is strict: repair reliability and truthfulness, prove one released golden path,
learn with 5-10 design partners, package the supported integration surfaces, use one anchor
launch, then adapt for operator communities and earned curation. Crossing any external
boundary - inviting a person, contacting a curator, opening a registry PR, or posting -
requires separate owner authorization at that time.

## Phase 0: repair readiness blockers

No outreach begins in this phase. Close or explicitly scope the highest-risk reliability,
security, data-root, startup reconciliation, reconnect, lifecycle, and documentation gaps.
Run the complete multi-OS CI and release checks from a clean commit. Prove the released
artifact, not a developer build, through a recorded golden journey and clean uninstall on
Windows, Linux, and macOS. The public status language must match the tested maturity.

## Phase 1: validate with a small cohort

Invite 5-10 opt-in design partners only after Phase 0 passes. Include mixed operating
systems, native and desktop container runtimes, an existing DNS sinkhole, a reverse proxy,
and at least one small-team LAN. Observe installation and the golden journey, then check
retained use two weeks later. Pause recruitment whenever a repeated defect appears.

## Phase 2: seed ecosystem surfaces

Connect the already-indexed `https://sylin.org/koi` landing page to GitHub's currently
empty homepage metadata, then align the site, repository, docs, and crates.io metadata
without rewriting the site's effective bounded positioning. Prepare and test WinGet
metadata without submitting it. Build a deliberately supported MCP OCI and/or MCPB artifact
and test it in two clients before considering registry publication. Keep Homebrew Core and
Awesome-Selfhosted as criteria watches, not launch tasks.

## Phase 3: anchor launch

Use Show HN as the single anchor only when CI is green on the release commit, the golden
demo works from immutable release assets, support capacity is reserved, and no security or
data-loss blocker is open. The maintainer must write the title, first comment, and replies
personally in their own voice; the generated planning pack is briefing material only.

## Phase 4: adapt for high-fit communities

Incorporate real questions from the cohort and anchor launch. Approach r/selfhosted only
after Koi can truthfully satisfy that community's production-ready and documentation
requirements. Do not copy the anchor message; focus on deployment, coexistence, backup,
upgrade, trust removal, and operational tradeoffs.

## Phase 5: enable earned discovery

After readiness is visible, offer selfh.st a concise, unpaid factual brief for independent
editorial consideration. Consider Awesome-Selfhosted only after maintainers confirm Koi's
category fit and all current criteria. Let independent package requests and actual usage,
not a growth target, determine whether Homebrew Core becomes appropriate.

## Phase 6: maintain and learn

Review first-success, retained use, issue quality, support load, integration use, and
uninstall confidence every two weeks during the first two months, then monthly. Keep release
notes, package metadata, demo evidence, security guidance, and compatibility claims in sync.
Stop acquisition whenever support debt threatens response quality or reliability.

| Activity | Purpose | Audience | Artifact | Owner | Prerequisite | Success signal | Stop condition | Follow-up |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Close P0 reliability and lifecycle gaps | Prevent known defects from becoming other people's outages | Current evaluators and future operators | Prioritized repair issues, regression tests, and explicit deferrals with safe documentation | Maintainer | Confirmed readiness audit and risk ranking | Every launch-blocking issue is fixed or removed from the promised surface; regression tests cover each fix | Any unresolved security, data-loss, startup-state, trust, or uninstall blocker | Re-run the readiness audit and update safe claims |
| Prove multi-OS release CI | Make the release commit and artifacts credible | Operators, package curators, and contributors | Green required checks, checksums, provenance, and a release-candidate evidence record | Release owner | P0 fixes merged into a clean release commit | All required Windows, Linux, macOS, integration, security, packaging, and provenance checks pass | Any required check is red, skipped without rationale, or passes only on a developer machine | Fix the failure and restart the release candidate from the clean commit |
| Record the golden demo and clean uninstall | Demonstrate the headline outcome from artifacts users actually receive | First-time homelabbers and LAN developers | Reproducible discover -> name -> trust -> serve script, recording, expected results, and cleanup verification | Maintainer plus one independent tester | Green release CI and immutable candidate artifacts | Three clean environments reach the expected result and remove service, state, and trust material as documented | More than one undocumented manual intervention or any residue that weakens host trust | Repair the journey, rerun all environments, and promote the evidence into docs |
| Connect and align owned discovery surfaces | Preserve effective positioning while making the indexed site easy to reach and every source truthful | Website and repository visitors, Rust users, security reviewers, and contributors | GitHub homepage link to `https://sylin.org/koi`; aligned site, README, quickstart, status, security, support, crate metadata, screenshots, topics, and release notes | Maintainer and docs owner | Golden path and safe claims verified | Three outside evaluators choose the right install path without clarification and no surface contradicts maturity or security scope | Any copy outruns evidence, duplicates the site unnecessarily, or creates recurring misunderstanding | Correct the canonical source and propagate only the necessary alignment changes |
| Run the 5-10 person design-partner cohort | Test real network diversity before public attention | Selected self-hosters, LAN developers, and small-team operators | Consent-aware invitation, task script, interview guide, issue rubric, and two-week check-in | Maintainer | Phase 0 complete and support time reserved for every participant | At least five participants finish the journey, at least three still use Koi after two weeks, and all severe defects are triaged | A repeated blocker affects two participants, severe trust concern appears, or support capacity is exceeded | Pause invitations, repair, rerun affected tasks, and summarize evidence without private details |
| Convert cohort learning into the release | Improve product truth and reduce repeated support | Future public users | Ranked friction log, fixed defects, docs updates, safe claim revisions, and decision record | Maintainer | Cohort evidence available | Top repeated failures are fixed or explicitly excluded; second-pass participants complete faster with fewer interventions | Changes invalidate the release candidate or reveal a new launch blocker | Cut a new candidate, rerun CI and golden demo, then recheck launch gates |
| Prepare supported MCP packaging | Turn the existing MCP capability into a reliable install surface | MCP client users and registry consumers | Tested OCI image with registry annotation and/or reproducible MCPB, `server.json`, hashes, and client matrix | MCP maintainer and release owner | Stable stdio behavior, versioned artifacts, token guidance, and clean shutdown | Clean install, discovery, operation, upgrade, and removal pass in at least two compatible clients | Registry schema drift, broken install, unclear auth, or package behavior differs from Koi docs | Repair packaging, revalidate official rules, and request owner approval before registry publication |
| Prepare WinGet manifest | Give Windows users a native, reviewable install path | Windows homelab and small-team operators | Versioned portable/ZIP manifest, direct release URLs, checksums, and Sandbox evidence | Windows release owner | Stable Windows release archive, upgrade behavior, and uninstall behavior | `winget validate`, Sandbox install, user/machine install, upgrade, uninstall, and PATH checks pass | Antivirus, URL, hash, install, upgrade, uninstall, or cleanup validation fails | Fix the artifact or manifest, rerun tests, and request owner approval before a manifest PR |
| Conduct the Show HN anchor launch | Reach technically capable evaluators with a runnable project and invite deep feedback | HN builders interested in networking, systems, Rust, security, containers, and local-first tools | Maintainer-authored submission and first comment linked to the released golden path | Maintainer personally | Green release CI, public golden demo, current limitations, support capacity, and explicit posting authorization | Qualified installs, substantive technical discussion, useful issues, and design-partner requests | Any launch gate regresses, maintainer cannot be present, or replies would be generated/AI-edited | Answer personally, reproduce failures, file issues, and summarize questions for later channel adapters |
| Offer selfh.st an unpaid curator brief | Earn trusted discovery among self-hosters without buying influence | selfh.st editor and directory/newsletter readers | Release-current factual brief with install, docs, license, activity, demo, and maturity links | Maintainer | Readiness visible, golden path public, and explicit contact authorization | Independent listing, editorial mention, or useful curator feedback | Facts are stale, readiness regresses, or the contact would imply payment for treatment | Correct facts; send at most one polite follow-up; respect no response |
| Publish a production-ready r/selfhosted post | Validate operational fit with the most relevant practitioner community | Self-hosters running containers, DNS, reverse proxies, and mixed LANs | Maintainer-affiliated, problem-first post with demo, deployment guidance, benefits, limits, and feedback request | Maintainer personally | Owner has truthfully declared production readiness; docs and support capacity meet current rules; explicit posting authorization | Real deployments, integration-specific questions, retained users, and reproducible reports | Koi remains pre-1.0/not load-bearing, the post cannot meet current rules, or support debt exceeds capacity | Reply personally, convert defects to issues, publish corrections, and review retention after two weeks |
| Verify Awesome-Selfhosted fit | Avoid a low-fit or rules-violating catalog submission | Awesome-Selfhosted maintainers and directory users | Human-reviewed eligibility checklist and category-fit decision | Maintainer | Production maturity, first release older than four months, active maintenance, secure operation, and current guidelines reviewed | Maintainer guidance confirms category fit and a compliant contribution is accepted | Koi is judged generic deployment automation, lacks maturity, or current rules change | Watch Awesome Sysadmin or another better-fit catalog; do not resubmit without changed evidence |
| Watch Homebrew Core eligibility | Let organic demand determine whether Core maintenance is justified | macOS/Linux package users and Homebrew maintainers | Quarterly notability, outside-use, stability, and supported-OS evidence check | Release owner | Independent users request a formula and published thresholds are met | Outside submission/request plus stable builds and sufficient notability | Metrics remain below policy, project is still unstable, or formula maintenance exceeds capacity | Continue official release/install script support and recheck no more than quarterly |
| Operate the learning and support loop | Help interested people become successful long-term users without exhausting the maintainer | Users, contributors, and integration partners | Biweekly dashboard, issue triage cadence, release notes, adoption activity ledger, and stop/go review | Maintainer | Any external adoption activity has begun | First-success rises, retained use and issue quality improve, response expectations remain sustainable | Severe defect, untriaged support backlog older than seven days, or repeated poor-fit installs | Pause outreach, publish factual corrections where authorized, repair, and resume only after capacity recovers |

## Decisions requiring owner approval

- Define the exact production-ready release gate and whether it is tied to 1.0 or an earlier
  evidence-backed release.
- Assign the release owner, Windows packaging owner, MCP packaging owner, docs owner, and
  weekly support capacity.
- Select and personally invite each design partner; participation and private feedback are
  not implied by this plan.
- Choose OCI, MCPB, or both as the supported MCP distribution contract.
- Approve each external action separately: design-partner outreach, MCP Registry publish,
  WinGet PR, Show HN submission, selfh.st contact, r/selfhosted post, or catalog PR.
- The maintainer must personally author final Show HN submission/comment text and all HN
  replies. Generated or AI-edited comment text is not allowed by HN's current guidelines.
- Confirm that support capacity is sufficient before choosing an anchor date. If it is not,
  extend the private cohort rather than compressing the phases.
- External publication remains unauthorized. Nothing in this plan changes product files,
  contacts a person, submits a package, opens a PR, or publishes a post.
