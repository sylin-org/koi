Status: complete
Run ID: 20260719T034411Z
Project: koi
Created: 2026-07-19T03:44:11Z

# Measurement plan

## Decisions this measurement should support

This plan is designed to answer four questions without adding product telemetry: whether Koi's local-service identity promise attracts the right operators, whether they can reach first value on real networks, which ecosystem contracts matter first, and whether maintainer support capacity can sustain a wider launch. Download and traffic counts are discovery signals, not proof of installation, successful use, or retention.

The next decision gate is a five-to-ten-operator evidence cohort. Broad promotion should follow only when the P0 readiness gate is green and at least three independent operators complete the golden path.

## Baseline

Collected from public GitHub and crates.io surfaces on 2026-07-19 UTC:

- GitHub: 0 stars, 0 forks, 0 subscribers, 0 open issues, and 11 open pull requests. Zero issues means there is no public feedback baseline; it does not mean zero defects.
- GitHub traffic for the available 14-day window: 10 views from 10 unique visitors and 64 clones from 23 unique cloners. Automation and CI can inflate clone counts.
- GitHub Releases: 19 visible releases and 162 aggregate asset downloads; v0.9.0 has 6 asset downloads. Checksum downloads and binary downloads are separate events, so neither total is an install count.
- crates.io `koi-net`: 181 all-time downloads, 152 recent downloads, and 18 downloads attributed to v0.9.0. Registry mirrors and CI may inflate these counts.
- Latest public release: v0.9.0, published 2026-06-25. The public main CI run and three consecutive scheduled QA runs are red, so current traffic should not be amplified.
- Product activation, cross-device success, time-to-value, retained deployments, uninstall reasons, and support minutes are not yet measured.

Sources: [GitHub repository API](https://api.github.com/repos/sylin-org/koi), [GitHub releases API](https://api.github.com/repos/sylin-org/koi/releases), [crates.io crate API](https://crates.io/api/v1/crates/koi-net). GitHub traffic is maintainer-only data and should be recorded as an aggregate snapshot, never as visitor-level data.

## Funnel signals

| Stage | Signal | Source | Baseline | Review window | Decision threshold | Privacy note |
| --- | --- | --- | --- | --- | --- | --- |
| Discover | Qualified visits to README, docs, release, or crate page | GitHub traffic and crates.io downloads | 10 unique GitHub viewers; 152 recent crate downloads | Weekly, four-week rolling | Directional growth plus at least 5 explicit problem-fit responses | Aggregate counts only; do not identify visitors |
| Evaluate | Operators who can restate the job and choose Koi over a DIY stack for a real LAN | Opt-in cohort intake and issue/discussion template | No baseline | Per cohort | At least 5 qualified operators from at least 2 primary personas | Ask only for network shape and desired outcome, not hostnames, IPs, or certificates |
| Activate | Verified install and daemon health on a supported OS | Consent-based checklist or support issue | No baseline | First session | At least 4 of 5 cohort members activate without maintainer shell access | Store pass/fail and OS class; redact machine and network identifiers |
| First value | A service becomes reachable as `https://name.internal` from a second device without a certificate warning | Golden-path evidence card completed by operator | No baseline | Within 30 minutes of activation | At least 3 independent completions; median under 15 minutes after installation | Operator reports outcome and elapsed time; no browsing telemetry |
| Collaborate | One tested partner workflow works with a declared ownership boundary | Versioned integration matrix and CI | Format-level evidence only for several partners | Every readiness release | Green real-container tests for each advertised "works with" claim | Use synthetic service names and isolated test networks |
| Retain | Deployment still active and useful | Opt-in 14- and 30-day follow-up | No baseline | Day 14 and day 30 | At least 2 of the first 3 successful operators still use it at day 30 | One short consent-based survey; no background reporting |
| Contribute | High-signal bug report, documentation fix, adapter test, or repeatable recipe | GitHub issues and pull requests | 0 open issues; 11 open PRs | Monthly | At least 3 external evidence contributions before broad launch | Public contribution is optional; provide a private reporting path |

## Adoption activity ledger

Use one row per deliberately shared artifact or community activity. Record exposure before interpreting results; the purpose is to improve usefulness, documentation, and stewardship, not to measure revenue conversion.

| Activity | Artifact/version | Audience | Start/end UTC | Reach | Qualified responses | Activations | First-value successes | Support minutes | Decision |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Baseline audit | Run `20260719T034411Z` | Maintainer | 2026-07-19 | 10 unique GitHub viewers in prior traffic window | No measured responses | No measured activations | No measured successes | Not measured | Repair before amplification |
| Design-partner cohort | Golden-path evidence kit, version chosen after P0 gate | 5-10 trusted-LAN operators | Owner schedules after green gate | Record invitations and accepts | Record problem-fit responses | Record checklist completions | Record second-device HTTPS outcomes | Record manually | Continue, adapt, or pause after cohort review |
| Public channel trial | Owner-rewritten channel-specific artifact | One selected community | Only after cohort proof and explicit authorization | Record impressions if supplied by channel | Record substantive replies and docs clicks | Record opt-in activations | Record opt-in outcomes | Record manually | Expand only if support and signal remain healthy |

## Continue, adapt, pause, and stop rules

- Continue the cohort when at least 60% of qualified participants activate, at least three independent operators reach the golden outcome, and median support stays below 30 minutes per successful activation.
- Adapt onboarding when evaluation is strong but fewer than 60% activate, or when the same obstacle appears twice. Repair the obstacle and rerun the same cohort size before increasing reach.
- Adapt positioning when visits rise but fewer than one in five qualified respondents recognize the trusted-LAN discovery/naming/HTTPS job.
- Pause promotion immediately for a security advisory affecting the shipped lockfile, red release gates, data-loss/trust-store incidents, unexplained certificate behavior, or support demand above the owner's declared capacity.
- Stop a channel after two measured trials produce no qualified operators, or when its rules/audience require claims Koi cannot substantiate. Do not chase raw stars, downloads, or comments.
- Expand to one new channel at a time only after the preceding activity has a recorded artifact, exposure, outcomes, and follow-up decision.

## Review cadence and owner

The maintainer owns the ledger and reviews readiness weekly while P0 work is active, each cohort at its end, and public channel experiments after 72 hours and again after 30 days. A release review should record CI state, advisory status, golden-path pass rate, integration-contract versions, support load, and any claim changes. No product telemetry is required; all user evidence should be opt-in, minimal, and redacted.
