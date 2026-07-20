Status: complete
Run ID: 20260719T034411Z
Project: koi
Created: 2026-07-19T03:44:11Z
Verified at (UTC): 2026-07-19
External publication authorized: no

# Channel research

Koi should earn discovery in layers: make the owned evaluation path trustworthy, learn
from a small design-partner cohort, seed install and integration surfaces, and only then
use one public anchor launch. Each public submission or curator contact remains a separate
owner decision. This document records current rules; it does not authorize an action.

## Ranked channel portfolio

| Priority | Channel | Audience and job | Official rules and evidence | Native format | Effort and support | Useful signal | Risk | Owner | Decision |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 0 | Owned website, GitHub repository, and docs | Evaluators, operators, contributors, and security reviewers deciding whether Koi is credible and usable | GitHub recommends a clear README, license, contribution guidance, code of conduct, and security controls; its community profile exposes missing health files: https://docs.github.com/en/repositories/creating-and-managing-repositories/best-practices-for-repositories and https://docs.github.com/en/communities/setting-up-your-project-for-healthy-contributions/about-community-profiles-for-public-repositories | Connect the already-strong https://sylin.org/koi page to GitHub's homepage field, then align its bounded positioning, first command, anti-scope, and pre-1.0 caveats with the README, golden tutorial, release notes, and issue forms | Medium repair effort now; steady issue triage after launch | Clean-install completion, tutorial completion, qualified issues, repeat evaluators, and fewer clarification questions | Recreating or contradicting the current site would fragment the story; promotion before reliability work would amplify known failures | Maintainer and release owner | Use now for connection and alignment, not reinvention. Any product or repository edit still needs separate authorization |
| 0 | crates.io package page for `koi-net` | Rust users looking for the CLI or embeddable crates | Cargo recommends complete license, description, homepage, repository, README, keywords, and categories, plus a package dry run before publication: https://doc.rust-lang.org/cargo/reference/publishing.html | Accurate crate metadata, concise README, docs.rs links, versioned changelog, and install command | Medium one-time metadata audit; release-by-release upkeep | Qualified crate downloads, docs.rs referrals, downstream dependents, and package-specific issues | The package name differs from the binary name, and immutable releases make metadata mistakes durable | Crate owner and release owner | Repair metadata now; publish a crate version only under separate release authorization |
| 1 | Private design-partner cohort of 5-10 people | Homelabbers, self-hosters, LAN developers, and small-team operators with real multi-service networks | Owner-run, opt-in research rather than a public channel; participants must understand the pre-1.0 scope and data requested | Short invitation, clean-install task, golden-demo script, structured interview, and two-week follow-up | High-touch but bounded; reserve support time for every participant | First-success time, install failures, retained use after two weeks, and high-quality bug reports | A cohort that is too friendly or homogeneous can validate the story without validating real networks | Maintainer | Start only after P0 reliability, security, and clean-install gates pass |
| 2 | MCP Registry | MCP client users seeking installable local servers | The registry is in preview and hosts metadata, not artifacts. It supports OCI packages with a matching `io.modelcontextprotocol.server.name` annotation and MCPB artifacts with a release URL containing `mcp` plus `fileSha256`: https://modelcontextprotocol.io/registry/package-types and https://modelcontextprotocol.io/registry/quickstart | Versioned `server.json` plus a tested GHCR OCI package and/or signed MCPB release artifact for stdio transport | Medium-to-high packaging and compatibility work; ongoing release synchronization | Successful clean installs in at least two clients, registry resolution, and MCP-specific retained use | Premature listing creates broken one-click installs; registry preview rules may change | MCP maintainer and release owner | Prepare after Koi supports and tests OCI or MCPB packaging; publish only with separate authorization |
| 2 | WinGet Community Repository | Windows operators who expect a trusted package-manager install and upgrade path | Microsoft requires a manifest PR, automated and possible manual validation, direct safe installer URLs, accurate metadata, silent installation behavior, and clean install/uninstall: https://learn.microsoft.com/en-us/windows/package-manager/package/repository | Portable/ZIP manifest backed by versioned GitHub release assets, checksums, and Sandbox tests | Medium initial manifest work; each release needs an update | Clean user- and machine-scope installs, upgrades, uninstalls, and Windows-originated qualified issues | A manifest can expose archive layout, upgrade, antivirus, or uninstall defects to a broad audience | Windows release owner | Prepare and validate locally after P0; submit only under separate authorization |
| 3 | Show HN | Technically curious builders who can run Koi, question its architecture, and compare it with point tools | Show HN requires something the audience can try, made by the submitter, with the submitter present to discuss it; no vote solicitation. HN also says not to post generated or AI-edited comments: https://news.ycombinator.com/showhn.html and https://news.ycombinator.com/newsguidelines.html | A runnable original project link, a maintainer-written title, a short maintainer-written first comment explaining why and how, and live technical replies | High-intensity launch day; the maintainer must be available for several hours and follow up for days | Successful installs, substantive architectural questions, qualified issues, and design-partner requests rather than points alone | A red CI run, weak demo, promotional tone, or generated replies would waste trust | Maintainer personally | Use as the single anchor launch only after green CI and a reproducible golden demo. The owner must rewrite all submission and comment text in their own voice |
| 4 | selfh.st/apps and Self-Host Weekly | Self-hosters who rely on a trusted curator for useful, maintained projects | selfh.st is an independent publication and its app directory invites project details by contact; activity and repository signals influence directory presentation: https://selfh.st/about/ and https://selfh.st/apps-about/ | A concise factual curator brief with release, install, docs, license, maturity, and repository links | Low outreach effort; medium preparation because facts must be release-current | Earned directory inclusion, newsletter mention, relevant referral traffic, and qualified self-hosting feedback | Contact before readiness looks like asking a curator to absorb Koi's validation work | Maintainer | Approach only after readiness gates. Keep the request unpaid and editorially independent; no sponsorship or quid pro quo |
| 5 | r/selfhosted | Practitioners running Docker/Podman, DNS, reverse proxies, homelabs, and small private networks | Current community moderation requires promoted apps to be self-hostable, released and downloadable, production-ready, documented, described with features and user benefit, and promoted without spam: https://www.reddit.com/r/selfhosted/about/rules/ | Maintainer-affiliated, problem-first post with a real deployment path, screenshots/demo, honest limits, and a specific request for operational feedback | High response load and community expectation of hands-on support | Completed deployments, environment-specific reports, integration questions, and repeat users | Koi currently describes itself as pre-1.0 and not load-bearing, so posting now would conflict with the channel's production-ready rule | Maintainer personally | Defer until the owner can truthfully call the release production-ready and documentation has been tested by the cohort |
| 8 | Awesome-Selfhosted | Operators browsing a durable catalog of free software network services and web applications | Contributions now go to `awesome-selfhosted-data`. The project must be working, maintained, secure, released for more than four months, accurately categorized, and not merely generic deployment automation; machine-generated contributions that ignore guidelines are barred: https://github.com/awesome-selfhosted/awesome-selfhosted-data/blob/master/CONTRIBUTING.md | Guideline-conformant YAML entry or issue, submitted only after category fit is confirmed | Low artifact effort, potentially high review/fit effort | Maintainer acceptance and qualified directory referrals | Koi's network-service role may fit, but its CLI/container-orchestration facets may be directed to Awesome Sysadmin instead | Maintainer | Watch and verify category fit, production maturity, release age, and current criteria before any submission |
| 9 | Homebrew Core | macOS and Linux CLI users who prefer a mainstream package manager | Core requires a stable tagged version, maintainability across supported OS versions, outside use, and notability. GitHub projects need at least 30 forks, 30 watchers, or 75 stars; self-submissions face three times those thresholds: https://docs.brew.sh/Acceptable-Formulae | Source-built formula and bottles maintained through Homebrew review | High policy and maintenance cost relative to current demand | Independent request or submission, successful bottles, and sustained installs | Koi had 0 stars, 0 watchers, and 0 forks on 2026-07-19, far below eligibility: https://github.com/sylin-org/koi | Release owner | Avoid submission now; watch for organic demand and independent eligibility |

## Channel adapters

### Owned website, GitHub, docs, and crates.io

- Preserve the current website's bounded positioning, first command, anti-scope, and
  pre-1.0 caveats. Add `https://sylin.org/koi` to GitHub's currently empty homepage field
  so indexed discovery reaches the canonical evaluation path.
- Make one journey canonical across the site, README, and docs: install a released artifact,
  run `koi mdns discover`, then complete the end-to-end discover -> name -> trust -> serve
  demo.
- Align repository description, topics, README, crate metadata, release notes, docs.rs, and
  screenshots around the same narrow promise. Do not claim that every LAN or trust problem
  is solved.
- Treat a green multi-OS CI run and a clean golden-demo recording from released artifacts
  as launch prerequisites, not substitutes for testing.

### Design partners

- Recruit 5-10 people across Windows, Linux, macOS, Docker Desktop, native Docker/Podman,
  and at least one existing Pi-hole/AdGuard plus reverse-proxy setup.
- Ask each person to start from a clean machine or VM, narrate the install, execute the
  golden journey, remove Koi and its trust root, and return two weeks later.
- Capture first-success time, confusing steps, unexpected network behavior, trust and
  uninstall confidence, retained use, and what existing tool Koi complemented.
- Stop recruitment when repeated failures identify a shared blocker; repair and rerun the
  failed path before inviting more people.

### Show HN

- Link to the runnable project, not a launch essay or signup page. The demo must use a
  released binary and work without an account or external cloud dependency.
- The maintainer must personally author the final title, first comment, and every reply.
  These planning documents are research notes only and must not be pasted or AI-edited
  into HN comments.
- Explain the personal problem, the wiring insight, the tradeoffs, and why Koi complements
  Pi-hole/AdGuard, Tailscale, Caddy/Traefik, Prometheus, and container runtimes.
- Be available to reproduce failures and convert useful reports into issues. Never ask
  design partners, friends, or users to vote or comment.

### r/selfhosted

- Do not post while Koi's own status says pre-1.0 and not load-bearing.
- After the production-ready gate, disclose maintainer affiliation in the first paragraph,
  show the supported deployment path, state exact features and benefits, and include the
  current limitations and support route.
- Write for operators: DNS coexistence, container networking, reverse-proxy integration,
  backup/restore, trust removal, upgrade behavior, and clean uninstall matter more than a
  long capability list.
- Stagger this post after the anchor launch so the maintainer can incorporate real
  questions and has capacity to answer new ones.

### selfh.st

- Send a short, factual brief only after the released install and golden demo are stable.
- Ask for editorial consideration, not guaranteed coverage. Do not purchase sponsorship
  in exchange for inclusion, ranking, or favorable language.
- Give the curator an accurate one-paragraph description, release link, license, supported
  platforms, install path, screenshot/demo, activity signal, and candid maturity note.
- One polite follow-up is the maximum; silence is a valid editorial decision.

### MCP Registry

- Decide whether the supported artifact is OCI, MCPB, or both. The existing general Koi
  image is not automatically a supported MCP package.
- For OCI, test the exact stdio entrypoint in a clean client and add the registry's matching
  ownership annotation. For MCPB, build a reproducible bundle, publish it in a GitHub
  release, and record its SHA-256 in `server.json`.
- Test install, startup, capability discovery, token behavior, shutdown, and upgrade in at
  least two compatible clients before registry publication.
- Re-verify preview documentation on the submission day because schemas and policies may
  change.

### WinGet

- Model Koi as a versioned portable/ZIP package backed directly by immutable GitHub release
  assets; use checksums and accurate architecture metadata.
- Validate the manifest, test it in Windows Sandbox, and test install, `koi version`,
  upgrade, uninstall, PATH cleanup, service cleanup, and trust-root cleanup where relevant.
- Keep manifest preparation separate from submission. A PR to `microsoft/winget-pkgs` is
  an external publication action and needs explicit owner authorization.

### Homebrew Core and Awesome-Selfhosted

- Homebrew Core is a watch item, not a growth tactic. Recheck notability only after organic
  users request the package and the stability criteria are true.
- For Awesome-Selfhosted, first ask whether Koi is accepted as a network service or belongs
  in Awesome Sysadmin. Verify the current data schema and all criteria immediately before
  drafting a human-reviewed contribution.

## Rejected or deferred channels

- **Broad simultaneous launch:** rejected. It would multiply support load before one
  channel teaches the maintainer what users misunderstand.
- **Product Hunt and generic startup directories:** avoid for the first cycle. Their broad
  audience is less aligned than self-hosting, LAN tooling, Rust, and MCP surfaces.
- **Paid placement or sponsored editorial coverage:** rejected as an adoption shortcut.
  Paid distribution must never buy product influence, ranking, or favorable coverage.
- **Homebrew Core now:** avoid because published eligibility and independent-use signals
  are not met.
- **r/selfhosted now:** deferred because the project currently disclaims production use.
- **MCP Registry now:** deferred until the listed package is a deliberately supported,
  clean-installable OCI and/or MCPB artifact rather than merely a general release binary.

## Facts, inferences, and hypotheses

### Facts verified on 2026-07-19

- Show HN requires a runnable project and the maker's presence; HN prohibits generated or
  AI-edited comments.
- r/selfhosted's current promotion rule requires a released, downloadable,
  production-ready, documented, self-hostable application with a useful description.
- The MCP Registry is in preview and supports OCI and MCPB with package-specific ownership
  and integrity metadata.
- WinGet submissions are public manifest PRs subject to automated and possible manual
  installation, safety, URL, and policy validation.
- Homebrew Core's published notability thresholds are not met by Koi's current public
  repository metrics.
- Awesome-Selfhosted currently accepts data contributions through
  `awesome-selfhosted-data` and applies maturity, maintenance, security, category, and
  release-age criteria.
- selfh.st describes itself as an independent publication and invites project details for
  its directory and newsletter consideration.
- `https://sylin.org/koi` is the indexed owned landing page with bounded positioning and a
  first command, while GitHub's homepage metadata was empty at verification time.

### Inferences

- Koi's strongest niche is not another mDNS, DNS, CA, proxy, or container tool in
  isolation. It is the local-network wiring layer that lets those existing tools keep
  their jobs while sharing discovery, names, trust, and service state.
- A small cross-platform design cohort will produce more decision-quality evidence than a
  large launch while Koi remains pre-1.0.
- Show HN is the best eventual anchor because the architecture is technically interesting
  and directly runnable, but only after the released golden path is boringly reliable.
- selfh.st and r/selfhosted are better follow-on surfaces because they will judge Koi by
  operational fit, documentation, and maintainer behavior rather than novelty alone.

### Hypotheses to test

- The phrase "discover -> name -> trust -> serve" helps users understand the category
  faster than a feature list.
- First-class Windows support and offline operation differentiate Koi for mixed homelabs.
- Existing Pi-hole/AdGuard, Tailscale, Caddy/Traefik, Prometheus, Docker/Podman, and MCP
  users will value Koi more as a complement than as a replacement.
- Registry and package-manager installs will improve retained use only after the same
  uninstall, trust-removal, and upgrade confidence is demonstrated in the cohort.
