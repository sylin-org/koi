# Koi: delight mandates and proposed product experience

Date: 2026-09-04. Follow-up to the [1.0 assessment](2026-09-delight-and-1.0-assessment.md), incorporating the user's explicit mandates and seven supplied desktop screenshots.

**Status:** The mandates below are user requirements. The user explicitly welcomes break-and-rebuild proposals that reshape Koi's surface, while retaining the Sylin visual language, Rust foundation, mascot card, and the four top-menu destinations specified below. Packaging, old workflows, terminology, and interface boundaries remain open to replacement; the earlier assessment's preference for incremental surface changes is not a constraint on this design work. Interaction details and acceptance targets remain recommendations, not implemented behavior or final design approval. Any rebuilt candidate will need its own acceptance evidence.

**User mandates to preserve**

- Installation must end in a working product, with sane defaults and immediate value.
- Installing on a second machine must establish mDNS participation automatically, reusing existing support where appropriate.
- Processes must be as delightful as installation: common tasks should complete with very little assembly by the user.
- The experience must use simple terms and concepts, with advanced detail available when needed.
- Overlapping UIs must give way to clear answers to users' questions and clear ways to complete their tasks.
- Finding and opening local HTTP services is a major product outcome. The network view should serve as a launchpad even when the user cannot remember a service's name.
- An opted-in container should appear automatically when its application becomes available, connecting discovery to the trusted-service journey.
- Break-and-rebuild is acceptable when it produces the right experience. Proposals may reshape Koi's surface rather than preserving the current screens and workflows.
- Stay on Rust for portability. The shared service model, lifecycle operations, and platform integration remain Rust responsibilities; evaluate shared Rust-authored views as the UI direction.
- Preserve the small trading-card mascot as a sylin.org signature. Retain the existing Koi artwork and recognizable collectible-card anatomy.
- Retain the original Sylin/Ghostlight visual language and layout conventions: dark appearance, a status band, and horizontal top-menu module buttons named **Home**, **Devices**, **Settings**, and **About**. About presents the full mascot card alongside product information. This supersedes the earlier side-rail, three-destination, and light/dark mockup proposals.

**Product direction**

Make Koi the place people go to find and use their local services. Each additional capability should improve that experience: names make services recognizable, discovery keeps them current, certificates enable trusted connections, health explains trouble, and events explain meaningful change.

The first screen should answer “What can I use?” The selected service should answer “How do I open it, and is there anything I need to do?” Technical inspection should answer “What exactly is happening?”

The screenshots require a sharper judgment than the initial source-based desktop review. Glance has useful structural ideas, but its displayed content is still a stream of repeated resolutions and opaque device identifiers. The existence of grouping and a “since you last looked” section does not establish a useful summary.

**Structural changes now worth proposing**

The product model should be simple: devices host services; services offer ways to connect; connections have observable conditions and sometimes need setup. This model can guide both human and programmatic interfaces without making every user learn Koi's implementation domains.

1. **Replace the separate human frontends with one application experience.** The desktop workbench and built-in web UI should converge on a common frontend and presentation contract. The desktop adds native installation and OS integration; local web serves headless installations; phone sharing exposes the permitted subset. Retire superseded screens as complete journeys replace them. Determine the build/repository arrangement during implementation exploration; a framework migration is not itself a product outcome.

2. **Make a shared service catalog the basis of presentation.** Screens currently organize different projections of observations. Define an explicit service view with stable identity where evidence supports it, friendly naming, host relationship, endpoints, discovery provenance, freshness, meaningful condition, and available actions. Keep user favorites and aliases attached to stable identities through restart and rediscovery. Preserve ambiguous correlations as ambiguous. Build this projection in the composition/presentation boundary over domain-owned state, rather than duplicating discovery and trust rules in each client or adding a second lifecycle owner.

3. **Make installation own the working configuration.** The recommended desktop distribution should provide the service and the application together, with compatible versions and one update path. The recommended headless distribution should establish equivalent background participation and a usable local control entry point. Detect platform capabilities and make the initial configuration automatically. Keep specialized deployment choices accessible to people who need them. Runtime connectivity and discovery provider failures should be actionable installation states rather than surprises in an otherwise empty dashboard.

4. **Expose user tasks directly through the CLI and API.** Proposed command shapes such as `koi services`, `koi open notes`, and `koi diagnose <url>` should correspond to actual useful tasks. These are design examples, not current command documentation. The UI, CLI, and MCP should consume consistent service identities and state explanations; their permitted actions still differ by caller and transport. Keep domain operations available for precise automation and inspection. Introduce versioned contracts where necessary instead of making every client independently reconstruct the service model.

5. **Treat making a service usable as an owned operation.** Guided secure access spans naming, issuance, trust, and routing. Give it observable progress, explicit prerequisites, retry/recovery behavior, and ownership of resources it creates. Compose existing domain commands on the backend so closing a window does not strand the process. Let users inspect and manage the resulting domain resources through the established interfaces. The initial experience may guide manual client steps while still accurately tracking what has and has not been verified.

6. **Give diagnostics an intentionally separate level of detail.** Preserve raw discovery, DNS editing, comparisons, certificate inspection, and event streams in clearly labeled advanced views. Build the everyday summary from meaningful state transitions: an application became usable, a favorite stopped responding, a device returned, or a connection needs attention. Repeated protocol activity remains available as evidence. Replace ambiguous global reassurance with specific, scoped observations and freshness.

The break can include routes, command names, information architecture, packaging boundaries, and public contracts where the benefit justifies migration. Each deliberate incompatibility should be named in the release changes. Preserve or explicitly migrate user settings, favorites, certificates, keys, and trust relationships; replacing an interface does not imply discarding durable user state. Existing cryptographic identities and frozen protocol constants have a different consequence from moving a tab.

Keep the tested domain responsibilities and native lifecycle evidence as foundations for the rebuild. Accept each replacement through a complete user journey, then remove its superseded path. A long-lived compatibility layer that perpetuates both confusing experiences would increase the maintenance burden and weaken the product decision.

For 1.0, this means the product experience is part of the release definition. A coherent release could center on install/discover/open, automatic container participation, and trusted access from a second machine, with specialist capabilities available through advanced interfaces. Timing should follow the acceptance evidence for that promise.

**What the screenshots reveal**

| Observation | User consequence | Direction |
|---|---|---|
| Discover and Browser both list network observations; Open appears deep in Browser | The main useful action is difficult to find, and choosing a tab requires understanding internal distinctions | One network home with prominent service actions; raw announcements in technical details |
| The same application appears under HTTP and another service type | Users must infer whether rows represent different applications | Correlate advertisements into services where evidence supports it; preserve their sources in details |
| Glance and Status repeat resolutions, identifiers, and appearances | Users must decide whether ordinary network activity matters | Summarize meaningful changes to services and devices; retain the full event stream for diagnosis |
| Diff shows “all quiet” before a second node has been selected | An unperformed comparison appears to be a successful check | Say “Choose another device to compare”; do not report a result before one exists |
| Trust says this machine has no CA or identity, then says the CA lives elsewhere | Mutually inconsistent explanations make the state hard to trust | Show one coherent state and its applicable next action |
| DNS leads with record and TXT forms | Users must translate “I want a usable name” into protocol operations | Put naming in service setup; keep direct DNS editing in advanced settings |
| “Calm,” “posture,” “family,” “Burst,” and “Ping the pond” occupy functional controls | Personality adds vocabulary before delivering understanding | Prefer concrete labels such as Connected, All devices, Check again, and Compare devices |
| Text and actions are subdued; status controls follow a very long feed | The visual hierarchy hides useful information and interaction | Increase legibility, shorten summaries, put the primary action near the object it affects |

These are screenshot observations and product judgments, not a new runtime trace or a measured accessibility audit.

**Proposed information architecture**

Use the four user-specified top-menu destinations: **Home**, **Devices**, **Settings**, and **About**. Keep the top menu at narrow widths through wrapping/reflow. Keep recent changes on Home with a link to a full activity view; activity does not need equal prominence as a permanent top-level tab initially.

| Destination | Question it answers | Contents |
|---|---|---|
| Home | What can I open or use? | Search, favorites, available services, a small needs-attention area, recent meaningful changes |
| Devices | Where is something running, and what is connected? | Device summaries, hosted services, Koi presence, applicable connection and identity information |
| Settings | How do I configure Koi? | This installation, container connections, secure connections, sharing, updates, and clearly grouped advanced tools |
| About | What is Koi, and where can I learn more? | Original mascot trading card, product identity, version, local operating context, and useful entry points |

Discover and Browser become two levels of the same experience. Glance becomes Home's concise summary. Diff becomes “Compare what devices can see,” available from a device and from diagnostics. DNS editing, raw announcements, audit records, and event logs remain directly reachable through clearly labeled advanced tools. About remains a first-class top-menu destination.

Use service details to expose addresses, protocols, TXT records, certificate names, discovery sources, and relevant diagnostics. Experts should be able to bookmark an advanced view and select a dense table layout. Simplicity must not mean repeatedly navigating through a wizard to reach familiar tools.

**The launchpad**

Use the source implementation rather than recreating the look from screenshots. Ghostlight defines the family base in `browser-mcp/crates/orchestrator/ui/styles.css`; Koi desktop already carries that base in `koi-desktop/ui/styles.css`, changes the accent to Koi blue, and adds product-specific views. The [source-derived visual dictionary](2026-09-sylin-visual-dictionary.md) records the tokens, components, motion, and proposed product-language mapping. Keep primary actions and text legible. The About page pairs the full mascot card with product information, stacking at narrow widths. Preserve its original pixel art, version medallion, network/trust symbols, rules, and flavor text. Decorative foil can respond to deliberate interaction and respect reduced motion. Routine service items need a practical hierarchy of name, device, condition, and action; they need not all become trading cards.

Service details should open alongside the catalog when there is room and flow into a focused detail view on narrow displays. Keep the selected service and its relevant action together. Details progressively reveal addresses, publication sources, certificates, and troubleshooting. The UI should distinguish services on the network from services found only on this computer.

The default service item needs a recognizable name, a short description when known, the device it runs on, an understandable condition, and a prominent primary action. Search should match friendly names, user aliases, device names, addresses, and service categories. Favorites should persist across restarts; a missing favorite remains visible with its last-seen state.

For a browser-usable service, that action is Open. Other protocols get an appropriate supported action or clear details. An arbitrary discovered TCP port is not sufficient evidence that it is a web page. Make the destination inspectable and use a real accessible link for HTTP(S) navigation.

Do not require users to interpret multiple advertisements for one application. Group them only when endpoint and identity evidence justify it; preserve uncertainty rather than merging unrelated services merely because names resemble each other. A device may host many distinct applications.

Useful service states include “Starting,” “Found on the network,” “Responding,” and “Not responding.” Connection security is a separate fact. Avoid a single “Trusted” badge that conflates seeing an advertisement, authenticating a device, and validating HTTPS. Details should explain where and when a check ran. A check from the daemon does not establish trust or reachability from every browser or phone.

Refresh and reconnect should normally happen automatically. Preserve a working view during reconnect with a visible freshness indication. Distinguish no discoveries, no search matches, an unavailable discovery connection, and saved services that are currently absent.

**Installation ends with a useful result**

The recommended install path should install the appropriate components, start the background service, arrange startup, select working discovery providers, and open the local experience or print its URL on a headless host. A graphical user should not have to discover that the workbench and daemon require separate setup steps. Portable and standalone modes remain documented alternatives for people who choose them.

Reuse existing native discovery support where it supplies the required behavior. Fill missing capability through the supported platform path. Validate browsing and publication separately, and validate native hostname resolution where the install promises it. Provider selection should be an implementation responsibility.

At completion, show discovered services as they arrive. A quiet network should get a useful empty state, with confirmation of what was checked and a way to publish a first service. An installation error should preserve progress and offer the specific next action. A copied executable alone is not the success criterion for the recommended install.

Apply the same standard to upgrade and uninstall: retain settings and favorites across upgrades; restore Koi-owned host changes accurately when removing it. Existing third-party discovery support should continue working.

**The second-machine experience**

On a supported shared local network, installing Koi on machine B should make it participate in discovery without a manual scan, daemon command, provider selection, or address entry. Existing services should appear automatically; Koi presence on B should become visible from A. Closing the desktop window must not stop background participation.

This promise needs an explicit network test envelope. Guest isolation, multicast filtering, and network segmentation can prevent visibility. The product should diagnose what it can establish and give a useful next step; it cannot claim that a successful local install proves network-wide reachability. Compare-devices diagnosis can help once the necessary peers and access are available.

Discovery should work before certmesh enrollment. Joining an existing trust group is a short, intentional follow-on action using Koi's invitation mechanism. Installing near another machine must not silently grant that machine authority or install its root. This distinction preserves automatic discovery while keeping the meaning of joining understandable.

**The container experience**

The existing parser already supports `KOI_MDNS_ANNOUNCE=<name>` and the equivalent `koi.announce` label. This is a useful foundation, not a new proposed configuration syntax. See [runtime guide](../guides/runtime.md) and [metadata parsing](../../crates/koi-runtime/src/instance.rs).

The target journey is:

1. Install Koi on the container host; recognize a usable local runtime connection or explain the one missing step.
2. Run an application with the announce shorthand and a reachable published endpoint.
3. Show the service on Home as it becomes known; explain startup while it is not ready.
4. Make Open prominent when there is a browser-usable destination; readiness claims must use suitable evidence rather than equating container-running with application-ready.
5. Show the same service on the second machine, without manually entering its address.
6. Track restarts and removal accurately, retaining a favorite's identity and indicating absence when appropriate.

The simple case should infer the endpoint when there is one unambiguous choice. For several ports, missing port publication, or an inaccessible runtime, explain the specific missing information. An environment variable cannot by itself establish container-host access or make an unpublished port reachable.

**Secure access continues from the service**

Offer “Set up secure access” on an applicable service. Present the intended URL and guide the required naming, certificate, proxy, and client-trust steps together. If trusted infrastructure already exists, reuse it. If it does not, explain the setup in terms of making this service usable securely on the user's devices.

Before claiming completion, verify the name and certificate together, and test access from the intended second client. Keep client trust and resolver adoption explicit wherever the platform cannot complete them automatically. Koi DNS having a record is not sufficient evidence that a consumer can resolve it.

The current `koi.certmesh=true` flag remains request-only metadata; it does not supply a workload certificate. A finished first journey can use host TLS termination with correctly authorized service names. Per-container private keys and certificate delivery are a separate capability with their own lifecycle obligations.

The UI should explain actions in everyday language; certificate details and certmesh terminology remain available to operators. Reuse current domain commands and observed state. A new service presentation must not create a competing lifecycle engine in the frontend.

**Local-service discovery and deliberate sharing**

The user proposed detecting existing local containers and bare-metal services, then offering to make them available across the network. Treat this as a first-class product opportunity. It extends Koi from finding things already advertised to helping an operator share useful things that are currently private to one machine.

Example: Home shows **On this computer — Ollama — Not shared — Share…**. The review proposes a network name, displays the actual endpoint, and explains who will be able to connect. One Share action coordinates the work. The service then appears under **On your network**, with a connection action suited to an API rather than a misleading browser-launch action. Stop sharing reverses Koi-owned publication, routing, and firewall changes while leaving the original application running.

Discovery should use native local listener/process information and available container/runtime metadata, with small read-only identification checks where useful. A port number alone is insufficient identification. Unknown listeners remain unknown and can be named manually. Local candidate discovery and the sharing lifecycle belong behind the UI in Rust; the desktop displays and initiates them, and the operation continues if its window closes. Avoid duplicate suggestions for services already reachable or already managed by another integration.

The operation needs to establish all of these facts:

- The proposed name is available and actually resolves on the intended clients. An mDNS service advertisement does not, by itself, prove an arbitrary `ollama.local` hostname resolves. Handle alias publication and conflicts, and show the resulting name.
- The endpoint reaches the application. For a loopback-only service, a Koi-owned listener/forwarder can provide the selected network route while preserving the application's local binding. Detect port conflicts and report any resulting address change.
- The firewall change is restricted to the intended network/interface scope and owned by this share. Preserve unrelated rules and existing access supplied by others.
- The access policy is understandable and enforceable. Visibility, transport encryption, and caller authorization are distinct. “Joined devices” is only a valid promise if the serving path enforces their identity and the intended clients can use it.
- The operation survives restart, handles partial failure, and can be reversed. Never label local publication as peer-verified reachability before a peer check succeeds.

Ollama is a useful concrete case: its documented default listener is `127.0.0.1:11434`, and its local API does not require authentication. A direct LAN sharing option therefore needs a clear statement that other permitted network clients can make API requests; it must not imply certmesh enrollment automatically adds an access gate. A protected sharing path can be another supported choice when its client requirements are met. [Ollama network configuration](https://docs.ollama.com/faq), [Ollama authentication](https://docs.ollama.com/api/authentication).

The UI study demonstrates an example `http://ollama.local:11434` address and explicit private-network access. It simulates all state changes; it does not claim that local-service scanning, alias publication, or the full reversible sharing workflow currently ships. A useful acceptance fixture is a known loopback-only API: detect it, share it, resolve and call it from a second machine, restart Koi, then stop sharing and verify that local access still works while Koi's remote path is removed.

**One product experience across surfaces**

Desktop and the local web interface should share vocabulary, service identity, grouping rules, action semantics, and state explanations. Pond should expose the permitted read-only subset of that same experience. Native installation controls can remain specific to desktop. Consistency does not require identical permissions or an immediate UI framework migration.

The existing workbench uses a Rust/Tauri shell. A shared Rust-authored UI is worth prototyping with Dioxus, which has desktop and web targets; its desktop path uses system webviews. Compare that against retaining the current shell with a Rust-authored web frontend before choosing the runtime boundary. Validate tray, startup, authenticated local control, accessibility, packaging, and the card on the actual supported operating systems. Rust is the mandate; selecting a renderer requires evidence of those behaviors. [Dioxus platforms](https://dioxuslabs.com/learn/0.7/guides/platforms/), [Dioxus desktop](https://dioxuslabs.com/learn/0.7/guides/platforms/desktop/), [Tauri architecture](https://tauri.app/concept/architecture/).

Favor contextual details over a global novice/expert toggle. This follows established progressive-disclosure guidance: primary tasks stay immediately available and secondary controls have clear, findable entry points. The specific Koi organization above is a proposal to test. [Nielsen Norman Group](https://www.nngroup.com/articles/progressive-disclosure/).

**Proposed acceptance demonstrations**

These are targets to agree and measure, not results already achieved.

| Journey | Required demonstration |
|---|---|
| Fresh install | A new user completes the recommended install and opens an existing local web service without documentation or an extra daemon command |
| Second machine | Both machines discover their expected shared-network services automatically; existing native mDNS installations continue working |
| Container | The shorthand produces a recognizable service with Open; application startup, restart, and removal are reflected accurately on both machines |
| Secure service | The chosen URL opens with valid HTTPS on the intended second client, then continues through a renewal/restart exercise |
| Failure | A stopped application or broken discovery connection yields the correct state and a useful action, rather than an empty success message |
| Daily use | A user finds a forgotten service by name, device, category, or favorite; ordinary repeated resolutions do not fill the main screen |
| Accessibility | The same find/open/details task works with keyboard navigation and a narrow viewport, with readable text and visible focus |

For controlled fixtures, an initial candidate target is automatic appearance within ten seconds of service readiness on the same LAN, with a meaningful progress state shown immediately. Measure distributions across supported OS/provider combinations before making a public timing promise. Recovery from a missed event must also converge without manual refresh.

Recommended order: establish the installation contract and shared service presentation; deliver Home and the full two-machine container journey; complete contextual secure access; then consolidate the remaining advanced screens. Prototype the core tasks with representative users before migrating every existing view. Treat these outcomes as 1.0 acceptance work if they are part of the launch promise.
