# Koi contributor context

Koi helps container/LAN developers and capable homelab operators label a
container, open its actual application from another computer, and keep names and
state correct through restart, recreation and removal.

Certmesh is a visible second product pillar: private-space identity and trust.
Describe its existing enrollment, renewal and signed membership capabilities
for participating applications separately from the unfinished exact service-name
HTTPS workflow. Keep container discovery as the first task and preview gate.

## Read first

- [ADR-046](../docs/adr/046-container-lan-adoption.md): current product scope.
- [Epic 004](../fleet/epics/004-container-lan-adoption.md): task definitions.
- [Launch ledger](../fleet/launch/LEDGER.md): current claims and completion.
- [Release readiness](../docs/launch/README.md): actual artifacts and scenario claims.
- [Experience direction](../docs/ux/README.md): navigation, state/action language,
  visual rules and U01–U07 implementation boundaries.
- [One UI plan](../docs/ux/single-ui-plan.md): U07 retention, consolidation,
  deletion and all-entry-point acceptance; current owner correction.
- [Architecture](../docs/reference/architecture.md): source ownership.
- [Security model](../docs/reference/security-model.md): bind, auth and trust limits.

Early formative trials use existing CLI/HTTP surfaces for the real second-device
container task. The preview's selected UI must pass the core U06 experience gate;
Services, mDNS, Certmesh and Settings form one coherent journey. Exact service-name
HTTPS and one existing proxy/resolver integration form the next milestone.
The owner requires one shipped UI: consolidate useful desktop/browser capabilities
and remove the superseded screens, bundles and navigation bridges under U07.
An advanced-tool link or a visually aligned shell around partial functionality
does not satisfy that requirement. New Certmesh capabilities and service-name
HTTPS remain separate scope; retained existing tasks must work in the one UI.

Current instructions describe current source honestly. Check the artifact's
tagged docs when evaluating a released binary. Research and ADRs retain dated
evidence; the current epic and ledger own execution.

## Work selection

For “run fleet/task.md”, follow [the dispatcher](../fleet/task.md), including
host identity, own-host native mutation and capacity rules. Other user-authorized
repository tasks do not implicitly launch fleet sessions.

Inspect the worktree and preserve others' changes. Claim a bounded source task
before editing shared files. The current source integrator is CachyOS; other
fleet machines provide requested platform evidence. A direct owner request can
authorize a separate bounded documentation or implementation task.

Use the [exploration workflow](../.codex/skills/explore/SKILL.md) before production
code changes. Read relevant existing files, search constants/types, identify the
closest pattern and state exact placement. Proceed within existing authorization.

## Architecture invariants

- Domains own commands, immutable revisioned state, typed events, durable state,
  workers and acquired resources. Keep status snapshots and semantic events distinct.
- Domain crates do not import one another. Small shared contracts live in
  koi-common; cross-domain coordination lives in koi-compose.
- koi-serve owns transports, auth and composition-facing serving. The CLI,
  embedded consumers, MCP and UI consume authoritative state.
- A UI, adapter or observer must not manufacture a parallel inventory or infer
  success from configuration. Re-read current state after missed events.
- The pure shared renderer may import the existing Certmesh/DNS status DTOs
  named by the architecture guard. It may not acquire domain cores, commands,
  clients or runtime ownership. Adapters supply snapshots and bounded effects.
- Admission, persistence, publication and teardown retain their owners through
  cancellation. Do not orphan accepted work when a requester disconnects.
- RegistrationRegistry owns mDNS publication intent; DiscoveryHub owns browse
  demand; MdnsControlPlane owns capability routes and provider sessions.
- Only crates/koi-mdns/src/native.rs imports mdns-sd. Provider-native types stay
  in their adapters. See [mDNS rules](rules/mdns-boundary.md).
- Keep frozen koi-*-v1 protocol/domain-separation labels and consumer-neutral
  boundaries from [the stack canon](../docs/adr/STACK-0001-sylin-stack-canon.md).
- Follow the retained Rust renderer and authenticated native/headless boundaries;
  visual work does not grant a browser operator authority.

## Implementation and validation

Reuse existing source types and co-located constants. Keep typed errors at domain
boundaries; transport handlers decode, delegate and serialize. See
[HTTP rules](rules/http-adapter.md) and [source lookup](reference/utilities.md).

Test lifecycle, authorization, trust and recovery behavior appropriate to a
change. [CONTRIBUTING](../CONTRIBUTING.md) lists repository checks.
Update [SURFACES](../docs/SURFACES.md) when adding or changing a guard. A configured
test is not a passing native result. A candidate needs exact artifact evidence.

Never present prepared packages, unimplemented grant/listener workflows, a
Koi-only DNS query or disabled TLS validation as a successful user journey.
Keep existing durable settings and identity material safe through upgrade and
uninstall. Secrets and working machine notes belong in gitignored local/, never
in public docs or proof receipts.
