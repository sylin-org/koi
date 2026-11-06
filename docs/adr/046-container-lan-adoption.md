# ADR-046: Container-to-LAN adoption as the release objective

Status: Accepted by the project owner on 2026-09-12.
Decision owner: Koi maintainer.
Execution: [Epic 004](../../fleet/epics/004-container-lan-adoption.md).
Progress: [launch ledger](../../fleet/launch/LEDGER.md).

## Context

Koi has implemented substantial discovery, naming, runtime lifecycle and trust
machinery. The [viability and adoption assessment](../assessment/2026-09-12-viability-desirability-traction.md)
found credible engineering but very little independent adoption evidence.
Existing tools combine many of the same capabilities. The practical distinction
must be the effort Koi removes from a recurring task and its behavior when services
change.

The owner accepted the assessment's target and authorized replacing current
documentation, eliminating obsolete operating plans, recording this decision and
establishing a release/adoption epic. Existing ADRs and research remain evidence;
they are not competing dispatch instructions.

## Decision

### 1. Audience and task

Koi is an open-source solution for container/LAN developers and technically capable
homelab operators, with mixed Windows/Linux environments as the initial adoption
focus.

The entry task is:

> Label a container, find and open its application from another computer on the
> LAN, and keep its name and status correct when the container restarts, changes
> or leaves.

Find, Trust and Connect remain the product vocabulary. Public orientation starts
with this task and the exact setup needed to complete it. A service record alone
is not a successful outcome. Actual application access from an independent client
is the activation event.

A participating application can also discover LAN services through Koi's API.
That requires the application or an adapter to use the API; it does not make
every unmodified multicast application compatible.

### 2. Two release milestones

**Operator preview:** an installable, pinned artifact completes discovery, naming,
actual second-device access, restart/recreation/removal and useful failure recovery
on the declared Windows/Linux Docker matrix. CLI and HTTP are sufficient. This
milestone can recruit a bounded group of operators before service-specific HTTPS
and the broader desktop experience are complete.

**Trusted-service extension:** the same task gains an exact service-name
certificate, a real TLS listener, explicit client DNS/root setup, normal
certificate validation, renewal and recovery. One existing proxy/resolver
integration is verified end to end. Every trust claim identifies the client tested.

The preview must not claim automatic service certificates, universal browser
trust or a completed grant-based ACME setup. Security defects in the exposed
preview surface block that preview; missing optional HTTPS product wiring does
not become a reason to postpone every independent user trial.

Stable status is a separate verdict. It requires the selected version's published
contract, upgrade/recovery guarantees and appropriate validation; this ADR does
not declare the source stable.

### 3. Scope and interoperability

Prioritize the container runtime, mDNS, DNS, catalog, application reachability and
diagnostics needed for the entry task. Finish service grant, certificate and
listener composition for the trusted-service extension.

Preserve existing interfaces and capabilities with truthful reference
documentation. Keep users' proxies, resolvers and remote-access tools when
possible. One complete integration is preferred to several unsupported
compatibility claims.

The initial scenario matrix is Windows x64 with Docker Desktop and Linux glibc x64
with Docker Engine, using independent physical clients in both host/client
directions. Other existing platform builds and their regression obligations
remain; a distributed binary is not proof of that platform's complete journey.
Podman, macOS, musl and additional network shapes acquire scenario claims only
with evidence for those rows.

A broad desktop redesign, automatic local-application sharing, new runtimes,
overlay networking, enterprise PKI, general proxy feature parity, agent gateways
and whole-platform polish are outside the first milestone. They may follow
observed needs. Existing security and durable-state guarantees are not optional.

### 4. Architecture and security

Retain domain-owned commands, immutable current state, best-effort events and
joinable lifecycle ownership from ADR-043. Composition owns cross-domain
coordination; transport and rendering layers consume authoritative state.
Retain the service model, authorization boundaries and renderer ownership in
ADRs 040, 042, 044 and 045 where exercised.

A discovery name does not imply reachability, authorization or trust. Keep
private-CA distribution, certificate name matching, coarse principal authority,
ordinary-TLS revocation limits and remote transport requirements explicit.

Do not invent new commands or services in documentation to paper over missing
implementation. An unfinished capability is an epic task with an acceptance case.

### 5. Evidence before claims

Each release identifies its source, dependency lock, artifacts, checksums,
installer/recipe revisions and compatibility rows. Run a clean-checkout hosted
candidate dry run and affected native tests. Product changes invalidate affected
proof, and registry versions/tags are not repointed.

Measure the real application, ordinary client resolution and normal TLS
validation. Direct queries to Koi's resolver, disabled certificate verification,
mock providers and checkout-only UI are insufficient acceptance evidence.

Existing ADR/research snapshots remain unchanged. Current documentation contains
the operating model, supported instructions and current limits. Obsolete plans
and campaign narratives leave the current tree; minimal navigation at referenced
paths may remain to keep preserved evidence readable.

### 6. Independent adoption and sustainability

Begin formative observation while the preview is being completed. Recruit people
with a recurring container/LAN problem beyond the implementing team. Measure
setup time, interventions, failure stage, continued use, support effort and why
they return to their previous setup.

Initial exploratory targets for ten qualified operators are:
- seven complete the chosen task from documentation without live maintainer rescue;
- six still use Koi for a recurring task 30 days after their first observed attempt;
- at least two describe a concrete advantage over their previous setup.

These are decision thresholds, not forecasts or proof of market size. Keep all
ten qualified operators in the denominator, including activation failures. Record
missing follow-up as unknown, and do not manufacture retention from downloads.
Use voluntary reports and consented observation, without requiring product telemetry.

If discovery/lifecycle retains users while trust does not, simplify the default
experience accordingly. If downstream projects show stronger retention, invest in
the API/embedding path. Feature expansion is not the default answer to weak demand.

### 7. Authority and publication

This decision and Epic 004 are the current product and execution authority.
They supersede broader release prerequisites and old campaign sequencing in
ADRs 016, 023, 024, 031, 033, 034, 035 and 044 only where those prescribe a
conflicting launch scope or priority. Their applicable architecture, security,
platform and durable-state contracts remain.

The owner authorized the documentation/epic realignment and the direction toward
release. The epic defines concrete publication gates. No artifact, registry or
community post is considered published or approved by a status label alone.
Posting messages to people or communities requires explicit authorization for
that communication; prepare reviewable content first.

## Consequences

The project can reach users with a useful, bounded milestone. Contributors can
choose work by its effect on activation and reliability. Source breadth remains
available without forcing every user through every capability.

A narrower first release leaves some existing ambitions outside its acceptance
scope. This is deliberate prioritization. Evidence from real use, rather than
feature count or a complete redesign, determines the next investment.

## Alternatives considered

- Finish all desktop and platform journeys before recruiting users: delays the
  evidence most needed to choose the right product work.
- Position primarily as private PKI or an MCP platform: increases expectations
  in crowded categories and obscures the clearest existing integration task.
- Remove advanced capabilities immediately: risks breaking useful integrations
  without learning which capabilities independent operators value.
