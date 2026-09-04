# Koi delight realignment - executable prompt pack

[Epic 003](../../../fleet/epics/003-delight-realignment.md) turns the September assessment
and owner mandates into 30 bounded work orders. Linux execution is authorized through
fleet/task.md. R01 first prepares the contract and records actual Epic 002 completion
and restoration; product implementation waits for that handover.

The prompts are designed for smaller coding models: one outcome, existing source
entry points, explicit dependencies, sequenced steps, positive/negative acceptance
cases, verification, documentation and scope boundaries. No prior conversation,
external UI mockup or hidden personal memory is needed.

## Start an execution

On each participating Linux machine, synchronize the clean Koi `dev` checkout
and give the agent the same instruction:

```text
run fleet/task.md
```

The dispatcher resolves the hostname, preserves an inherited native run while
active, then selects the machine's fixed dependency-ready assignment from LEDGER.md.
[Linux routing](../../../fleet/delight-dispatch.md) defines claims, native peers,
publication and resumption. Do not assemble separate per-machine prompts.

A deliberately selected standalone work order can still be invoked by its path:

```text
Execute docs/prompts/delight/R17-reversible-service-sharing.md,
slice intent-contract. Follow CHARTER.md and the assigned row in LEDGER.md;
verify the dependency evidence, implement, test, document and report.
```

One fleet iteration executes one bounded slice, then publishes and reselects.
When a session ends at a dependency or context boundary, the same fleet prompt
resumes it. Windows physical proof remains pending for its own later dispatch.
Preparing this pack is not evidence that any implementation or native case passed.

## What to read

1. [Epic](../../../fleet/epics/003-delight-realignment.md): promise, requirements,
   gate definitions, native matrix and scope boundary.
2. [CHARTER.md](CHARTER.md): authority, architecture, workflow, test and report rules.
3. [LEDGER.md](LEDGER.md): progress and the exact next task/slice.
4. [CONTRACT.md](CONTRACT.md): R01 owner/type/API decisions and R06 component/build map.
5. The selected task and its bounded source set.

R01 and R06 deliberately settle the difficult shared decisions before later models
edit consuming code. If a contract changes, its owner records affected dependents
and required retests. Do not make each UI or adapter guess its own service/trust model.

## Work orders

| ID | Mission | Dependencies | Gate |
|---|---|---|---|
| [R01](R01-contract-and-handover.md) | Set the product contract and campaign handover | - | G0 |
| [R02](R02-critical-documentation-truth.md) | Correct high-consequence claims and pin their contracts | R01 | G1 |
| [R03](R03-discovery-record-correctness.md) | Fix discovery classification at its source | R01 | G1 |
| [R04](R04-service-catalog.md) | Build the authoritative service catalog projection | R01, R03 | G1 |
| [R05](R05-catalog-api-and-preferences.md) | Expose the catalog and durable personal preferences | R04 | G1 |
| [R06](R06-rust-ui-and-family-foundation.md) | Choose and build the Rust UI foundation with Sylin assets | R01, R05 | G2 |
| [R07](R07-home-launchpad.md) | Build Home as the service launchpad | R05, R06 | G2 |
| [R08](R08-devices-and-comparison.md) | Make Devices answer where services run | R07 | G2 |
| [R09](R09-settings-about-and-surface-consolidation.md) | Consolidate Settings, About, advanced tools and Pond | R08 | G2 |
| [R10](R10-meaningful-activity.md) | Make changes, favorites and notifications useful | R07 | G2 |
| [R11](R11-installation-contract.md) | Make installation a durable path to a working Koi | R01, R06 | G3 |
| [R12](R12-windows-installation.md) | Complete the Windows install and lifecycle journey | R11, R09 | G3 |
| [R13](R13-linux-installation.md) | Complete one Linux installation recipe per execution | R11, R09 | G3 |
| [R14](R14-automatic-second-machine.md) | Prove automatic second-machine discovery and recovery | R03, R07, R12, R13 | G3 |
| [R15](R15-container-ready-service.md) | Make an opted-in container become one usable service | R05, R07, R11 | G4 |
| [R16](R16-local-service-detection.md) | Detect useful services already running on this machine | R04, R11 | G4 |
| [R17](R17-reversible-service-sharing.md) | Own publication, routing and firewall changes as one share | R05, R11, R16 | G4 |
| [R18](R18-share-service-experience.md) | Deliver the local discovery to Share experience | R07, R16, R17 | G4 |
| [R19](R19-url-diagnosis.md) | Explain why a specific service URL fails | R04, R07 | G5 |
| [R20](R20-authorized-service-certificates.md) | Give a service the right name and authorized certificate | R01, R04 | G5 |
| [R21](R21-secure-service-operation.md) | Compose names, certificates and routing into secure access | R11, R19, R20 | G5 |
| [R22](R22-secure-access-and-client-onboarding.md) | Guide users from a service to verified HTTPS | R07, R15, R21 | G5 |
| [R23](R23-renewal-and-recovery.md) | Make renewal and recovery understandable and dependable | R21, R22 | G5 |
| [R24](R24-finished-acme-integration.md) | Finish one maintained external-proxy integration | R20, R22 | G6 |
| [R25](R25-developer-and-agent-experience.md) | Align CLI, SDK, MCP and embedding with service tasks | R05, R17, R19, R21 | G6 |
| [R26](R26-documentation-and-contributor-path.md) | Make documentation and contribution paths follow user goals | R02, R09, R14, R15, R18, R22, R23, R24, R25 | G6 |
| [R27](R27-accessibility-and-interaction-proof.md) | Prove the real UI is usable with keyboard, touch and interruption | R09, R10, R18, R22 | G7 |
| [R28](R28-ci-and-release-contracts.md) | Make routine CI validate the actual development and candidate tree | R01 | G7 |
| [R29](R29-candidate-fleet-acceptance.md) | Validate one exact realignment candidate across the native fleet | R02, R03, R09, R10, R12, R13, R14, R15, R18, R23, R24, R25, R26, R27, R28 | G7 |
| [R30](R30-usability-and-release-review.md) | Evaluate delight with real users and close the epic honestly | R29 | G8 |

The most complex and native tasks have bounded subrows in LEDGER.md. A model should
finish one row and hand off the next concrete step. It must not compress all Linux
recipes, every SDK, or a complete sharing transaction into an unreviewable session.

No task is accepted by code volume or green mock tests alone. Product changes include
their documentation; native claims require physical evidence; final delight requires
actual participant outcomes. The old June P01-P14 prompts remain historical and use
their own charter; they do not govern this pack.
