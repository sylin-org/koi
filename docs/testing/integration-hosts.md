# Installed-host integration work

Physical integration uses independently identified installed Koi participants. The initial preview matrix is Windows x64 with Docker Desktop and Linux glibc x64 with Docker Engine, with an actual application client on the other device. [Launch readiness](../launch/README.md) owns scenario status; this runbook contains no host credentials or private machine inventory.

## Before a run

Read [the fleet contract](../../fleet/CONTRACT.md) and the current [launch ledger](../../fleet/launch/LEDGER.md). Identify the candidate source revision, executable/package hashes, each native supervisor and the independent peer. Select the narrow assertion being tested and its restoration owner.

Record the baseline: installed binary path/hash, one intended Koi process/service, service enablement, configuration/data ownership, selected provider state, relevant listeners and firewall/network settings. Existing credentials stay in approved private access mechanisms and must not be copied into a report or command transcript.

Acceptance uses the product's installed lifecycle and normal paths. Isolated high-port daemons, temporary containers and lower-level embedded examples can diagnose an issue or guard a domain; they cannot certify installation or the full physical journey.

## Scenario

1. Verify the installed candidate's identity and health on both participants.
2. Start a run-owned application with explicit published port and Koi opt-in/name labels.
3. Observe discovery and request its expected application content from the independent peer.
4. Stop/recreate it and verify withdrawal/replacement and the real response.
5. Exercise the specific reconnect/restart boundary under review without widening the run.
6. Restore the exact captured host baseline and remove only run-owned resources.

A blocked or failed restoration is an unsuccessful run. Do not erase the evidence or disarm recovery before baseline health is proved.

## Specialist harnesses

The workspace `koi-lab` tool and scripts under `scripts/integration` implement additional bounded scenarios. Read their current help, configuration and source before selecting one. A harness name does not authorize a host change or prove compatibility with the present installation.

[Provider transitions](mdns-provider-transition.md) use real native facilities and preserve the installed process. Cross-process Certmesh and cross-container scripts establish their named protocol boundaries. They remain separate from the [complete container story](whole-story-e2e-surface.md).

## Evidence

Store source/artifact identity, topology/runtime versions, exact assertions, bounded timing, failures and restoration results. Distinguish supported build targets, source-tested capabilities and physically certified user scenarios. Do not transfer a pass across commits, reimages, runtimes, client trust stores or network configurations without a fresh relevant observation.
