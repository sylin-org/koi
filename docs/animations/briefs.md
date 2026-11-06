# Product demonstration brief

The demonstration should make the container/LAN outcome visible to developers and capable homelab operators: a labeled application appears, works on another device, disappears when stopped and returns accurately when recreated. [Launch readiness](../launch/README.md) controls what can be shown as verified behavior.

## Main sequence

| Scene | Show | Evidence required |
| --- | --- | --- |
| Application on its host | One container with an identifiable application response and published port | Real runtime/container identity and listener |
| Opt in | Add the supported Koi enable/name labels | Current label syntax and observed runtime metadata |
| Find it on another device | A separate physical device discovers the service | Independent peer observation with actual address/port |
| Use it | Open the actual application and show its response | Expected application content from the peer, not a Koi status page |
| Stop it | Stop the container; show honest transition and withdrawal | Recorded convergence time; no stale reachable badge |
| Recreate it | Replacement container appears and serves the real response | Correct replacement endpoint and no duplicate/stale row |

Use the exact certified Windows/Docker Desktop and Linux/Docker Engine scenario where available. State the demonstrated topology/runtime/version in the accompanying caption. For unsupported or untested variants, use diagrams labeled as explanation rather than fabricated live footage.

## Trust extension

Add a separate demonstration only after the public exact-service workflow is complete and certified: choose the intended service name, authorize that name, attach the matching certificate, configure the actual client's trust, and show the application over HTTPS. Include a renewal/restart observation and an understandable wrong-name/untrusted-root failure.

Do not depict a CA creation command, host enrollment, self-signed proxy or green host posture as automatic trusted HTTPS for every container. The animation must preserve the difference between naming, reachability and client trust.

## Existing-tool integration

Show one certified tool/version consuming the supported Koi format/protocol while retaining its existing role. Include a lifecycle update and removal. Do not imply all proxies/ACME clients work without provider configuration or that a sample config establishes interoperability.

## Visual and narration constraints

Keep labels and application state legible. Show two distinct devices and the real network boundary. Use plain narration: what the operator changes, what the other device observes and what happens on stop/recreate. Surface actual delays without implying instant propagation.

Avoid broad platform/uniqueness claims, unpublished package-manager commands and long tours of advanced features. MCP, UDP, webhooks, embedding and CA administration remain reference topics, not scenes required to explain the preview.

Tokens, invitations, private keys, recovery archives and machine credentials must stay out of captures. Record the source/artifact, scenario and observed results beside the final media in the current launch evidence workflow.
