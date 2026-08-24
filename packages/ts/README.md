# @sylin-org/koi-client (beta)

JavaScript/TypeScript client for [Koi](https://github.com/sylin-org/koi)'s frozen
HTTP API. Zero runtime dependencies — Node 18+ built-ins only.

**Scope**: status, health, certmesh status/posture, the Agent-Door discovery
card, the `/v1/events` SSE stream, and enrollment — `generateKeyPairAndCsr()`
keeps the private key in your process (ADR-015 F1) while `join()` / 
`enrollWithLocalDaemon()` drive the frozen wire contract. A `"client"` role
enrolls a non-serving principal (ADR-026).

Shapes are pinned by the repository's conformance vectors
(`docs/reference/vectors/`) and the language-neutral wire contract
(`docs/reference/trust-protocol.md`) — the test suite executes the same
Agent-Door vector as Rust, and the SDK's CSRs are accepted by the real CA
issuance path (`crates/koi-certmesh/tests/sdk_csr.rs`).

## Use

```js
import { KoiClient, generateKeyPairAndCsr } from "@sylin-org/koi-client";

const koi = new KoiClient("http://127.0.0.1:5641", { token: process.env.KOI_TOKEN });
const card = await koi.serverCard();   // Agent-Door discovery (no token needed)
const posture = await koi.posture();   // { signed, encrypted, level }

// Raw-custody enrollment against a remote CA:
const keys = generateKeyPairAndCsr("agent-7");     // key stays with you
const joined = await koi.join({                    // client points at the CA
  hostname: "agent-7", csr: keys.csrPem,
  inviteToken: process.env.KOI_INVITE, role: "client",
});
// persist keys.privateKeyPem (0600) — never send it anywhere

for await (const ev of koi.events()) console.log(ev.id, ev.event, ev.data);
```

Errors: non-2xx responses throw `KoiHttpError` (`error.status`, `error.body`).

## Not published yet

Publication is gated on Koi's stable `1.0.0` release and an explicit
external-publication decision (see `SESSION-HANDOFF.md`). Until then this
package lives in-tree and is exercised by its tests only.
