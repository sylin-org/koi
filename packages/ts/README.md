# @sylin-org/koi-client (beta)

JavaScript/TypeScript client for [Koi](https://github.com/sylin-org/koi)'s frozen
HTTP API. Zero runtime dependencies — Node 18+ built-ins only.

**Beta scope** (read side): `/v1/status`, `/healthz`, `/v1/certmesh/status`,
`/v1/certmesh/posture`, the Agent-Door discovery card, and the `/v1/events`
SSE stream. Enrollment (raw-CSR custody) is not yet in the beta surface.

Shapes are pinned by the repository's conformance vectors
(`docs/reference/vectors/`) and the language-neutral wire contract
(`docs/reference/trust-protocol.md`) — this test suite executes the same
Agent-Door vector as the Rust implementation.

## Use

```js
import { KoiClient } from "@sylin-org/koi-client";

const koi = new KoiClient("http://127.0.0.1:5641", { token: process.env.KOI_TOKEN });

const card = await koi.serverCard();   // Agent-Door discovery (no token needed)
const status = await koi.status();     // capability ladder + transport truth
const posture = await koi.posture();   // { signed, encrypted, level }
if (!(await koi.healthy())) throw new Error("koi daemon down");

for await (const ev of koi.events()) {
  console.log(ev.id, ev.event, ev.data);
}
```

Errors: non-2xx responses throw `KoiHttpError` (`error.status`, `error.body`).

## Not published yet

Publication is gated on Koi's stable `1.0.0` release and an explicit
external-publication decision (see `SESSION-HANDOFF.md`). Until then this
package lives in-tree and is exercised by its tests only.
