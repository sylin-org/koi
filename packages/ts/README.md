# TypeScript/JavaScript client

In-tree client for Koi's versioned HTTP API, using Node built-ins with no runtime dependencies. The package covers status, health, Certmesh bootstrap/status/posture, MCP discovery metadata, events and enrollment. It is not a complete wrapper for every domain command.

Use the local source while developing; registry availability is tracked in [launch readiness](../../docs/launch/README.md).

```js
import { KoiClient } from "./lib/client.js";

const koi = new KoiClient("http://127.0.0.1:5641", {
  token: process.env.KOI_TOKEN,
});
const status = await koi.certmeshStatus();
for await (const event of koi.events()) console.log(event.id, event.event, event.data);
```

Run this example from this package directory. Confirm the actual export path in `package.json` when integrating from another project. Non-success responses throw `KoiHttpError` with status/body.

Enrollment can retain the private key in the client process through `generateKeyPairAndCsr()`, or use `enrollWithLocalDaemon()` for local-daemon custody. Do not send private keys to the authority. A client-role principal is non-serving but has coarse management authority; it is not a scoped read-only identity.

```sh
node --test packages/ts/test/client.test.js
```

Run tests from the workspace root. Wire and trust semantics are in [trust protocol](../../docs/reference/trust-protocol.md); conformance vectors live beside that document.
