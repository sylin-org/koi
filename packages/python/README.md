# sylin-koi-client (beta)

Python client for [Koi](https://github.com/sylin-org/koi)'s frozen HTTP API.
Zero runtime dependencies — Python 3.9+ standard library only.

**Beta scope** (read side): `/v1/status`, `/healthz`, `/v1/certmesh/status`,
`/v1/certmesh/posture`, the Agent-Door discovery card, and the `/v1/events`
SSE stream. Enrollment (raw-CSR custody) is not yet in the beta surface.

Shapes are pinned by the repository's conformance vectors
(`docs/reference/vectors/`) and the language-neutral wire contract
(`docs/reference/trust-protocol.md`) — this test suite executes the same
Agent-Door vector as the Rust implementation.

## Use

```python
from koi_client import KoiClient

koi = KoiClient("http://127.0.0.1:5641", token=os.environ["KOI_TOKEN"])

card = koi.server_card()    # Agent-Door discovery (no token needed)
status = koi.status()       # capability ladder + transport truth
posture = koi.posture()     # {"signed": ..., "encrypted": ..., "level": ...}
if not koi.healthy():
    raise RuntimeError("koi daemon down")

for event in koi.events():
    print(event["id"], event["event"], event["data"])
```

Errors: non-2xx responses raise `KoiHttpError` (`err.status`, `err.body`).

## Not published yet

Publication is gated on Koi's stable `1.0.0` release and an explicit
external-publication decision (see `SESSION-HANDOFF.md`). Until then this
package lives in-tree and is exercised by its tests only.
