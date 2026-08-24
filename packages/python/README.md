# sylin-koi-client (beta)

Python client for [Koi](https://github.com/sylin-org/koi)'s frozen HTTP API.
Zero runtime dependencies — Python 3.9+ standard library only.

**Scope**: status, health, certmesh status/posture, the Agent-Door discovery
card, the `/v1/events` SSE stream, and enrollment — `join()` accepts any CSR
your X.509 library produces (the private key never leaves your process,
ADR-015 F1), and `enroll_with_local_daemon()` drives the daemon-custody flow.
A `"client"` role enrolls a non-serving principal (ADR-026).

Shapes are pinned by the repository's conformance vectors
(`docs/reference/vectors/`) and the language-neutral wire contract
(`docs/reference/trust-protocol.md`).

## Use

```python
from koi_client import KoiClient

koi = KoiClient("http://127.0.0.1:5641", token=os.environ["KOI_TOKEN"])
card = koi.server_card()    # Agent-Door discovery (no token needed)
posture = koi.posture()     # {"signed": ..., "encrypted": ..., "level": ...}

# Enrollment against a remote CA with a locally generated CSR:
csr = my_crypto_lib.make_csr(hostname="agent-7")   # key stays with you
joined = koi.join("agent-7", csr=csr, invite_token=os.environ["KOI_INVITE"], role="client")

for event in koi.events():
    print(event["id"], event["event"], event["data"])
```

Errors: non-2xx responses raise `KoiHttpError` (`err.status`, `err.body`).

## Not published yet

Publication is gated on Koi's stable `1.0.0` release and an explicit
external-publication decision (see `SESSION-HANDOFF.md`). Until then this
package lives in-tree and is exercised by its tests only.
