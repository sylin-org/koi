# Python client

In-tree Python client for Koi's versioned HTTP API, using the standard library. It covers status, health, Certmesh bootstrap/status/posture, MCP discovery metadata, events and enrollment. It is not a complete wrapper for every domain command.

Use `packages/python/src` on `PYTHONPATH` for local development. Registry availability is tracked in [launch readiness](../../docs/launch/README.md).

```python
import os
from koi_client import KoiClient

koi = KoiClient("http://127.0.0.1:5641", token=os.environ["KOI_TOKEN"])
status = koi.certmesh_status()
for event in koi.events():
    print(event["id"], event["event"], event["data"])
```

Non-success responses raise `KoiHttpError` with status/body. `join()` accepts a CSR generated locally by the caller's X.509 tooling; `enroll_with_local_daemon()` uses local-daemon custody. Private keys must remain with their owner. A client-role principal is non-serving but does not imply fine-grained permissions.

```sh
PYTHONPATH=packages/python/src python -m unittest discover -s packages/python/tests -v
```

Run from the workspace root; on PowerShell set `$env:PYTHONPATH = 'packages/python/src'` first. The cross-language CSR verification also needs Node and Python `cryptography`; a skipped result is not proof of that contract. See [trust protocol](../../docs/reference/trust-protocol.md).
