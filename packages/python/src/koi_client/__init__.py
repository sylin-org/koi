"""Koi HTTP client (beta) — read-side surfaces over the versioned HTTP API.

Zero runtime dependencies: Python 3.9+ standard library only. Shapes are pinned
by the repository's conformance vectors (docs/reference/vectors/) and the
language-neutral wire contract (docs/reference/trust-protocol.md).

Beta scope: status, health, certmesh status/bootstrap/posture, Agent-Door discovery, and
the /v1/events SSE stream. Enrollment (raw-CSR custody) is not yet in the beta
surface; it will land as a 0.x addition without breaking these shapes.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any, Dict, Iterator, Optional

DEFAULT_TIMEOUT = 10.0


class KoiHttpError(Exception):
    """A non-2xx response from the daemon."""

    def __init__(self, status: int, body: str) -> None:
        super().__init__(f"koi responded {status}: {body[:500]}")
        self.status = status
        self.body = body


class KoiClient:
    """A client for one Koi daemon's HTTP adapter.

    ``token`` is the Daemon Access Token; it is sent on EVERY request when set
    (the loopback model treats GETs as exempt, but sending it always is
    harmless and matches the MCP Door contract).
    """

    def __init__(self, base: str, token: Optional[str] = None, timeout: float = DEFAULT_TIMEOUT) -> None:
        if "://" not in base:
            raise ValueError("base must be an absolute http(s) URI")
        self._base = base.rstrip("/")
        self._token = token
        self._timeout = timeout

    def server_card(self) -> Dict[str, Any]:
        """The Agent-Door discovery card (unauthenticated by design)."""
        return self._json("GET", "/.well-known/mcp/server-card.json")

    def status(self) -> Dict[str, Any]:
        """/v1/status — capability ladder + transport truth."""
        return self._json("GET", "/v1/status")

    def healthy(self) -> bool:
        """Liveness probe; True iff 2xx."""
        try:
            with self._request("GET", "/healthz") as res:
                res.read()
                return 200 <= res.status < 300
        except KoiHttpError:
            return False

    def certmesh_status(self) -> Dict[str, Any]:
        """The authoritative Certmesh status for operator tooling.

        The response identifies this node's ``role``, ``posture``, local
        ``identity`` health and diagnosis. Authority-only enrollment and roster
        state lives under the optional ``authority`` member. Remote calls need
        a Daemon Access Token; enrollment discovery uses
        :meth:`certmesh_bootstrap` instead.
        """
        return self._json("GET", "/v1/certmesh/status")

    def certmesh_bootstrap(self) -> Dict[str, Any]:
        """Minimal public authority preflight for discovery and enrollment.

        This call deliberately omits the client's token so a local daemon token
        can never be sent to a remote enrollment authority.
        """
        return self._json("GET", "/v1/certmesh/bootstrap", no_auth=True)

    def posture(self) -> Dict[str, Any]:
        """/v1/certmesh/posture — ``{signed, encrypted, level}``."""
        return self._json("GET", "/v1/certmesh/posture")

    def join(
        self,
        hostname: str,
        csr: Optional[str] = None,
        invite_token: Optional[str] = None,
        sans: Optional[list] = None,
        role: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Enroll against a CA: ``POST /v1/certmesh/join`` — the ONE DAT-exempt
        mutation. The caller keeps its private key and sends only the CSR
        (ADR-015 F1); the response carries ``ca_cert`` + ``service_cert`` and
        NEVER a ``service_key``.

        Bring your own CSR (any X.509 library can produce one for a P-256 key),
        or use :meth:`enroll_with_local_daemon` to have the local daemon hold
        the key. A ``role`` of ``"client"`` enrolls a non-serving principal
        (ADR-026).
        """
        if not hostname:
            raise ValueError("hostname is required")
        body: Dict[str, Any] = {"hostname": hostname, "sans": sans or []}
        if invite_token:
            body["invite_token"] = invite_token
        if csr:
            body["csr"] = csr
        if role:
            if role not in ("member", "client"):
                raise ValueError(f'unknown membership kind {role!r}; expected "member" or "client"')
            body["role"] = role
        # noAuth: /join is DAT-exempt and targets a REMOTE CA — this daemon's
        # local token must never travel to another host.
        return self._json("POST", "/v1/certmesh/join", body=body, no_auth=True)

    def enroll_with_local_daemon(
        self,
        ca_endpoint: str,
        hostname: str,
        role: Optional[str] = None,
        ca_mtls_port: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Full enrollment using the LOCAL daemon for key custody (the same
        flow ``koi certmesh join`` drives): this client's base must point at
        the local daemon; the keypair is generated daemon-side (0600), only
        the CSR crosses to the CA, and the signed leaf is installed locally
        with pull-renewal armed.
        """
        if not ca_endpoint:
            raise ValueError("ca_endpoint is required")
        if not hostname:
            raise ValueError("hostname is required (SDK callers state their identity explicitly)")
        member_csr = self._json("POST", "/v1/certmesh/member-csr", body={"hostname": hostname})
        joined = self.join(hostname, csr=member_csr["csr"], sans=[hostname], role=role)
        if joined.get("service_key"):
            raise RuntimeError(
                "custody violation: the join response carried a private key (ADR-015 F1)"
            )
        installed = self._json(
            "POST",
            "/v1/certmesh/member-cert",
            body={
                "hostname": hostname,
                "cert_pem": joined["service_cert"],
                "ca_pem": joined["ca_cert"],
                "ca_endpoint": ca_endpoint,
                **({"ca_mtls_port": ca_mtls_port} if ca_mtls_port else {}),
            },
        )
        return {"joined": joined, "installed": installed}

    def events(self) -> Iterator[Dict[str, Any]]:
        """Iterate the merged domain event stream (``GET /v1/events``, SSE).

        Yields ``{"id": ..., "event": ..., "data": ...}`` where ``data`` is the
        parsed JSON payload. Stops cleanly when the server closes the stream.
        """
        req = urllib.request.Request(
            f"{self._base}/v1/events",
            headers={
                "accept": "text/event-stream",
                **({"x-koi-token": self._token} if self._token else {}),
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as res:
                yield from _sse_frames(res)
        except urllib.error.HTTPError as err:
            try:
                body = err.read().decode("utf-8", "replace")
            finally:
                err.close()
            raise KoiHttpError(err.code, body) from None

    def _request(self, method: str, path: str, body: Optional[Dict[str, Any]] = None, no_auth: bool = False) -> Any:
        headers = {
            "accept": "application/json",
            **({"x-koi-token": self._token} if self._token and not no_auth else {}),
        }
        data = None
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["content-type"] = "application/json"
        req = urllib.request.Request(
            f"{self._base}{path}",
            method=method,
            data=data,
            headers=headers,
        )
        try:
            return urllib.request.urlopen(req, timeout=self._timeout)
        except urllib.error.HTTPError as err:
            try:
                body = err.read().decode("utf-8", "replace")
            finally:
                err.close()
            raise KoiHttpError(err.code, body) from None

    def _json(self, method: str, path: str, body: Optional[Dict[str, Any]] = None, no_auth: bool = False) -> Dict[str, Any]:
        with self._request(method, path, body=body, no_auth=no_auth) as res:
            payload = res.read().decode("utf-8")
        try:
            return json.loads(payload)
        except json.JSONDecodeError as err:
            raise ValueError(f"koi returned non-JSON body for {path}: {err}") from None


def _sse_frames(res: Any) -> Iterator[Dict[str, Any]]:
    """Parse an SSE byte stream into ``{id, event, data}`` frames (data = JSON)."""
    event_name = "message"
    frame_id: Optional[str] = None
    data_lines: list = []

    def flush():
        nonlocal event_name, frame_id, data_lines
        if not data_lines:
            return
        raw = "\n".join(data_lines)
        data_lines = []
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            data = raw  # heartbeat frames are `{}`; tolerate non-JSON gracefully
        yield {"id": frame_id, "event": event_name, "data": data}
        event_name = "message"
        frame_id = None

    for raw_line in res:
        line = raw_line.decode("utf-8").rstrip("\r\n")
        if line == "":
            yield from flush()
        elif line.startswith("event:"):
            event_name = line[6:].strip()
        elif line.startswith("id:"):
            frame_id = line[3:].strip()
        elif line.startswith("data:"):
            data_lines.append(line[5:].lstrip(" "))
        # comments (`:` prefix) and unknown fields are ignored per SSE
    yield from flush()
