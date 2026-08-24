"""Koi HTTP client (beta) — read-side surfaces over the frozen HTTP API.

Zero runtime dependencies: Python 3.9+ standard library only. Shapes are pinned
by the repository's conformance vectors (docs/reference/vectors/) and the
language-neutral wire contract (docs/reference/trust-protocol.md).

Beta scope: status, health, certmesh status/posture, Agent-Door discovery, and
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
        """/v1/certmesh/status — roster summary + CA posture booleans."""
        return self._json("GET", "/v1/certmesh/status")

    def posture(self) -> Dict[str, Any]:
        """/v1/certmesh/posture — ``{signed, encrypted, level}``."""
        return self._json("GET", "/v1/certmesh/posture")

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
            raise KoiHttpError(err.code, err.read().decode("utf-8", "replace")) from None

    def _request(self, method: str, path: str) -> Any:
        req = urllib.request.Request(
            f"{self._base}{path}",
            method=method,
            headers={
                "accept": "application/json",
                **({"x-koi-token": self._token} if self._token else {}),
            },
        )
        try:
            return urllib.request.urlopen(req, timeout=self._timeout)
        except urllib.error.HTTPError as err:
            raise KoiHttpError(err.code, err.read().decode("utf-8", "replace")) from None

    def _json(self, method: str, path: str) -> Dict[str, Any]:
        with self._request(method, path) as res:
            body = res.read().decode("utf-8")
        try:
            return json.loads(body)
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
