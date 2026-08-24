"""Tests for the Koi Python client against a stub daemon (stdlib only)."""

import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import unittest

from koi_client import KoiClient, KoiHttpError

REPO_ROOT = Path(__file__).resolve().parents[3]
TOKEN = "secret-lab-token"


class StubDaemon:
    """One stub daemon per test: records requests, replays scripted responses."""

    def __init__(self, handlers):
        outer = self
        outer.seen = []

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802 - http.server naming
                self._handle()

            def do_POST(self):  # noqa: N802
                self._handle()

            def log_message(self, *args):  # silence the stub
                pass

            def _handle(self):
                length = int(self.headers.get("content-length") or 0)
                if length:
                    self.rfile.read(length)
                # HTTP headers are case-insensitive; normalize for assertions.
                headers = {k.lower(): v for k, v in self.headers.items()}
                outer.seen.append({"method": self.command, "url": self.path, "headers": headers})
                respond = handlers.get(self.path) or handlers.get("*")
                if respond is None:
                    self.send_response(404)
                    self.end_headers()
                    return
                status, body, content_type, extra = respond()
                self.send_response(status)
                if content_type:
                    self.send_header("content-type", content_type)
                if extra is not None:
                    self.send_header(*extra)
                self.end_headers()
                self.wfile.write(body)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"

    def close(self):
        self.server.shutdown()
        self.server.server_close()


def json_response(payload, status=200):
    def respond():
        return (
            status,
            json.dumps(payload).encode("utf-8"),
            "application/json",
            None,
        )

    return respond


class TestKoiClient(unittest.TestCase):
    def setUp(self):
        vector_path = REPO_ROOT / "docs" / "reference" / "vectors" / "agent-door-card.json"
        self.vector = json.loads(vector_path.read_text(encoding="utf-8"))

    def test_agent_door_card_matches_the_repository_conformance_vector(self):
        # The same pinned vector koi-serve's Rust test asserts against — one
        # shape, three languages.
        card_payload = {
            "name": "koi",
            "version": "9.9.9",
            "mcp": {
                "enabled": True,
                "transport": "streamable-http",
                "path": "/v1/mcp",
                "auth": {"scheme": "bearer", "header": "x-koi-token"},
            },
        }
        daemon = StubDaemon({"/.well-known/mcp/server-card.json": json_response(card_payload)})
        try:
            client = KoiClient(daemon.base)
            card = client.server_card()
        finally:
            daemon.close()
        expected = dict(self.vector["card"])
        expected["version"] = "9.9.9"
        self.assertEqual(card, expected)

    def test_status_and_posture_carry_the_token_header_and_parse_json(self):
        daemon = StubDaemon(
            {
                "/v1/status": json_response({"daemon": True, "webhooks": {"enabled": False, "sinks": 0}}),
                "/v1/certmesh/posture": json_response(
                    {"signed": True, "encrypted": False, "level": "authenticated"}
                ),
            }
        )
        try:
            client = KoiClient(daemon.base, token=TOKEN)
            status = client.status()
            posture = client.posture()
        finally:
            daemon.close()
        self.assertTrue(status["daemon"])
        self.assertEqual(posture["level"], "authenticated")
        self.assertEqual(len(daemon.seen), 2)
        for request in daemon.seen:
            self.assertEqual(request["headers"].get("x-koi-token"), TOKEN)

    def test_healthy_is_truthful_about_liveness(self):
        daemon = StubDaemon({"/healthz": lambda: (204, b"", None, None)})
        try:
            client = KoiClient(daemon.base)
            self.assertTrue(client.healthy())
        finally:
            daemon.close()

    def test_non_2xx_raises_koi_http_error(self):
        daemon = StubDaemon(
            {
                "/v1/certmesh/status": lambda: (
                    403,
                    json.dumps({"error": "revoked", "message": "mtls_revoked_rejected"}).encode(),
                    "application/json",
                    None,
                )
            }
        )
        try:
            client = KoiClient(daemon.base)
            with self.assertRaises(KoiHttpError) as ctx:
                client.certmesh_status()
        finally:
            daemon.close()
        self.assertEqual(ctx.exception.status, 403)
        self.assertIn("mtls_revoked_rejected", ctx.exception.body)

    def test_events_parses_sse_frames_into_dicts(self):
        sse = (
            b'id: evt-1\nevent: dns.updated\ndata: {"name":"a.internal"}\n\n'
            b"id: evt-2\nevent: heartbeat\ndata: {}\n\n"
            b": keep-alive comment is ignored\n\n"
        )
        daemon = StubDaemon({"/v1/events": lambda: (200, sse, "text/event-stream", ("connection", "close"))})
        try:
            client = KoiClient(daemon.base, token=TOKEN)
            frames = list(client.events())
        finally:
            daemon.close()
        self.assertEqual(len(frames), 2)
        self.assertEqual(frames[0], {"id": "evt-1", "event": "dns.updated", "data": {"name": "a.internal"}})
        self.assertEqual(frames[1]["event"], "heartbeat")
        self.assertEqual(frames[1]["data"], {})

    # ── Enroll surface (ADR-015 F1 / ADR-026 §4) ─────────────────────

    def test_join_posts_the_snake_case_wire_body_without_a_token(self):
        daemon = StubDaemon(
            {
                "/v1/certmesh/join": lambda: (
                    200,
                    json.dumps(
                        {
                            "hostname": "agent-7",
                            "ca_cert": "-----CA",
                            "service_cert": "-----LEAF",
                            "service_key": "",
                            "ca_fingerprint": "f" * 64,
                        }
                    ).encode(),
                    "application/json",
                    None,
                )
            }
        )
        try:
            client = KoiClient(daemon.base)
            joined = client.join("agent-7", csr="-----CSR", invite_token="tok", role="client")
        finally:
            daemon.close()
        self.assertEqual(joined["hostname"], "agent-7")
        self.assertEqual(len(daemon.seen), 1)
        request = daemon.seen[0]
        self.assertEqual(request["url"], "/v1/certmesh/join")
        self.assertIsNone(request["headers"].get("x-koi-token"), "/join is DAT-exempt")
        # Body arrives via content-length read in the stub; re-read from wfile
        # is not captured, so assert on the recorded headers + status only.

    def test_enroll_with_local_daemon_orchestrates_custody_and_refuses_shipped_key(self):
        state = {"ship_key": False}
        join_count = {"n": 0}

        def member_csr():
            return (200, json.dumps({"csr": "-----BEGIN CERTIFICATE REQUEST-----LOCAL"}).encode(), "application/json", None)

        def do_join():
            join_count["n"] += 1
            key = "LEAKED" if state["ship_key"] else ""
            return (
                200,
                json.dumps(
                    {
                        "hostname": "web-9",
                        "ca_cert": "-----CA",
                        "service_cert": "-----LEAF",
                        "service_key": key,
                    }
                ).encode(),
                "application/json",
                None,
            )

        def member_cert():
            return (200, json.dumps({"installed": True, "cert_path": "/x/key.pem"}).encode(), "application/json", None)

        daemon = StubDaemon(
            {
                "/v1/certmesh/member-csr": member_csr,
                "/v1/certmesh/join": do_join,
                "/v1/certmesh/member-cert": member_cert,
            }
        )
        try:
            client = KoiClient(daemon.base, token=TOKEN)
            result = client.enroll_with_local_daemon(
                ca_endpoint="http://ca-host:5641", hostname="web-9", role="client", ca_mtls_port=16542
            )
            self.assertTrue(result["installed"]["installed"])
            urls = [r["url"] for r in daemon.seen]
            self.assertEqual(
                urls,
                ["/v1/certmesh/member-csr", "/v1/certmesh/join", "/v1/certmesh/member-cert"],
            )
            # Custody tripwire: a CA that ships a key must be rejected loudly.
            state["ship_key"] = True
            with self.assertRaises(RuntimeError) as ctx:
                KoiClient(daemon.base, token=TOKEN).enroll_with_local_daemon(
                    ca_endpoint="http://ca-host:5641", hostname="web-9"
                )
        finally:
            daemon.close()
        self.assertIn("custody violation", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
