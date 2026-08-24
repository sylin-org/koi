#!/usr/bin/env python3
"""Run-owned webhook sink fixture for the koi-lab webhook-fanout scenario.

Receives ADR-028 webhook deliveries over HTTP and appends one JSON line per
delivery to the output file:

    {"event_id": ..., "sig_valid": ..., "path": ..., "body_ok": ...}

The HMAC secret arrives via the KOI_SINK_SECRET environment variable (never in
argv, so it cannot leak through process listings or evidence). The fixture
itself verifies each delivery's x-koi-signature at receive time.
"""

import hashlib
import hmac
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

OUT_PATH = None
SECRET = None


class SinkHandler(BaseHTTPRequestHandler):
    def do_POST(self):  # noqa: N802 - stdlib naming
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        signature = self.headers.get("x-koi-signature", "")
        expected = "sha256=" + hmac.new(
            SECRET.encode(), body, hashlib.sha256
        ).hexdigest()
        sig_valid = hmac.compare_digest(signature, expected)

        body_ok = False
        event_id = ""
        event_type = ""
        try:
            parsed = json.loads(body.decode("utf-8"))
            body_ok = (
                isinstance(parsed, dict)
                and parsed.get("v") == 1
                and isinstance(parsed.get("event"), dict)
                and isinstance(parsed["event"].get("id"), str)
                and isinstance(parsed["event"].get("type"), str)
                and isinstance(parsed.get("provenance"), dict)
            )
            if body_ok:
                event_id = parsed["event"]["id"]
                event_type = parsed["event"]["type"]
        except Exception:
            body_ok = False

        record = {
            "event_id": event_id,
            "event_type": event_type,
            "sig_valid": sig_valid,
            "body_ok": body_ok,
            "path": self.path,
        }
        with open(OUT_PATH, "a", encoding="utf-8") as out:
            out.write(json.dumps(record) + "\n")

        self.send_response(200 if (sig_valid and body_ok) else 400)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, fmt, *args):  # silence stderr noise
        pass


def main() -> int:
    port = int(sys.argv[sys.argv.index("--port") + 1])
    global OUT_PATH, SECRET
    OUT_PATH = sys.argv[sys.argv.index("--out") + 1]
    secret = os.environ.get("KOI_SINK_SECRET")
    if not secret:
        print("KOI_SINK_SECRET is required", file=sys.stderr)
        return 2
    SECRET = secret

    server = ThreadingHTTPServer(("0.0.0.0", port), SinkHandler)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
