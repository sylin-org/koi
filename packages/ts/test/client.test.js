import test from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { createPublicKey, verify as cryptoVerify } from "node:crypto";

import { KoiClient, KoiHttpError, composeCsr, generateKeyPairAndCsr } from "../lib/client.js";

const repoRoot = fileURLToPath(new URL("../../../", import.meta.url));

/** One stub daemon per test: records requests (+JSON bodies), replays responses. */
async function stubDaemon(handlers) {
  const seen = [];
  const server = createServer((req, res) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      const raw = Buffer.concat(chunks).toString("utf8");
      let body;
      try {
        body = raw ? JSON.parse(raw) : undefined;
      } catch {
        body = raw;
      }
      seen.push({ method: req.method, url: req.url, headers: req.headers, body });
      const respond = handlers[req.url] ?? handlers["*"];
      if (!respond) {
        res.writeHead(404, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: "not_found", message: "stub" }));
        return;
      }
      respond(res);
    });
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.once("listening", resolve);
    server.listen(0, "127.0.0.1");
  });
  return {
    base: `http://127.0.0.1:${server.address().port}`,
    seen,
    close: () =>
      new Promise((resolve) => {
        server.close(() => resolve());
      }),
  };
}

const TOKEN = "secret-lab-token";

const CERTMESH_STATUS = {
  revision: 7,
  role: "authority",
  posture: { signed: true, encrypted: false },
  identity: {
    condition: "healthy",
    info: {
      hostname: "ca-01",
      ca_fingerprint: "f".repeat(64),
      renewal: {
        expires_at: "2026-09-10T00:00:00Z",
        next_renewal_at: "2026-09-07T00:00:00Z",
        expires_in_days: 7,
        renew_overdue: false,
        expired: false,
      },
    },
  },
  diagnosis: {
    posture: { signed: true, encrypted: false },
    overall: "healthy",
    checks: [],
  },
  authority: {
    locked: false,
    ca_fingerprint: "f".repeat(64),
    auth_method: "totp",
    enrollment_open: true,
    requires_approval: false,
    enrollment_state: "open",
    member_count: 1,
    seq: 3,
    policy: {
      leaf_lifetime_days: 7,
      renew_threshold_days: 3,
      grace_days: 1,
    },
    members: [],
  },
};

const CERTMESH_BOOTSTRAP = {
  revision: 7,
  authority_available: true,
  ca_fingerprint: "f".repeat(64),
  enrollment_open: true,
  requires_approval: false,
};

test("agent door card matches the repository conformance vector", async (t) => {
  // The same pinned vector koi-serve's Rust test asserts against — one shape,
  // two languages.
  const vector = JSON.parse(
    readFileSync(`${repoRoot}docs/reference/vectors/agent-door-card.json`, "utf8"),
  );
  const daemon = await stubDaemon({
    "/.well-known/mcp/server-card.json": (res) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(
        JSON.stringify({
          name: "koi",
          version: "9.9.9",
          mcp: {
            enabled: true,
            transport: "streamable-http",
            path: "/v1/mcp",
            auth: { scheme: "bearer", header: "x-koi-token" },
          },
        }),
      );
    },
  });
  t.after(() => daemon.close());

  const client = new KoiClient(daemon.base);
  const card = await client.serverCard();
  const expected = structuredClone(vector.card);
  expected.version = "9.9.9";
  assert.deepEqual(card, expected);
});

test("status surfaces use the authoritative shapes and right auth boundary", async (t) => {
  const daemon = await stubDaemon({
    "/v1/status": (res) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ daemon: true, webhooks: { enabled: false, sinks: 0 } }));
    },
    "/v1/certmesh/posture": (res) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ signed: true, encrypted: false, level: "authenticated" }));
    },
    "/v1/certmesh/status": (res) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(CERTMESH_STATUS));
    },
    "/v1/certmesh/bootstrap": (res) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(CERTMESH_BOOTSTRAP));
    },
    "*": (res) => res.writeHead(404).end("{}"),
  });
  t.after(() => daemon.close());

  const client = new KoiClient(daemon.base, { token: TOKEN });
  const status = await client.status();
  assert.equal(status.daemon, true);
  const posture = await client.posture();
  assert.equal(posture.level, "authenticated");
  const certmesh = await client.certmeshStatus();
  assert.equal(certmesh.role, "authority");
  assert.equal(certmesh.identity.condition, "healthy");
  assert.equal(certmesh.authority.member_count, 1);
  const bootstrap = await client.certmeshBootstrap();
  assert.equal(bootstrap.authority_available, true);
  assert.equal("members" in bootstrap, false);

  assert.equal(daemon.seen.length, 4);
  for (const request of daemon.seen.slice(0, 3)) {
    assert.equal(request.headers["x-koi-token"], TOKEN, "token on every request");
    assert.equal(request.headers.accept, "application/json");
  }
  assert.equal(daemon.seen[3].url, "/v1/certmesh/bootstrap");
  assert.equal(
    daemon.seen[3].headers["x-koi-token"],
    undefined,
    "public remote preflight must not receive the local daemon token",
  );
});

test("healthy() is truthful about liveness", async (t) => {
  const daemon = await stubDaemon({
    "/healthz": (res) => res.writeHead(204).end(),
    "*": (res) => res.writeHead(503).end(),
  });
  t.after(() => daemon.close());
  const client = new KoiClient(daemon.base);
  assert.equal(await client.healthy(), true);
});

test("non-2xx raises KoiHttpError with the body", async (t) => {
  const daemon = await stubDaemon({
    "/v1/certmesh/status": (res) => {
      res.writeHead(403, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: "revoked", message: "mtls_revoked_rejected" }));
    },
  });
  t.after(() => daemon.close());
  const client = new KoiClient(daemon.base);
  await assert.rejects(
    () => client.certmeshStatus(),
    (error) => {
      assert.ok(error instanceof KoiHttpError);
      assert.equal(error.status, 403);
      assert.match(error.body, /mtls_revoked_rejected/);
      return true;
    },
  );
});

test("events() parses SSE frames into typed objects", async (t) => {
  const daemon = await stubDaemon({
    "/v1/events": (res) => {
      res.writeHead(200, { "content-type": "text/event-stream" });
      res.write('id: evt-1\nevent: dns.updated\ndata: {"name":"a.internal"}\n\n');
      res.write('id: evt-2\nevent: heartbeat\ndata: {}\n\n');
      res.write(': keep-alive comment is ignored\n\n');
      res.end();
    },
  });
  t.after(() => daemon.close());

  const client = new KoiClient(daemon.base, { token: TOKEN });
  const frames = [];
  for await (const frame of client.events()) frames.push(frame);
  assert.equal(frames.length, 2);
  assert.deepEqual(frames[0], {
    id: "evt-1",
    event: "dns.updated",
    data: { name: "a.internal" },
  });
  assert.equal(frames[1].event, "heartbeat");
  assert.deepEqual(frames[1].data, {});
});

// ── Enroll surface (ADR-015 F1 / ADR-026 §4) ─────────────────────────

test("generated CSR is a verifiable self-signed PKCS#10 for its subject", () => {
  const generated = generateKeyPairAndCsr("sdk-agent-1");
  assert.match(generated.csrPem, /BEGIN CERTIFICATE REQUEST/);
  // The signature must verify against the CSR's own public key over exactly
  // the certificationRequestInfo bytes — Node does the crypto; we did the
  // DER serialization, so this proves the structure byte-for-byte.
  const ok = cryptoVerify(
    "sha256",
    generated._criDer,
    createPublicKey(generated.privateKeyPem),
    // Re-extract the DER signature from the PEM: last BIT STRING payload.
    // DER is the default dsaEncoding for verify().
    derLastBitString(Buffer.from(pemBody(generated.csrPem), "base64")),
  );
  assert.ok(ok, "CSR signature must verify against its own key");
});

test("join() posts the snake_case wire body without a token", async (t) => {
  let captured = null;
  const daemon = await stubDaemon({
    "/v1/certmesh/join": (res) => {
      captured = daemon.seen.at(-1);
      res.writeHead(200, { "content-type": "application/json" });
      res.end(
        JSON.stringify({
          hostname: "agent-7",
          ca_cert: "-----BEGIN CERTIFICATE-----CA",
          service_cert: "-----BEGIN CERTIFICATE-----LEAF",
          service_key: "",
          ca_fingerprint: "f".repeat(64),
        }),
      );
    },
  });
  t.after(() => daemon.close());

  const client = new KoiClient(daemon.base);
  const joined = await client.join({
    hostname: "agent-7",
    inviteToken: "tok",
    csr: "-----BEGIN CERTIFICATE REQUEST-----X",
    role: "client",
  });
  assert.equal(joined.hostname, "agent-7");
  assert.deepEqual(captured.body, {
    hostname: "agent-7",
    invite_token: "tok",
    csr: "-----BEGIN CERTIFICATE REQUEST-----X",
    sans: [],
    role: "client",
  });
  assert.equal(captured.headers["x-koi-token"], undefined, "/join is DAT-exempt");
});

test("enrollWithLocalDaemon orchestrates custody and refuses a shipped key", async (t) => {
  let shipKey = false;
  const daemon = await stubDaemon({
    "/v1/certmesh/member-csr": (res) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ csr: "-----BEGIN CERTIFICATE REQUEST-----LOCAL" }));
    },
    "/v1/certmesh/join": (res) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(
        JSON.stringify({
          hostname: "web-9",
          ca_cert: "-----CA",
          service_cert: "-----LEAF",
          service_key: shipKey ? "LEAKED" : "",
        }),
      );
    },
    "/v1/certmesh/member-cert": (res) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ installed: true, cert_path: "/x/key.pem" }));
    },
  });
  t.after(() => daemon.close());

  const client = new KoiClient(daemon.base, { token: TOKEN });
  const { joined, installed } = await client.enrollWithLocalDaemon({
    caEndpoint: "http://ca-host:5641",
    hostname: "web-9",
    role: "client",
    caMtlsPort: 16542,
  });
  assert.equal(installed.installed, true);
  // Three calls in order: member-csr (local, tokened) → join (remote shape,
  // tokenless) → member-cert (local, tokened).
  assert.deepEqual(
    daemon.seen.map((request) => `${request.url}`),
    ["/v1/certmesh/member-csr", "/v1/certmesh/join", "/v1/certmesh/member-cert"],
  );
  assert.equal(daemon.seen[0].headers["x-koi-token"], TOKEN);
  assert.equal(daemon.seen[1].headers["x-koi-token"], undefined);

  // Custody tripwire: a CA that ships a key must be rejected loudly.
  shipKey = true;
  await assert.rejects(
    () =>
      new KoiClient(daemon.base, { token: TOKEN }).enrollWithLocalDaemon({
        caEndpoint: "http://ca-host:5641",
        hostname: "web-9",
      }),
    /custody violation/,
  );
});

function pemBody(pem) {
  return pem
    .split("\n")
    .filter((line) => line && !line.startsWith("-----"))
    .join("");
}

/** Walk the CSR's inner TLVs (inside the outer SEQUENCE) and return the DER
 * signature payload of its final BIT STRING. */
function derLastBitString(csrDer) {
  // Descend into the outermost SEQUENCE first.
  let offset = 1;
  let len = csrDer[offset];
  offset += 1;
  if (len & 0x80) {
    const n = len & 0x7f;
    len = 0;
    for (let i = 0; i < n; i++) {
      len = len * 256 + csrDer[offset];
      offset += 1;
    }
  }
  const end = offset + len;
  let last = null;
  while (offset < end) {
    const tag = csrDer[offset];
    offset += 1;
    let contentLen = csrDer[offset];
    offset += 1;
    if (contentLen & 0x80) {
      const n = contentLen & 0x7f;
      contentLen = 0;
      for (let i = 0; i < n; i++) {
        contentLen = contentLen * 256 + csrDer[offset];
        offset += 1;
      }
    }
    last = { tag, start: offset, len: contentLen };
    offset += contentLen;
  }
  assert.equal(last.tag, 0x03, "CSR must end with the signature BIT STRING");
  // Skip the unused-bits octet.
  return csrDer.subarray(last.start + 1, last.start + last.len);
}
