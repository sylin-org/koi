import test from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { KoiClient, KoiHttpError } from "../lib/client.js";

const repoRoot = fileURLToPath(new URL("../../../", import.meta.url));

/** One stub daemon per test: records requests, replays scripted responses. */
async function stubDaemon(handlers) {
  const seen = [];
  const server = createServer((req, res) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      seen.push({ method: req.method, url: req.url, headers: req.headers });
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

test("status and posture carry the token header and parse json", async (t) => {
  const daemon = await stubDaemon({
    "/v1/status": (res) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ daemon: true, webhooks: { enabled: false, sinks: 0 } }));
    },
    "/v1/certmesh/posture": (res) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ signed: true, encrypted: false, level: "authenticated" }));
    },
    "*": (res) => res.writeHead(404).end("{}"),
  });
  t.after(() => daemon.close());

  const client = new KoiClient(daemon.base, { token: TOKEN });
  const status = await client.status();
  assert.equal(status.daemon, true);
  const posture = await client.posture();
  assert.equal(posture.level, "authenticated");

  assert.equal(daemon.seen.length, 2);
  for (const request of daemon.seen) {
    assert.equal(request.headers["x-koi-token"], TOKEN, "token on every request");
    assert.equal(request.headers.accept, "application/json");
  }
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
