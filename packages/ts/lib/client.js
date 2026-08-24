// Koi HTTP client (beta) — read-side surfaces over the frozen HTTP API.
//
// Zero runtime dependencies: Node 18+ built-ins only. Shapes are pinned by the
// repository's conformance vectors (docs/reference/vectors/) and the language-
// neutral wire contract (docs/reference/trust-protocol.md).
//
// Beta scope: status, health, certmesh status/posture, Agent-Door discovery,
// and the /v1/events SSE stream. Enrollment (raw-CSR custody) is not yet in
// the beta surface; it is documented in trust-protocol.md §4/§8 and will land
// as a 0.x addition without breaking these shapes.

import { request } from "node:http";
import { request as httpsRequest } from "node:https";

const DEFAULT_TIMEOUT_MS = 10_000;

/**
 * A client for one Koi daemon's HTTP adapter.
 *
 * @param {string} baseUri  e.g. "http://127.0.0.1:5641"
 * @param {{ token?: string, timeoutMs?: number }} [options]
 *   `token` is the Daemon Access Token; it is sent on EVERY request when set
 *   (the loopback model treats GETs as exempt, but sending it always is
 *   harmless and matches the MCP Door contract).
 */
export class KoiClient {
  #base;
  #token;
  #timeoutMs;

  constructor(baseUri, options = {}) {
    const url = new URL(baseUri);
    if (url.username || url.password) {
      throw new TypeError("credentials do not belong in a Koi base URI");
    }
    this.#base = url.toString().replace(/\/+$/, "");
    this.#token = options.token ?? null;
    this.#timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  }

  /** The Agent-Door discovery card (unauthenticated by design). */
  async serverCard() {
    return this.#json("GET", "/.well-known/mcp/server-card.json");
  }

  /** `/v1/status` — capability ladder + transport truth. */
  async status() {
    return this.#json("GET", "/v1/status");
  }

  /** Liveness probe; resolves to true iff 2xx. */
  async healthy() {
    const res = await this.#request("GET", "/healthz");
    res.resume();
    return res.statusCode >= 200 && res.statusCode < 300;
  }

  /** `/v1/certmesh/status` — roster summary + CA posture booleans. */
  async certmeshStatus() {
    return this.#json("GET", "/v1/certmesh/status");
  }

  /** `/v1/certmesh/posture` — `{signed, encrypted, level}`. */
  async posture() {
    return this.#json("GET", "/v1/certmesh/posture");
  }

  /**
   * Async-iterate the merged domain event stream (`GET /v1/events`, SSE).
   *
   * Yields `{ id, event, data }` where `data` is the parsed JSON payload.
   * Stops cleanly when the server closes the stream or `abort` fires.
   *
   * @param {{ signal?: AbortSignal }} [options]
   */
  async *events(options = {}) {
    const res = await this.#request("GET", "/v1/events", {
      accept: "text/event-stream",
      signal: options.signal,
      // Long-lived stream: the response body outlives the request timeout.
      timeoutMs: undefined,
    });
    if (res.statusCode !== 200) {
      res.resume();
      throw new KoiHttpError(res.statusCode ?? 0, await readBody(res));
    }
    for await (const frame of sseFrames(res)) {
      yield frame;
    }
  }

  #json(method, path) {
    return this.#request(method, path).then(async (res) => {
      const body = await readBody(res);
      if (res.statusCode < 200 || res.statusCode >= 300) {
        throw new KoiHttpError(res.statusCode ?? 0, body);
      }
      try {
        return JSON.parse(body);
      } catch (error) {
        throw new Error(`Koi returned non-JSON body for ${path}: ${error.message}`);
      }
    });
  }

  #request(method, path, { accept, signal, timeoutMs } = {}) {
    return new Promise((resolve, reject) => {
      const done = (fn, value) => {
        cleanup();
        fn(value);
      };
      let timer;
      let req;
      const cleanup = () => {
        if (timer) clearTimeout(timer);
        if (signal) signal.removeEventListener("abort", onAbort);
      };
      const onAbort = () => {
        if (req) req.destroy();
        done(reject, new Error(`request aborted: ${method} ${path}`));
      };
      timer = setTimeout(
        () => {
          if (req) req.destroy();
          done(reject, new Error(`timeout after ${timeoutMs}ms: ${method} ${path}`));
        },
        timeoutMs ?? this.#timeoutMs,
      );
      if (signal) {
        if (signal.aborted) return onAbort();
        signal.addEventListener("abort", onAbort, { once: true });
      }
      const transport = this.#base.startsWith("https") ? httpsRequest : request;
      req = transport(
        `${this.#base}${path}`,
        {
          method,
          headers: {
            accept: accept ?? "application/json",
            ...(this.#token ? { "x-koi-token": this.#token } : {}),
          },
        },
        resolve,
      );
      req.on("error", (error) => done(reject, error));
      req.end();
    });
  }
}

/** A non-2xx response from the daemon. */
export class KoiHttpError extends Error {
  /** @param {number} status @param {string} body */
  constructor(status, body) {
    super(`koi responded ${status}: ${body.slice(0, 500)}`);
    this.name = "KoiHttpError";
    this.status = status;
    this.body = body;
  }
}

async function readBody(res) {
  const chunks = [];
  for await (const chunk of res) chunks.push(chunk);
  return Buffer.concat(chunks).toString("utf8");
}

/** Parse an SSE byte stream into `{ id, event, data }` frames (data = JSON). */
async function* sseFrames(res) {
  let eventName = "message";
  let id = null;
  let dataLines = [];
  const flush = async function* () {
    if (dataLines.length === 0) return;
    const raw = dataLines.join("\n");
    dataLines = [];
    let data;
    try {
      data = JSON.parse(raw);
    } catch {
      data = raw; // heartbeat frames are `{}`; tolerate non-JSON gracefully
    }
    yield { id, event: eventName, data };
    eventName = "message";
    id = null;
  };
  let buffer = "";
  for await (const chunk of res) {
    buffer += chunk.toString("utf8");
    let index;
    while ((index = buffer.indexOf("\n")) !== -1) {
      let line = buffer.slice(0, index);
      buffer = buffer.slice(index + 1);
      if (line.endsWith("\r")) line = line.slice(0, -1);
      if (line === "") {
        yield* flush();
      } else if (line.startsWith("event:")) {
        eventName = line.slice(6).trim();
      } else if (line.startsWith("id:")) {
        id = line.slice(3).trim();
      } else if (line.startsWith("data:")) {
        dataLines.push(line.slice(5).trimStart());
      }
      // comments (`:` prefix) and unknown fields are ignored per SSE
    }
  }
  yield* flush();
}
