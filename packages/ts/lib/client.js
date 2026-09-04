// Koi HTTP client (beta) — read-side surfaces over the versioned HTTP API.
//
// Zero runtime dependencies: Node 18+ built-ins only. Shapes are pinned by the
// repository's conformance vectors (docs/reference/vectors/) and the language-
// neutral wire contract (docs/reference/trust-protocol.md).
//
// Beta scope: status, health, certmesh status/bootstrap/posture, Agent-Door discovery,
// and the /v1/events SSE stream. Enrollment (raw-CSR custody) is not yet in
// the beta surface; it is documented in trust-protocol.md §4/§8 and will land
// as a 0.x addition without breaking these shapes.

import { request } from "node:http";
import { request as httpsRequest } from "node:https";
import {
  createPublicKey,
  generateKeyPairSync,
  sign as cryptoSign,
} from "node:crypto";

const DEFAULT_TIMEOUT_MS = 10_000;

// ── CSR generation (ADR-015 F1 custody: the key never crosses the wire) ──
//
// Node performs all cryptography (P-256 keygen + ECDSA signing); this module
// only serializes the PKCS#10 structures — the same division of labor rcgen
// uses in the Rust implementation.

/** DER primitive: tag + length + content. */
function tlv(tag, content) {
  const len = content.length;
  if (len < 0x80) return Buffer.concat([Buffer.from([tag, len]), content]);
  const sizeBytes = [];
  let n = len;
  while (n > 0) {
    sizeBytes.unshift(n & 0xff);
    n >>= 8;
  }
  return Buffer.concat([
    Buffer.from([tag, 0x80 | sizeBytes.length, ...sizeBytes]),
    content,
  ]);
}

/** DER object identifier from its dotted form. */
function derOid(dotted) {
  const parts = dotted.split(".").map(Number);
  const body = [parts[0] * 40 + parts[1]];
  for (const part of parts.slice(2)) {
    let stack = [];
    let value = part;
    do {
      stack.unshift(value & 0x7f);
      value >>= 7;
    } while (value > 0);
    for (let i = 0; i < stack.length - 1; i++) stack[i] |= 0x80;
    body.push(...stack);
  }
  return tlv(0x06, Buffer.from(body));
}

const OID_COMMON_NAME = "2.5.4.3";
const OID_EC_PUBLIC_KEY = "1.2.840.10045.2.1";
const OID_PRIME256V1 = "1.2.840.10045.3.1.7";
const OID_ECDSA_WITH_SHA256 = "1.2.840.10045.4.3.2";

/**
 * Generate a P-256 keypair and a CSR for `hostname` (CN only).
 *
 * Returns `{ privateKeyPem, csrPem, publicKey }` — the private key is the
 * caller's to persist (0600 / platform-sealed); only `csrPem` goes on the wire
 * to `KoiClient.join`.
 */
export function generateKeyPairAndCsr(hostname) {
  if (!hostname || typeof hostname !== "string") {
    throw new TypeError("hostname is required");
  }
  const { publicKey, privateKey } = generateKeyPairSync("ec", {
    namedCurve: "prime256v1",
  });
  const { csrDer, criDer } = composeCsr(hostname, publicKey, privateKey);
  return {
    privateKeyPem: privateKey.export({ type: "sec1", format: "pem" }).toString(),
    csrPem: pemEncode("CERTIFICATE REQUEST", csrDer),
    _publicKey: publicKey,
    _criDer: criDer,
  };
}

/** Compose the PKCS#10 structure and sign it (exported for the conformance test). */
export function composeCsr(hostname, publicKey, privateKey) {
  const spki = publicKey.export({ type: "spki", format: "der" });
  const subject = tlv(
    0x30,
    tlv(
      0x31,
      tlv(
        0x30,
        Buffer.concat([
          derOid(OID_COMMON_NAME),
          tlv(0x0c, Buffer.from(hostname, "utf8")),
        ]),
      ),
    ),
  );
  const algorithm = tlv(
    0x30,
    Buffer.concat([derOid(OID_EC_PUBLIC_KEY), derOid(OID_PRIME256V1)]),
  );
  // SPKI arrives as a complete SEQUENCE — reuse it verbatim.
  const certificationRequestInfo = tlv(
    0x30,
    Buffer.concat([tlv(0x02, Buffer.from([0])), subject, spki, tlv(0xa0, Buffer.alloc(0))]),
  );
  const signature = cryptoSign("sha256", certificationRequestInfo, {
    key: privateKey,
    dsaEncoding: "der",
  });
  const signatureAlgorithm = tlv(0x30, derOid(OID_ECDSA_WITH_SHA256));
  // BIT STRING carries one leading unused-bits octet before the DER signature.
  const signatureValue = tlv(
    0x03,
    Buffer.concat([Buffer.from([0]), signature]),
  );
  const csrDer = tlv(
    0x30,
    Buffer.concat([certificationRequestInfo, signatureAlgorithm, signatureValue]),
  );
  return { csrDer, criDer: certificationRequestInfo };
}

function pemEncode(label, der) {
  const b64 = der.toString("base64");
  const lines = b64.match(/.{1,64}/g) ?? [];
  return `-----BEGIN ${label}-----\n${lines.join("\n")}\n-----END ${label}-----\n`;
}

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

  /**
   * The authoritative Certmesh status for operator tooling. Authority-only
   * enrollment and roster state lives under the optional `authority` member.
   * Remote calls require a Daemon Access Token.
   */
  async certmeshStatus() {
    return this.#json("GET", "/v1/certmesh/status");
  }

  /**
   * Minimal public authority preflight for discovery and enrollment. The
   * client's token is deliberately omitted so a local DAT cannot leak to a
   * remote authority.
   */
  async certmeshBootstrap() {
    return this.#json("GET", "/v1/certmesh/bootstrap", undefined, { noAuth: true });
  }

  /** `/v1/certmesh/posture` — `{signed, encrypted, level}`. */
  async posture() {
    return this.#json("GET", "/v1/certmesh/posture");
  }

  /**
   * Enroll against a CA: `POST /v1/certmesh/join` — the ONE DAT-exempt
   * mutation. The caller keeps its private key and sends only the CSR
   * (ADR-015 F1); the response carries `ca_cert` + `service_cert` and NEVER a
   * `service_key`.
   *
   * @param {{ hostname: string, inviteToken?: string, csr?: string,
   *           sans?: string[], role?: "member"|"client",
   *           auth?: object }} options
   *   Generate the CSR with [`generateKeyPairAndCsr`]; a role of `"client"`
   *   enrolls a non-serving principal (ADR-026).
   */
  async join(options) {
    const { hostname, inviteToken, csr, sans = [], role } = options ?? {};
    if (!hostname) throw new TypeError("hostname is required");
    // noAuth: /join is the one DAT-exempt mutation and it targets a REMOTE CA —
    // this daemon's local token must never travel to another host.
    return this.#json(
      "POST",
      "/v1/certmesh/join",
      {
        hostname,
        ...(inviteToken ? { invite_token: inviteToken } : {}),
        ...(csr ? { csr } : {}),
        sans,
        ...(role ? { role } : {}),
      },
      { noAuth: true },
    );
  }

  /**
   * Full enrollment using the LOCAL daemon for key custody (the same flow
   * `koi certmesh join` drives): this client's base must point at the local
   * daemon; the keypair is generated daemon-side (0600), only the CSR crosses
   * to the CA, and the signed leaf is installed locally with renewal armed.
   *
   * @param {{ caEndpoint: string, hostname?: string, role?: "member"|"client",
   *           caMtlsPort?: number }} options
   */
  async enrollWithLocalDaemon(options) {
    const { caEndpoint, hostname, role, caMtlsPort } = options ?? {};
    if (!caEndpoint) throw new TypeError("caEndpoint is required");
    if (!hostname) {
      throw new TypeError(
        "hostname is required (SDK callers state their identity explicitly)",
      );
    }
    if (role && !["member", "client"].includes(role)) {
      throw new TypeError(`unknown membership kind ${role}; expected "member" or "client"`);
    }
    // 1. Local custody: keypair generated here, CSR returned.
    const memberCsr = await this.#json("POST", "/v1/certmesh/member-csr", {
      hostname,
    });
    // 2. Remote CA signs the CSR (join is tokenless by contract).
    const joined = await this.join({
      hostname,
      inviteToken: options?.inviteToken,
      csr: memberCsr.csr,
      sans: [hostname],
      role,
    });
    if (joined.service_key) {
      throw new Error(
        "custody violation: the join response carried a private key (ADR-015 F1)",
      );
    }
    // 3. Install the leaf next to the local key; arm pull-renewal.
    const installed = await this.#json("POST", "/v1/certmesh/member-cert", {
      hostname,
      cert_pem: joined.service_cert,
      ca_pem: joined.ca_cert,
      ca_endpoint: caEndpoint,
      ...(caMtlsPort ? { ca_mtls_port: caMtlsPort } : {}),
    });
    return { joined, installed };
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

  #json(method, path, body, requestOptions) {
    return this.#request(method, path, { jsonBody: body, ...requestOptions }).then(async (res) => {
      const responseBody = await readBody(res);
      if (res.statusCode < 200 || res.statusCode >= 300) {
        throw new KoiHttpError(res.statusCode ?? 0, responseBody);
      }
      try {
        return JSON.parse(responseBody);
      } catch (error) {
        throw new Error(`Koi returned non-JSON body for ${path}: ${error.message}`);
      }
    });
  }

  #request(method, path, { accept, signal, timeoutMs, jsonBody, noAuth } = {}) {
    return new Promise((resolve, reject) => {
      const payload = jsonBody === undefined ? null : JSON.stringify(jsonBody);
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
            ...(payload !== null
              ? { "content-type": "application/json", "content-length": Buffer.byteLength(payload) }
              : {}),
            ...(this.#token && !noAuth ? { "x-koi-token": this.#token } : {}),
          },
        },
        resolve,
      );
      req.on("error", (error) => done(reject, error));
      if (payload !== null) req.write(payload);
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
