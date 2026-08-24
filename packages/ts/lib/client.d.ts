// Type declarations for the Koi HTTP client (beta).
//
// Shapes follow docs/reference/trust-protocol.md; unknown fields may appear —
// consumers must tolerate them (the daemon never relies on their absence).

export interface AgentDoorCard {
  name: "koi";
  version: string;
  mcp: {
    enabled: boolean;
    transport: "streamable-http";
    path: string;
    auth: { scheme: "bearer"; header: string };
  };
  [key: string]: unknown;
}

export interface Posture {
  signed: boolean;
  encrypted?: boolean;
  level?: "open" | "authenticated" | "confidential";
  [key: string]: unknown;
}

/** `{ id, event, data }` — `data` is the parsed JSON payload of the frame. */
export interface KoiEvent {
  id: string | null;
  event: string;
  data: unknown;
}

export interface EventsOptions {
  signal?: AbortSignal;
}

/**
 * A client for one Koi daemon's HTTP adapter.
 *
 * @param baseUri e.g. "http://127.0.0.1:5641"
 * @param options.token Daemon Access Token, sent on every request when set.
 */
export declare class KoiClient {
  constructor(baseUri: string, options?: { token?: string; timeoutMs?: number });
  serverCard(): Promise<AgentDoorCard>;
  status(): Promise<Record<string, unknown>>;
  healthy(): Promise<boolean>;
  certmeshStatus(): Promise<Record<string, unknown>>;
  posture(): Promise<Posture>;
  events(options?: EventsOptions): AsyncIterable<KoiEvent>;
}

/** A non-2xx response from the daemon. */
export declare class KoiHttpError extends Error {
  status: number;
  body: string;
}
