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
  encrypted: boolean;
  level?: "open" | "authenticated" | "confidential";
  [key: string]: unknown;
}

export type CertmeshRole = "open" | "member" | "authority";
export type IdentityCondition = "absent" | "healthy" | "expired" | "invalid" | "revoked";

export interface RenewalHealth {
  expires_at: string;
  next_renewal_at: string;
  expires_in_days: number;
  renew_overdue: boolean;
  expired: boolean;
}

export interface CertmeshIdentityStatus {
  condition: IdentityCondition;
  info?: {
    hostname: string;
    ca_fingerprint: string;
    renewal: RenewalHealth;
  };
  reason?: string;
}

export interface DiagnosisCheck {
  name: string;
  status: "ok" | "warn" | "red" | "not_applicable";
  detail: string;
  remedy?: string;
}

export interface TrustDiagnosis {
  posture: Posture;
  overall: "healthy" | "degraded" | "red";
  checks: DiagnosisCheck[];
}

export interface CertPolicy {
  leaf_lifetime_days: number;
  renew_threshold_days: number;
  grace_days: number;
}

export interface CertmeshMemberStatus {
  hostname: string;
  role: "primary" | "standby" | "member" | "client";
  status: "active" | "revoked";
  cert_fingerprint: string;
  cert_expires: string;
  cert_sans?: string[];
  last_seen?: string;
  proxy_entries?: Array<{
    name: string;
    listen_port: number;
    backend: string;
    allow_remote: boolean;
  }>;
}

export interface CertmeshAuthorityStatus {
  locked: boolean;
  ca_fingerprint?: string;
  auth_method?: string;
  enrollment_open: boolean;
  requires_approval: boolean;
  enrollment_state: "open" | "closed";
  member_count: number;
  seq: number;
  policy: CertPolicy;
  members: CertmeshMemberStatus[];
}

export interface CertmeshStatus {
  revision: number;
  role: CertmeshRole;
  posture: Posture;
  identity: CertmeshIdentityStatus;
  diagnosis: TrustDiagnosis;
  authority?: CertmeshAuthorityStatus;
}

export interface CertmeshBootstrapStatus {
  revision: number;
  authority_available: boolean;
  ca_fingerprint?: string;
  enrollment_open: boolean;
  requires_approval: boolean;
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
  certmeshStatus(): Promise<CertmeshStatus>;
  certmeshBootstrap(): Promise<CertmeshBootstrapStatus>;
  posture(): Promise<Posture>;
  events(options?: EventsOptions): AsyncIterable<KoiEvent>;
}

/** A non-2xx response from the daemon. */
export declare class KoiHttpError extends Error {
  status: number;
  body: string;
}
