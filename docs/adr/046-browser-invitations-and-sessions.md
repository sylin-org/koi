# ADR-046: Browser invitations and revocable sessions

- Status: Parked by operator, 2026-09-07. Implementation removed; not an active contract.

Browser access, phone QR pairing and browser sessions are removed from the product.
The owner stopped this work because its setup and infrastructure costs outweighed
its value. No phone acceptance, firewall automation, hosted certificate service or
Android work is scheduled. The design below is historical context only; reopening
requires an explicit new product decision. The native Home launchpad continues.
- Relates to ADR-040, ADR-042, ADR-043 and ADR-045.

## Decision and experience

The local UI and CLI offer the same short-lived, one-use browser invitation as a
link and QR. Scanning opens a connection page; only pressing Connect consumes the
invitation. Preview/GET requests never redeem it. The person chooses temporary
access or Remember this browser, then reaches Home. A valid session survives
navigation, reload and ordinary daemon restart, preserving the Home query.
Reopening reuses a valid browser session without consuming a new invitation.
Invitation fragments also work when navigation stays in the same document.
The local `koi launch` action obtains an invitation through authenticated local
control and opens it; it never prints or puts the daemon access token in a URL.

Browser access is explicitly enabled. Private phone access additionally requires
usable CertMesh server identity and its separately enabled HTTPS listener. The
listener never falls back to HTTP or public access on identity loss. Legacy Pond
remains a separately armed, explicitly public read-only surface. Management still
requires local operator authorization, independent of CertMesh's state.

This iteration grants browser sessions **view services** only. It does not turn a
phone into a machine operator or CertMesh member. Invite creation, access settings,
session listing and revocation stay on authenticated, loopback-only operator routes.
Future browser management requires explicit permissions and its own reviewed routes.

## Ownership and transport

`koi-common::browser_access` owns schema-1 values. `koi-serve::browser_access` owns
the admission/session repository and browser routes; `koi-serve::browser_tls` owns
the joined HTTPS listener. Both belong to the existing serving lifecycle. Crypto
primitives remain in koi-crypto, HTTP client adaptation in koi-client, CLI commands
in koi, shared presentation in koi-ui, and native controls/opening in koi-desktop.
No second daemon, cloud account, browser extension or parallel catalog is introduced.

Local browser routes use the existing operator listener, with their own browser
authorization; they do not relax DAT on any existing route. The optional phone
listener uses the next port after Pond (operator port + 4), only after explicit
enablement. It mounts only browser bootstrap/assets, exchange and authenticated
Home reads. It never merges the operator, MCP, trust or Pond routers. Existing
four-port installations remain unchanged when phone access is off. A conflict is
reported; no foreign service is stopped and no firewall rule is silently added.

CertMesh's existing usable-identity port supplies server TLS material for members
as well as authorities. The listener uses server-auth TLS without changing the
existing mTLS client-certificate requirement. Identity loss closes owned connections;
rotation reloads through bounded restart. Returned HTTPS addresses use the identity
hostname. The phone must already resolve that name and trust the certificate chain
normally. Enabling CertMesh does not prove client trust. UI/CLI explain this prerequisite
and report bind/identity errors; they never advise bypassing a certificate warning.

## Exchange and session contract

Invitations contain 256 bits of random authority, expire after two minutes, and
are held hashed in memory. An atomic redemption creates one session or fails;
expiry, replay, bad keys and wrong origin cannot spend another invitation.
The URL fragment carries only the invitation, is removed immediately by bootstrap,
and is never included in HTTP requests, logs or referrers. It remains a temporary
bearer capability visible to its viewer; avoid screenshots/logging; it expires automatically or is revoked by disabling
browser access. Generating another code does not invalidate a code already in use. No DAT appears in the URL or browser storage.

A browser generates a non-extractable P-256 signing key using WebCrypto. The
session is an opaque identifier bound to the public key, exact origin and, for
phone access, current CertMesh trust anchor. Each protected request signs a
short-lived, single-use server challenge, HTTP method and exact path/query with
the `koi-browser-session-v1` domain separator. IDs alone grant no access.
This avoids cookies leaking between different local application ports, and avoids
placing reusable bearer credentials in JavaScript-readable persistent storage.
It does not claim to defend against active same-origin XSS or browser-profile compromise.

IndexedDB stores the non-extractable key. A session-only pointer in sessionStorage
selects temporary access (12-hour maximum); an explicitly remembered pointer can
persist for 30 days. The server stores only public keys/session metadata in its
atomic schema-1 repository; it retains those sessions across ordinary restarts.
Stale client key records are removed on disconnect and expiry/rejection. Limits:
32 pending invitations, 64 sessions, bounded short-lived challenges. Unknown/future
repository schemas fail closed and are never overwritten. Revocation/disable is
persisted before success; disable clears invitations and sessions. A grant works only with the trust anchor it was paired with. Restoring that
original anchor can resume an unexpired grant; Disconnect or Disable provides
durable revocation independently of subsequent identity recovery.

All browser routes enforce exact Host and Origin and use no permissive CORS.
Sensitive responses are no-store, no-referrer, frame-denied and restrictive CSP.
State-changing exchange requires JSON POST and same-origin intent; asset loading
alone grants nothing. Browser signatures authorize only the browser router, never DAT APIs.

## Verification and consequences

Verify one-use concurrent redemption, preview safety, expiry, replay, wrong key,
origin, method/query, unknown schema, interrupted persistence, scoped revocation,
disable/re-enable, restart continuity, TLS identity loss, listener cancellation and
absence of operator routes. Exercise UI/CLI QR, real browser key persistence,
Notes open/return/reload and both remembered/temporary choices. Test supported
browser secure-context behavior; TLS fixtures do not establish phone trust.

The CLI/UI use plain Open, Connect, Remember this browser and Disconnect language.
Headless users can create an invitation over their authorized local/SSH terminal.
Physical phone/Windows/native proof remains explicit until performed; source and
fixture tests cannot accept R07 or the fleet candidate by themselves.

References: [RFC 8628](https://www.rfc-editor.org/rfc/rfc8628.html),
[OWASP storage guidance](https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html#storage-apis),
[RFC 6265 cookie port limitations](https://www.rfc-editor.org/rfc/rfc6265.html#section-8.5).
This is a local Koi protocol, not an OAuth conformance claim.

Private invitation origins use the CertMesh identity hostname exactly. They do not
append a discovery suffix: a reachable alias may not be covered by the certificate.
The receiving device must resolve that certified name and trust its issuer.
