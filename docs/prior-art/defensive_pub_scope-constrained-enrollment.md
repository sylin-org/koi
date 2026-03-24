# Defensive Publication: Scope-Constrained Certificate Enrollment with Auto-Closing Time Windows

**Publication Type:** Defensive Publication (Prior Art Establishment)
**Publication Date:** 2026-03-24
**Inventor:** Leo Botinelly (Leonardo Milson Botinelly Soares)
**Project:** Koi — a cross-platform local network service daemon written in Rust
**Family:** 6 — Scope-Constrained Enrollment

---

## Abstract

This disclosure describes a certificate enrollment system that combines three independent constraint layers — time-windowed enrollment with automatic deadline enforcement, hostname domain suffix validation, and CIDR subnet range validation — in a single enrollment pipeline. The enrollment window uses lazy evaluation: the auto-close transition occurs on the next enrollment attempt after the deadline elapses, not via a background timer. The domain suffix constraint uses strict dotted-suffix matching to prevent partial-suffix false positives. The system integrates with TOTP authentication, rate limiting with lockout, revocation checking, duplicate enrollment prevention, and optional operator approval with asynchronous channel-based timeout. Three pre-defined trust profiles (JustMe, MyTeam, MyOrganization) provide zero-configuration security posture selection with graduated defaults.

---

## Field of the Invention

Public Key Infrastructure; certificate enrollment; access control; enrollment policy; certificate authority management; scope-constrained authentication; time-windowed authorization.

---

## Keywords

certificate enrollment, scope constraints, domain suffix, CIDR subnet, enrollment window, auto-close, deadline, PKI policy, zero-configuration, TOTP authentication, rate limiting, operator approval, trust profiles, revocation checking, audit trail, lazy evaluation, certificate authority

---

## Problem Statement

Local network PKI systems (private certificate authorities serving organizational networks) need mechanisms to control which hosts can enroll for certificates and when enrollment is permitted. Enterprise PKI systems (Microsoft AD CS, EJBCA, OpenXPKI) rely on external infrastructure (Active Directory, LDAP, RADIUS) for access control. In LAN environments — small offices, labs, schools, home networks — this external infrastructure does not exist.

### Existing Certificate Enrollment Protocols

**SCEP (Simple Certificate Enrollment Protocol, RFC 8894):**
- Authentication: Shared challenge password. Anyone with the password can enroll.
- Scope constraints: None. No hostname validation, no network restrictions, no time windows.
- Enrollment windows: None. SCEP is always open as long as the CA is running.
- Typical use: Router/switch certificate enrollment in enterprise networks.

**EST (Enrollment over Secure Transport, RFC 7030):**
- Authentication: TLS client certificate or HTTP basic authentication.
- Scope constraints: None built-in. Can use TLS client certificate attributes for implicit scoping, but this requires pre-provisioned certificates (chicken-and-egg problem for initial enrollment).
- Enrollment windows: None.
- Typical use: IoT device certificate enrollment.

**CMP (Certificate Management Protocol, RFC 4210):**
- Authentication: Multiple modes (shared secret, existing certificate, external PKI).
- Scope constraints: Deferred to the RA (Registration Authority) policy engine. CMP itself does not define scope constraints.
- Enrollment windows: None built-in. The RA can implement time restrictions, but CMP does not specify how.
- Typical use: Enterprise PKI with dedicated RA infrastructure.

**ACME (Automatic Certificate Management Environment, RFC 8555):**
- Authentication: Domain validation via DNS challenge, HTTP challenge, or TLS-ALPN challenge.
- Scope constraints: Domain ownership verification (you must control the domain to get a certificate). No network restrictions.
- Enrollment windows: None. Always open for validated domain owners.
- Typical use: Public web server certificates (Let's Encrypt).

**Microsoft NDES (Network Device Enrollment Service):**
- Authentication: AD group membership + SCEP challenge password.
- Scope constraints: AD group membership (requires Active Directory infrastructure).
- Enrollment windows: None.
- Typical use: Windows network device enrollment.

**EJBCA / OpenXPKI / Dogtag:**
- Authentication: Configurable (certificate, password, LDAP, RADIUS, etc.).
- Scope constraints: Certificate profiles can constrain certificate content (allowed SANs, key usage), but these constrain the issued certificate, not enrollment eligibility. Enrollment eligibility is controlled by external authentication backends.
- Enrollment windows: Not built-in as a first-class concept. Can be approximated by disabling/enabling certificate profiles.

### Gap in the State of the Art

No existing enrollment system provides ALL of the following as built-in, first-class features:

1. Time-windowed enrollment with automatic deadline enforcement (lazy evaluation)
2. Hostname domain suffix constraint (strict dotted-suffix matching)
3. CIDR subnet constraint (IPv4 and IPv6)
4. Integration of time, domain, and subnet constraints in a single enrollment pipeline
5. Pre-defined trust profiles for zero-configuration security posture selection
6. TOTP-authenticated enrollment (no pre-provisioned certificates required)
7. Rate limiting with lockout on authentication failure
8. Optional two-party operator approval with asynchronous timeout
9. Revocation checking (previously revoked hosts cannot re-enroll)
10. All of the above without external infrastructure (no AD, no LDAP, no RADIUS)

---

## Detailed Technical Description

### 1. System Architecture

The enrollment system is a component of a certificate mesh (certmesh) domain crate within a multi-crate Rust workspace. The enrollment pipeline is invoked when a host sends a join request to the certificate authority.

```
+------------------+     +-----------------------+     +------------------+
|  Joining Host    |     |  Certmesh CA (daemon) |     |  Operator        |
|                  |     |                       |     |  (if approval    |
|  POST /join      |---->|  process_enrollment() |     |   required)      |
|  {hostname,      |     |   1. Window check     |     |                  |
|   auth_response} |     |   2. Auth verify      |     |                  |
|                  |     |   3. Rate limit       |     |                  |
|                  |     |   4. Domain scope     |     |                  |
|                  |     |   5. Subnet scope     |<--->|  approve/deny    |
|                  |     |   6. Revocation check |     |                  |
|                  |     |   7. Duplicate check   |     |                  |
|                  |     |   8. Operator approval |     |                  |
|                  |     |   9. Issue certificate |     |                  |
|  <-- {cert,      |<----|                       |     |                  |
|       ca_cert,   |     |                       |     |                  |
|       ca_fp}     |     |                       |     |                  |
+------------------+     +-----------------------+     +------------------+
```

### 2. Three-Layer Constraint Model

Every enrollment request passes through three independent constraint layers, evaluated in order. Each layer independently gates enrollment — failure at any layer rejects the request.

#### Layer 1 — Enrollment Window (Time Constraint)

The enrollment state is stored in `RosterMetadata`:

```
RosterMetadata:
    enrollment_state: EnrollmentState   // Open | Closed
    enrollment_deadline: Option<DateTime<Utc>>  // When the window auto-closes
    ...
```

**State Machine:**

```
                  open_enrollment(deadline?)
    +--------+  --------------------------->  +------+
    | Closed |                                | Open |
    +--------+  <---------------------------  +------+
                  close_enrollment()              |
                  OR                               |
                  deadline elapses (lazy)          |
                                                   |
                                    auto-close when
                                    now >= deadline
```

**Lazy Deadline Evaluation:**

The enrollment window does NOT use a background timer to auto-close at the deadline. Instead, the `is_enrollment_open()` method checks the deadline on each call:

```
fn is_enrollment_open(&mut self) -> bool:
    if self.enrollment_state != Open:
        return false

    if let Some(deadline) = self.enrollment_deadline:
        if Utc::now() >= deadline:
            self.enrollment_state = Closed
            self.enrollment_deadline = None
            log("Enrollment window expired, auto-closed")
            return false

    return true
```

**Properties of Lazy Evaluation:**
1. No background timer thread or task is needed. The window closes exactly when it matters — when someone tries to enroll.
2. The state transition is atomic: checking and closing happen in the same method call, under the same lock.
3. The deadline is cleared after auto-close to prevent repeated log messages on subsequent calls.
4. The method takes `&mut self` because it may modify the enrollment state. This is a deliberate design choice — the caller must hold a mutable reference to the roster, which serializes concurrent enrollment checks.

**Opening Enrollment:**

```
fn open_enrollment(&mut self, deadline: Option<DateTime<Utc>>):
    self.enrollment_state = Open
    self.enrollment_deadline = deadline
```

The deadline is an absolute timestamp (`DateTime<Utc>`). The CLI and API accept both absolute timestamps (RFC 3339 format, e.g., "2026-03-25T12:00:00Z") and relative durations (e.g., "2h", "1d", "30m", "1h30m"). The conversion from relative duration to absolute timestamp happens at the API/CLI layer, not in the roster model.

**Duration String Parsing:**

The `parse_deadline()` function supports the following formats:
- RFC 3339 timestamp: "2026-03-25T12:00:00Z" (parsed directly)
- Duration with unit suffix: "2h" (2 hours), "1d" (1 day), "30m" (30 minutes), "90s" (90 seconds)
- Compound duration: "1h30m" (1 hour 30 minutes), "2d6h" (2 days 6 hours)

The function first attempts RFC 3339 parsing. On failure, it scans for digit-letter sequences and accumulates the total duration. The absolute deadline is then `Utc::now() + total_duration`.

**Closing Enrollment:**

```
fn close_enrollment(&mut self):
    self.enrollment_state = Closed
    self.enrollment_deadline = None
```

Closing always clears the deadline. This prevents a stale deadline from affecting a future `open_enrollment()` call.

#### Layer 2 — Domain Scope (Hostname Constraint)

The optional `allowed_domain` field in `RosterMetadata` specifies a domain suffix constraint:

```
RosterMetadata:
    allowed_domain: Option<String>  // e.g., "school.local"
    ...
```

**Validation Algorithm:**

```
fn validate_scope(hostname: &str, metadata: &RosterMetadata) -> Result<()>:
    if let Some(domain) = metadata.allowed_domain:
        domain_lower = domain.to_lowercase()
        host_lower = hostname.to_lowercase()

        // Exact match: hostname == domain
        if host_lower == domain_lower:
            return Ok(())

        // Dotted-suffix match: hostname ends with ".domain"
        if host_lower.ends_with(&format!(".{}", domain_lower)):
            return Ok(())

        // No match — reject
        reason = format("hostname '{}' outside domain '{}'", hostname, domain)
        audit_log("scope_violation", hostname=hostname, reason=reason)
        return Err(ScopeViolation(reason))

    return Ok(())  // No constraint set
```

**Strict Dotted-Suffix Matching:**

The critical detail is the dot prefix in the suffix check: `.{domain}`, not just `{domain}`. This prevents partial-suffix false positives:

| Allowed Domain | Hostname | Match? | Reason |
|---------------|----------|--------|--------|
| `school.local` | `server.school.local` | YES | Ends with `.school.local` |
| `school.local` | `lab.server.school.local` | YES | Ends with `.school.local` |
| `school.local` | `school.local` | YES | Exact match |
| `school.local` | `notschool.local` | NO | Ends with `school.local` but NOT `.school.local` |
| `school.local` | `evil-school.local` | NO | Same — no dot boundary |

Without the dot prefix, `notschool.local` would incorrectly match `school.local` because the string "notschool.local" ends with the substring "school.local". The dot prefix ensures the match occurs at a domain label boundary.

**Case Insensitivity:**

Both the hostname and the allowed domain are lowercased before comparison. DNS names are case-insensitive per RFC 1035.

**Audit Logging:**

Failed scope validations are logged to the audit trail with the hostname, the attempted domain, and the allowed domain. This provides forensic evidence of enrollment attempts from outside the allowed scope.

#### Layer 3 — Subnet Scope (Network Constraint)

The optional `allowed_subnet` field in `RosterMetadata` specifies a CIDR range constraint:

```
RosterMetadata:
    allowed_subnet: Option<String>  // e.g., "192.168.1.0/24"
    ...
```

**Validation Algorithm:**

```
fn validate_subnet(ip: &str, metadata: &RosterMetadata) -> Result<()>:
    if let Some(cidr) = metadata.allowed_subnet:
        network = parse_cidr(cidr)?       // e.g., IpNet from "192.168.1.0/24"
        client_ip = parse_ip(ip)?         // e.g., IpAddr from "192.168.1.42"

        if !network.contains(client_ip):
            reason = format("IP '{}' outside subnet '{}'", ip, cidr)
            audit_log("scope_violation", ip=ip, reason=reason)
            return Err(ScopeViolation(reason))

    return Ok(())  // No constraint set
```

**Supported CIDR Formats:**

| Format | Example | Meaning |
|--------|---------|---------|
| IPv4 CIDR | `192.168.1.0/24` | All IPs in 192.168.1.0 - 192.168.1.255 |
| IPv4 host | `10.0.0.5/32` | Single host 10.0.0.5 |
| IPv6 CIDR | `fd00::/8` | All IPs starting with fd |
| IPv6 CIDR | `2001:db8::/32` | Documentation prefix |

**Early Validation:**

CIDR strings are validated at policy-set time (when the operator calls `set_policy()`), not at enrollment time. The `parse_cidr()` function is called when the policy is set, and invalid CIDR strings are rejected immediately with a `ScopeViolation` error. This fail-fast approach prevents a misconfigured policy from silently accepting all enrollment requests due to an unparseable CIDR string.

```
fn parse_cidr(cidr: &str) -> Result<IpNet>:
    cidr.parse()
        .map_err(|_| ScopeViolation(format("invalid CIDR format: {}", cidr)))
```

**Audit Logging:**

Failed subnet validations are logged to the audit trail with the IP address, the attempted subnet, and the allowed subnet.

**Note on IP Availability:**

The subnet constraint uses the client's IP address as seen by the HTTP handler. For enrollment via the HTTP API, this is the TCP source address extracted by the web framework (axum). For enrollment via IPC (if supported in the future), the client IP would need to be provided out-of-band. The current implementation defers subnet validation to the HTTP layer where the client IP is available from the TCP connection.

### 3. The Enrollment Pipeline

The `process_enrollment()` function executes a nine-step pipeline. Each step is a gate — failure at any step rejects the enrollment request and returns an error. The steps are executed in order with no backtracking.

**Step 1 — Check Enrollment Window:**
```
if !roster.is_enrollment_open():
    return Err(EnrollmentClosed)
```
This call may auto-close the enrollment window if the deadline has elapsed (lazy evaluation, as described in Layer 1).

**Step 2 — Verify Authentication:**
```
adapter = adapter_for(auth_state)  // TOTP adapter or FIDO2 adapter
valid = adapter.verify(auth_state, challenge, request.auth)
```
The authentication system uses a pluggable `AuthAdapter` trait. The current implementations are:
- **TOTP adapter:** Verifies a 6-digit TOTP code against a stored secret. Uses the standard TOTP algorithm (RFC 6238) with a 30-second time step and SHA-1 HMAC. Allows a +/-1 time step window for clock drift.
- **FIDO2 adapter:** Verifies an ECDSA P-256 signature over a challenge. The public key was registered during CA creation or a previous `rotate-auth` operation.

The adapter selection is based on the current `AuthState` (which records which authentication method is configured), not on the enrollment request contents. This prevents an attacker from choosing a weaker authentication method.

**Step 3 — Rate Limiting:**
```
match rate_limiter.check_and_record(valid):
    Ok(()) -> proceed              // Valid code, or failure within limit
    Err(LockedOut { remaining_secs }) ->
        return Err(RateLimited { remaining_secs })
    Err(InvalidCode { .. }) ->
        return Err(InvalidAuth)
```
The rate limiter tracks recent authentication attempts. After 3 consecutive failures, it locks out the client for a configurable duration (default: 60 seconds). The lockout response includes `remaining_secs` so the client can display a countdown.

The rate limiter records both successes and failures. A success resets the failure counter. This means a client that fails twice and then succeeds is not penalized — only 3+ consecutive failures trigger lockout.

**Step 4 — Validate Domain Scope:**
```
validate_scope(hostname, &roster.metadata)?
```
As described in Layer 2. Skipped if no `allowed_domain` is set.

**Step 5 — Validate Subnet Scope (deferred to HTTP layer):**

Subnet validation uses the client's TCP source IP, which is only available at the HTTP handler level. The `process_enrollment()` function validates domain scope (hostname is in the request body) but defers subnet scope to the HTTP handler that calls it.

The HTTP handler calls `validate_subnet(client_ip, &roster.metadata)` before calling `process_enrollment()`. This separation keeps the enrollment function testable without network mocking.

**Step 6 — Check Revocation:**
```
if roster.is_revoked(hostname):
    return Err(Revoked(hostname))
```
Previously revoked hosts cannot re-enroll. The revocation list is checked by hostname. This prevents a revoked host from re-enrolling by simply re-running the join process with a valid TOTP code.

The revocation list is stored in `roster.revocation_list`, a vector of `RevokedMember` records containing the hostname, revocation timestamp, revoking operator, and reason.

**Step 7 — Check Duplicate Enrollment:**
```
if roster.is_enrolled(hostname):
    return Err(AlreadyEnrolled(hostname))
```
A host that is already enrolled cannot enroll again. This prevents certificate duplication. If a host needs a new certificate, the existing enrollment must be revoked first (or the host uses the renewal mechanism, which is a separate operation).

**Step 8 — Operator Approval (conditional):**
```
if roster.requires_approval() and approved_by.is_empty():
    return Err(ApprovalDenied)
```

When the trust profile requires approval (`requires_approval: true`), the enrollment pipeline requires an `approved_by` value — the name of the operator who approved the enrollment. This value comes from the caller (HTTP handler or daemon).

The HTTP handler implements the approval flow as follows:
1. The enrollment request arrives.
2. Steps 1-7 pass (window open, auth valid, scope valid, not revoked, not duplicate).
3. The handler sends an `ApprovalRequest` through a `tokio::sync::mpsc` channel to the daemon's operator prompt.
4. The operator sees: "Host 'server.school.local' is requesting enrollment. Approve? [y/N]"
5. The operator responds within 300 seconds (5-minute timeout).
6. If approved, the handler calls `process_enrollment()` with `approved_by = Some("alice")`.
7. If denied or timeout, the handler returns `Err(ApprovalDenied)`.

```
ApprovalRequest:
    hostname: String
    reply: oneshot::Sender<ApprovalDecision>

ApprovalDecision:
    Approved { operator: String }
    Denied
```

The approval channel uses `tokio::sync::mpsc` (multiple producers, single consumer) because multiple enrollment requests may be pending simultaneously. Each request creates its own `oneshot` reply channel for the response.

**Step 9 — Issue Certificate and Record:**

After all gates pass:

1. **Issue certificate:** Call the CA to generate an ECDSA P-256 certificate for the hostname with the specified SANs (Subject Alternative Names). Default validity: 30 days. The certificate is signed by the CA's private key.

2. **Write certificate files:** Write the service certificate (PEM), private key (PEM), and CA certificate (PEM) to the certmesh data directory.

3. **Add to roster:** Create a `RosterMember` record and append it to the roster:
   ```
   RosterMember:
       hostname: String
       role: MemberRole          // Primary | Standby | Member | Client
       enrolled_at: DateTime<Utc>
       enrolled_by: Option<String>  // Operator name or None
       cert_fingerprint: String
       cert_expires: DateTime<Utc>
       cert_sans: Vec<String>
       cert_path: String
       status: MemberStatus      // Active | Revoked
       reload_hook: Option<String>
       last_seen: Option<DateTime<Utc>>
       pinned_ca_fingerprint: Option<String>
       proxy_entries: Vec<ProxyConfigEntry>
   ```

4. **First member is Primary:** The first host to enroll automatically receives the `Primary` role. Subsequent hosts receive the `Member` role. This bootstraps the CA's primary node without a separate configuration step.

5. **Audit log:** Append an audit entry recording the enrollment: hostname, certificate fingerprint, role, approving operator.

6. **Return response:** The enrollment response contains:
   ```
   JoinResponse:
       hostname: String
       ca_cert: String          // PEM-encoded CA certificate
       service_cert: String     // PEM-encoded service certificate
       service_key: String      // PEM-encoded private key
       ca_fingerprint: String   // CA certificate fingerprint for pinning
       cert_path: String        // Filesystem path where certs were written
   ```

### 4. Trust Profiles

Three pre-defined trust profiles provide zero-configuration security posture selection:

#### JustMe Profile

**Intended use:** Single administrator controlling all machines on a home or personal network.

| Setting | Value |
|---------|-------|
| Enrollment default | Open |
| Requires approval | No |
| Auto-unlock on boot | Yes |
| Operator name | Not required |

Anyone with the TOTP code can join immediately. The CA key auto-unlocks when the daemon starts. No operator interaction needed for enrollment.

#### MyTeam Profile

**Intended use:** Small team (2-10 people) sharing a lab or office network.

| Setting | Value |
|---------|-------|
| Enrollment default | Open |
| Requires approval | Yes |
| Auto-unlock on boot | Yes |
| Operator name | Required |

Anyone with the TOTP code can initiate enrollment, but an operator must approve each request. The operator's name is recorded in the audit log for accountability.

#### MyOrganization Profile

**Intended use:** Organization with strict access control requirements (school lab, corporate network).

| Setting | Value |
|---------|-------|
| Enrollment default | Closed |
| Requires approval | Yes |
| Auto-unlock on boot | No (manual passphrase) |
| Operator name | Required |

Enrollment starts closed — machines cannot join until an operator explicitly opens enrollment. Each enrollment requires operator approval. The CA key requires manual passphrase entry on every daemon restart.

#### Custom Profile

Operators can select "custom" during CA creation to choose each policy individually:
- Enrollment open/closed at creation
- Approval required yes/no
- Unlock method: auto, token (TOTP/FIDO2), or passphrase

The custom profile resolves to one of the three standard profiles as a baseline (for determining defaults not explicitly chosen) based on the selected combination:
- (open, no approval) -> JustMe baseline
- (open, approval) -> MyTeam baseline
- (closed, approval) -> MyOrganization baseline
- (closed, no approval) -> JustMe baseline

### 5. Policy Management API

Operators manage scope constraints through the policy API:

**Set Policy (`PUT /v1/certmesh/set-policy`):**
```json
{
  "domain": "school.local",
  "subnet": "192.168.1.0/24"
}
```

Either field can be null to leave the existing constraint unchanged. To clear a constraint, set it explicitly to null with `"clear": true`:

```json
{
  "clear": true
}
```

This clears both domain and subnet constraints.

The request type is:
```
PolicyRequest:
    domain: Option<String>
    subnet: Option<String>
    clear: bool
```

When `clear` is true, both `allowed_domain` and `allowed_subnet` are set to None. When `clear` is false, only the specified fields are updated (non-null values overwrite, null values leave existing).

The CIDR string in `subnet` is validated at set-time via `parse_cidr()`. Invalid CIDR strings are rejected with a 400 Bad Request.

**Open Enrollment (`POST /v1/certmesh/open-enrollment`):**
```json
{
  "until": "2h"
}
```

The `until` field is optional. If absent, enrollment opens with no deadline. If present, it specifies when the window auto-closes:
- Duration string: "2h", "1d", "30m", "1h30m" (relative to now)
- RFC 3339 timestamp: "2026-03-25T12:00:00Z" (absolute)

```
OpenEnrollmentRequest:
    until: Option<String>
```

**Close Enrollment (`POST /v1/certmesh/close-enrollment`):**

No body required. Closes enrollment immediately and clears any deadline.

**CLI Commands:**
```
koi certmesh open-enrollment [--until 2h]
koi certmesh close-enrollment
koi certmesh set-policy --domain school.local --subnet 192.168.1.0/24
koi certmesh set-policy --clear
```

### 6. Data Flow Example

Complete enrollment scenario with all constraints active:

1. Operator creates CA with MyTeam profile:
   - Enrollment: Open
   - Requires approval: Yes
   - TOTP authentication configured

2. Operator sets scope policy:
   ```
   koi certmesh set-policy --domain school.local --subnet 192.168.1.0/24
   ```

3. Operator opens enrollment with 2-hour deadline:
   ```
   koi certmesh open-enrollment --until 2h
   ```

4. Host `lab-server.school.local` (IP: 192.168.1.42) sends join request:
   ```json
   POST /v1/certmesh/join
   {
     "hostname": "lab-server.school.local",
     "auth": {"totp": "123456"}
   }
   ```

5. Pipeline execution:
   - Step 1: Enrollment open? YES (state=Open, deadline=2h from now, now < deadline).
   - Step 2: TOTP valid? YES (code matches secret within time window).
   - Step 3: Rate limit? PASS (no recent failures).
   - Step 4: Domain scope? PASS (hostname "lab-server.school.local" ends with ".school.local").
   - Step 5: Subnet scope? PASS (IP 192.168.1.42 is within 192.168.1.0/24).
   - Step 6: Revoked? NO (hostname not in revocation list).
   - Step 7: Duplicate? NO (hostname not in member list).
   - Step 8: Approval required? YES. Sends ApprovalRequest to operator.
   - Operator sees: "Host 'lab-server.school.local' is requesting enrollment. Approve?"
   - Operator types: "y" (approve, operator name "alice").
   - Step 9: Certificate issued, files written, member added to roster, audit logged.

6. Response:
   ```json
   {
     "hostname": "lab-server.school.local",
     "ca_cert": "-----BEGIN CERTIFICATE-----\n...",
     "service_cert": "-----BEGIN CERTIFICATE-----\n...",
     "service_key": "-----BEGIN PRIVATE KEY-----\n...",
     "ca_fingerprint": "SHA256:abc123...",
     "cert_path": "/var/lib/koi/certs/lab-server.school.local/"
   }
   ```

7. Two hours later, host `new-server.school.local` tries to enroll:
   - Step 1: `is_enrollment_open()` checks deadline. `Utc::now() >= deadline`. Auto-closes enrollment.
   - Returns `Err(EnrollmentClosed)`.

8. Rejection scenario — wrong domain:
   - Host `evil.corp.local` (IP: 192.168.1.99) sends join request.
   - Step 4: Domain scope? FAIL. "evil.corp.local" does not end with ".school.local" and does not equal "school.local".
   - Returns `Err(ScopeViolation("hostname 'evil.corp.local' outside domain 'school.local'"))`.
   - Audit log records: scope_violation, hostname=evil.corp.local.

9. Rejection scenario — wrong subnet:
   - Host `lab-server.school.local` (IP: 10.0.0.5) sends join request (from a different network).
   - Step 5: Subnet scope? FAIL. 10.0.0.5 is not within 192.168.1.0/24.
   - Returns `Err(ScopeViolation("IP '10.0.0.5' outside subnet '192.168.1.0/24'"))`.

### 7. Roster Data Model

The roster is the CA's source of truth — persisted as JSON on disk:

```
Roster:
    metadata: RosterMetadata
    members: Vec<RosterMember>
    revocation_list: Vec<RevokedMember>
```

```
RosterMetadata:
    created_at: DateTime<Utc>
    trust_profile: TrustProfile       // JustMe | MyTeam | MyOrganization
    operator: Option<String>          // Operator name (for MyTeam/MyOrganization)
    requires_approval: Option<bool>   // Override for backward compatibility
    enrollment_state: EnrollmentState // Open | Closed
    enrollment_deadline: Option<DateTime<Utc>>
    allowed_domain: Option<String>    // Domain suffix constraint
    allowed_subnet: Option<String>    // CIDR subnet constraint
```

```
RevokedMember:
    hostname: String
    revoked_at: DateTime<Utc>
    revoked_by: Option<String>
    reason: Option<String>
```

**Backward Compatibility:**

The `requires_approval` field in `RosterMetadata` is `Option<bool>` (not `bool`) to support backward compatibility with rosters created before the approval feature was added. When absent, the `requires_approval()` method falls back to the trust profile's default:

```
fn requires_approval(&self) -> bool:
    self.metadata.requires_approval
        .unwrap_or(self.metadata.trust_profile.requires_approval())
```

### 8. Authentication System

The enrollment authentication uses a pluggable `AuthAdapter` trait:

```
trait AuthAdapter:
    fn verify(&self, state: &AuthState, challenge: &AuthChallenge, response: &AuthResponse) -> bool
```

**TOTP Authentication:**
- Secret: 160-bit (20 bytes), stored as hex-encoded string.
- Algorithm: SHA-1 HMAC (per RFC 6238 / RFC 4226).
- Time step: 30 seconds.
- Window: +/-1 step (allows 30 seconds of clock drift).
- Digits: 6.
- URI format: `otpauth://totp/{issuer}:{account}?secret={base32}&issuer={issuer}`
- The TOTP secret is generated during CA creation and provisioned to the operator via QR code (scanned by authenticator app).

**FIDO2 Authentication:**
- Algorithm: ECDSA P-256 (secp256r1).
- The public key is registered during CA creation or via `rotate-auth`.
- The challenge is a 32-byte random value generated per enrollment attempt.
- The response is a signature over the challenge bytes.

**Rate Limiting:**
- Counter: Tracks consecutive authentication failures.
- Lockout threshold: 3 consecutive failures.
- Lockout duration: Configurable (default: 60 seconds).
- Success resets the failure counter.
- The lockout remaining time is included in the error response for client display.

### 9. Error Types and HTTP Status Mapping

| Error | HTTP Status | Meaning |
|-------|------------|---------|
| `EnrollmentClosed` | 403 | Enrollment window is closed |
| `InvalidAuth` | 401 | Authentication code is invalid |
| `RateLimited { remaining_secs }` | 429 | Too many failed attempts |
| `ScopeViolation(reason)` | 403 | Hostname or IP outside allowed scope |
| `Revoked(hostname)` | 403 | Previously revoked host |
| `AlreadyEnrolled(hostname)` | 409 | Host already has a certificate |
| `ApprovalDenied` | 403 | Operator denied the enrollment |
| `ApprovalTimeout` | 408 | Operator did not respond in time |
| `CaNotInitialized` | 503 | CA has not been created yet |
| `CaLocked` | 503 | CA key is encrypted and locked |

### 10. Comparison with Prior Art

| Property | SCEP | EST | CMP | ACME | EJBCA | This Invention |
|----------|------|-----|-----|------|-------|----------------|
| Time-windowed enrollment | No | No | No | No | Manual profile toggle | Yes (auto-close deadline) |
| Domain hostname constraint | No | No | RA policy | DNS challenge | Certificate profile SAN | Yes (dotted-suffix match) |
| Subnet CIDR constraint | No | No | RA policy | No | No | Yes (IPv4/IPv6 CIDR) |
| Lazy deadline evaluation | N/A | N/A | N/A | N/A | N/A | Yes |
| Trust profiles | No | No | No | No | Certificate profiles | Yes (JustMe/MyTeam/MyOrg) |
| TOTP enrollment auth | No | No | Shared secret | HTTP/DNS challenge | Configurable | Yes |
| Rate limiting | No | No | No | Rate limits on orders | Configurable | Yes (with lockout) |
| Operator approval | No | No | RA approval | No | Approval workflow | Yes (async with timeout) |
| Revocation re-enroll block | No | No | No | No | Configurable | Yes |
| No external infrastructure | No (needs RA) | TLS setup | Complex RA | DNS/HTTP infra | LDAP/AD | Yes |

---

## Variants and Extensions

1. **Additional scope constraint types:** Hostname regex patterns, organizational unit attributes, custom TXT record attributes, machine certificate attributes.

2. **Enrollment quotas:** Maximum N enrollments per window (e.g., "open for 2 hours or until 10 machines join, whichever comes first").

3. **Pre-approved hostname lists:** A whitelist of hostnames that can enroll without TOTP authentication (for fully automated deployment scenarios).

4. **Cascading scope:** Inherit scope constraints from a parent CA in a hierarchical PKI.

5. **Webhook-based approval:** Send an HTTP webhook to an external approval service (Slack, Teams, PagerDuty) instead of prompting a local operator.

6. **Staged enrollment:** Multi-phase enrollment where a host first receives a temporary certificate (short validity), and then receives a full certificate after a probation period.

7. **Geo-fencing:** Scope constraints based on geographic location (derived from IP geolocation databases).

8. **Time-of-day constraints:** Enrollment only permitted during business hours (e.g., 9am-5pm in a specific timezone).

9. **Per-host lease duration:** Different certificate validity periods based on the host's role or scope (e.g., shorter validity for guest devices).

10. **Enrollment delegation:** Allow enrolled members with a specific role to approve enrollment of new members, distributing the approval workload.

---

## Implementation Evidence

The described system is implemented in the Koi project:

- `crates/koi-certmesh/src/enrollment.rs` — `validate_scope()` (hostname domain suffix validation with strict dotted-suffix matching), `validate_subnet()` (CIDR range validation using `ipnet::IpNet`), `parse_cidr()` (early CIDR validation), `process_enrollment()` (9-step pipeline: window check, auth verify, rate limit, domain scope, revocation check, duplicate check, approval gate, certificate issuance, roster update, audit log).
- `crates/koi-certmesh/src/roster.rs` — `Roster` struct, `RosterMetadata` (enrollment_state, enrollment_deadline, allowed_domain, allowed_subnet), `EnrollmentState` enum (Open/Closed), `is_enrollment_open()` (lazy deadline evaluation with atomic auto-close), `open_enrollment()`, `close_enrollment()`, `RosterMember`, `RevokedMember`, `MemberRole` (Primary/Standby/Member/Client), `MemberStatus` (Active/Revoked). Includes `new_with_policy()` for custom policy overrides.
- `crates/koi-certmesh/src/lib.rs` — `CertmeshCore::open_enrollment()`, `close_enrollment()`, `set_policy()`. `ApprovalRequest` and `ApprovalDecision` types for async operator approval. `CertmeshState` (pub(crate)) holding CA state, roster, auth state, rate limiter.
- `crates/koi-certmesh/src/protocol.rs` — `PolicyRequest` (domain, subnet, clear), `OpenEnrollmentRequest` (until), `PolicySummary` (current policy display), `JoinRequest` (hostname, auth response), `JoinResponse` (cert chain, CA fingerprint, cert path).
- `crates/koi-certmesh/src/http.rs` — HTTP endpoints: `/enrollment/open`, `/enrollment/close`, `/policy` (mounted at `/v1/certmesh/`). Subnet validation at the HTTP handler level using client TCP source IP.
- `crates/koi-certmesh/src/profiles.rs` — `TrustProfile` enum (JustMe, MyTeam, MyOrganization) with `enrollment_default_open()`, `requires_approval()`, `from_str_loose()` methods.
- `crates/koi-certmesh/src/audit.rs` — `append_entry()` for audit trail logging of scope violations, enrollment events, and administrative actions.
- `crates/koi-crypto/src/auth.rs` — `AuthAdapter` trait, `AuthState`, `AuthChallenge`, `AuthResponse`, `adapter_for()` dispatcher.
- `crates/koi-crypto/src/totp.rs` — `RateLimiter` with `check_and_record()`, `RateLimitError` (LockedOut, InvalidCode).

---

## Claims-Style Disclosures

1. A method for time-windowed certificate enrollment with automatic deadline enforcement, wherein: (a) an enrollment window has an explicit open/closed state with an optional absolute deadline timestamp; (b) the window automatically transitions from open to closed when the deadline elapses; (c) the deadline evaluation is lazy — it occurs on each enrollment attempt rather than via a background timer; (d) the state transition is atomic (check and close in the same operation under the same lock); (e) the deadline is cleared after auto-close to prevent redundant transitions; distinct from SCEP, EST, CMP, and ACME which have no built-in enrollment windows, and from EJBCA which requires manual profile toggling.

2. A method for scope-constrained certificate enrollment using a three-layer constraint model wherein: (a) Layer 1 validates a time window with auto-closing deadline (lazy evaluation); (b) Layer 2 validates the requesting hostname against a domain suffix constraint using strict dotted-suffix matching (the hostname must either match the domain exactly or end with a dot followed by the domain, preventing partial-suffix false positives like "notschool.local" matching "school.local"); (c) Layer 3 validates the requesting host's IP address against a CIDR subnet range (IPv4 or IPv6); (d) all three layers are evaluated independently in sequence, with failure at any layer rejecting the enrollment request; (e) failed constraint validations are recorded in an audit trail.

3. A method for hostname domain suffix validation in certificate enrollment systems that prevents partial-suffix false positives, wherein: (a) the hostname is compared case-insensitively against the allowed domain; (b) an exact match (hostname equals domain) passes validation; (c) a dotted-suffix match (hostname ends with dot-domain) passes validation; (d) a bare suffix match (hostname ends with domain but without the preceding dot) fails validation; (e) the dot boundary prevents hostnames like "notschool.local" from passing a "school.local" constraint.

4. A method for two-party certificate enrollment approval using an asynchronous channel, wherein: (a) the enrollment pipeline pauses after authentication and scope validation; (b) an approval request containing the requesting hostname is sent through an asynchronous channel (mpsc) to a daemon-side operator prompt; (c) the operator sees the hostname and approves or denies within a configurable timeout (default 300 seconds); (d) the approving operator's identity is recorded in the membership roster alongside the enrolled member; (e) if the operator does not respond within the timeout, the enrollment is denied.

5. A system for zero-configuration PKI enrollment policy selection using trust profiles, wherein: (a) three pre-defined profiles (JustMe, MyTeam, MyOrganization) encode graduated security postures with different defaults for enrollment state, approval requirements, and key unlock behavior; (b) a "custom" profile allows individual policy selection that resolves to a standard profile baseline; (c) the selected profile determines the initial enrollment state (open or closed), whether operator approval is required, and whether the CA key auto-unlocks on boot; (d) scope constraints (domain, subnet) and enrollment windows can be layered on top of any profile; (e) the system requires no external infrastructure (no Active Directory, no LDAP, no RADIUS).

6. A certificate enrollment pipeline that combines, in a single sequential flow: (a) time-window validation with lazy auto-close; (b) pluggable authentication (TOTP or FIDO2) via an adapter trait; (c) rate limiting with lockout after consecutive failures; (d) hostname domain suffix validation with strict dotted-suffix matching; (e) CIDR subnet range validation; (f) revocation list checking to prevent re-enrollment of revoked hosts; (g) duplicate enrollment checking; (h) optional operator approval with asynchronous timeout; (i) certificate issuance, file writing, roster update, and audit logging; distinct from all known enrollment protocols in combining all nine steps in a single built-in pipeline without external infrastructure dependencies.

---

## Antagonist Review Log

### Round 1

**Antagonist Attack — Abstraction Gap (Subnet Validation Placement):**

The disclosure states subnet validation is "deferred to the HTTP layer" but `process_enrollment()` is described as a 9-step pipeline. If subnet validation happens outside the pipeline, it is not truly a 9-step pipeline — it is an 8-step pipeline with a pre-condition. This inconsistency could weaken the disclosure.

**Author Revision:**

The description is accurate: `process_enrollment()` performs 8 of the 9 steps. The subnet validation (step 5) is performed by the HTTP handler before calling `process_enrollment()`, because the HTTP handler has access to the client's TCP source IP address while the `process_enrollment()` function receives the hostname from the request body.

The pipeline is logically 9 steps from the enrollment flow perspective, even though the implementation splits them between two call sites. The disclosure now explicitly documents this in Step 5: "Subnet validation uses the client's TCP source IP, which is only available at the HTTP handler level. The `process_enrollment()` function validates domain scope (hostname is in the request body) but defers subnet scope to the HTTP handler that calls it."

The step numbering in the code comments confirms this:
```
// 1. Check enrollment is open
// 2. Verify auth response
// 3. Validate scope constraints [domain only in process_enrollment]
// 3b. Reject revoked members
// 4. Check not already enrolled
// 5. Approval handled by caller
// 6. Issue certificate
// 7. Write cert files
// 8. Add to roster
// 9. Audit log
```

The logical pipeline is consistent; the implementation partitions it for practical reasons (IP availability).

---

**Antagonist Attack — Reproducibility Gap (TOTP Secret Storage):**

The disclosure mentions TOTP secrets but does not specify how they are stored. Are they in plaintext? Encrypted? In the roster? In a separate file?

**Author Revision:**

The TOTP secret for enrollment authentication is stored as part of the `AuthState` within the `CertmeshState` structure. The `AuthState` contains the secret bytes and the authentication method identifier.

The secret is stored in memory in the `CertmeshState` (behind a Mutex). It is persisted to disk as part of the certmesh state directory. The secret is NOT stored in the roster (which is the membership ledger, not the authentication store).

When the CA key is locked (encrypted at rest), the TOTP secret is stored alongside the encrypted CA key material. It is accessible without unlocking the CA key — otherwise, TOTP verification for enrollment would be impossible while the CA is locked.

The TOTP secret uses zeroize-on-drop semantics: when the `TotpSecret` struct is dropped, the memory is zeroed. The `TotpSecret` type does NOT implement `Clone` — to create a copy (e.g., for returning from a function), `TotpSecret::from_bytes()` must be called to create a new instance from the raw bytes.

---

**Antagonist Attack — Prior Art Weakness (SPIFFE/SPIRE):**

SPIFFE/SPIRE provides identity attestation with scope constraints (trust domains, SPIFFE IDs). How does this differ?

**Author Revision:**

SPIFFE/SPIRE is a workload identity framework for cloud-native environments. Key differences:

1. **Trust domain model:** SPIFFE uses URI-based trust domains (`spiffe://trust-domain/workload`) with attestation plugins (Kubernetes, AWS, GCP). This invention uses hostname-based domain suffix matching and CIDR subnet matching. SPIFFE trust domains are organizational; this invention's domains are DNS-based.

2. **Attestation vs. authentication:** SPIFFE uses attestation (the workload proves it is running in a specific environment — e.g., a specific Kubernetes pod, a specific AWS instance). This invention uses knowledge-based authentication (TOTP code or FIDO2 assertion). The "proof" is different: environment attestation vs. shared secret/key possession.

3. **Infrastructure requirements:** SPIFFE/SPIRE requires a SPIRE server, SPIRE agent on each node, and platform-specific attestation plugins. This invention requires only the daemon and a TOTP authenticator app (which the operator already has on their phone).

4. **Time-windowed enrollment:** SPIFFE/SPIRE has no concept of enrollment windows. Workloads are attested continuously.

5. **Operator approval:** SPIFFE/SPIRE has no built-in human approval step. Attestation is fully automated.

6. **Target environment:** SPIFFE/SPIRE targets cloud-native (Kubernetes, VMs, serverless). This invention targets LAN environments (offices, labs, schools, home networks) where cloud infrastructure is not available.

---

**Antagonist Attack — Scope Hole (IPv6 Link-Local):**

The subnet constraint uses CIDR matching. What about IPv6 link-local addresses (fe80::/10)? These are auto-configured on every interface and could circumvent subnet restrictions if the constraint is set for a different address range.

**Author Revision:**

The subnet constraint validates the IP address as seen by the HTTP handler's TCP connection. If the client connects using a link-local IPv6 address (fe80::...), that address is checked against the CIDR constraint. If the constraint is set to a routable subnet (e.g., "192.168.1.0/24"), a link-local IPv6 connection would fail the check because fe80::... is not within 192.168.1.0/24.

If the operator wants to restrict enrollment to link-local connections only, they can set the constraint to "fe80::/10". If they want to allow both IPv4 LAN and IPv6 link-local, they would need to either:
1. Not set a subnet constraint (relying on domain constraint and authentication alone), or
2. Set a broader constraint that encompasses both ranges.

The current implementation supports only a single CIDR constraint. A variant could support multiple CIDR ranges (a list of allowed subnets), which would address the dual-stack scenario.

This limitation is documented but does not affect the core disclosure — the mechanism (CIDR containment checking) is complete and correct for any single CIDR range.

---

**Antagonist Attack — Missing Edge Case (Clock Skew and Lazy Evaluation):**

The lazy deadline evaluation uses `Utc::now()`. If the daemon's clock is adjusted backward after the deadline passes, could a closed window appear to re-open?

**Author Revision:**

No. The auto-close transition is permanent: when `is_enrollment_open()` detects that `Utc::now() >= deadline`, it sets `enrollment_state = Closed` and clears `enrollment_deadline = None`. After this transition, the state is `Closed` with no deadline. Even if the clock is subsequently adjusted backward, the enrollment state remains `Closed` because the state is stored persistently and the cleared deadline prevents any further auto-close check.

The only way to re-open enrollment after auto-close is an explicit `open_enrollment()` call. This is by design — auto-close is a one-way transition to prevent security policy circumvention through clock manipulation.

---

### Round 2

**Antagonist Attack — Reproducibility Gap (Certificate Issuance Details):**

The disclosure mentions "ECDSA P-256 certificate" and "30-day validity" but does not specify the certificate's subject, key usage, or basic constraints. A PHOSITA might produce a non-interoperable certificate.

**Author Revision:**

The certificate issuance details are:

1. **Key algorithm:** ECDSA with the P-256 (secp256r1) curve.
2. **Subject:** Common Name (CN) is the hostname (e.g., "lab-server.school.local").
3. **Subject Alternative Names (SANs):** DNS names specified in the enrollment request. Typically includes the hostname and any additional aliases.
4. **Key Usage:** Digital Signature, Key Encipherment.
5. **Extended Key Usage:** TLS Server Authentication, TLS Client Authentication.
6. **Basic Constraints:** CA: false (end-entity certificate, not an intermediate CA).
7. **Validity:** 30 days from issuance.
8. **Issuer:** The CA's subject (set during CA creation).
9. **Serial Number:** Random (128-bit, generated using a CSPRNG).

These are standard X.509 certificate attributes for TLS server/client certificates. The CA certificate itself has `CA: true` and appropriate key usage for signing.

---

**Antagonist Attack — Prior Art Weakness (Smallstep Certificates):**

Smallstep's `step-ca` has provisioner-based access control and ACME with attestation. Doesn't it cover similar ground?

**Author Revision:**

Smallstep `step-ca` is the closest prior art. Key differences:

1. **Provisioner model:** Smallstep uses "provisioners" that define who can request certificates. Provisioners can be OIDC, JWK, ACME, SSHPOP, etc. This is a pluggable authentication model, but provisioners do not include hostname domain suffix constraints or CIDR subnet constraints as built-in features. Provisioner constraints are on certificate content (allowed SANs, key types), not on enrollment eligibility by hostname or network.

2. **Enrollment windows:** Smallstep has no built-in enrollment window concept with auto-closing deadlines. Provisioners are either enabled or disabled.

3. **Trust profiles:** Smallstep requires explicit configuration of each provisioner's settings. This invention provides pre-defined trust profiles (JustMe, MyTeam, MyOrganization) that set all policy defaults from a single selection.

4. **Operator approval:** Smallstep's ACME provisioner does not include a human approval step. The JWK provisioner requires a pre-shared token but no real-time operator approval.

5. **Lazy deadline evaluation:** Smallstep does not have this concept — there is no time-based auto-disable of provisioners.

6. **Scope constraint combination:** Smallstep does not combine domain suffix + CIDR subnet + time window in a single enrollment check.

Smallstep is closer to this invention than SCEP/EST/CMP, but the specific combination of features (three-layer scope constraints, trust profiles, lazy auto-close, operator approval) is not present in Smallstep.

---

**Antagonist Attack — Terminology Drift (Enrollment Window vs. Certificate Validity):**

The "enrollment window" could be confused with the certificate's validity period. Are these the same thing?

**Author Revision:**

They are completely different concepts:

- **Enrollment window:** The time period during which NEW hosts can join the certificate mesh. Controlled by `enrollment_state` (Open/Closed) and `enrollment_deadline`. When the window is closed, no new hosts can enroll (but existing members retain their certificates).

- **Certificate validity:** The time period during which an ISSUED certificate is valid (default: 30 days from issuance). Controlled by the `not_before` and `not_after` fields in the X.509 certificate. When a certificate expires, it must be renewed (a separate operation from enrollment).

An enrollment window of 2 hours means "new hosts can join for the next 2 hours." A certificate validity of 30 days means "this certificate is valid for 30 days." A host enrolled in minute 1 of a 2-hour window receives a certificate valid for 30 days — the certificate validity is independent of the enrollment window.

The disclosure uses "enrollment window" consistently to refer to the enrollment time constraint and "validity" or "cert_expires" to refer to certificate validity. There is no ambiguity in the technical text.

---

**Antagonist declares: "No further objections — this disclosure is sufficient to block patent claims on the described invention."**

The disclosure provides:
- Precise constraint algorithms (domain suffix with dot-boundary matching, CIDR containment, lazy deadline evaluation)
- Complete pipeline specification (9 steps with exact ordering and error types)
- Concrete data structures (RosterMetadata, RosterMember, RevokedMember, EnrollmentState, PolicyRequest, ApprovalRequest)
- Trust profile definitions (JustMe, MyTeam, MyOrganization with exact defaults)
- Full data flow example showing all constraint layers in action
- Clear differentiation from SCEP, EST, CMP, ACME, EJBCA, SPIFFE, and Smallstep
- Edge case coverage (clock skew, IPv6 link-local, concurrent enrollment, subnet validation placement)
- Working implementation references (8+ source files)
- Certificate issuance details sufficient for interoperable implementation

A person having ordinary skill in the art of PKI and certificate enrollment could reproduce the complete scope-constrained enrollment system from this disclosure.
