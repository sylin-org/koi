# Koi Validation Test Suite

**For:** Claude (coding agent) — run after each phase and as final acceptance
**Project:** Koi — Local Network Toolkit
**Companion to:** `koi-spec.md`, `koi-implementation-prompt.md`
**Date:** February 2026

---

## How to Use This Document

This is both a manual checklist and a specification for automated tests. Each test has:

- **ID** — reference number (capability prefix + sequence)
- **Phase** — the implementation phase that must be complete before this test is relevant
- **Category** — what layer is being tested
- **Test** — what to do
- **Expected** — what should happen
- **Automated?** — whether this should be an integration test in CI, or manual-only

Run the tests relevant to your current phase after completing it. Run the full suite after Phase 8 as final acceptance.

### Test Environment

Unless noted otherwise, tests assume:

- Two machines (or two VMs/containers simulating separate machines) on the same LAN subnet
- Machine A: `stone-01` at `192.168.1.10`
- Machine B: `stone-05` at `192.168.1.15`
- A third machine C (`stone-09` at `192.168.1.22`) for multi-member tests
- A plain HTTP service (e.g., `python3 -m http.server 3000`) available on Machine B for proxy tests
- TOTP code available (either from a real authenticator or a test harness that generates codes from a known secret)

For CI, use loopback interfaces with different ports to simulate separate machines. mDNS tests that require actual multicast should be marked `#[ignore]` in CI and run manually.

---

## Phase 0: Restructure

### P0 — CLI Migration

| ID | Test | Expected | Auto? |
|----|------|----------|-------|
| P0-01 | Run `koi mdns discover` | Executes discovery (same behavior as old `koi discover`) | ✓ |
| P0-02 | Run `koi mdns announce` | Executes announcement (same behavior as old `koi announce`) | ✓ |
| P0-03 | Run `koi mdns status` | Shows discovered services (same behavior as old `koi status`) | ✓ |
| P0-04 | Run old command `koi discover` | Executes successfully AND prints deprecation warning to stderr | ✓ |
| P0-05 | Run old command `koi announce` | Executes successfully AND prints deprecation warning to stderr | ✓ |
| P0-06 | Run `koi status` | Shows unified dashboard with mDNS line | ✓ |
| P0-07 | Run `koi version` | Prints version, build date, feature flags, git hash | ✓ |
| P0-08 | Run `koi mdns discover --json` | Returns valid JSON array of discovered services | ✓ |
| P0-09 | Run `koi status --json` | Returns valid JSON object with capability statuses | ✓ |
| P0-10 | Run `koi help` | Shows all capability monikers with descriptions | ✓ |
| P0-11 | Run `koi mdns help` | Shows mDNS subcommands only | ✓ |

### P0 — REST API Migration

| ID | Test | Expected | Auto? |
|----|------|----------|-------|
| P0-20 | GET `/v1/mdns/discover` | Returns service list (same as old `/discover`) | ✓ |
| P0-21 | GET `/v1/mdns/status` | Returns status (same as old `/status`) | ✓ |
| P0-22 | GET old endpoint `/discover` | Returns 301 redirect to `/v1/mdns/discover` | ✓ |
| P0-23 | GET old endpoint `/status` | Returns 301 redirect to `/v1/mdns/status` | ✓ |
| P0-24 | GET `/v1/status` | Returns unified status JSON | ✓ |

### P0 — Workspace Structure

| ID | Test | Expected | Auto? |
|----|------|----------|-------|
| P0-30 | `cargo build` | Compiles successfully from workspace root | ✓ |
| P0-31 | `cargo build --no-default-features --features mdns` | Compiles with mDNS only, no crypto dependencies | ✓ |
| P0-32 | `cargo test` | All existing tests pass without modification to test logic | ✓ |
| P0-33 | Inspect workspace `Cargo.toml` | Placeholder crates exist for certmesh, dns, health, proxy | ✓ |

---

## Phase 1: Moniker Infrastructure + mDNS Enhancements

| ID | Test | Expected | Auto? |
|----|------|----------|-------|
| P1-01 | Register a mock capability, run `koi status` | Dashboard shows the mock capability's status line | ✓ |
| P1-02 | Advertise `_certmesh._tcp` via mDNS | Service appears in `koi mdns discover` on another machine | Manual |
| P1-03 | Advertise `_dns._udp` via mDNS | Service appears in `koi mdns discover` on another machine | Manual |
| P1-04 | Start mDNS, wait for a service to appear, then disappear | Event system fires `ServiceAppeared` and `ServiceDisappeared` events | ✓ |
| P1-05 | Check last-seen timestamp on a discovered service | Timestamp is present, updates on subsequent sightings | ✓ |
| P1-06 | Verify `~/.koi/` directory structure is created on first run | `config.toml`, `certs/`, `state/`, `logs/` subdirectories exist | ✓ |
| P1-07 | Verify `~/.koi/config.toml` is valid TOML | Parseable with default values | ✓ |

---

## Phase 2: Certmesh Core

### P2 — CA Creation

| ID | Test | Expected | Auto? |
|----|------|----------|-------|
| P2-01 | Run `koi certmesh create` with profile "Just Me" | CA created, QR code displayed, self-signed cert written to `~/.koi/certs/stone-01/` | Manual |
| P2-02 | Verify CA key is encrypted at rest | `~/.koi/certmesh/ca/` contains encrypted key file, not plaintext PEM | ✓ |
| P2-03 | Verify cert files at standard path | `cert.pem`, `key.pem`, `ca.pem`, `fullchain.pem` all exist under `~/.koi/certs/<hostname>/` | ✓ |
| P2-04 | Verify `fullchain.pem` = `cert.pem` + `ca.pem` | Concatenation matches | ✓ |
| P2-05 | Verify cert file permissions (Unix) | `key.pem` is 0600, others are 0644 | ✓ |
| P2-06 | Verify self-signed cert SANs | Certificate includes: hostname, FQDN, mDNS name, all LAN IPs | ✓ |
| P2-07 | Verify mDNS advertisement | `_certmesh._tcp` appears on the network | Manual |
| P2-08 | Verify audit log first entry | `pond_initialized` with operator and profile | ✓ |
| P2-09 | Verify trust store installation | Root CA cert is in OS trust store (`update-ca-certificates` ran on Linux) | Manual |
| P2-10 | Run `koi certmesh status` | Shows roster with self, cert expiry, CA health | ✓ |

### P2 — Entropy Collection

| ID | Test | Expected | Auto? |
|----|------|----------|-------|
| P2-20 | Entropy collection with keyboard mashing | Progress bar advances, completes at 256 bits, key generated | Manual |
| P2-21 | Entropy from auto-generated passphrase | XKCD-style words displayed, key generated | Manual |
| P2-22 | Entropy mixed with system RNG | Key differs from pure keyboard input (entropy sources combined) | ✓ |

### P2 — TOTP Enrollment

| ID | Test | Expected | Auto? |
|----|------|----------|-------|
| P2-30 | Run `koi certmesh join` on Machine B | Discovers CA via mDNS, prompts for TOTP | Manual |
| P2-31 | Enter valid TOTP code | Enrollment succeeds, cert files written to `~/.koi/certs/stone-05/` | ✓ |
| P2-32 | Enter invalid TOTP code | Enrollment fails with clear error message | ✓ |
| P2-33 | Enter 3 invalid codes | 5-minute lockout triggered, subsequent valid codes rejected | ✓ |
| P2-34 | Wait for lockout to expire, enter valid code | Enrollment succeeds | ✓ |
| P2-35 | Verify TOTP comparison is constant-time | No timing difference between valid and invalid codes (use statistical test) | ✓ |
| P2-36 | Verify Machine B's cert SANs | Includes stone-05's hostname, FQDN, mDNS name, all LAN IPs | ✓ |
| P2-37 | Verify Machine B has root CA in trust store | `curl https://stone-01.lan` succeeds without `--insecure` | Manual |
| P2-38 | Verify audit log entry | `stone_joined` with host and approver | ✓ |

### P2 — Trust Profiles

| ID | Test | Expected | Auto? |
|----|------|----------|-------|
| P2-40 | Create mesh with "Just Me" profile | No approval prompt, enrollment always open | ✓ |
| P2-41 | Create mesh with "My Team" profile | Approval prompted, operator name prompted | ✓ |
| P2-42 | Create mesh with "My Organization" profile | Enrollment closed by default, approval required, operator required | ✓ |
| P2-43 | Verify profile stored in roster metadata | `trust_profile` field matches selection | ✓ |

### P2 — Cross-Machine TLS

| ID | Test | Expected | Auto? |
|----|------|----------|-------|
| P2-50 | From Machine B, `curl https://stone-01.lan` | 200 OK, no cert warnings | Manual |
| P2-51 | From Machine A, `curl https://stone-05.lan` | 200 OK, no cert warnings | Manual |
| P2-52 | Open `https://stone-05.lan` in Chrome on Machine A | Green lock, no security warnings | Manual |
| P2-53 | Open `https://stone-05.lan` in Firefox on Machine A | Green lock (if NSS trust store installed) | Manual |

---

## Phase 3: Failover + Lifecycle

### P3 — Promotion

| ID | Test | Expected | Auto? |
|----|------|----------|-------|
| P3-01 | Run `koi certmesh promote` on Machine B | TOTP verified, CA key transferred, Machine B becomes standby | Manual |
| P3-02 | Verify standby has full roster | Roster on Machine B matches Machine A | ✓ |
| P3-03 | Verify standby syncs periodically | Add Machine C to mesh on primary, verify standby picks up new member | ✓ |
| P3-04 | Verify roster sync integrity | Signed manifest validates on standby | ✓ |

### P3 — Failover

| ID | Test | Expected | Auto? |
|----|------|----------|-------|
| P3-10 | Stop Koi on primary (Machine A) | `_certmesh._tcp` disappears from mDNS | Manual |
| P3-11 | Wait 60 seconds | Standby (Machine B) promotes to primary, logs failover event | Manual |
| P3-12 | Verify new primary serves enrollments | Machine C can `koi certmesh join` against Machine B | Manual |
| P3-13 | Verify new primary renews certs | Existing members receive renewed certs from Machine B | ✓ |
| P3-14 | Restart Machine A | Machine A discovers Machine B is primary, defers to standby | Manual |
| P3-15 | Verify Machine A pulls current roster from Machine B | Machine A has Machine C in roster (added during A's absence) | ✓ |
| P3-16 | Verify no split-brain | Only one `_certmesh._tcp` primary on the network at any time | Manual |
| P3-17 | Start both A and B simultaneously (cold start) | Deterministic tiebreaker: lower hostname wins primary | ✓ |
| P3-18 | Both CAs down, verify members still work | Existing certs valid, HTTPS between members works, no renewals | Manual |

### P3 — Cert Renewal

| ID | Test | Expected | Auto? |
|----|------|----------|-------|
| P3-20 | Set cert lifetime to 5 minutes (test mode), wait for renewal | New cert files appear at standard path, old ones overwritten | ✓ |
| P3-21 | Verify `fullchain.pem` updated on renewal | New cert concatenated with CA | ✓ |
| P3-22 | Verify renewed cert SANs | Same SANs as original (plus any new DNS aliases) | ✓ |
| P3-23 | Verify audit log entry | `cert_renewed` with host and expiry | ✓ |

### P3 — Reload Hooks

| ID | Test | Expected | Auto? |
|----|------|----------|-------|
| P3-30 | Set reload hook: `koi certmesh set-hook --reload "touch /tmp/koi-reloaded"` | Hook stored in config | ✓ |
| P3-31 | Trigger cert renewal | Hook executes after cert files written, `/tmp/koi-reloaded` exists | ✓ |
| P3-32 | Set reload hook to a failing command | Renewal completes, hook failure logged as degraded, cert files still in place | ✓ |

### P3 — Unlock

| ID | Test | Expected | Auto? |
|----|------|----------|-------|
| P3-40 | Reboot Machine A (simulate by restarting Koi) | CA cannot sign, status shows "CA locked" | ✓ |
| P3-41 | Run `koi certmesh unlock` with correct passphrase | CA resumes signing | ✓ |
| P3-42 | Run `koi certmesh unlock` with wrong passphrase | Unlock fails, CA still locked | ✓ |
| P3-43 | Verify members get helpful error if CA is locked | Enrollment attempts return "CA is locked, contact administrator" | ✓ |

---

## Phase 4: Institutional Controls

| ID | Test | Expected | Auto? |
|----|------|----------|-------|
| P4-01 | Enrollment with approval required | CA terminal shows approval prompt, enrollment waits for y/N | Manual |
| P4-02 | Deny enrollment | Enrolling machine gets rejection, audit log records denial | ✓ |
| P4-03 | Open enrollment window `--duration 1m` | Enrollment succeeds within window | ✓ |
| P4-04 | Attempt enrollment after window closes | Valid TOTP rejected with "enrollment closed" message | ✓ |
| P4-05 | Auto-close after duration expires | Window closes without manual intervention | ✓ |
| P4-06 | Create mesh with `--operator "Test User"` | Operator name in roster metadata and audit log | ✓ |
| P4-07 | Create mesh with `--subnet 192.168.1.0/24` | Cert request from IP outside subnet refused | ✓ |
| P4-08 | Create mesh with `--domain "test.local"` | Cert request for hostname outside domain refused | ✓ |
| P4-09 | Scope violation logged | Audit log records refused request with reason | ✓ |
| P4-10 | `koi certmesh compliance` with personal profile | Simple health check output | ✓ |
| P4-11 | `koi certmesh compliance` with organization profile | Full audit-ready summary with all fields | ✓ |
| P4-12 | `koi certmesh rotate-secret` | New QR code, old codes invalid, existing members unaffected | Manual |
| P4-13 | Attempt enrollment with old TOTP after rotation | Rejected | ✓ |
| P4-14 | Enroll new member with new TOTP after rotation | Succeeds | ✓ |

---

## Phase 5: Backup, Restore, Hardening

| ID | Test | Expected | Auto? |
|----|------|----------|-------|
| P5-01 | `koi certmesh backup` | Prompts for confirmation ("Type EXPORT"), creates encrypted file | ✓ |
| P5-02 | Backup file is encrypted | File is not readable as plaintext, no PEM headers visible | ✓ |
| P5-03 | `koi certmesh restore` with correct passphrase | CA rebuilt, roster restored, audit log restored | ✓ |
| P5-04 | `koi certmesh restore` with wrong passphrase | Restore fails, clear error message | ✓ |
| P5-05 | After restore, existing members can connect | Cert chain still valid, heartbeat succeeds | Manual |
| P5-06 | After restore, new members can join | Enrollment works with the restored TOTP secret | Manual |
| P5-07 | `koi certmesh revoke stone-05` | stone-05 added to revocation list | ✓ |
| P5-08 | Revocation list pushed to members | Other members see stone-05 as revoked | ✓ |
| P5-09 | Revoked member's certmesh connections rejected | stone-05 cannot connect to CA's certmesh API | ✓ |
| P5-10 | Revoked member's existing cert still works for TLS (until expiry) | HTTPS to stone-05 still works (cert is technically valid) | Manual |
| P5-11 | After 30-day cert expiry, revoked member's TLS fails | Cert expired, not renewed (member is revoked) | Manual |
| P5-12 | Verify `zeroize` on key material | Key structs implement `ZeroizeOnDrop` (compile-time check) | ✓ |
| P5-13 | Verify no secrets in logs | `RUST_LOG=trace`, run enrollment — no TOTP codes, keys, or passphrases in output | ✓ |

---

## Phase 6: Local DNS Resolver

### P6 — Basic Resolution

| ID | Test | Expected | Auto? |
|----|------|----------|-------|
| P6-01 | `koi dns serve` starts on port 5353 (high port for tests) | Listening, no errors | ✓ |
| P6-02 | `koi dns add test.lan 192.168.1.99` | Static entry added | ✓ |
| P6-03 | `dig test.lan @localhost -p 5353` | Returns A record: 192.168.1.99 | ✓ |
| P6-04 | `koi dns remove test.lan` | Static entry removed | ✓ |
| P6-05 | `dig test.lan @localhost -p 5353` after removal | NXDOMAIN | ✓ |
| P6-06 | `koi dns list` | Shows all resolvable names with sources | ✓ |
| P6-07 | `koi dns lookup test.lan` | Shows resolution result (diagnostic) | ✓ |
| P6-08 | `koi dns status` | Shows registered names count, upstream config, zone | ✓ |

### P6 — Record Sources

| ID | Test | Expected | Auto? |
|----|------|----------|-------|
| P6-10 | Add static entry, also have certmesh SAN for same name | Static entry wins (priority 1) | ✓ |
| P6-11 | Certmesh member `stone-05` enrolled | `stone-05.lan` resolves to stone-05's IP (from certmesh SANs) | ✓ |
| P6-12 | mDNS discovers `_grafana._tcp` on stone-05 | `grafana.lan` resolves to stone-05's IP (service alias) | ✓ |
| P6-13 | Two machines advertise `_grafana._tcp` | `grafana.lan` returns both IPs (round-robin) | ✓ |
| P6-14 | Two instances: `grafana-stone-05.lan` and `grafana-stone-09.lan` | Each resolves to its specific machine's IP | ✓ |
| P6-15 | `koi dns list` shows source for each name | Static, certmesh, or mDNS clearly labeled | ✓ |

### P6 — Upstream Forwarding

| ID | Test | Expected | Auto? |
|----|------|----------|-------|
| P6-20 | `dig google.com @localhost -p 5353` | Returns valid A record (forwarded upstream) | ✓ |
| P6-21 | `dig nonexistent.lan @localhost -p 5353` | NXDOMAIN (not forwarded — `.lan` is our zone) | ✓ |
| P6-22 | Set upstream to unreachable IP | Non-local queries timeout with appropriate error, local zone still works | ✓ |

### P6 — Security

| ID | Test | Expected | Auto? |
|----|------|----------|-------|
| P6-30 | `koi dns add evil.lan 8.8.8.8` | Rejected: RFC 1918 enforcement (public IP in local zone) | ✓ |
| P6-31 | `koi dns add evil.lan 192.168.1.50` | Accepted: private IP is fine | ✓ |
| P6-32 | Send 1000 queries in 1 second | Rate limiting kicks in, excess queries dropped | ✓ |
| P6-33 | Verify query logging off by default | No DNS query log entries at default log level | ✓ |
| P6-34 | Set `RUST_LOG=debug`, verify query logging | DNS queries appear in debug output | ✓ |

### P6 — SAN Feedback Loop

| ID | Test | Expected | Auto? |
|----|------|----------|-------|
| P6-40 | DNS creates alias `grafana.lan` for stone-05 | Certmesh is notified of new alias | ✓ |
| P6-41 | Trigger cert renewal on stone-05 | New cert includes `grafana.lan` in SANs | ✓ |
| P6-42 | Verify `curl https://grafana.lan` after renewal | TLS validates (cert SAN matches DNS name) | Manual |

---

## Phase 7: Network Health

### P7 — Machine Health

| ID | Test | Expected | Auto? |
|----|------|----------|-------|
| P7-01 | `koi health status` with all machines up | All machines show "✓ up" with last-seen timestamps | ✓ |
| P7-02 | Stop Koi on Machine C, wait 60s | Machine C shows "✗ down" in health status | Manual |
| P7-03 | Restart Koi on Machine C | Machine C returns to "✓ up" | Manual |
| P7-04 | Machine with cert expiring in <7 days | Health status shows expiry warning | ✓ |
| P7-05 | Machine health derived purely from existing signals | No new network traffic generated for machine health | ✓ |

### P7 — Service Health

| ID | Test | Expected | Auto? |
|----|------|----------|-------|
| P7-10 | `koi health add testhttp --http http://localhost:3000` | Check registered, first check runs immediately | ✓ |
| P7-11 | Service returns 200 | Status shows "✓ 200" | ✓ |
| P7-12 | Stop the service | Status shows "✗ connection refused" or "✗ timeout" | ✓ |
| P7-13 | `koi health add testdb --tcp localhost:5432` | TCP check registered | ✓ |
| P7-14 | Port is open | Status shows "✓ open" | ✓ |
| P7-15 | Port is closed | Status shows "✗ closed" | ✓ |
| P7-16 | `koi health remove testhttp` | Check removed, no longer appears in status | ✓ |

### P7 — State Transitions

| ID | Test | Expected | Auto? |
|----|------|----------|-------|
| P7-20 | Service goes from 200 to 502 | State transition logged: `200 → 502` | ✓ |
| P7-21 | Service goes from 502 back to 200 | State transition logged: `502 → 200` | ✓ |
| P7-22 | Service stays at 200 for 10 checks | No log entries (only transitions are logged) | ✓ |
| P7-23 | `koi health log` | Shows all state transitions with timestamps | ✓ |
| P7-24 | Machine goes offline | Transition logged: `up → down` with reason | ✓ |

### P7 — Live Watch

| ID | Test | Expected | Auto? |
|----|------|----------|-------|
| P7-30 | `koi health watch` | Terminal shows live view, refreshes every 30s | Manual |
| P7-31 | While watching, take a service down | Line turns from green to red in terminal | Manual |
| P7-32 | Ctrl+C | Clean exit, terminal restored to normal state | Manual |

---

## Phase 8: TLS-Terminating Proxy

### P8 — Basic Proxy

| ID | Test | Expected | Auto? |
|----|------|----------|-------|
| P8-01 | Start plain HTTP server on port 3000 | Accessible at `http://localhost:3000` | ✓ |
| P8-02 | `koi proxy add testapp --listen 8443 --backend http://localhost:3000` | Proxy starts, HTTPS listener on 8443 | ✓ |
| P8-03 | `curl https://localhost:8443` | Returns same content as `http://localhost:3000` | ✓ |
| P8-04 | Verify TLS certificate on proxy | Cert is from certmesh, includes machine's SANs | ✓ |
| P8-05 | `koi proxy status` | Shows active proxy with listen port and backend | ✓ |
| P8-06 | `koi proxy list` | Lists all configured proxies | ✓ |
| P8-07 | `koi proxy remove testapp` | Proxy stops, port 8443 freed | ✓ |
| P8-08 | `curl https://localhost:8443` after removal | Connection refused | ✓ |

### P8 — Cert Hot-Reload

| ID | Test | Expected | Auto? |
|----|------|----------|-------|
| P8-10 | Start proxy, then trigger cert renewal | Proxy serves new cert without restart | ✓ |
| P8-11 | Existing connections during renewal | No dropped connections during cert swap | ✓ |
| P8-12 | Verify new cert is served after renewal | `openssl s_client` shows updated cert serial | ✓ |

### P8 — Backend Safety

| ID | Test | Expected | Auto? |
|----|------|----------|-------|
| P8-20 | `koi proxy add x --listen 8443 --backend http://192.168.1.99:3000` (no --backend-remote) | Rejected: non-localhost backend requires explicit flag | ✓ |
| P8-21 | `koi proxy add x --listen 8443 --backend http://192.168.1.99:3000 --backend-remote` | Accepted with warning about unencrypted backend traffic | ✓ |
| P8-22 | `koi proxy add x --listen 8443 --backend http://localhost:3000` | Accepted, no warning | ✓ |
| P8-23 | `koi proxy add x --listen 8443 --backend http://127.0.0.1:3000` | Accepted, no warning | ✓ |

### P8 — Headers

| ID | Test | Expected | Auto? |
|----|------|----------|-------|
| P8-30 | Backend inspects `X-Forwarded-For` header | Contains client's IP address | ✓ |
| P8-31 | Backend inspects `X-Forwarded-Proto` header | Contains `https` | ✓ |

---

## Cross-Capability Integration Tests

These tests verify that capabilities compose correctly. Run after all relevant phases are complete.

### INT — mDNS + Certmesh (Phase 2+)

| ID | Test | Expected | Auto? |
|----|------|----------|-------|
| INT-01 | Start Koi on Machine A, create certmesh | `_certmesh._tcp` appears in mDNS | Manual |
| INT-02 | Start Koi on Machine B, run `koi certmesh join` | Discovers CA automatically via mDNS, no IP address needed | Manual |
| INT-03 | New mDNS service appears on enrolled machine | Certmesh includes service-related SANs in next cert renewal | ✓ |

### INT — Certmesh + DNS (Phase 6+)

| ID | Test | Expected | Auto? |
|----|------|----------|-------|
| INT-10 | Enroll Machine B, start DNS | `stone-05.lan` resolves from certmesh SAN data | ✓ |
| INT-11 | DNS generates alias `grafana.lan` → cert renewed → SAN includes `grafana.lan` | Full feedback loop completes within one renewal cycle | ✓ |
| INT-12 | `curl https://grafana.lan` after SAN feedback | TLS validates (cert SAN matches DNS name) | Manual |

### INT — DNS + Health (Phase 7+)

| ID | Test | Expected | Auto? |
|----|------|----------|-------|
| INT-20 | DNS name `stone-05.lan` resolves, machine goes down | Health detects down, DNS still returns the A record (stale but present) | ✓ |
| INT-21 | Health service check uses DNS name | `koi health add grafana --http https://grafana.lan:3000/health` works | ✓ |

### INT — Certmesh + Proxy (Phase 8+)

| ID | Test | Expected | Auto? |
|----|------|----------|-------|
| INT-30 | Add proxy for HTTP service | Proxy uses certmesh cert files automatically | ✓ |
| INT-31 | Certmesh renews cert | Proxy hot-reloads new cert, TLS still valid | ✓ |
| INT-32 | Revoke machine, proxy still serves (until expiry) | Proxy cert is technically valid until expiration | Manual |

### INT — DNS + Proxy (Phase 8+)

| ID | Test | Expected | Auto? |
|----|------|----------|-------|
| INT-40 | DNS resolves `grafana.lan`, proxy terminates TLS on that machine | `https://grafana.lan` works end to end | Manual |
| INT-41 | DNS SAN feedback includes `grafana.lan` in cert, proxy serves that cert | TLS validates in browser, no warnings | Manual |

### INT — Health + Proxy (Phase 8+)

| ID | Test | Expected | Auto? |
|----|------|----------|-------|
| INT-50 | Proxy backend goes down | Health detects service failure, proxy returns 502 | ✓ |
| INT-51 | Proxy backend comes back | Health detects recovery, proxy resumes forwarding | ✓ |

---

## End-to-End Scenarios

These are the "it all works" tests. Run as final acceptance after Phase 8.

### E2E-01: Homelab Zero to Hero

**Setup:** Two fresh machines on the same LAN. Grafana running on Machine B as plain HTTP on port 3000.

| Step | Command | Expected |
|------|---------|----------|
| 1 | Machine A: `koi certmesh create` (profile: Just Me) | CA created, QR code displayed |
| 2 | Scan QR code into authenticator | TOTP secret stored |
| 3 | Machine B: `koi certmesh join` | Discovers CA, prompts for TOTP, enrolls |
| 4 | Machine A: `koi dns serve` | DNS resolver starts |
| 5 | Verify: `koi dns list` | Shows `stone-01.lan`, `stone-05.lan`, `grafana.lan` |
| 6 | Machine B: `koi proxy add grafana --listen 443 --backend http://localhost:3000` | Proxy starts |
| 7 | Any device on LAN: open `https://grafana.lan` in browser | Green lock, Grafana dashboard, no warnings |
| 8 | `koi status` on Machine A | All 5 capabilities show healthy |

**Time to complete steps 1–7:** Under 5 minutes, without reading documentation.

### E2E-02: Failover Resilience

**Setup:** E2E-01 complete. Machine B promoted to standby.

| Step | Action | Expected |
|------|--------|----------|
| 1 | Promote Machine B: `koi certmesh promote` | Standby established |
| 2 | Kill Koi on Machine A | Primary goes dark |
| 3 | Wait 60 seconds | Machine B becomes primary |
| 4 | Machine C: `koi certmesh join` | Joins via Machine B (new primary) |
| 5 | `https://grafana.lan` still works | Proxy + DNS + TLS all unaffected |
| 6 | Restart Machine A | Defers to Machine B, becomes standby |
| 7 | `koi certmesh status` on Machine A | Shows self as standby, Machine B as primary |

### E2E-03: Organization Enrollment Ceremony

**Setup:** Fresh Machine A.

| Step | Command | Expected |
|------|---------|----------|
| 1 | `koi certmesh create --operator "Maria Santos"` (profile: Organization, scope: `test.local`, `192.168.1.0/24`) | Enrollment closed by default |
| 2 | `koi certmesh open-enrollment --duration 5m` | Window opens |
| 3 | Machine B: `koi certmesh join` | TOTP accepted, approval prompt on Machine A |
| 4 | Machine A: approve | Machine B enrolled with operator attribution |
| 5 | Wait 5 minutes | Window auto-closes |
| 6 | Machine C: `koi certmesh join` | TOTP rejected: "enrollment closed" |
| 7 | `koi certmesh compliance` | Full audit summary with all details |
| 8 | `koi certmesh log` | Every step audited with operator names |

### E2E-04: Cert Renewal Lifecycle

**Setup:** E2E-01 complete. Set cert lifetime to 2 minutes for testing.

| Step | Action | Expected |
|------|--------|----------|
| 1 | Note cert serial: `openssl x509 -in ~/.koi/certs/stone-05/cert.pem -serial` | Record serial A |
| 2 | Wait for renewal (at 80% of lifetime) | Cert files overwritten |
| 3 | Check serial again | Different serial B |
| 4 | Verify `fullchain.pem` updated | New cert in fullchain |
| 5 | If reload hook set, verify it fired | Hook command executed |
| 6 | `https://grafana.lan` still works | Proxy hot-reloaded new cert |
| 7 | `koi certmesh log` | `cert_renewed` entry |

### E2E-05: The Full Loop — Container to Browser

**Narrative test.** Start with a working mesh and DNS. Then:

1. `docker run -d -p 3000:3000 grafana/grafana` on Machine B
2. Within seconds: mDNS discovers `_grafana._tcp`
3. `koi dns list` shows `grafana.lan`
4. `koi proxy add grafana --listen 443 --backend http://localhost:3000`
5. Open `https://grafana.lan` on any device on the network
6. Green lock. Works. No config files edited. No IP addresses typed.

**This is the product promise.** If this test fails, the product isn't done.

---

## Negative Tests — What Must Not Work

These verify that security boundaries hold.

| ID | Test | Expected |
|----|------|----------|
| NEG-01 | Attempt enrollment with random 6-digit code | Rejected |
| NEG-02 | Attempt enrollment from IP outside subnet scope | Rejected with scope violation logged |
| NEG-03 | Attempt enrollment when window is closed (organization profile) | Rejected with "enrollment closed" |
| NEG-04 | Extract CA private key from enrolled member's filesystem | Key is NOT on member machines — only public CA cert and own service cert |
| NEG-05 | Add DNS static entry with public IP (e.g., 8.8.8.8) to local zone | Rejected: RFC 1918 enforcement |
| NEG-06 | Set proxy backend to remote host without `--backend-remote` | Rejected |
| NEG-07 | Access certmesh API with revoked member's certificate | Rejected |
| NEG-08 | Two CAs claim primary simultaneously | Deterministic tiebreaker resolves within seconds, one defers |
| NEG-09 | `koi certmesh backup` without typing "EXPORT" | Backup aborted |
| NEG-10 | Grep all log files for TOTP codes, private keys, passphrases | Zero matches |
| NEG-11 | Run `koi certmesh create` on a machine that is already in a mesh | Error: "Already part of a mesh. Run `koi certmesh revoke` first or use a different data directory." |
| NEG-12 | Run `koi certmesh join` when no CA is on the network | Timeout with helpful message: "No certmesh CA found on this network." |

---

## Performance Baselines

Not strict requirements, but targets that indicate healthy implementation.

| Metric | Target | Notes |
|--------|--------|-------|
| Enrollment (create → join → TLS works) | < 30 seconds | Excluding QR scan time |
| DNS query latency (local zone) | < 5ms | For cached/static records |
| DNS query latency (upstream forward) | < upstream + 10ms | Proxy overhead minimal |
| Health check cycle (30s interval) | < 1% CPU on 15-service mesh | Should be negligible |
| Proxy TLS handshake overhead | < 20ms vs. direct TLS | Proxy shouldn't noticeably slow connections |
| Cert renewal (including file write + hook) | < 5 seconds | End to end |
| Failover detection + promotion | < 90 seconds | 60s grace + processing |
| Binary size (full features, release) | < 30 MB | Reasonable for single binary |
| Memory usage (idle, 15 members) | < 50 MB RSS | Long-running daemon should be light |
| Startup time | < 2 seconds | From launch to mDNS listening |

---

## Checklist Summary

For quick reference — the must-pass gates at each phase:

| Phase | Gate Test | Pass? |
|-------|-----------|-------|
| 0 | Old commands work with deprecation notice, new `koi mdns` commands work, `--json` on all, workspace compiles | ☐ |
| 1 | `koi status` shows mDNS, event system fires on service appear/disappear, `~/.koi/` structure exists | ☐ |
| 2 | Two machines enrolled via TOTP, cert files at standard path, mutual TLS works, browser shows green lock | ☐ |
| 3 | Failover within 60s, old primary defers on return, cert renewal overwrites files, reload hook fires | ☐ |
| 4 | Org profile requires approval + operator + scope, enrollment windows auto-close, compliance summary adapts | ☐ |
| 5 | Backup/restore cycle works, revocation propagates, no secrets in logs, key material zeroized | ☐ |
| 6 | `grafana.lan` resolves, three record sources in priority order, RFC 1918 enforced, SAN feedback loop works | ☐ |
| 7 | Machine health automatic (zero config), service checks detect failures, state transitions logged, `watch` works | ☐ |
| 8 | Proxy terminates TLS for HTTP backend, cert hot-reload works, `https://grafana.lan` works end-to-end | ☐ |
| Final | E2E-05 passes: container → mDNS → cert → DNS → proxy → browser, green lock, under 5 minutes | ☐ |
