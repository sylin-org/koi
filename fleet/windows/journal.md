# fleet/windows/journal.md — stone-leaded-sparkle (Windows workstation, orchestrator)

## 2026-09-01 — ADR-039 Windows leg: Win32 DNS-SD + Bonjour adapters, standalone two-host validation

commit: this commit, based on 340da23 (`8975f43` ADR-039 control plane) | gates: workspace `cargo check` clean; `cargo clippy -p koi-mdns -p koi-compose -p koi-lab --all-targets` 0 warnings; koi-mdns 110 passed / 3 environment-gated ignored; gate binary built and exercised (see below); Linux cross-target check of the changed crates blocked only by `ring`'s C toolchain on this box (no linux-gcc) — the Linux fleet gates cover it
koi state now: unchanged installed `koi` service (PID 5360, LocalSystem, `target\release\koi.exe --daemon`, API on 127.0.0.1:5641) still on the pre-ADR-039 artifact; one healthy daemon, one `_mcp._tcp` self-publication alive and peer-resolvable throughout. No firewall, service-control, or network-profile mutation was applied (an attempted profile flip was refused — shell is not elevated).

### Baseline (measured 2026-09-01, unprivileged)

- Windows 10.0.26200; hostname `stone-leaded-sparkle`; Ethernet 192.168.1.137; **network profile: Public**.
- DNS Client (`Dnscache`) Running/Automatic. `EnableMulticast` unset in both Dnscache Parameters and the Policies key (OS default = enabled).
- Firewall: all three profiles on, default inbound NotConfigured; the OS built-in `mDNS (UDP-In)` Allow rules exist for Private/Domain/Public, scoped to `svchost.exe`/`dnscache`, local port 5353.
- UDP 5353 is shared by three binders: `Dnscache` (PID 3464), the installed `koi` service (PID 5360, mdns-sd), and Chrome's cast responder (PID 14872).
- **Bonjour is NOT installed**: no `Bonjour Service`, no `C:\Program Files\Bonjour`.

### Probe findings (`tools/koi-lab/examples/win32_dnssd_probe.rs`, real dnsapi.dll calls, JSON evidence lines)

1. **Register/deregister are real and acknowledged** under the workstation identity on the Public profile: `DnsServiceRegister` returns `DNS_REQUEST_PENDING` (9506) and the completion callback carries status 0. Names are stable (no auto-rename observed), the instance name must be the **full DNS-SD form** `<label>._<type>._tcp.local`, and the OS **overrides the advertised host** to its own mDNS identity (`leo-main.local`, not `stone-leaded-sparkle.local`). `DnsServiceDeRegister` completes with status 0.
2. **Announcements reach both Linux peers**: test-01 and test-02 Avahi both emitted `+` for every probe registration.
3. **The OS responder answers nothing**: while a dnsapi record was held alive, peers received no SRV/TXT/A answers — not to Avahi multicast resolves, not to QU-flagged queries, not to unicast `dig`, not even for the OS's own `leo-main.local` A record. Cross-checked controls: Windows received test-01's multicast answers fine (3 responses), and the local **mdns-sd** stack answered peers correctly throughout (test-02's Koi fully resolved the installed daemon's `_mcp._tcp` record). Candidate causes (Public-profile suppression, competing local responders) are not isolable without elevation — this box's `sudo` is disabled and the shell is non-admin.
4. **The consumer side is fully functional**: `DnsServiceBrowse` actively queries (it found long-announced `_mcp._tcp` records on test-01/02/03 plus the local daemon), the meta-query `_services._dns-sd._udp.local` enumerates types, and `DnsServiceResolve` returned complete SRV/TXT/A data for a third-party Bonjour-class peer (ZenGarden at .82).

### Implementation

- `crates/koi-mdns/src/windows_dnsapi.rs` — `windows-dns-sd` adapter (priority 200, `Win32DnsApi`). Assesses dnsapi exports, Dnscache state, and multicast policy (read-only SCM/registry queries, cached). Session contributes the **read routes only**: continuous browse (browse+resolve two-step, mirroring mdns-sd's Resolved events), browse-resolves, and direct point resolution; a health task drives `Ready ↔ Recovering` on Dnscache stop/start. Publication is deliberately **not claimed** — finding 3 means the route would strand announcements. This mirrors the resolve1/polkit pattern from ADR-039.
- `crates/koi-mdns/src/windows_bonjour.rs` — `bonjour` adapter (priority 150, `BonjourDnsSd`), full provider minus explicit-address. dnssd.dll is **runtime-loaded** (LoadLibrary + typed bindings; no import library and no load failure when absent); add/remove browse events map to Found/Removed, register/reply and resolve are acknowledged, conflicts map to typed errors. Bonjour is absent here, so `assess` reports `Absent` honestly and the session paths are real-but-unexercised — validation is pending a genuinely installed Bonjour (ignored tests included).
- Composition (`koi-compose/src/mdns.rs`) lists both ahead of the reserved native provider. The armed plan on this box is the designed composite: **`publish=native, browse=windows-dns-sd, resolve=windows-dns-sd`**.
- A live defect was caught and fixed during validation: `DnsServiceResolve` requires the full instance name while the control plane hands sessions the bare label — the adapter now joins label+regtype (unit-tested).

### Validation (standalone `koi --standalone mdns …`, artifact `target-gate/release/koi.exe`)

- Standalone core armed `publish=native, browse=windows-dns-sd, resolve=windows-dns-sd` (log line evidence).
- Windows → peers: `koi --standalone mdns announce` published via the native route; test-01's Avahi fully resolved it (`stone-leaded-sparkle.local / 192.168.1.137 / 43191 / "source=win-gate" "phase=adr039"`), test-02's Koi API resolved the same record with full TXT. A pinned-address announcement resolved with the pinned IP. After the acknowledged timeout withdrawal, Avahi emitted the `-` removal on the peer.
- Peers → Windows: `koi --standalone mdns discover` (meta and `_mcp._tcp`) enumerated types and resolved all four LAN Koi records through the dnsapi route; `koi --standalone mdns resolve "Koi MCP (test-02)._mcp._tcp.local"` returned host/IP/port/TXT via `DnsServiceResolve`.
- Peer-side probe evidence retained in this entry; capture files on the peers under `/tmp/win-probe-*.txt`, `/tmp/gate2b.txt`.

### Open items (honest residue)

1. **Dnscache responder silence** (finding 3) is the one defect blocking `windows-dns-sd` from claiming publication. Isolation needs elevation (flip the profile to Private, stop Chrome/koi responders, or capture 5353 with pktmon). If a probe proves peers can resolve dnsapi records, the descriptor widens and publication moves to the official API.
2. **Installed-service transition gate**: the deployment still runs the pre-ADR-039 artifact. Redeploying needs elevation (rename-locked-exe + graceful shutdown works only if SCM failure-actions restart; a graceful stop needs `sc start` rights). The two-host installed-service Windows gate (docs/testing/mdns-provider-transition.md adaptation) runs after that.
3. **Bonjour validation** on a host that genuinely has it (install Bonjour Print Services or use a machine with iTunes components).
4. Windows DNS cache serves stale mDNS records after a publisher dies (observed: a withdrawn record still resolved locally from cache until TTL) — platform cache behavior, noted for consumers.
