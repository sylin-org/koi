# omarchy-linux — journal

## 2026-08-31 12:40 UTC — canary v2 (orchestrator-driven)
commit: da6032b | gates: cargo check -p koi-net →     Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.27s
koi state now: standing daemon on port 5641 (untouched by the canary)
stack: Hyprland gnome-keyring-d start-hyprland 
ladder (head): {"capabilities":[{"healthy":false,"name":"mdns","summary":"skipped: avahi-daemon is active"},{"healthy":true,"name":"certmesh","summary":"ready — run certmesh create"},{"healthy":false,"name":"dns","summary":"stopped"},{"healthy":true,"name":"health","summary":"0 services up (0 total)"},{"healthy"
findings: none (canary run)

## 2026-08-31 20:35 EDT — ADR-039 independent-peer gate
commit: ADR-039 implementation in the shared test-01 checkout | role: independent Koi API peer for run `20260901T004947Z-280219`
koi state now: exactly one enabled user `koi.service`, PID 89908, `/home/test/.local/bin/koi --daemon`, installed SHA-256 `05f15f4fcd80ff720c044698f7d2eff545823e7803ca59e0e1e4170e15c8e369`; loopback API healthy; Avahi owns all routes; one desired/established permanent self-publication and zero pending/failed.
findings:
1. The existing user service was stopped, replaced in place, and restarted; no parallel daemon or alternate port was used.
2. Its Koi API created and withdrew a unique real publication during every test-01 provider phase. test-01 resolved each peer record and TXT, while this host resolved test-01's ordinary and explicit-address publications.
3. PID/hash and Avahi service/socket plus resolved service activity/enablement were byte-for-byte equal before and after the gate. This host's providers were not mutated.
