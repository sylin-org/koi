# mDNS provider transition gate

This is ADR-039's physical acceptance gate. It validates one real installed Koi
on each of two independent LAN hosts while the subject's provider catalog changes
underneath the running process. Unit tests and an adapter's self-publish test do
not replace it.

Run on the subject host:

```bash
scripts/integration/mdns-provider-transition.sh \
  --allow-system-mutation \
  --peer user@independent-lan-host
```

Both hosts need exactly one installed Koi service, its normal loopback API and
breadcrumb, plus preconfigured SSH authentication. The subject also needs Avahi,
`curl`, `jq`, `ss`, and service-control privilege. The default systemd profile
additionally requires systemd-resolved. The peer login
must read its breadcrumb and hash its running service executable directly, through
passwordless sudo, or through a peer-local `PEER_SUDO_ASKPASS` helper. The DAT and
sudo credential are consumed on the peer and never cross SSH. Optional environment
settings are documented by `--help`.

For unattended lab execution, the gate honors the standard `SUDO_ASKPASS`
mechanism and applies it to every privileged operation, including cleanup.
Password-authenticated SSH may use a local `PEER_SSH_ASKPASS`; a user-scoped
peer is selected with `PEER_KOI_SERVICE_SCOPE=user`. Optional peer sudo remains
peer-local, and an omitted `PEER_SUDO_ASKPASS` is transported as an explicit
sentinel so OpenSSH cannot collapse the argument vector.

The peer's supervisor is independent of the subject's. The gate auto-detects a
live systemd runtime or an installed OpenRC toolset; set
`PEER_KOI_SERVICE_MANAGER=systemd|openrc` only when evidence should pin that
choice. A systemd peer is tied to its `MainPID`. An OpenRC peer must report the
installed service active and enabled, expose exactly one `koi` process, and retain
its captured Avahi activity/enablement. In both cases the gate hashes the running
`/proc/<pid>/exe` directly or through peer-local sudo and rejects any PID, hash,
service, or provider-state change.

For a real per-user installation, run the gate as the unit-owning user and select
the user service manager explicitly:

```bash
KOI_SERVICE_SCOPE=user scripts/integration/mdns-provider-transition.sh \
  --allow-system-mutation \
  --peer user@independent-lan-host
```

The system scope uses `/run/koi.endpoint`; the user scope uses
`$XDG_RUNTIME_DIR/koi.endpoint` by default. Provider mutations remain system-level
in both modes and therefore still require local service-control privilege.

On an OpenRC host with Avahi installed but stopped as its normal baseline, select
the capability-appropriate profile (the manager is auto-detected, but spelling it
out makes retained evidence self-describing):

```bash
KOI_SERVICE_MANAGER=openrc \
MDNS_PROVIDER_PROFILE=openrc-avahi-native \
scripts/integration/mdns-provider-transition.sh \
  --allow-system-mutation \
  --peer user@independent-lan-host
```

That profile starts Avahi and proves all routes select it, stops Avahi and proves
native publish/browse continuity, then starts Avahi again and proves promotion.
Cleanup returns Avahi to the captured stopped/enablement state. It reports the absent
activation socket and resolved provider as absent instead of manufacturing either
facility. The cross-host publication, explicit-address publication, long-lived
subscription, removal, synchronization, process-identity, and peer-restoration
assertions are identical to the systemd profile.

The gate captures the service/socket enablement, activity, and resolved mDNS
configuration baseline before any mutation and installs cleanup before it starts.
If resolved is running with mDNS disabled, the gate uses a run-owned volatile
drop-in under `/run/systemd/resolved.conf.d/` and enables mDNS only on the LAN link
used for the peer. External responder mutation is break-before-make: the initial
Avahi plan is proved before resolved is armed; Avahi is fully stopped before the
gate enables resolved mDNS; and resolved returns to its captured mDNS configuration
before Avahi is restarted. This avoids manufacturing a host-name conflict between
two system responders while still exercising every Koi route plan. Avahi's service
requires its activation socket, so the gate runtime-masks both activation paths,
stops the service before the socket, and unmasks both only when restoration is safe.
Resolved socket-activation units, when present, are stopped for the native-only
phase; its own runtime-only mask prevents D-Bus or socket activation from quietly
restarting it during peer traffic. Configuration, service, trigger-socket, and
runtime-mask baselines are all restored exactly, including on failure. Restoration
is idempotent so cleanup cannot re-arm a provider after the final phase. It never
launches Koi. It asserts that both installed Koi service scopes,
activity, enablement, PIDs, and executable hashes remain unchanged; the peer's
provider services must also remain byte-for-byte equal to their captured facts.
Route decisions are checked through `control_plane` fields on
`/v1/mdns/admin/status`; the gate never parses the human capability summary.
Every cross-host synchronization assertion uses a bounded settle loop and stores
the exact structured peer status it accepted; one instantaneous observation is
not treated as a convergence verdict.
It proves:

1. healthy Avahi collapses every route to `avahi`;
2. stopping Avahi dynamically selects `systemd-resolved+native`;
3. stopping resolved as well selects native Koi alone;
4. restoring resolved and then Avahi promotes only after stability;
5. ordinary and explicit-address subject publications remain resolvable by peer Koi;
6. a peer Koi publication remains resolvable by subject Koi in every plan;
7. one long-lived Koi subscription survives provider generations;
8. withdrawals reach the peer; and
9. desired and materialized publication counts converge with no pending failures;
10. subject provider state and both installed Koi processes are restored exactly.

Evidence is retained under `target/mdns-provider-transition/<run-id>/`. A failed
restoration is itself a failed run and is printed prominently. Do not weaken the
gate to a second process on either host, alternate ports, a loopback peer,
adapter-local self-observation, or an Avahi helper standing in for peer Koi.

The CachyOS/Omarchy reference execution
`20260901T004947Z-280219` passed all five phases with test-01 PID `280122` and
test-02 PID `89908` unchanged on artifact SHA-256
`05f15f4fcd80ff720c044698f7d2eff545823e7803ca59e0e1e4170e15c8e369`.
Generations 1–5 selected `avahi → systemd-resolved+native → native →
systemd-resolved+native → avahi`; every phase held three desired and three
established publications with zero pending/failed, and cleanup restored all
captured unit, socket, enablement, and resolved-link facts.

The Bluefin reimage reference execution
`20260901T205042Z-45196` repeated the gate after test-02 was reimaged. The
unchanged Bluefin subject was system PID `37751`, SHA-256
`8a0a14dda27b49dbd72f0bfeb79efc3e73cb3392c144c74924f2443f73bb6b27`;
the unchanged test-01 peer was system PID `404624`, SHA-256
`1a994a78b8b40218bd27abf76f992db60b9fc42124187a43cf782c8ca887581c`.
Generations 9–13 selected `avahi → systemd-resolved+native → native →
systemd-resolved+native → avahi`, with three desired/established publications
and zero pending/failed in every phase. The native-only structured plan has no
`resolve` route because the embedded provider deliberately does not claim direct
point resolution; its continuous browse/cache still carried the gate's physical
peer resolution. Missing JSON keys must therefore be compared to provider
capabilities, not interpreted as a crashed control plane. Cleanup restored
resolved's original global/link `MulticastDNS=no`, all activation sockets, and
Avahi exactly.

The current candidate reference execution `20260902T004825Z-546815` ran from
CachyOS against Bluefin after ADR-042 deployment. The unchanged test-01 subject
was system PID `542996`, SHA-256
`8e3b94a9cfcaaa66f8c751bbb10e59f5b2196a2057d848c0ff8020d9395e24c3`;
the unchanged Bluefin peer was system PID `9720`, SHA-256
`89bc5ed0f0edfa7fd9163847a5cab0b23fa3a03fed9fc32789e39ea4d690658f`.
Generations 1–5 again selected `avahi → systemd-resolved+native → native →
systemd-resolved+native → avahi`, with three desired/established publications
and zero pending/failed throughout. The gate restored Avahi, resolved, their
activation sockets, global/link mDNS configuration, both Koi units, PIDs, and
artifact hashes to the captured baseline.

The Alpine OpenRC reference execution `20260903T014605Z-1730` ran from test-03
against the unchanged Debian test-04 peer. The Alpine subject stayed on supervised
PID `2688`, SHA-256
`8cedf10927a75189ac1e98262116b157138a9a994c55e650d292107202af3003`;
the Debian peer stayed on system PID `24507`, SHA-256
`a74edba5e75402fef9f5364b87ef2a60dac2ddd01c432371314a0df313ce491f`.
Generations 2–4 selected `avahi → native → avahi`, with three desired and three
established publications and zero pending/failed in every phase. Cleanup returned
test-03 to generation 5 native routing with Avahi installed but stopped and
disabled. A separately pre-armed `ifup` then recovered a real `eth0` down/up cycle
to the captured `192.168.1.221/24` lease and default route; both Koi PIDs and bytes
remained unchanged, bidirectional publication/read/removal passed again, and neither
host retained a run-owned registration.

The frozen-candidate mixed-supervisor execution
`20260903T125812Z-925941` ran from CachyOS against the unchanged Alpine OpenRC
peer. The CachyOS subject stayed on system PID `924696`, SHA-256
`f0e999b0077eb25935f1ad563aee33f2e659ffde915d3f3c55f5aa568691682b`;
the Alpine peer stayed on PID `24201`, SHA-256
`4db6a257b9303157bd8dff03887b478b2c8f5a20f777166d35a59f77436a95e9`.
Generations 1–5 selected `avahi → systemd-resolved+native → native →
systemd-resolved+native → avahi`. Every settled phase held three desired and
three established publications with zero pending/failed. A real late resolve1
conflict exposed `3/1/2/0` before automatic recovery to `3/3/0/0`. Cleanup
returned CachyOS's services, activation sockets, and global/link mDNS modes and
Alpine's installed-but-stopped Avahi state exactly; both inventories again held
only their permanent publication.

On Windows, preserve the same story and invariants while substituting its catalog:
official Windows DNS-SD, installed Apple Bonjour/mDNSResponder, then native Koi.
Provider-specific mutations must be baseline-captured and restored by the Windows
agent; there is still one installed Koi service and one owner per capability route.
The exact candidate must first be deployed through the product install/upgrade path.
A standalone core or control-plane example beside an untouched installed service is
useful only for diagnosis and is not acceptance evidence.
