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

Both hosts need exactly one installed `koi.service`, its normal loopback API and
breadcrumb, plus preconfigured SSH authentication. The subject also needs Avahi,
systemd-resolved, `curl`, `jq`, `ss`, and service-control privilege. The peer login
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

The gate captures the service/socket enablement, activity, and resolved mDNS
configuration baseline before any mutation and installs cleanup before it starts.
If resolved is running with mDNS disabled, the gate uses a run-owned volatile
drop-in under `/run/systemd/resolved.conf.d/` and enables mDNS only on the LAN link
used for the peer. Resolved socket-activation units, when present, are stopped for
the native-only phase; a runtime-only mask prevents D-Bus or socket activation
from quietly restarting resolved during peer traffic. Configuration, service,
trigger-socket, and runtime-mask baselines are all restored exactly, including on
failure. It never launches Koi. It asserts that both installed Koi unit scopes,
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

On Windows, preserve the same story and invariants while substituting its catalog:
official Windows DNS-SD, installed Apple Bonjour/mDNSResponder, then native Koi.
Provider-specific mutations must be baseline-captured and restored by the Windows
agent; there is still one installed Koi service and one owner per capability route.
The exact candidate must first be deployed through the product install/upgrade path.
A standalone core or control-plane example beside an untouched installed service is
useful only for diagnosis and is not acceptance evidence.
