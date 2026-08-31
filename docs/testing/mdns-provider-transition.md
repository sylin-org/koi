# mDNS provider transition gate

This is ADR-038's physical acceptance gate. It validates one real installed Koi
against an independent LAN peer while the host provider catalog changes underneath
the running process. Unit tests and an adapter's self-publish test do not replace it.

Run on the subject host:

```bash
scripts/integration/mdns-provider-transition.sh \
  --allow-system-mutation \
  --peer user@independent-lan-host
```

The peer needs `avahi-publish-service` and `avahi-browse`, plus preconfigured SSH
authentication. The subject needs the installed `koi.service`, its normal API and
breadcrumb, Avahi, systemd-resolved, `curl`, `jq`, `ss`, and service-control
privilege. Optional environment settings are documented by `--help`.

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
failure. It never launches Koi. It asserts that the installed Koi unit scope,
activity, enablement, PID, and executable hash remain unchanged while it proves:

1. healthy Avahi collapses every route to `avahi`;
2. stopping Avahi dynamically selects `systemd-resolved+native`;
3. stopping resolved as well selects native Koi alone;
4. restoring resolved and then Avahi promotes only after stability;
5. ordinary and explicit-address Koi publications remain visible from the peer;
6. a peer publication remains resolvable through Koi in every plan;
7. one long-lived Koi subscription survives provider generations;
8. withdrawals reach the peer; and
9. provider activity/enablement and the single installed Koi are restored exactly.

Evidence is retained under `target/mdns-provider-transition/<run-id>/`. A failed
restoration is itself a failed run and is printed prominently. Do not weaken the
gate to a second daemon, alternate ports, a loopback peer, or adapter-local
self-observation.

On Windows, preserve the same story and invariants while substituting its catalog:
official Windows DNS-SD, installed Apple Bonjour/mDNSResponder, then native Koi.
Provider-specific mutations must be baseline-captured and restored by the Windows
agent; there is still one installed Koi service and one owner per capability route.
