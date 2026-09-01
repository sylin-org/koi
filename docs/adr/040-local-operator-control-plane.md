# ADR-040: Authenticated local operator control plane

- **Status:** Accepted
- **Date:** 2026-09-01
- **Supersedes/relates:** ADR-011, ADR-031, ADR-033, ADR-035, ADR-039

## Context

The daemon access token (DAT) is intentionally written owner-only. That is correct for a
foreground or per-user daemon, but an installed machine service owns the breadcrumb as
root/SYSTEM while the workbench and CLI run as the interactive operator. Making the file
world-readable would turn every local account into a Koi administrator. Hard-coding port
5641 in the workbench also fails when the installer has legitimately shifted the port trio.

The existing Unix socket/named pipe carried mDNS NDJSON only, was skipped when mDNS was
disabled, and trusted filesystem defaults rather than a declared workstation principal.
Its connection loops manually notified mDNS after EOF; any writer error returned first and
left session registrations alive. Windows' default named-pipe DACL is not an authorization
policy for a machine control plane.

## Decision

Koi has one trusted machine-local control transport. It is part of the installed daemon,
not a helper process or second service.

1. `koi install` captures one operator principal while elevation provenance is available:
   the sudo/pkexec caller's UID on Unix and the elevated user's SID on Windows. Packages and
   direct-root installs can state it with `--operator`. The machine-owned policy is stored as
   `state/local-access.json`; it contains no secret.
2. The daemon keeps the DAT breadcrumb owner-only. A versioned `access` request returns the
   running HTTP endpoint, DAT, and resolved data root only over the authenticated local
   transport. The data root is additive and optional on the wire: older clients ignore it,
   while newer clients talking to an older daemon report it as unknown and never infer an OS
   default. A disabled HTTP adapter returns a real typed error.
3. The Unix socket is `0600`, owned by the recorded UID, and every accepted connection's peer
   UID is verified. The Windows pipe has an explicit protected DACL for SYSTEM,
   Administrators, and the recorded SID; remote clients are rejected and the connected
   process token SID is verified before any bytes are answered. Authorization failure is a
   silent connection rejection and never a token-bearing response.
4. CLI, MCP, and desktop local discovery try a readable private breadcrumb first and then
   the local transport. A desktop may have `XDG_RUNTIME_DIR` while a machine service does
   not, so discovery checks both the user runtime and machine runtime socket. Explicit
   `--endpoint` remains a separate remote trust decision and never inherits the local DAT.
5. Local control is independent of mDNS. The same connection may also carry the existing
   provider-neutral mDNS NDJSON protocol when mDNS is enabled; otherwise those requests get
   `capability_disabled` while access still works.
6. mDNS owns transport session lifetime through `RegistrationSession`. Its `Drop` drains all
   session leases after EOF, cancellation, parse failure, or writer failure. Transports do
   not remember to perform domain cleanup themselves.

The wire types live in `koi-common`, operator policy in `koi-config`, synchronous discovery
in `koi-client`, platform authentication in `koi-serve::local_ipc`, and UI adaptation in the
desktop's single `local_daemon` module. No HTTP endpoint bypasses DAT authentication.

## Consequences

- The real root/SYSTEM service and ordinary workbench user share one secure deployment.
- Shifted HTTP ports propagate automatically to the CLI, MCP server, desktop streams,
  mutations, tray posture, and pond QR target.
- The workbench can show a custom or platform-default data root exactly as the running daemon
  resolved it. Public `/v1/status` and the LAN Pond bundle do not disclose that machine-local
  path; browser mode hides the tile.
- Service upgrades should run through `koi install` once to capture the desired operator.
  A pre-policy foreground daemon safely falls back to its own identity and logs that fact.
- Another local account cannot use the socket merely because it knows the path. Root and
  administrators can still read machine state by virtue of their OS authority; the IPC
  surface does not expand that privilege.
- The local protocol is deliberately small. Future operator-only operations extend the
  versioned contract rather than adding shared files, loopback auth exemptions, or helpers.

## Validation

- Wire tests pin the versioned request, current access response, and deserialization of a
  legacy response without `data_root`.
- Client and serving-stack suites exercise both breadcrumb and authenticated transport paths;
  strict clippy covers the shared implementation and a Windows GNU target check covers the
  Windows service composition root.
- On Bluefin, one root-owned installed daemon exposed its owner-private socket to the recorded
  UID. The native 0.1.1 workbench consumed that handoff after a real reboot and its live
  Wayland accessibility text contained `/var/lib/koi`. Public `/v1/status` lacked the field,
  the published Pond bundle contained no local path, and exactly one daemon/UI remained.
