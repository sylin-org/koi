# Pond needs an independently managed read-only LAN listener

## Impact

The workbench's **Phone** action says it will open the same view “on any screen
on this network.” On a standard secure Koi install it publishes the UI files and
builds a QR URL from the machine's LAN address, but the only HTTP listener remains
`127.0.0.1:5641`. The generated URL is therefore unreachable from the phone or
any independent host.

Silently changing the full daemon API to `0.0.0.0` is not an acceptable fix. The
loopback default is deliberate, and several GET surfaces expose operator/network
state even though mutations remain DAT-gated.

## Physical reproduction (Bluefin, 2026-09-01)

1. Install one system daemon with the default configuration and native workbench
   RPM; verify `ss` reports `127.0.0.1:5641`.
2. Invoke **Phone** through the real GNOME/Wayland workbench. The authenticated
   `PUT /v1/ui` succeeds and local `GET /` changes from 503 to 200.
3. From test-01, request the exact LAN target:

   ```text
   curl http://192.168.1.95:5641/healthz
   curl: (7) Failed to connect to 192.168.1.95 port 5641
   ```

The published 0.1.1 bundle itself is safe: it contains no `%ProgramData%` or
`/var/lib/koi`, `body.readonly #data-root-tile` is present, and public
`/v1/status` has no `data_root` field.

## Architectural acceptance

Keep the full operator API loopback by default. Model Pond exposure as its own
small runtime adapter/lifecycle, activated by an authenticated local operator
action:

1. It owns a real LAN listener and returns an advertised URL only after the bind
   is reachable. Port/interface/firewall assessment and failure belong to this
   adapter, not to UI guesswork.
2. Its router is read-only and contains only the Pond assets and explicitly
   selected read models/events required by browser mode. It does not mount the
   mutation router or inherit a local DAT exemption.
3. Activation, interface churn, restart recovery, disable, and shutdown are
   idempotent and visible in structured capability state. There is one daemon,
   not a helper service or parallel backend.
4. The workbench consumes the returned URI; it never constructs a LAN URL from
   routing-table heuristics and never claims success before the listener settles.
5. Acceptance uses a second physical host to open the URL and exercise read-only
   parity, while tokenless mutations and excluded reads are refused. Cleanup
   restores any firewall/listener state exactly.

This is the minimum meaningful separation: one Pond adapter and one deliberate
read-only router, composed by the existing serving layer. It should not become a
second domain model or a generic remote copy of the operator API.
