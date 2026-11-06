# Find and open a service

**Services** is the first destination of Koi's interface. Open it with
`koi launch`, which opens `http://localhost:5641/ui` in your browser, or from the
desktop app. The browser view asks for the daemon access token (`koi token show`
prints it); the token stays in that page's memory and **Forget token** clears it.

## Search and filter

Type in **Search services**, then press Enter or **Apply**. Every word must match
some part of a service: its name or friendly name, its host or device name, a
device address, an endpoint or its category (Web, API, Printer, Database, Runtime,
Proxy or other). Word order and case do not matter, so `office web` can find a
forgotten web app on an office workstation.

The **Host**, **State** and **Sort** controls narrow and order the same list.
State includes **Needs attention** and **Absent**. **Clear filters** returns to
the complete list.

## Inspect a service

Select a service name to open its details: host, endpoints, checks and source
evidence. Details sit beside the list on a wide window and open as a modal dialog
on a narrow one; Escape closes them and returns focus to the service's row.

If a filter excludes the selected service, or the service leaves the catalog, the
view says "The selected service is no longer in this view." It never substitutes
another service, even one with the same name. Unmanaged discovery identities may
change after a daemon restart; select the service again once it is rediscovered.

## Open a service

**Open** appears only for a web endpoint that the catalog grants Open and whose
HTTP(S) destination passes Koi's strict validation, including its real port and
path. API-only, absent, stale, ambiguous or unsafe endpoints show their address
instead of an invented link. The desktop app's shared pane does not offer Open yet;
it shows the address. Discovery does not prove reachability, permission or TLS
trust: a listed service can still refuse you or present a certificate your browser
does not trust.

If the browser reports that the service's name cannot be resolved, see
[Services lists a service, but Open says its name cannot be resolved](../guides/troubleshooting.md#services-lists-a-service-but-open-says-its-name-cannot-be-resolved).

## Updates and stale evidence

The browser view re-reads the catalog five seconds after each completed read while
the page is visible. Background reads keep your focus, unsent search text,
selection and expanded details. **Refresh** reads immediately.

If Koi becomes temporarily unreachable, the last view stays on screen marked
**Stale evidence**, its Open controls are disabled, and reads retry after 1, 2, 4,
8 and then every 15 seconds. The first successful read clears the marker. If the
token is rejected, or the daemon returns unexpected content, the view is cleared
and the token forgotten; enter the token again to continue.

## Discovery status

Above the list, Services reports what local-network discovery is doing. The
status comes from the daemon's mDNS browse routes, not from the number of rows:

- **Not reported:** the daemon did not report a status, for example an older
  version. An empty list is not proof that the network is empty.
- **Observing:** discovery is watching the local network. A listed service is not
  proof that it is reachable.
- **Partially unavailable:** some services may be missing.
- **Unavailable:** services from saved or other sources may remain.

The last two offer **Inspect mDNS sources**, which opens the mDNS destination.

## Empty views

- **No services found yet:** discovery is observing and the catalog is empty.
- **No services in this snapshot:** the catalog is empty but discovery is not
  confirmed to be observing; this is not proof that the network is empty.
- **No services match these filters:** the catalog has services, but the search or
  filters exclude all of them. Use **Clear filters**.
- **Cannot read the local catalog:** Koi could not be read. Check that it is
  running, then refresh. This is an access or service problem, not zero
  discoveries.
