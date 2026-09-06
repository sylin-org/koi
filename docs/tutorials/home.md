# Find and open a service from Home

These controls are on the development shared Home view, not a claim about an older
installed package. Use the native workbench or the authenticated `/ui` operator view.

Enter a friendly name, alias, device name, address, endpoint host or category in
**Search services**, then press Enter or Search. Multiple words must all match.
For example, `office web` can find a forgotten Notes app on an office workstation.
Favorites appear first; check **Favorites only** and submit to restrict the list.
**Clear filters** restores the list without silently changing the selected identity.
Existing favorite/alias editing and watched-item import remain in Advanced tools.

Select a service name to inspect its device, endpoint, check observer/time and
source details. Details sit alongside the list on a wide window; on a narrow
window they take focus, with **Back to services** returning to the list.
Automatic updates keep that narrow details route visible. If the selected identity
leaves the catalog, Home says so instead of choosing a same-named replacement.
Unmanaged discovery identities may change after a daemon restart; the service can
then be selected again when rediscovered.

**Open** uses the displayed HTTP(S) destination, including its real port and path.
The native workbench opens it through your system's browser association. API-only,
absent, ambiguous or unsafe destinations show connection details instead of an
invented dashboard. Discovery does not prove reachability, permission or browser
TLS trust. An absent favorite remains a saved reference, not an available service.

Home reads authoritative snapshots automatically, five seconds after each successful
read. It preserves submitted search, favorite filter and selection, plus an unsent
search draft, focus and expanded details during background updates. **Refresh snapshot**
is an optional immediate read, not a recovery requirement. Temporary connection loss
marks retained evidence stale and disables old Open links; retries back off from one
to fifteen seconds and recover automatically. Browser access/schema rejection instead
clears the view and requires sign-in again. “No matches” means the filter excluded the snapshot's services;
“Cannot read the local catalog” means an access/service/schema problem, not zero
discoveries. The separate local-network discovery status reports whether demanded
browse routes are observing, partially unavailable, unavailable, or not reported.
It comes from the daemon, not the number of service rows. Older daemons report no
status and therefore show unknown, never an invented healthy result. Saved or
other-source services can remain visible while network discovery is unavailable.

In the native app, choose **Browser access**, enable **Allow browser access**, and
choose **Open in browser**. From a local terminal, `koi launch` enables local browser
access and opens Home with an automatic, temporary connection. No token copying is
needed, and loopback access does not require CertMesh.

To connect a phone privately, also enable **Allow private phone access with
CertMesh**. Once HTTPS is ready, choose **Connect a device · show QR**. The CLI
provides the same flow with `koi web enable --phone`, `koi web status`, and
`koi web invite --phone`. Scan the QR, name the browser, optionally select
**Remember this browser for 30 days**, and tap **Connect**. The code works once,
expires after two minutes, and scanning/preview alone does not consume it.
Temporary access lasts for the tab, up to 12 hours. Both choices survive reload
and returning from an opened service, subject to browser storage/session restoration.

Private phone access needs a usable CertMesh certificate, name resolution, normal
certificate trust on the phone, and a reachable HTTPS port (normally 5645). Koi
reports missing prerequisites; it does not add a firewall rule or bypass a browser
certificate warning. Identity loss closes private access without switching to
HTTP. Public read-only Pond sharing remains a separate, explicitly enabled option.

Browser sessions can view and open services, not change Koi settings. Choose
**Disconnect this browser**, or disconnect a named browser in the native app.
`koi web status` lists identifiers for `koi web disconnect <id>`.
`koi web disable` revokes all sessions and closes private browser HTTPS.
The [browser access ADR](../adr/046-browser-invitations-and-sessions.md) records
storage, session scope and security boundaries. Physical phone and installed
platform acceptance are tracked separately in R07.
