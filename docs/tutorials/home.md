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
discoveries. An empty snapshot alone does not establish discovery-provider health.

In the browser, the operator token stays in page memory and request headers, never
Home query links. Forget token or leaving the page clears it. Use HTTPS or a loopback
tunnel, not remote cleartext HTTP. Opening a service in the current browser tab
leaves Home; returning requires authenticating again.
