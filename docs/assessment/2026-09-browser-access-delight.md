# Browser access that follows the user's intent

> Parked by the owner on 2026-09-07; implementation removed.
> [ADR-046](../adr/046-browser-invitations-and-sessions.md) preserves the historical design.
> The exploration below is historical, not scheduled work or a product promise.

Original exploration date: 2026-09-06.

## Experience contract

Opening Koi through an already authorized local app or terminal should reach Home
without asking the person to retrieve a secret. Returning from an opened service,
reloading, or recovering a temporary disconnect should retain the current task.
A new browser's first authorization should explain the computer and permission
being connected. Browsing deliberately shared services should not grant management.

The primary product vocabulary is Open, Connect, Allow, and Disconnect. Token
management remains an advanced integration concern. No cloud account or browser
extension should be necessary for ordinary local access.

## Measured starting point

Source: Koi b762456, desktop 24d619f; installed shared source 17fb591.

- `crates/koi-serve/assets/ui-login.html` asks for a daemon access token before
  displaying Home; `/v1/ui/shell` requires DAT even on loopback.
- `crates/koi-serve/assets/ui-transport.js` holds DAT in page memory and clears it
  on pagehide. Returning after opening a service requires authentication again,
  as documented in `docs/tutorials/home.md`.
- ADR-040 already authenticates the local operator through Unix peer UID or
  Windows SID. Desktop/CLI can obtain local access without user secret entry.
- `crates/koi/src/main.rs` currently handles `koi launch` by constructing
  `http://localhost:{cli.port}` and opening the legacy dashboard. It does not
  discover the actual endpoint or establish a browser session.
- The native external opener exists in sibling `src/external.rs`. A browser
  connection callback/OS URI registration is not established by that opener.
- Pond remains separately enabled and read-only. Browser access must not silently
  expose the loopback operator listener or expand Pond authority.

## Proposed journeys

| Arrival | Person's actions | Proposed result |
| --- | --- | --- |
| Desktop or tray | Open in browser | Home opens authorized, ideally at the same service/search |
| Local terminal | `koi launch` | Real daemon endpoint discovered; same authorized Home |
| Previously connected browser | Open bookmark | Home resumes while its authorization remains valid |
| New local browser/direct URL | Connect with Koi; approve in the native app | Original tab proceeds automatically and retains destination |
| Deliberately shared phone view | Scan the displayed Pond QR | Permitted service list opens; no management credentials |
| New remote management browser | Request access; approve exact request on an authorized device | Scoped access over a verified secure connection, if separately supported |
| Headless installation | Authorize through the existing operator terminal/SSH access | Browser connects through an explicit secure route, without requiring a desktop |

The first two are the recommended first implementation slice. The direct-URL
journey needs one native confirmation because visiting a webpage alone must not
silently authorize it. The app-initiated Open action already expresses intent and
should not trigger another redundant confirmation. Browser/OS launch prompts may
still occur; the product must handle them honestly and preserve the initiating tab.

For a new browser, proposed copy is: “Connect this browser to Koi on Workshop?”
followed by the actual access scope and Allow/Cancel. Workshop is an illustrative
computer label. Browser names supplied by the browser are hints, not verified
identity. Show a matching code when the connection cannot otherwise be reliably
associated with the request the person initiated. Do not silently approve a pending
request merely because a native app is running.

For headless access, reuse the authenticated terminal as the approval authority.
A request-specific command/code can be an accessible fallback when automatic
opening is unavailable. No general DAT is printed into the browser workflow.
An SSH tunnel establishes reachability but does not by itself authenticate every
webpage to Koi. Do not ask the user to bind the operator API to the LAN to connect.

## Alternatives and fit

- Automatic app-to-browser handoff: best default on the same machine; reuse the
  trusted local control boundary and native opener.
- Native approval after direct browser arrival: good first-connection fallback;
  costs a context switch but makes the permission decision understandable.
- QR plus matching request confirmation: useful across devices; unnecessary
  ceremony for every same-machine launch. Scanning a QR is not identity proof.
- Passkeys: potential later return-access method for remote administration, after
  the stable HTTPS origin and recovery model exist. They do not solve first trust
  or local-origin lifecycle by themselves.
- Manual token entry: useful for advanced integrations, poor ordinary Home entry.
- Browser extension: adds installation and permission burden to a job the local
  app/daemon should support directly; not a required component of this proposal.

## Mechanism to investigate, not a finalized protocol

Use ADR-040 local authorization to admit a short-lived, single-use browser
handoff. Redeem it into an independently revocable browser session with explicit
permissions. Keep the general daemon token out of the page. Bind the exchange to
the intended request, installation, permitted destination, and browser proof where
applicable; reject replay, expiry, foreign redirects and unsolicited requests.

The launch URL must not contain the DAT. A fragment is not sufficient protection
for a redeemable secret: browser history, extensions and process arguments need
consideration. Exact challenge/proof transport is a design-and-test obligation,
not something this experience sketch declares solved.

Do not globally accept browser cookies as DAT equivalents on the existing API.
Explicit browser route permissions, mutation CSRF/origin protection and rejection
of malformed Host/foreign-origin requests are required. Broad localhost CORS must
not accidentally become broad authenticated browser authority.

Session storage requires a concrete origin decision. HttpOnly cookies are useful
on an appropriately isolated HTTPS origin, but cookies are not isolated by port;
“just set a cookie on 127.0.0.1” needs scrutiny against unrelated local services.
Ordinary local HTTP also cannot inherit assumptions about remote HTTPS cookies.
Test the chosen design in the supported browsers before committing to it.

Temporary outages should reconnect with selection/draft retained. An intentional
revocation should clear privileged data and offer Connect again. Normal daemon
restart and browser restart need an explicit session lifetime/persistence policy;
do not claim continuity by storing DAT indefinitely. Remembering a browser longer
can be offered with clear scope and a reversible Connected browsers entry.

Sessions name access to Koi. They do not grant access to a discovered application's
own account, prove its TLS trust, or establish CertMesh membership.

## Delight and negative acceptance

1. From desktop/tray and local terminal, one launch action opens useful Home with
   zero secret entry and no redundant Koi approval prompt. Record latency; target
   two seconds on the reference warm machine, not a public performance claim.
2. Search, open Notes, save, return, and reload without reauthentication while the
   session is valid; selection and task context survive.
3. First direct-browser connection offers one understandable native approval and
   completes in the original tab. Cancel, expired request and blocked app launch
   each preserve context and show one useful next action.
4. A temporary daemon outage and normal restart exercise the stated recovery
   policy. A revoked session does not recover authorization automatically.
5. Concurrent tabs/requests cannot authorize the wrong browser. Replayed/stolen
   handoffs, another local account, hostile web origins and unrelated local HTTP
   services fail at the appropriate boundary.
6. QR has a keyboard/text alternative; native approval works without notifications
   or animations. Test real browser and native focus, narrow layout and back/forward.
7. Read-only second-device access cannot mutate Koi or reveal operator secrets.
   Application authentication and secure-client failures remain explicit.
8. Observe an uncoached user launch and reconnect. A functional exchange alone
   does not establish that the experience is understandable or delightful.

## Scope and next design work

Prototype the local launch, direct arrival, return/reload and disconnected states
as one vertical journey. Before production changes, specify browser-session
ownership and route contracts in ADR-040/CONTRACT, including session lifetime,
storage/origin and atomic handoff redemption. Expected owners: koi-common protocol,
koi-serve authenticated exchange/session transport, koi-client local access,
koi CLI launch, shared koi-ui presentation, and desktop native launch/approval.
Avoid a second daemon or generic identity framework. Exact state ownership must
be resolved from the architecture rather than invented by separate adapters.

R07 is affected by Home entry/return; R09 by surface authority and settings; R11
by installed launch; R27/R29 by accessibility and actual native/browser proof.
No acceptance status, peer assignment, deployment or permission was changed by
this exploration. Second-device management remains a separate scope decision.

## Primary references and applicability

- [RFC 8252](https://www.rfc-editor.org/rfc/rfc8252.html): external browser/native
  app communication and interception defenses. Koi's proposed authorization
  direction differs; this is relevant prior art, not an OAuth compliance claim.
- [RFC 8628](https://www.rfc-editor.org/rfc/rfc8628.html): request-specific device
  approval, QR optimization, code usability and phishing considerations. Useful
  design principles for cross-device fallback, not a mandate for cloud OAuth.
- [OWASP session guidance](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html):
  session identifiers, lifecycle and cookie defenses. Supports the session design
  work; it does not validate an unimplemented loopback scheme.
- [RFC 6265 section 8](https://www.rfc-editor.org/rfc/rfc6265.html#section-8): cookie
  security limitations, including absence of port isolation.
