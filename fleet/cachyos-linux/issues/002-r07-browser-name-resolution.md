# R07 Notes destination fails the workstation resolver

Status: resolved on this host by `R07/resolver-notes-20260907`; no shared provider
defect was established.

## Initial observation

Run `R07/browser-native-20260907`, installed Koi cce33e5 and desktop5388b71,
found and selected the real temporary Notes announcement. Chromium Open followed
its returned `koi-…local:18707` destination and displayed ERR_NAME_NOT_RESOLVED.
The HTTP endpoint returned200 through its measured address. Replacing the temporary
publication with normal host advertisement returned `test-01-2.local`; this also
failed through curl/system resolution, while `avahi-resolve -4` returned the
correct address. Source catalog/service projection is not proof of browser DNS.

Both Avahi and systemd-resolved are active. NSS uses `resolve [!UNAVAIL=return]`
and the system resolver uses resolved's stub; Avahi has used the conflict-renamed
`test-01-2.local` since before this run. A scoped temporary mDNS firewall allowance
did not repair resolution. Original firewall bytes were restored. No resolver,
provider or hosts-file mutation was made.

## Resolution — 2026-09-07 UTC

The installed `nss-mdns` package was absent from the application's NSS lookup path.
Direct `getent -s mdns_minimal ahosts test-01-2.local` returned IPv6 and IPv4,
while ordinary lookup failed and `resolvectl query` timed out. Under a fresh
root-private restoration guard, only `/etc/nsswitch.conf`'s hosts line changed:

```text
before: hosts: mymachines resolve [!UNAVAIL=return] files myhostname dns
after:  hosts: mymachines mdns_minimal [NOTFOUND=return] resolve [!UNAVAIL=return] files myhostname dns
```

This connects ordinary application lookup to the existing Avahi service, using
the dual-stack minimal module. See [upstream NSS activation guidance](https://github.com/avahi/nss-mdns#activation).
This is a measured host configuration fix, not a universal resolver order or a
diagnosis of the underlying Avahi/resolved multicast interaction. Neither service
was reconfigured or restarted. Localhost, unicast lookup and ordinary external
HTTPS remained working.

The unchanged installed daemon c89f237 and desktop 5388b71 then passed actual
Home → Notes Open → save → reload → Back → reopen. Stable service ID
`svc_r07_resolver_notes_20260907` returned
`http://koi-bda81e6e7ba470c4.local:18707/`; Chromium loaded this exact URL.
Native Open also launched it and displayed the saved content. Withdrawal produced
stale evidence with no Open links. Run services, registration, stored note and
browser grants were removed; the NSS fix is retained and its rollback guard has
been accepted and removed. Full evidence is in the [R07 report](../../../docs/prompts/delight/reports/R07.md).

The owner subsequently removed browser access and parked phone pairing. There is
no remaining phone prerequisite for this issue. The retained resolver correction
still supports opening discovered services from native Home.
