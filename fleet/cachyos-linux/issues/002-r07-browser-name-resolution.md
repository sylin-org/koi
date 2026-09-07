# R07 Notes destination fails the workstation resolver

Status: open host prerequisite; no shared provider defect is established.

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

Next: diagnose the measured Avahi/systemd-resolved resolver discrepancy on this
host under a fresh guard, then repeat ordinary installed Home → Notes Open → save
→ return/reload against the actual advertised target. Use an explicit stable test
service ID to keep address changes from introducing separate catalog identities.
Do not change a returned URL, force browser DNS, or count a direct-IP sanity request
as the Home journey. Phone proof separately needs a physical device that resolves
the certified name and trusts the CertMesh issuer.
