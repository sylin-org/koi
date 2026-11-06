# Operator-trial invitation draft

Draft for maintainer review; no message has been sent. Choose a channel and check
its current rules before publication. Link only to an actual artifact that fits
the task and limits stated in the invitation.

I maintain Koi, an open-source project for container developers and homelab
operators. The task we're concentrating on is simple to state: label a container,
open its application from another computer on the LAN, and keep its name and
status correct when the container changes or leaves.

Koi also includes Certmesh for private-space identity and trust: run your own CA,
enroll machines, renew their identities and share signed membership information
with participating applications. It is available when your services need shared
identity; the initial container trial does not require creating a CA.

We're validating that workflow on Windows/Linux Docker setups and looking to
understand where the existing combination of discovery, DNS and routing causes
repeated work. Trusted service-name HTTPS is a separate next step; this is not a
claim that every client or network already works automatically.

If you run this kind of setup, the useful feedback is your actual task, what
you use today, where the instructions fail and whether the result is worth
keeping. Participation is voluntary; private addresses, tokens and keys are
not needed in a public report.

[Project](https://github.com/sylin-org/koi) ·
[Readiness and limits](https://github.com/sylin-org/koi/blob/dev/docs/launch/README.md)

Before sending, replace development links with the selected published artifact's
instructions and confirm whether the invitation is for observation or a released
preview. Do not silently turn this draft into a release announcement.
