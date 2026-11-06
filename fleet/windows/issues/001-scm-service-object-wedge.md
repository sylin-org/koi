# Windows SCM recovery constraint

A service object can persistently reject StartService with ERROR_ACCESS_DENIED even
when its restored binary and complete configuration are valid. The precise trigger
is not reproducible on demand; do not claim a known causal mechanism.

The installer recovery boundary must preserve its exact registration descriptor and
byte-verified rollback material. Recreating a service object is a last-resort recovery
step only after a complete restored descriptor still produces the specific persistent
denial. A partial descriptor must never authorize deletion. Retain recovery material
until the recreated service passes startup and health verification.

Any new native test belongs to an addressed Windows assignment in
[the launch ledger](../../launch/LEDGER.md), with own-host authorization, baseline
capture and interruption-safe restoration under [the protocol](../../PROTOCOL.md).
The current candidate's outcome remains pending until tested; this constraint is not
a carried-forward pass.
