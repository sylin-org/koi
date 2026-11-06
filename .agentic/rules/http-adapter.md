---
globs: crates/*/src/http.rs,crates/koi-serve/src/http.rs
alwaysApply: false
---

# HTTP adapter rules

Domain crates own their relative routes and domain commands. koi-serve mounts
them, classifies access, and owns listener-level policy. Use the existing handler
in the affected domain and crates/koi-serve/src/http.rs as the pattern.

Handlers deserialize and validate transport input, call the domain owner and
serialize the typed result. Do not acquire private domain locks or duplicate
lifecycle/status logic in HTTP. Use existing error-to-response helpers and
established wire shapes; do not wrap every domain in an invented universal shape.

Every new route needs an explicit authorization classification in the
[route/auth matrix](../../docs/reference/http-route-auth-matrix.md) and its actual
enforcement. Unknown peer identity must not create a loopback exemption. SSE and
aggregate endpoints need their own access review; a GET is not automatically public.

For mDNS, verify current lease defaults and heartbeat paths in
crates/koi-mdns/src/http.rs and the [mDNS guide](../../docs/guides/mdns.md).
A dropped connection must not detach durable admitted work or leak native leases.

Use the [security model](../../docs/reference/security-model.md) for exact current
bind/auth/CORS behavior. Confirm docs examples against current routes and tests.
