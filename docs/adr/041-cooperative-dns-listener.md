# ADR-041: DNS serving is a cooperative desired-state listener

- **Status:** Accepted
- **Date:** 2026-09-01
- **Supersedes/relates:** ADR-011, ADR-031, ADR-035

## Context

Koi's default DNS intent is UDP+TCP port 53 on the machine. Linux commonly has
systemd-resolved bound to specific stub addresses such as `127.0.0.53`, which makes a
wildcard bind fail even though `127.0.0.1` and LAN interface addresses remain available.
The prior runtime attempted one wildcard pair, logged an error, and stayed stopped until a
human called start again. Its boolean status could not distinguish an operator stop from
contention, retry, or partial useful service.

Silently changing resolved configuration would be invasive: link DNS routing is broader
than opening a Koi listener and may disrupt VPN, split-DNS, or administrator policy.

## Decision

Socket acquisition is a DNS transport adapter (`listener.rs`); resolution and record logic
remain in `DnsCore`. `DnsRuntime` owns the desired-state loop.

1. An explicit bind address is exact operator intent. Koi acquires one exclusive UDP+TCP
   pair there or reports a waiting reason; it never changes addresses behind the operator's
   back.
2. The default unspecified address first acquires the wildcard UDP+TCP pair. Only an
   `AddrInUse` collision activates cooperative binding: enumerate loopback plus useful IPv4
   interface addresses and retain every address for which both protocols can be acquired.
   A UDP-only or TCP-only address is not advertised as working DNS.
3. One or more acquired pairs is useful service. Status reports `running`, exact endpoints,
   and the wildcard-collision reason. If none can be acquired, status is `waiting`, preserves
   the reason, and retries without dropping the DNS domain or spamming startup as a fatal
   error.
4. `start` arms desire idempotently; `stop` is the only operation that disarms retry. Listener
   failure returns to waiting. Cooperative listeners observe interface-set changes and
   reconcile their socket set. Wildcard listeners naturally follow interfaces.
5. Runtime status has `stopped`, `reconciling`, `running`, and `waiting` states plus
   `desired`, `endpoints`, and `reason`; the legacy `running` boolean remains for compatible
   clients. `/v1/status` and `/v1/dns/status` surface this truth.
6. Port zero (tests/embedded use) is one real kernel-selected UDP+TCP pair, not two unrelated
   ephemeral ports.

Koi does not modify systemd-resolved, `/etc/resolv.conf`, interface DNS, firewall rules, or
another resolver's service state as part of this decision. Making Koi a system resolver is a
separate explicit opt-in product operation if later desired.

## Consequences

- Koi can fully serve useful addresses alongside a specific-address incumbent without
  fighting it or hiding the compromise.
- A temporary collision heals automatically; a manual stop stays stopped.
- Consumers can distinguish “DNS records are available in-process” from “the network
  listener is accepting queries” and can show the exact remedy/reason.
- IPv6 cooperative address enumeration is not claimed yet. An explicit IPv6 bind and a
  successful IPv6 wildcard bind remain real; IPv6 per-interface fallback requires its own
  interface/scope validation before being advertised.

