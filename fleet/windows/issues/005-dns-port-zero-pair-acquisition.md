# Intermittent DNS port-zero pair acquisition on Windows

Status: open, reproduced intermittently; remediation and deterministic regression proof pending. The latest full workspace test run passed. This issue does not mark that run blocked or failed.

## Observed results

During Windows U02 source verification on 2026-09-12, a workspace run failed six of the 63 `koi-dns` library tests. The requested follow-up, `cargo test -p koi-dns --lib --locked -- --test-threads=1`, exited 101 with 60 passed and three failed:

| Test | Workspace failure | Serial follow-up |
| --- | --- | --- |
| `listener::tests::port_zero_is_one_real_udp_tcp_pair` | Bind error 10013 | Same bind error |
| `resolver::tests::lookup_and_local_wire_preserve_upstream_absence_and_failure` | Index 0 of empty endpoints | Same failure |
| `resolver::tests::malformed_wire_request_is_formerr_and_invalid_facade_name_is_typed` | Index 0 of empty endpoints | Same failure |
| `runtime::tests::port_zero_reports_the_real_endpoint` | Waiting instead of Running | Passed |
| `runtime::tests::status_feed_is_immediate_revisioned_and_suppresses_noop_start` | Waiting instead of Running | Passed |
| `runtime::tests::restart_waits_until_the_retiring_generation_is_reaped` | Waiting instead of Running | Passed |

The listener error was `Bind("127.0.0.1:0: An attempt was made to access a socket in a way forbidden by its access permissions. (os error 10013)")`. Serial execution therefore did not eliminate the failure.

A later full workspace run using `--no-fail-fast` completed with exit 0, including all 63 DNS tests, without intervening DNS production edits. That passing run establishes the latest suite result; it does not establish a fix for the reproduced intermittent behavior.

Local observation files were `.tmp/u02-workspace-test-final.log`, `.tmp/u02-dns-serial.log`, and `.tmp/u02-workspace-test-complete.log`. These are disposable local logs, not durable published receipts. The results above preserve the relevant observations.

## Source mechanism and evidence limits

The source baseline was `791f87ebe0a8ba93246f60ce0b283c13fb86595b`, with U02 working-tree changes. Inspection found no working-tree changes to DNS production source; only its README differed. The [DNS dependency list](https://github.com/sylin-org/koi/blob/791f87ebe0a8ba93246f60ce0b283c13fb86595b/crates/koi-dns/Cargo.toml#L15-L37) has no `koi-ui` dependency. No observed failure points to UI rendering; this is not a blanket claim that every transitive workspace dependency was unchanged.

[Listener acquisition, lines 160–166](https://github.com/sylin-org/koi/blob/791f87ebe0a8ba93246f60ce0b283c13fb86595b/crates/koi-dns/src/listener.rs#L160-L166), binds UDP first, obtains its kernel-selected port, and binds TCP to the same endpoint once. A port available to UDP need not be available to TCP. A failed pair propagates its error without selecting another ephemeral candidate in that acquisition attempt.

[Runtime start, lines 493–495](https://github.com/sylin-org/koi/blob/791f87ebe0a8ba93246f60ce0b283c13fb86595b/crates/koi-dns/src/runtime.rs#L493-L495), promises to arm reconciliation, not immediate readiness. [The reconciler, lines 1001–1021](https://github.com/sylin-org/koi/blob/791f87ebe0a8ba93246f60ce0b283c13fb86595b/crates/koi-dns/src/runtime.rs#L1001-L1021), publishes Waiting with empty endpoints on bind failure, acknowledges initial startup, and retries later. The two [resolver fixtures, lines 1438–1467](https://github.com/sylin-org/koi/blob/791f87ebe0a8ba93246f60ce0b283c13fb86595b/crates/koi-dns/src/resolver.rs#L1438-L1467), immediately index the first endpoint after `start()` succeeds, obscuring the useful bind reason with an index panic.

Read-only `netsh interface ipv4 show excludedportrange protocol=tcp` and the corresponding UDP query showed different exclusions on this host: TCP included 54232–54831; UDP included 60520–61119. Both also excluded 50000–50059. The dynamic ranges both began at 49152 and contained 16384 ports.

A bounded direct socket probe successfully bound UDP on loopback ports 54232, 54500, and 54831, then received Windows error 10013 when binding TCP to each same endpoint. Pairs at 54832 and 58006 succeeded. A separate 24-candidate UDP-port-zero probe selected 58006–58029 and all pairs succeeded. Probe sockets were closed; no excluded ranges or host configuration were changed.

This reproduces a host-dependent cross-protocol reservation mechanism compatible with the listener failure. The failed Rust tests did not report the selected ephemeral port or which bind failed, so the observations do **not** prove that every failing test hit those reserved ranges. An unrelated process collision or another bind restriction remains distinguishable only with better failure detail. The direct probes also do not verify the Rust runtime's complete behavior.

## Bounded remediation and verification

- Consider bounded fresh-candidate retries only when the requested port is zero and the paired TCP bind rejects an otherwise successful UDP candidate. Release the unsuccessful candidate fully, keep UDP and TCP on one final endpoint, and return an actionable error with protocol and selected endpoint if the bound is exhausted. Preserve exact-address and nonzero-port semantics; do not silently move an operator-requested endpoint.
- Add deterministic coverage for a rejected first TCP candidate followed by a valid pair, exhaustion, resource release, and nonzero-port refusal. Do not depend on the host happening to select a reserved port.
- Make real-listener fixtures establish readiness within a bounded interval and report the runtime status/reason before accessing endpoints. Preserve the production contract that accepted `start()` may be Waiting; do not weaken assertions to accept absent listeners as a pass.
- Verify the relevant DNS tests serially and with normal concurrency on Windows, then run the full locked workspace suite with `--no-fail-fast`. Record both failures and later passes. Closure requires an implemented remedy and targeted regression evidence, not an unexplained successful retry.

No DNS production changes, host reconfiguration, or firewall cleanup were performed for this investigation. Any additional native assignment must follow [the fleet protocol](../../PROTOCOL.md) and [the Windows test firewall ownership constraint](003-cargo-test-firewall-rule-residue.md). This issue itself authorizes no system mutation.
