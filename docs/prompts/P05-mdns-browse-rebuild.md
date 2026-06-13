# P05 — mDNS Browse Multiplexing Rebuild

> Paste this entire file as the task for a fresh agent session in the Koi repo.
> Size: M · Prereqs: none · Read `docs/prompts/CHARTER.md` first.

## Mission

koi-mdns's facade hands out unlimited "independent" `BrowseHandle`s per service type —
but the underlying mdns-sd 0.17 keeps exactly **one querier per type**
(`service_queriers: HashMap<String, Sender<…>>`): a second browse of a type overwrites
the first, and `stop_browse` kills the type's only querier *and clears its cache*.
Verified consequences: two concurrent SSE `discover` streams of the same type silently
kill each other; `resolve()` (which browses-then-stop_browses) terminates concurrent
subscribers; `BrowseHandle::drop` does the same; and the dashboard's meta-browse cache
permanently loses any type this happens to. Rebuild browsing around a **single real
browse per type with reference-counted fan-out**, and restore the crate's violated
single-import rule while you're in there.

## Load context first

1. `docs/prompts/CHARTER.md` and `.agentic/rules/mdns-boundary.md`
2. `docs/assessment/findings/verification-2026-06.md` claim 14, and
   `docs/assessment/findings/reader-mdns-core.md` (full analysis)
3. All of `crates/koi-mdns/src/` — especially `daemon.rs`, `browse.rs`, `lib.rs`
4. Ground truth: read mdns-sd 0.17 source in your cargo registry cache
   (`service_daemon.rs` — `service_queriers`, `exec_command_browse` overwrite comment,
   `exec_command_stop_browse` cache clearing)
5. Consumers: `crates/koi/src/integrations.rs` (MdnsBridge meta-browse),
   `koi-mdns/src/http.rs` SSE handlers, `resolve()` path, koi-embedded's browse adapter

## Research phase

Map every call path that triggers `browse`/`stop_browse` today and what breaks for
each under concurrency. Decide the fan-out primitive: per-type
`tokio::sync::broadcast` vs per-subscriber mpsc registry — weigh lagging-subscriber
behavior (broadcast drops oldest; a slow SSE client must not stall others) and justify
in the plan. Decide where the hub lives: inside `MdnsDaemon` (keeps mdns-sd types
fully private — preferred) vs a layer above.

## Target architecture (north star)

```rust
// daemon.rs — the ONLY mdns-sd-importing file, enforced again
struct BrowseHub {
    // one real mdns-sd browse per ty_domain, fanned out to N subscriptions
    types: Mutex<HashMap<String, TypeBrowse>>,   // TypeBrowse { refcount, tx: broadcast::Sender<MdnsEvent>, pump: JoinHandle }
}

impl MdnsDaemon {
    /// Subscribe to a type. First subscriber starts the real browse;
    /// last drop stops it. Events are Koi types — mdns_sd never escapes.
    pub async fn subscribe_type(&self, ty: &str) -> Result<BrowseSubscription>;
}

pub struct BrowseSubscription {            // replaces BrowseHandle
    rx: broadcast::Receiver<MdnsEvent>,    // koi MdnsEvent, not mdns_sd's
    _guard: Arc<TypeGuard>,                // refcount decrement + conditional stop on drop
}
```

Behavioral contract (encode as tests):

- N concurrent subscriptions to one type each receive every event; dropping one does
  not disturb the others; dropping the last stops the underlying browse.
- `resolve()` is implemented as a temporary subscription through the hub — it can no
  longer kill anyone (and gains: a concurrent subscriber's browse warms its cache).
- The Removed-event fullname is parsed **once at the boundary** into instance name +
  service type (delete `extract_service_type`/`extract_instance_name` from
  integrations.rs; un-overload `ServiceRecord.name`).
- `.agentic/rules/mdns-boundary.md` becomes true again: `browse.rs` either disappears
  into `daemon.rs` or contains zero `mdns_sd` imports. Add the enforcement test:
  a unit test that greps the crate's sources for `mdns_sd` outside daemon.rs (cheap,
  prevents regression).

## Plan, then implement

Per charter. Write the concurrency tests *first* (they fail against current code —
that's your proof of the bug); then the hub; then migrate `MdnsCore::browse`,
`resolve`, HTTP SSE handlers, MdnsBridge, and koi-embedded's adapter; then delete the
old BrowseHandle machinery.

## Acceptance criteria

- [ ] Test: two concurrent subscriptions to `_test._tcp` both receive a registered
      service's events; dropping one leaves the other live (this test fails on the old
      code).
- [ ] Test: `resolve()` during an active subscription does not terminate it.
- [ ] Test: refcount — last drop stops the real browse (observable via the hub's map).
- [ ] Boundary restored: zero `mdns_sd` references outside daemon.rs, with the
      grep-test guarding it; daemon.rs's "ONLY file" doc-comment is true.
- [ ] MdnsBridge no longer needs its never-respawn `active` set workaround; dashboard
      cache survives resolve/subscriber churn (adjust integrations.rs accordingly).
- [ ] Removed events carry parsed instance + type; integrations.rs string-parsing
      helpers deleted.
- [ ] All existing koi-mdns tests still pass (85); `cargo test` workspace-green.

## Verification

`cargo test -p koi-mdns && cargo test && cargo clippy -- -D warnings`. Manual smoke:
run `koi --daemon`, open two terminals with `koi mdns discover _http._tcp` simultaneously,
`koi mdns resolve` something in a third — all keep streaming.

## Do NOT

- Change the wire protocol shapes or HTTP endpoints (Response enum work is out of
  scope; note observations in the plan file instead).
- Touch the lease/registry engine — it is the best code in the project.
- Upgrade mdns-sd in the same session (isolate variables).
