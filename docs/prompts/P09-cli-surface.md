# P09 — CLI Surface Unification

> Paste this entire file as the task for a fresh agent session in the Koi repo.
> Size: M · Prereqs: none (rebase mentally if P08 changed commands) ·
> Read `docs/prompts/CHARTER.md` first.

## Mission

The CLI's *design* is a genuine differentiator (catalog, `koi <cmd>?` detail pages,
graceful terminal degradation) but its *implementation* maintains three parallel
command descriptions — clap definitions, a hand-written 1,931-line `surface.rs`
manifest (54 entries, **zero tests**), and docs — and the manifest has verified drift:
it registers `certmesh rotate-totp` while the real command is `rotate-auth` (so
`koi certmesh rotate-auth?` fails), and advertises five flags that don't exist. The
generic `command-surface` crate (1,043 lines, one consumer, zero tests) carries dead
Confirmation/by_tag/by_scope machinery while actual confirmation prompts are hand-rolled
twice. Unify: **clap is the single source of truth**; the catalog renders from it; the
crate folds into the binary; confirmation gates become real. Also close the verified
`--endpoint` token trap.

## Load context first

1. `docs/prompts/CHARTER.md` (principles 3–5 are the spec)
2. `docs/assessment/findings/verification-2026-06.md` claims 7, 10, 11;
   `findings/reader-binary-cli-dx.md` (full drift list)
3. `crates/koi/src/surface.rs`, `cli.rs`, `main.rs` (dispatch + `?` handling),
   `crates/command-surface/src/` (all), `commands/factory_reset.rs` +
   `commands/certmesh.rs` (the hand-rolled prompts), `commands/mod.rs` detect_mode
   (~51–55), `commands/certmesh.rs` require_daemon (~89)

## Research phase

- Inventory what the catalog renders that clap *cannot* natively carry: glyphs,
  category grouping, curated examples, HTTP-API equivalents, long descriptions.
  Decide the augmentation mechanism — recommended shape: keep a small typed
  `CommandMeta { glyph, category, examples, http_equiv, confirm }` map **keyed by the
  clap command path**, with a conformance test that walks the clap tree and the meta
  map both ways (every leaf command has meta; every meta key parses via
  `Cli::try_parse_from`). Full codegen from clap is acceptable too — choose and
  justify; the non-negotiable is that drift becomes a *compile/test failure*.
- List every confirmed manifest lie to fix or delete (rotate-totp; `--totp`, `--exec`,
  `--cidr`→`--subnet`, `--process`, `--include-logs`; CNAME/TXT/SRV claims; the
  factory-reset "logs preserved" falsehood).
- Examine each example string: every one must `Cli::try_parse_from` successfully —
  that's a unit test, not a review task.
- Token trap mechanics: `--endpoint` → `token: String::new()`; certmesh pairs explicit
  endpoints with the *local* breadcrumb token. Design the fix: `--token <T>` /
  `KOI_TOKEN`; explicit endpoint **without** token ⇒ tokenless (and a clear 401 hint:
  "remote daemon requires a token — pass --token or KOI_TOKEN"); never send the local
  breadcrumb token to an explicit endpoint.

## Target experience (north star)

```console
$ koi certmesh rotate-auth?        # works (drift bug dead by construction)
$ koi dns lookup?
  koi dns lookup <name> [--record-type A|AAAA|ANY]   # only flags that EXIST
  Examples:                                          # every example parse-tested
    koi dns lookup grafana
    koi dns lookup grafana --record-type AAAA
  HTTP: GET /v1/dns/lookup?name=grafana

$ koi certmesh destroy             # confirmation now flows through ONE gate
  This permanently destroys the CA, all member records, and the audit log.
  Type DESTROY to confirm: _
$ koi certmesh destroy --json      # non-tty/json: REFUSES without --yes (no silent bypass)
  error: destructive command requires --yes in non-interactive mode

$ koi mdns announce "X" _http._tcp 8080 --endpoint http://10.0.0.5:5641
  error: remote daemon requires a token (pass --token or set KOI_TOKEN)
```

Structural shape: `command-surface` crate is deleted; its used rendering subset
(profile detection, glyph degradation, catalog/detail writers — concrete, no generics)
moves to `crates/koi/src/help/`. The `CommandMeta` map replaces `build_manifest()`'s
1,390 lines of stringly data with typed entries co-located per domain
(`commands/dns.rs` owns dns meta, etc. — or one help/meta.rs; choose for lowest drift).
Confirmation becomes one function consulted by dispatch
(`confirm::gate(level, token_word, flags)`) used by destroy/factory-reset; the two
hand-rolled prompts are deleted; `--json`/non-tty paths require `--yes`.

## Plan, then implement

Per charter: conformance tests first (they fail against today's drift — proof), then
the meta/rendering migration, then confirmation unification, then the token fix, then
delete command-surface and prune `Cargo.toml`/workspace members.

## Acceptance criteria

- [ ] Tests: every clap leaf command has catalog meta and vice versa; every example
      string parses; `koi certmesh rotate-auth?` test passes. These run in `cargo test`.
- [ ] All verified drift instances fixed (list each in commit messages).
- [ ] `command-surface` crate removed from the workspace; rendering lives in the
      binary; net LOC reduction reported (expect ≥ 400).
- [ ] One confirmation gate; destructive commands refuse non-interactive without
      `--yes`; behavior tested.
- [ ] `--token`/`KOI_TOKEN` exist; explicit-endpoint flows never use the local
      breadcrumb token; 401s give the actionable hint; tested.
- [ ] Catalog output visually unchanged for a normal terminal (paste before/after of
      `koi` and one `cmd?` page in the plan file).
- [ ] Workspace green per charter commands.

## Do NOT

- Redesign the moniker structure, add/remove commands (except as P08 already did), or
  change human output formats beyond truth fixes.
- Keep any generic trait machinery "for future consumers" — one consumer means
  concrete code.
- Touch the NDJSON pipe adapter question (separate decision, assessment §6 Tier 3).
