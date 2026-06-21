# P09 — CLI Surface Unification — Plan

> Branch: `dev` (autonomous). Verify per charter: `cargo test && cargo clippy -- -D warnings && cargo fmt --check`.
> Research: the `p09-cli-surface-research` workflow (4 facets) — full map archived in the run transcript.

## Goal

Clap is the single source of truth; the catalog renders from it via a typed `CommandMeta`
map keyed by the clap command path; drift becomes a **compile/test failure**; the generic
`command-surface` crate folds into `crates/koi/src/help/` (concrete, no generics);
confirmation becomes one real gate; the `--endpoint` token trap is closed.

## Verified drift to fix (each = a conformance-test failure today)

| Drift | Reality (clap) | surface.rs |
|---|---|---|
| `health add --process <name>` | only `--http` / `--tcp` | 1601 |
| `certmesh set-hook --exec` | only `--reload` (required) | 1147, 1157 |
| `certmesh join --totp 123456` | Join takes only `endpoint` | 1058 |
| `factory-reset --include-logs` + "logs preserved" | FactoryReset has NO args; handler deletes logs too | 1891, 1911 |
| `dns lookup` "A, AAAA, CNAME, TXT, SRV" | resolver supports A / AAAA / ANY | 1441 |

## Design

### Augmentation mechanism (drift → test failure)
A typed `CommandMeta { glyph, category, long_description, examples: &[&str], http_equiv, confirm }`
map keyed by the **clap moniker path** (e.g. `"certmesh rotate-auth"`), in `help/meta.rs`.
Two conformance tests (run in `cargo test`):
1. **Every clap leaf has meta, every meta key is a real leaf** — walk `Cli::command()` to
   enumerate leaf paths; assert the set equals the meta map's keys (both directions). This
   kills `rotate-totp`-style drift by construction.
2. **Every example string parses** — for each meta example, `Cli::try_parse_from(split)` must
   succeed. This kills `--process`/`--exec`/`--totp`/`--include-logs` examples.
   (Flag descriptions in `long_description` are prose; the examples are the enforced contract —
   so phantom flags must leave the prose too, verified by a grep-style assertion that the
   long_description mentions no `--flag` absent from that command's clap args.)

### Rendering move (delete the crate)
Move the **used concrete subset** of `command-surface` into `crates/koi/src/help/render.rs`:
`TerminalProfile` (detect_stdout / resolve_glyph / resolve_color), `ColorSupport`,
`Color`/`Presentation`, `write_catalog`, `write_command_detail`, `write_overview`,
`CatalogOptions`, `AnsiWriter`/`PlainWriter` — **concrete, no `<C,T,S>` generics**. Drop the
dead generics + `by_tag`/`by_scope`/`get`/`all_sorted`/`write_summary_catalog`/`KoiScope::Internal`
/ the non-highlight badge paths. Delete `crates/command-surface/` from the tree + workspace
members + publish.yml + any `.workspace` dep. The catalog/`cmd?` output must be **visually
identical** for a normal terminal (before/after captured below).

### Confirmation (one gate)
`help::confirm::gate(token_word: &str, json: bool, yes: bool) -> anyhow::Result<()>`:
- `--yes` (new global flag) → pass silently.
- non-interactive (`json` or non-tty) without `--yes` → **refuse**:
  `error: destructive command requires --yes in non-interactive mode`.
- interactive tty → prompt `Type <WORD> to confirm:` and require an exact match.
Wire `certmesh destroy` (DESTROY) + `factory-reset` (RESET) through it; delete the two
hand-rolled prompts; fix the `backup`/`restore` non-tty stdin hang (route through the gate or
guard on `IsTerminal`).

### Token trap (close it)
Add global `--token <T>` (+ `KOI_TOKEN` env). Fix `certmesh::require_daemon` (certmesh.rs:92):
an explicit `--endpoint` must use the `--token`/`KOI_TOKEN` value if present, else **tokenless**
— NEVER the local breadcrumb token. Breadcrumb endpoint keeps the breadcrumb token. A 401 from
a tokenless explicit endpoint prints the hint:
`remote daemon requires a token (pass --token or set KOI_TOKEN)`. Apply the same rule in
`resolve_endpoint`/`detect_mode` (already tokenless for explicit endpoints — thread `--token`).

## Execution (per charter: conformance tests first)

- **Stage A** (structural): write the two conformance tests (they FAIL on today's drift =
  proof) → build `help/meta.rs` from the 46 leaf commands (fixing the 5 drifts) → move the
  render subset to `help/render.rs` → repoint `surface.rs`/`infra.rs`/`main.rs`/`dispatch.rs`
  → delete `command-surface` + prune. Catalog visually unchanged.
- **Stage B** (correctness): the confirmation gate + the `--token`/trap fix, with tests
  (`--json certmesh destroy` refuses; explicit endpoint never sends the breadcrumb token;
  401 hint).

## Before (for the visual-unchanged check)

`koi dns lookup?` (before — note the CNAME/TXT/SRV drift to fix):
```
[dns] koi dns lookup
Lookup a name through the resolver
────────────────────────────────────────────────────────────
Queries the local DNS resolver for a name. Supports A, AAAA, CNAME,
TXT, and SRV record types via --record-type.
...
Examples
  koi dns lookup example.lan  # Query default (A) record
  koi dns lookup example.lan --record-type AAAA  # Query IPv6
HTTP API
  GET     /v1/dns/lookup
```
(After: same layout; the record-type line says "A, AAAA, or ANY" to match clap.)
