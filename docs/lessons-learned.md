# Lessons Learned

Field-tested rules from Koi's release and lab work. Each entry: what happened → the
rule that now governs. When a new lesson contradicts an old one, both stay and the
newer wins with its evidence.

---

## Release engineering

### RL-1 — Global ignore rules silently drop release content (2026-08-24)

The SDK CSR fixture (`sdk-csr-fixture.pem`) was excluded by the global `*.pem`
anti-secret ignore rule. It compiled locally, so every local gate passed; CI's
checkout lacked it and the hosted dry run failed at `include_str!` **before tagging**.

**Rules:** (a) never tag without a green `workflow_dispatch` dry run on the exact
commit — it validates the checkout, not your workstation; (b) when a commit's tree
differs from your working tree for *non-secret* reasons, use a targeted `.gitignore`
negation (`!crates/koi-certmesh/tests/fixtures/*.pem`) rather than force-add, so the
intent is reviewable.

### RL-2 — Registry versions are immutable; supersede, never repoint (2026-08-24)

The July session pushed tag `v1.0.0-rc.1`, which published crates.io `1.0.0-rc.1`,
a GHCR image, and a GitHub prerelease. Re-pointing the same version at newer code
would have created divergent crates↔GitHub supply chains.

**Rule:** before preparing any version, check registry state
(`crates.io/api/v1/crates/<name>`, `gh release list`, full `git ls-remote --tags`
— untruncated). If burned, bump to the next rc and supersede; delete stale
prereleases only with their tags, and record the deletion.

### RL-3 — Truncated listings are false negatives (2026-08-24)

`git ls-remote --tags | Select-Object -First 5` showed only v0.x tags and hid the
existing `v1.0.0-rc.1`. The mistake surfaced two steps later as a rejected push.

**Rule:** filter remotely (`| grep`), never truncate locally. A "not found" is only
true if the untruncated list says so.

## Distributed testing

### RL-4 — Transports pin the interpreter; accounts keep their shells (2026-08-24)

test-01's login shell is fish. Every POSIX loop sent through plink died with exit
127 ("Missing end to balance this for loop") before reaching any real command.

**Rule:** the harness wraps all remote commands in `sh -c '…'` (implemented in
`PuttyTransport::run`). Never assume the login shell, and never ask operators to
change it for the lab.

### RL-5 — Complex payloads cross shells as files, not quoted strings (2026-08-24)

Inline quoting PowerShell → plink → fish/sh mangled arguments repeatedly (merged
argv, eaten `$`, split words). The reliable primitive everywhere was: stage a file
(`pscp`), execute `sh <file>`, pass data inside files (invite codes, JSON bodies).

**Rule:** if a remote invocation contains quotes-within-quotes, it is wrong. Write
the script, ship the script. This matches koi-lab's own scenario pattern; manual
operations must follow it too.

### RL-6 — sudo rewires the environment; explicit paths or bust (2026-08-24)

`sudo systemd-run … $HOME/koi-dogfood/koi` resolved `$HOME=/root` and the unit died
with status 127; the root-owned daemon's breadcrumb then became unreadable to the
unprivileged CLI.

**Rule:** scripts that may run under sudo take the dogfood root as an explicit
argument. Within one host, pick one ownership domain (root here) for daemon +
state + CLI operations and stay inside it; document the choice.

### RL-7 — Kernel bind semantics are empirical, not doctrinal (2026-08-24)

ADR-030's detection premise — "a no-reuse probe fails against a SO_REUSEADDR
holder" — held locally and failed on Ubuntu 24's kernel (mixed binds permitted).
The unit test asserting it broke CI.

**Rules:** (a) network-semantics assumptions get measured on target kernels before
they enter portable tests; assert only deterministic facts; (b) when measurement
contradicts design, amend the ADR with the measured reality (ADR-030 "Measured
limitation") and move the open verdict to physical validation — which is exactly
what the four-host lab exists for.

### RL-8 — Workstations are the best test instruments (2026-08-24)

The "messy" machines found what pristine CI cannot: avahi holding 5353 produced the
adaptive-mDNS product decision (ADR-030), fish produced transport pinning (RL-4),
missing sudo produced honest per-machine mutation grants. None of these surface on
two identical Debian boxes.

**Rule:** every distinct host class (distro, shell family, privilege posture,
pre-existing services) is treated as a coverage axis in the catalog, and preflight
records each machine's constraints as first-class evidence.

### RL-9 — Pre-report failures without captured output are instrumentation defects (D15, restated)

Two transient scenario failures went undiagnosed because an operator loop discarded
stderr. Reruns passed; the cause remains unknown forever.

**Rule:** standalone scenario invocations always retain stderr. A failure you cannot
reconstruct is a hole in the harness, not noise.

## Process

### RL-10 — The dry run is the gate, not a formality

Two consecutive dry runs found (RL-1) a release-blocking missing file and (RL-2's
cousin) confirmed registry/version identity before anything irreversible ran. Total
cost: two ~10-minute workflow runs. The alternative costs are tagging broken trees
into immutable registries.

### RL-11 — Ledger drift is found by re-reading against the tree

The handoff once said "V1-08 not implemented" while protocol groundwork already sat
uncommitted in the tree; later, "rc.1 will be re-prepped" turned out to require
"rc.2" because July had published rc.1. Both were caught by checking claims against
reality (tree state, registries) rather than trusting prose.

**Rule:** every resume step begins by re-verifying its written premises. Update the
ledger in the same breath as the discovery, not at session end.

## Product soak

### RL-12 — Test machines run the real installer; transient scaffolding lies (2026-08-24)

The standing mesh bootstrapped daemons with hand-rolled transient units and a
setsid user process. The result soaked fine for hours and then failed the first
honest question — "why doesn't it survive reboot?" — because what it soaked was
not the product users get. Operator verdict: *"there should be no transient
install. Everything on the TEST machines must be real."*

**Rules:** (a) long-running soak evidence must come from `koi install`'s own
output — enabled unit, default data root, default binds — with deviations (like a
CA's LAN-expose drop-in) explicit, minimal, and reversible; (b) when a soak setup
script exists only because the real path is inconvenient, that inconvenience IS
the finding.

### RL-13 — Per-machine credentials fail loudly, wrong-variable credentials fail confusingly (2026-08-24)

A session repeatedly sent brook's password to test-01 (wrong variable from a
shared helper). Each failure looked like something else: rate limiting, PAM
lockout, "the password changed". Two operator reboots were spent chasing phantoms
before the diff (`-pw 'test'` vs `-pw $pw`) surfaced.

**Rules:** (a) per-machine credentials go through the catalog's `password_env`,
never through a shared variable reused across hosts; (b) before theorizing about
bans or lockouts, diff the exact bytes you sent — auth infrastructure is rarely
wrong, credential plumbing often is; (c) when one host's credential differs,
prove which one you are sending *first*.

## Physical-run findings

### RL-14 — `canonicalize()` hands out `\\?\` paths; external tools reject them (2026-08-25)

W4's first physical run added firewall rules with
`program=\\?\F:\...\koi.exe` because `Lab::load` canonicalizes the repo root and
Rust's `std::fs::canonicalize` prefixes Windows paths with `\\?\`. netsh refused
the rule ("The parameter is incorrect.") **on stdout**, so the scenario's
stderr-only error surfaced as an empty message. Three direct pwsh repros passed,
which is what isolated the argv from the path.

**Rules:** (a) paths crossing a process boundary into non-Rust tools get the
extended-length prefix stripped first (see `netsh_program_path`); (b) when an
external tool fails, capture BOTH streams in the error — netsh reports parameter
errors on stdout, so a stderr-only message diagnoses nothing.

### RL-15 — A remote kill pattern must not match its own transport wrapper (2026-08-25)

W4's revocation step ran `pkill -f '{run_dir}/koi --daemon'` over the lab
transport, which wraps every command as `sh -c '<command>'`. The shell's own
argv contained the pattern, so pkill killed its own session: empty output,
mysterious exit 128, no stderr. The pid-file-based, owner-checked
`stop_run_daemon` primitive exists precisely to avoid this.

**Rules:** (a) never inline process-kill patterns into transported commands;
use the run-owned pid file primitives (`stop_run_daemon`, preserve-state
`restart_run_daemon`) — they are owner-checked AND wrapper-safe; (b) a restart
of a daemon whose data dir already exists needs the preserve-state variant;
fresh-start prepare refuses by design.

### RL-16 — Fail-loud CLI exit codes are evidence, not errors, when RED is expected (2026-08-25)

`koi trust diagnose` exits non-zero on a RED diagnosis and refusal reasons land
on stderr with a non-zero exit. W4's checks *expected* both, but used
fail-on-nonzero plumbing — so the expected results aborted the scenario. Fixed
by judging captured stdout/stderr (`remote_output`) instead of exit-status-only
helpers.

**Rule:** for any step whose negative outcome is the assertion, use raw-output
capture and assert on content + status together; reserve `run_checked` for
steps that must succeed.
