# Certmesh Create Wizard — UX Proposal

**Status:** Implemented  
**Date:** 2026-02-13  
**Scope:** `koi certmesh create` interactive flow  
**Lineage:** Zen Garden `place keystone` wizard → this proposal

---

## Problem

Today, `koi certmesh create` accepts flags and silently creates an irrevocable
root of trust. A user who types the command with no context gets no guidance, no
explanation, and no chance to cancel. Three passphrase-adjacent concepts
(entropy seed, CA passphrase, auth credential) are introduced in a single
interaction with no separation. The flow was designed for scripting, not for
humans.

---

## Design principles

1. **Nothing irrevocable happens without consent.** Every step waits for input.
   The review screen is the single commitment point.

2. **Teach one concept per step.** The user learns what they need at the moment
   they need it.

3. **The fastest path produces the strongest result.** Enter-through defaults
  yield a generated passphrase proposal that can be accepted or replaced.

4. **Flags are the scripting bypass.** Pre-filled parameters skip their
   corresponding wizard step. All flags provided = review screen only.
   `--json` = fully non-interactive.

5. **Color is relational, not decorative.** Cyan marks the active
   trigger-effect pair: the key and the thing it activates. Nothing else.

---

## Color system

Color carries semantic meaning. Every use answers: "what would the user lose
if this were monochrome?"

| Treatment | Role | Used for |
|---|---|---|
| **Cyan** | Active trigger-effect pair | `Enter` + the thing Enter activates (e.g. `Just me`). Only one pair at a time. |
| **Cyan bold** | Critical value to capture | The passphrase, the TOTP manual code (or FIDO2 registration) |
| **Green** | Completed / success | `✓` checkmarks, "Certificate mesh created" title |
| **Yellow** | Irreversible warning | "No recovery mechanism", "will not be shown again" |
| **Red** | Error | `✗` wrong input, failed verification |
| **Default (white)** | Always-available escape | `ESC` — findable when needed, doesn't compete with the action pair |
| **Dim** | Supporting / secondary | Option descriptions, `Cancel`, `Navigate`, `Go back`, memorization hints |

Accessibility: symbols (`✓`, `✗`, `⚠`, `›`, `●`, `○`) carry meaning
independently. The design degrades to monochrome without information loss.

---

## Pre-flight check

Before the wizard starts, check if a CA already exists:

```
$ koi certmesh create

  ⚠  A certificate mesh already exists on this machine.

     Profile:        Just me
     CA fingerprint: a1b2c3d4...
     Members:        3 active

  To inspect:   koi certmesh status
  To destroy:   koi certmesh destroy

  No changes made.
```

If a daemon isn't running, bail with guidance before the wizard starts.

---

## Wizard flow

### Intro (no gate)

```
  ╭──────────────────────────────────────────────────────╮
  │  Create a certificate mesh                           │
  │                                                      │
  │  A certificate mesh is a private Certificate         │
  │  Authority (CA) for your local network. It lets      │
  │  your machines issue and trust TLS certificates      │
  │  without relying on an external provider.            │
  │                                                      │
  │  ESC at any time to cancel.                          │
  ╰──────────────────────────────────────────────────────╯
```

No "Press Enter to begin." Step 1 appears immediately below. The user's first
interaction is a real choice, not a formality.

`ESC` is **default (white)** — always available, never the primary action.

---

### Step 1 of 2 — Profile

```
  Step 1 of 2 — Who is this mesh for?

  › ● Just me            You control every machine on the network.
                          Anyone with the authenticator code can join.

    ○ My team             A small group. An operator name is recorded
                          in the audit log for accountability.

    ○ My organization     Strict access control. Enrollment starts
                          closed — each machine must be approved.

    ○ Custom              Choose each policy individually.

  ↑↓ Navigate  Enter Just me  ESC Cancel
```

Color:
- `Just me` in the list is **cyan** — it's what you'll get.
- `Enter` and `Just me` in the bottom bar are **cyan** — cause and effect.
- The bottom bar label **changes with the selection**: arrow to "My team" and
  it reads `Enter My team`.
- `↑↓` and `Navigate` are **dim**.
- `ESC` is **default (white)**. `Cancel` is **dim**.
- Option descriptions are **dim**.

**Just me** — Enter advances immediately. No sub-prompts.

**My team** or **My organization** — operator sub-prompt:

```
  ✓ My team

    Operator name (for audit trails): _
    (default: stone-01\onose)

  Enter Confirm  ESC Cancel
```

Enter on blank input accepts the default (system username). The operator field
is part of step 1, not a separate step.

**Custom** — policy sub-prompts within step 1:

```
  ✓ Custom

    Enrollment when mesh is created:

    › ● Open              Any machine with a valid auth credential can join
                           immediately. You can close enrollment later.

      ○ Closed            Machines cannot join until you explicitly
                           run 'certmesh open-enrollment'.

    ↑↓ Navigate  Enter Open  ESC Cancel
```

```
    ✓ Enrollment: Open

    Require approval for each join request?

    › ● No                Auth credential is sufficient. Machine joins
                           immediately after verification.

      ○ Yes               After auth verification, an operator must
                           approve the request before a cert is issued.

    ↑↓ Navigate  Enter No  ESC Cancel
```

```
    ✓ Approval: No

    Operator name (for audit trails):
    Leave blank for none. (default: none)

    Enter Confirm  ESC Cancel
```

After completion:

```
  ✓ Custom (Open enrollment, no approval)
```

The `✓` is **green**. The label is default — settled fact.

Backspace within the Custom sub-flow navigates up one level. Backspace at the
top of the sub-flow returns to the profile picker. ESC always cancels the
entire wizard.

---

### Step 2 of 2 — CA passphrase

```
  Step 2 of 2 — CA passphrase

  This passphrase protects your CA's private key. You'll need
  it every time the daemon restarts.

  ┌─────────────────────────────────────────────────────┐
  │  ⚠  There is no recovery mechanism.                 │
  │     If you lose this passphrase, the entire mesh    │
  │     must be recreated from scratch.                 │
  └─────────────────────────────────────────────────────┘

  › ● Let me mash the keyboard!   Fun & secure. (default)

    ○ Generate one for me          Quick — just wait.

    ○ I'll type my own             For password manager users.

  ↑↓ Navigate  Enter Let me mash the keyboard!  ESC Cancel
```

- Warning box: `⚠` and "no recovery mechanism" are **yellow**.
- Same cause-effect color pairing on Enter + selected option.

All three paths collect entropy (OS RNG + operator input), then generate an
XKCD-style passphrase from that entropy. The passphrase protects the key at
rest; the entropy seed determines the key itself. They are independent inputs
to key generation, and all three paths produce both.

#### Keyboard mashing path (default)

Keyboard mashing is the default because it's the most engaging option and
adds genuine timing entropy on top of OS RNG. Following the Zen Garden
lineage: "Security should feel empowering, not restrictive."

```
  Mash your keyboard randomly... GO!

  ████████████████░░░░░░░░░░░░░░░░░░░░░░░░ 24/64
```

- `GO!` is **cyan** — call to action.
- Filled bar portion is **cyan**. Unfilled is dim.
- Minimum 64 keystrokes. Timing deltas between keypresses are mixed into
  the entropy pool alongside the key values and OS RNG samples.

After reaching 64:

```
  ████████████████████████████████████████ 64/64

  ✓ Collected entropy from 64 keystrokes

  Press Enter to see your passphrase...
```

- `✓` is **green**.
- `Enter` is **cyan**.

The collected entropy (keystroke timing + key values + OS RNG) is hashed
and used to seed the passphrase generator. The passphrase is derived *from*
the mashing — it's the human-readable form of what the user just created.

#### Generate path

For users who want "just give me something secure" without interaction.
Uses OS RNG only — no keystroke input.

```
  Generating a secure passphrase...

  ✓ Done! Secure entropy collected.

  Press Enter to see your passphrase...
```

- `✓ Done!` is **green**.
- `Enter` is **cyan**.

#### Passphrase proposal

The "Keyboard mashing" and "Generate" paths converge here. The entropy has
been collected; now the user sees the passphrase it produced:

```
  Your generated passphrase:

      compass-twilight-harvest-82

  Memorization hint: "A compass at twilight, harvest #82"

  › ● Accept this passphrase

    ○ I'll use my own instead

  ↑↓ Navigate  Enter Accept  ESC Cancel
```

- The passphrase is **cyan bold** — the most important text on screen.
- The memorization hint is **dim**.
- Same cause-effect pairing.

The passphrase was generated from the entropy the user just provided (mashing
or OS RNG). Accepting it means no further input. Switching to "I'll use my
own" replaces the generated passphrase but preserves the entropy seed —
operator-provided passphrases still get mixed with the existing pool.

**Accept** — confirm by typing the last word:

```
  Confirm by typing the last word: harvest

  > _
```

- `harvest` is **cyan bold** — the exact thing to type.

Correct:

```
  > harvest
  ✓ Passphrase set
```

Wrong:

```
  > harvst
  ✗ That doesn't match. Try again.

  > _
```

- `✗` is **red**.

#### "I'll use my own" path

Skips entropy collection and passphrase generation entirely. For users who
have a passphrase from a password manager or their own method. Entropy is
derived from the passphrase itself, mixed with OS RNG.

**Freeform entry:**

```
  Passphrase:         my-secret-phrase-here
  Confirm passphrase: my-secret-phrase-here

  ✓ Passphrase set (entropy: 48 bits — strong)
```

- `strong` is **green**.

Passphrase is shown in cleartext — not masked. The user is on their own
terminal. The threat model for "Just me" and "My team" does not include
shoulder-surfing.

If too weak:

```
  Passphrase:         abc123

  ⚠ Entropy: 19 bits — too weak
     Minimum: 40 bits. Try a longer phrase,
     or accept a generated one.

  Passphrase: _
```

- `⚠` and `too weak` are **yellow**.

---

### Review

```
  ╭── Review ──────────────────────────────────────────╮
  │                                                     │
  │  1. Profile:     Just me                            │
  │  2. Passphrase:  compass-twilight-harvest-82        │
  │                                                     │
  │  This will:                                         │
  │  • Generate an ECDSA P-256 CA keypair               │
  │  • Create a CA on this machine (stone-01)           │
  │  • Install the CA in your system trust store        │
  │  • Open enrollment for other machines               │
  │                                                     │
  │  (passphrase will not be shown again after creation)│
  │                                                     │
  ╰─────────────────────────────────────────────────────╯

  Enter Create  1-2 Go back  ESC Cancel
```

- `Enter` and `Create` are **cyan** — the primary action pair.
- The passphrase is **cyan bold** — last chance to see it.
- `(passphrase will not be shown again after creation)` is **yellow**.
- `1-2` is **default (white)** — available but secondary.
- `Go back` is **dim**.
- `ESC` is **default (white)**. `Cancel` is **dim**.

`1` navigates back to profile. `2` navigates back to passphrase. All choices
are preserved when returning.

**This is the single commitment point.** Nothing irrevocable has happened
until Enter is pressed here.

---

### Creation

```
  Creating certificate mesh...

  ✓ CA keypair generated (ECDSA P-256)
  ✓ Private key encrypted (Argon2id + AES-256-GCM)
  ✓ Roster initialized
  ✓ CA installed in system trust store
  ✓ Audit log started
```

- All `✓` are **green**.
- Trust store failure (non-fatal):

```
  ⚠ Could not install CA in trust store (run as admin to fix)
```

- `⚠` is **yellow**. Creation continues.

---

### Auth setup (post-creation output)

```
  Authenticator setup

  When other machines join this mesh, they'll prove
  authorization with a one-time code from an authenticator
  app (Google Authenticator, Authy, 1Password, etc.)
  or a FIDO2 security key.

  Scan this QR code:

  █████████████████████████████
  █ ▄▄▄▄▄ █ ▄ ▄ ██▀██ ▄▄▄▄▄ █
  ...

  Or enter this code manually: JBSWY3DPEHPK3PXP

  ┌─────────────────────────────────────────────────────┐
  │  Save this now. It will not be shown again.         │
  │  (rotate later with 'koi certmesh rotate-auth')      │
  └─────────────────────────────────────────────────────┘

  Enter Continue  ESC Cancel
```

- The manual code `JBSWY3DPEHPK3PXP` is **cyan bold** — critical value.
- "will not be shown again" is **yellow**.
- `Enter` and `Continue` are **cyan** — cause-effect pair.

The auth credential is generated server-side during the `POST /v1/certmesh/create` call.
It's shown here as output, not as a wizard step. The user isn't making a
decision — they're acknowledging and recording.

The raw code is always displayed alongside the QR for headless/SSH terminals
where the QR may not render.

---

### Verification

```
  Verifying setup...

  ✓ CA certificate valid (expires 2036-02-13)
  ✓ Trust store recognizes the CA
  ✓ CA key decrypts successfully
  ✓ mDNS announcing _certmesh._tcp
  ✓ Auth verification ready
```

- All `✓` **green**. Failed checks: `✗` in **red** with explanation.

---

### Summary

```
  ╭── Certificate mesh created ────────────────────────╮
  │                                                     │
  │  Profile:        Just me                            │
  │  CA fingerprint: a1b2c3d4e5f6...                   │
  │  Hostname:       stone-01                           │
  │  Certificates:   %ProgramData%\koi\certs\stone-01  │
  │                                                     │
  ╰─────────────────────────────────────────────────────╯

  What's next:
  • On another machine:       koi certmesh join
  • After a daemon restart:   koi certmesh unlock
  • Check status anytime:     koi certmesh status
```

- `Certificate mesh created` is **green**.
- Commands in "What's next" are **cyan** — action targets.

---

## Flag pre-fill behavior

Any flag pre-fills its corresponding step. If all inputs for a step are
provided, that step is skipped entirely. The wizard only asks what it doesn't
already know.

| Flags provided | Steps shown |
|---|---|
| none | 1 → 2 → Review |
| `--profile just-me` | 2 → Review |
| `--profile team --operator Alice` | 2 → Review |
| `--passphrase "..."` | 1 → Review |
| `--profile just-me --passphrase "..."` | Review only |
| all flags + `--json` | No UI. Execute. JSON output. |
| `--json` with missing flags | Immediate JSON error: `{"error": "missing_flags", "required": [...]}` |

The `--entropy` flag is removed from the HTTP API — keyboard mashing is a
CLI-only interactive concept that doesn't belong in a programmatic interface.
In non-interactive mode (`--json`), `--passphrase "..."` implies
user-provided passphrase. Entropy is always auto-generated and mixed with
OS RNG.

---

## Implementation notes

### Server API unchanged

The CLI derives the passphrase and entropy seed from the unified wizard flow
and still sends them as separate fields to the daemon (`passphrase` +
`entropy_hex`). The server-side `POST /v1/certmesh/create` handler is
unaffected.

### Entropy is never wasted

All three paths produce an entropy seed mixed with OS RNG:

- **Keyboard mashing**: keystroke timing + key values + OS RNG → entropy seed
  → passphrase generated from seed. Strongest entropy pool.
- **Generate**: OS RNG only → entropy seed → passphrase generated from seed.
- **I'll use my own**: passphrase hash + OS RNG → entropy seed.

The passphrase protects the key at rest (typed on daemon restart); the entropy
seed determines the key itself. They are independent inputs to key generation.
In the mashing and generate paths, the passphrase is *derived from* the
entropy — it's the human-readable handle for the randomness the user created.

### Terminal compatibility

- Box drawing (`╭──╮`) requires Unicode support. Degrade to `+--+` on
  non-Unicode terminals.
- Color requires ANSI support. Degrade to bold/underline, then to plain text.
  Symbols (`✓`, `✗`, `⚠`) carry meaning independently of color.
- The dynamic bottom bar (`Enter Just me`) requires cursor repositioning.
  Implement with crossterm's cursor/clear-line commands.
- Narrow terminals: drop box borders, use indentation only. Test at 60
  columns minimum.

### Crossterm dependency

The wizard uses terminal rendering primitives for:
- Interactive selection and prompts
- Cursor positioning (dynamic bottom bar updates)
- ANSI color output

This is already a dependency via the entropy module.

---

## Scope of changes

| Component | Change |
|---|---|
| `crates/koi/src/commands/certmesh.rs` | Replace `create()` handler with wizard flow |
| `crates/koi-certmesh/src/entropy.rs` | Keep `KeyboardMashing` mode for CLI; remove from HTTP API surface |
| `crates/koi/src/cli.rs` | Remove `--entropy` flag. Keep `--profile`, `--operator`, `--passphrase` |
| `crates/command-surface/src/lib.rs` | No changes (wizard is CLI-specific) |
| `crates/koi/src/surface.rs` | Update `certmesh-create` CommandDef to reflect new flags |
| New: `crates/koi/src/wizard/` | Reusable wizard primitives: selector, text input, progress bar, review screen |
| `docs/guide-certmesh.md` | Update "Creating a certificate mesh" section |

The wizard primitives (`wizard/`) should be generic enough to reuse for other
interactive flows (e.g., `koi certmesh join`, `koi install`).
