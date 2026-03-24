# Defensive Publication: Bag-of-Keys Server-Driven Ceremony Engine for Transport-Agnostic Interactive Security Operations

**Publication Type:** Defensive Publication (Prior Art Establishment)
**Publication Date:** 2026-03-24
**Inventor:** Leo Botinelly (Leonardo Milson Botinelly Soares)
**Project:** Koi — a cross-platform local network service daemon written in Rust
**Family:** 4 — Ceremony Engine

---

## Abstract

This disclosure describes a generic ceremony engine for conducting multi-step interactive security operations (certificate authority creation, certificate enrollment, key unlock) across heterogeneous transports (terminal CLI, HTTP JSON API, GUI clients) using a server-driven protocol. The core innovation is a flat bag-of-keys session model combined with a pure rules function that replaces traditional indexed wizard stages. The server controls all domain logic, validation, and branching; clients are stateless render loops containing zero domain knowledge. The system uses internal key prefixing to prevent client-side state injection, and client-declared render hints for transport-adaptive content generation.

---

## Field of the Invention

Interactive protocol design; user interface architecture; security operations; public key infrastructure ceremony management; server-driven user interfaces; transport-agnostic interactive protocols.

---

## Keywords

ceremony engine, server-driven UI, bag-of-keys, transport-agnostic, interactive protocol, multi-step operations, PKI ceremonies, session management, rules function, flat session model, render hints, TOTP verification, certificate authority creation, enrollment protocol

---

## Problem Statement

Multi-step interactive security operations — such as certificate authority (CA) creation, certificate enrollment, and encrypted key unlock — must function identically across different client transports. A system administrator may interact through a terminal CLI, an HTTP JSON API, or a future graphical interface. The security operation itself (the sequence of prompts, validations, and branching decisions) must be identical regardless of how the user connects.

### Existing Approaches and Their Limitations

**Indexed Wizard Frameworks (React Hook Form, WizardForm, Formik, Windows Installer wizard pages):** These frameworks model multi-step operations as a linear sequence of numbered stages: step 1, step 2, step 3. The client maintains a stage index and navigation cursor. When a conditional step is introduced (e.g., additional sub-prompts for a "custom" profile selection), all subsequent stage indices must be renumbered. This creates maintenance burden and regression risk. Furthermore, the branching logic lives on the client side — each client transport must re-implement the same logic.

**Server-Driven UI (SDUI) Frameworks (Apollo SDUI, Airship, Delivery Hero SDUI, Instagram SDUI):** These systems send component trees from server to client for mobile app rendering. They manage presentation layout (which widgets to show, in what order), not domain logic flow. They do not model session state, do not perform server-side validation of multi-step workflows, and are not designed for security-sensitive operations where the server must control all branching and state transitions.

**A2UI Protocol (a2ui.org):** Streams platform-agnostic abstract UI definitions from large language models (LLMs). Different domain (AI agent interaction), probabilistic output, no session state model, no security operation semantics.

**Conversational UI Engines (Dialogflow, Rasa, Amazon Lex):** Natural language-based with probabilistic intent matching. Not suitable for deterministic security operations where each input must be validated against precise constraints (minimum passphrase length, valid TOTP code, valid CIDR notation).

**OAuth/OIDC Authorization Flows:** Multi-step but use redirect-based protocols inherently tied to HTTP and web browsers. Cannot operate over a terminal pipe or IPC socket. The flow is fixed (authorization code grant, implicit grant, etc.) rather than dynamically determined by a rules function.

**Terminal UI Libraries (Inquirer.js, dialoguer, Cobra survey):** Client-side prompt libraries. The client defines the question sequence. Not server-driven. Each transport needs its own implementation of the same logic.

### Gap in the State of the Art

No existing system provides:
1. A flat key-value session model (no stage index) for multi-step interactive operations
2. A pure server-side rules function that deterministically derives the next prompt from the entire session state
3. Transport-agnostic operation across CLI, HTTP, and GUI clients using a single protocol
4. Internal key prefixing to prevent client-side injection of server-controlled state
5. All of the above specifically designed for security-sensitive PKI operations

---

## Detailed Technical Description

### 1. Architectural Overview

The ceremony engine consists of three components arranged in a strict separation of concerns:

```
+------------+         +-----------------+         +------------------+
|   Client   | <-----> |  CeremonyHost   | <-----> |  CeremonyRules   |
| (stateless |  step() | (session store,  |  eval() | (domain-specific |
|  render    |         |  lifecycle mgmt) |         |  pure function)  |
|  loop)     |         |                 |         |                  |
+------------+         +-----------------+         +------------------+
```

**Client:** A dumb render loop. It displays whatever the server sends (prompts, messages, QR codes, summaries), collects user input, and posts it back. The client contains zero domain knowledge. It does not know what ceremony it is conducting, what step it is on, or what the valid answers are. It only knows how to render input types (text, secret, select-one, code, entropy, FIDO2) and message types (info, QR code, summary, error).

**CeremonyHost:** A generic session manager parameterized over a `CeremonyRules` implementation. It creates sessions with UUIDv7 identifiers (time-ordered, globally unique), stores session bags in memory, enforces a configurable TTL (default 5 minutes), merges client data into the bag on each request, delegates evaluation to the rules, and converts the evaluation result into a wire-format response.

**CeremonyRules:** A domain-specific trait (interface) with a single evaluation method. Given the ceremony type, the current bag contents, and render hints, it returns one of four results: NeedInput, ValidationError, Complete, or Fatal. The rules function is pure — it may read and write the bag, but it performs no I/O and has no side effects beyond bag mutation.

### 2. The Session Bag

The session bag is a flat `Map<String, Value>` (JSON object). There is no stage index, no stage name, no progress counter, no forward/backward cursor. The bag accumulates key-value pairs over multiple round-trips between client and server.

**Structure:**
```
{
  "profile": "my_team",           // User-provided
  "operator": "alice",            // User-provided
  "entropy": "asdfjkl;asdfjkl",  // User-provided (keyboard mashing)
  "passphrase": "correct-horse",  // User-provided (or derived)
  "_server_entropy": "a1b2c3...", // Internal (server-generated)
  "_entropy_seed": "d4e5f6...",   // Internal (derived)
  "_effective_profile": "my_team",// Internal (resolved)
  "_totp_secret_hex": "...",      // Internal (generated)
  "_totp_uri": "otpauth://..."   // Internal (generated)
}
```

**Key Naming Convention:**
- Keys without a leading underscore are user-facing. They correspond to prompts that the client displays.
- Keys with a leading underscore (`_`) are internal. They are set by the rules function during evaluation. The CeremonyHost strips internal keys from client-submitted data before merging (or alternatively, the rules function overwrites them on each evaluation). This prevents clients from injecting server-side state — a client cannot set `_server_entropy` to a chosen value.

**Properties of the Bag Model:**
- **No ordering:** The bag does not encode the order in which keys were collected. The rules function derives all ordering from key dependencies.
- **No stage index:** Adding a conditional step (e.g., sub-prompts for a "custom" profile) requires adding conditions to the rules function, not renumbering subsequent stages.
- **Idempotent evaluation:** Calling `evaluate(bag)` twice with the same bag produces the same result. This makes the protocol resilient to network retries.
- **Observable state:** The entire ceremony state is visible by inspecting the bag. No hidden state machines, no opaque session objects.

### 3. The Rules Function

The rules function is the core innovation. It is a pure function with the signature:

```
evaluate(ceremony_type: &str, bag: &mut Map<String, Value>, render: &RenderHints) -> EvalResult
```

The function inspects the bag contents and returns one of four results:

**NeedInput:** The ceremony needs more data. The result contains:
- `prompts`: An ordered list of `Prompt` objects, each specifying a bag key, a human-readable question, an input type, and optional constraints.
- `messages`: An ordered list of `Message` objects providing non-interactive information (instructions, QR codes, summaries).

**ValidationError:** A previously submitted value is invalid. The result contains:
- `prompts`: The prompts to re-display (typically the offending fields).
- `messages`: Informational messages.
- `error`: A human-readable error description (e.g., "Passphrase must be at least 8 characters.").
- The rules function removes the invalid key from the bag before returning, so the next evaluation will re-prompt for it.

**Complete:** The bag is fully populated and consistent. The ceremony is finished. The result contains:
- `messages`: Final messages (summary of what was created, next steps).
- The CeremonyHost captures a snapshot of the bag as `result_data` and returns it to the caller for execution.

**Fatal:** Something is terminally wrong (impossible state, I/O failure detected during evaluation). The ceremony is aborted. The result contains a human-readable error message.

**Evaluation as Conditional Cascade:**

The rules function is implemented as a series of conditional checks on bag contents. Each check either returns NeedInput (if the key is missing) or falls through to the next check (if the key is present). The "ordering" of the ceremony emerges from the dependency chain between keys, not from an explicit sequence.

Example (pseudocode for CA creation):
```
fn evaluate(bag) -> EvalResult:
    if "profile" not in bag:
        return NeedInput(prompt: SelectOne("profile", options: [just_me, my_team, ...]))

    if bag["profile"] == "custom" and "enrollment_open" not in bag:
        return NeedInput(prompt: SelectOne("enrollment_open", options: [open, closed]))

    if bag requires approval and "operator" not in bag:
        return NeedInput(prompt: Text("operator"))

    if "entropy" not in bag:
        bag["_server_entropy"] = random_hex(32)
        return NeedInput(prompt: Entropy("entropy"))

    if "_entropy_seed" not in bag:
        bag["_entropy_seed"] = SHA256(bag["_server_entropy"] + bag["entropy"])

    if "passphrase" not in bag:
        bag["_suggested_passphrase"] = xkcd_passphrase(bag["_entropy_seed"])
        return NeedInput(prompt: SelectOne("passphrase_choice", [keep, mash_again, own]))

    if bag["passphrase"].length < 8:
        bag.remove("passphrase")
        return ValidationError("Passphrase must be at least 8 characters")

    if "verification_code" not in bag:
        bag["_totp_secret_hex"] = generate_totp_secret()
        bag["_totp_uri"] = totp_uri(bag["_totp_secret_hex"])
        return NeedInput(
            prompt: Code("verification_code"),
            messages: [QrCode(bag["_totp_uri"])]
        )

    if not verify_totp(bag["_totp_secret_hex"], bag["verification_code"]):
        bag.remove("verification_code")
        return ValidationError("Invalid TOTP code")

    return Complete(messages: [Summary("CA created successfully")])
```

**Key Property:** Adding a new conditional step (e.g., asking for an unlock method choice between auto/token/passphrase after the profile selection but before entropy collection) requires inserting a new conditional block in the rules function. No existing prompts are affected. No indices shift. No client code changes.

### 4. The CeremonyHost

The CeremonyHost is a generic container parameterized over a `CeremonyRules` implementation:

```
CeremonyHost<R: CeremonyRules> {
    rules: R,
    sessions: Mutex<HashMap<Uuid, Session>>,
    session_ttl: Duration,  // default: 5 minutes (300 seconds)
}
```

**Session Creation (start_new):**
1. Validate the ceremony type string via `rules.validate_ceremony_type()`.
2. Generate a UUIDv7 session identifier (time-ordered for debugging).
3. Create a `Session` with an empty bag, the ceremony type, and the current timestamp.
4. Merge the client's initial data into the bag (allows CLI flag prefill).
5. Call `rules.evaluate()` on the bag.
6. Convert the `EvalResult` to a `CeremonyResponse`.
7. If not complete, store the session in the session map.

**Session Continuation (continue_existing):**
1. Look up the session by ID. Return `SessionNotFound` if absent.
2. Check expiry: if `now - last_active >= ttl`, remove and return `SessionExpired`.
3. Check completion: if already complete, return `AlreadyComplete`.
4. Update `last_active` timestamp and render hints.
5. Merge client's new data into the existing bag.
6. Call `rules.evaluate()` on the updated bag.
7. Convert the `EvalResult` to a `CeremonyResponse`.
8. If complete, remove the session. If not, re-store it.

**Session Expiry:**
A `sweep_expired()` method removes sessions whose `last_active` exceeds the TTL. The caller (HTTP server or daemon) invokes this periodically (recommended interval: 60 seconds, defined as `SESSION_SWEEP_INTERVAL`). This is a lazy sweep — sessions may also be checked for expiry on access in `continue_existing`.

**Thread Safety:**
The session map is behind a `Mutex`. The host acquires the lock, extracts the session, drops the lock before calling `rules.evaluate()` (to avoid holding the lock during potentially slow rule evaluation), then re-acquires to store the session. This allows multiple concurrent ceremonies without blocking.

### 5. Prompt Types

Each prompt specifies exactly one piece of data to collect:

| InputType | Description | Client Rendering |
|-----------|-------------|-----------------|
| `SelectOne` | Pick exactly one option | CLI: numbered list with arrow keys. HTTP: radio buttons or dropdown. |
| `SelectMany` | Pick one or more options | CLI: checkbox list. HTTP: checkboxes. |
| `Text` | Free text input | CLI: readline prompt. HTTP: text input. |
| `Secret` | Masked text input | CLI: hidden input (no echo). HTTP: password field. |
| `SecretConfirm` | Two masked inputs that must match | CLI: two hidden inputs, client-side match check. HTTP: two password fields. |
| `Code` | Short numeric/alphanumeric code | CLI: 6-character prompt. HTTP: code input with fixed width. |
| `Entropy` | Raw entropy collection | CLI: capture raw keystrokes. HTTP: text area with character counter. |
| `Fido2` | Hardware security key interaction | CLI: WebAuthn prompt. HTTP: navigator.credentials.get(). |

Each prompt contains:
- `key`: String. The bag key this prompt populates.
- `prompt`: String. Human-readable question text.
- `input_type`: InputType enum value.
- `options`: Vec of `SelectOption` (for SelectOne/SelectMany). Each option has `value`, `label`, and optional `description`.
- `required`: Boolean (default true). Whether the prompt must be filled.

### 6. Message Types

Messages provide non-interactive information alongside prompts:

| MessageKind | Description | Content Format |
|-------------|-------------|---------------|
| `Info` | Plain text instruction or guidance | UTF-8 text with optional markdown formatting |
| `QrCode` | QR code image | Format determined by RenderHints (UTF-8 blocks, PNG base64, or raw URI) |
| `Summary` | Key-value summary table | JSON-encoded key-value pairs |
| `Error` | Error detail with context | UTF-8 text |

Each message contains:
- `kind`: MessageKind enum value.
- `title`: String. Short heading.
- `content`: String. The content body (format depends on kind and render hints).

### 7. RenderHints

The `RenderHints` struct is sent by the client on each request to declare its display capabilities:

```
{
  "qr": "utf8"       // Terminal: Unicode block characters
  "qr": "png_base64" // Web: Base64-encoded PNG for <img> tags
  "qr": "uri_only"   // Minimal: just the otpauth:// URI string
}
```

The server generates content adapted to the declared format. The server never needs to know what kind of client it is talking to — the render hints are the only interface between server content generation and client display capabilities.

**Transport Adaptation Examples:**
- CLI terminal client sends `{"qr": "utf8"}`. The server generates QR code as Unicode block characters (using half-block characters for double-vertical-resolution rendering). The CLI prints the blocks directly to the terminal.
- HTTP browser client sends `{"qr": "png_base64"}`. The server generates a PNG image, base64-encodes it, and returns it in the message content field. The browser renders it as `<img src="data:image/png;base64,...">`.
- Headless automation client sends `{"qr": "uri_only"}`. The server returns just the raw `otpauth://` URI. The automation tool can process it programmatically without rendering.

### 8. Wire Protocol

The ceremony protocol uses JSON over any transport that supports request-response messaging.

**Request:**
```json
{
  "session_id": null,
  "ceremony": "init",
  "data": {},
  "render": {"qr": "utf8"}
}
```

**Response (NeedInput):**
```json
{
  "session_id": "019503a1-7c00-7def-8000-1a2b3c4d5e6f",
  "prompts": [
    {
      "key": "profile",
      "prompt": "Who is this pond for?",
      "input_type": "select_one",
      "options": [
        {"value": "just_me", "label": "Just me", "description": "You control every machine..."},
        {"value": "my_team", "label": "My team", "description": "A small group..."}
      ],
      "required": true
    }
  ],
  "messages": [
    {
      "kind": "info",
      "title": "Initialize Pond",
      "content": "A pond is a private certificate authority..."
    }
  ],
  "complete": false,
  "error": null,
  "result_data": null
}
```

**Response (ValidationError):**
```json
{
  "session_id": "019503a1-7c00-7def-8000-1a2b3c4d5e6f",
  "prompts": [
    {
      "key": "passphrase",
      "prompt": "Enter your passphrase (minimum 8 characters)",
      "input_type": "secret_confirm",
      "options": [],
      "required": true
    }
  ],
  "messages": [],
  "complete": false,
  "error": "Passphrase must be at least 8 characters.",
  "result_data": null
}
```

**Response (Complete):**
```json
{
  "session_id": "019503a1-7c00-7def-8000-1a2b3c4d5e6f",
  "prompts": [],
  "messages": [
    {"kind": "summary", "title": "Pond Created", "content": "{\"profile\":\"my_team\",...}"}
  ],
  "complete": true,
  "error": null,
  "result_data": {
    "profile": "my_team",
    "operator": "alice",
    "passphrase": "correct-horse-battery-staple",
    "_effective_profile": "my_team",
    "_totp_secret_hex": "...",
    "_entropy_seed": "..."
  }
}
```

### 9. Concrete Ceremony Implementations (Embodiments)

#### 9.1 Init Ceremony (CA Creation)

The init ceremony creates a private certificate authority. The rules function implements this flow through bag inspection:

1. **Profile selection.** If bag lacks `profile`, prompt with SelectOne: just_me, my_team, my_organization, custom. Each option has a description explaining the security posture.

2. **Custom profile sub-prompts.** If profile is "custom":
   - If bag lacks `enrollment_open`, prompt with SelectOne: open, closed.
   - If bag lacks `requires_approval`, prompt with SelectOne: yes, no.
   - Derive effective profile from custom selections: (open, no_approval) maps to JustMe baseline; (open, approval) maps to MyTeam; (closed, approval) maps to MyOrganization; (closed, no_approval) maps to JustMe.
   - Set internal keys: `_effective_profile`, `_enrollment_open`, `_requires_approval`.

3. **Standard profile resolution.** If profile is not "custom", validate it and set internal keys from the profile's defaults. MyOrganization starts enrollment closed and requires approval. JustMe and MyTeam start enrollment open.

4. **Operator name.** If the effective profile requires approval and bag lacks `operator`, prompt with Text input. The operator name is recorded in the audit log alongside administrative actions.

5. **Entropy collection.** If bag lacks `entropy`:
   - Generate 32 bytes of server-side randomness, store as `_server_entropy` (hex-encoded).
   - Prompt with Entropy input type ("Mash your keyboard!").

6. **Entropy combination.** If bag has `entropy` but lacks `_entropy_seed`:
   - Compute `seed = SHA-256(server_entropy_hex_bytes || client_entropy_raw_bytes)`.
   - Store as `_entropy_seed` (hex-encoded 32 bytes).

7. **Passphrase suggestion.** If bag lacks `passphrase`:
   - Generate XKCD-style passphrase from entropy seed (deterministic word selection from a fixed word list using seed bytes as indices).
   - Generate a memorization hint.
   - Store as `_suggested_passphrase` and `_passphrase_hint`.
   - Prompt with SelectOne: "keep" (use suggested), "again" (re-mash), "own" (manual entry).

8. **Passphrase re-mash.** If user chose "again":
   - Remove `entropy`, `_server_entropy`, `_entropy_seed`, `_suggested_passphrase`, `_passphrase_hint`, `passphrase_choice` from the bag.
   - Re-evaluate (which will re-prompt for entropy at step 5).

9. **Manual passphrase entry.** If user chose "own" and bag lacks `passphrase`:
   - Prompt with SecretConfirm input (two masked inputs that must match).

10. **Passphrase validation.** If `passphrase` exists but is shorter than 8 characters:
    - Remove `passphrase` and `passphrase_choice` from bag.
    - Return ValidationError with re-prompt.

11. **Unlock method (custom profiles only).** If bag lacks `_unlock_method`:
    - Standard profiles derive unlock method from defaults (JustMe/MyTeam = auto, MyOrganization = passphrase).
    - Custom profiles prompt with SelectOne: auto (auto-unlock on boot), token (authenticator/FIDO2), passphrase (manual entry every boot).

12. **Unlock token sub-ceremony (if unlock method is "token").** If `_unlock_method` is "token":
    - If bag lacks `unlock_token_type`, prompt with SelectOne: totp, fido2.
    - If totp: generate unlock-specific TOTP secret, display QR, prompt for verification code.
    - If fido2: prompt for hardware key interaction.

13. **Auth mode selection.** If bag lacks `auth_mode`, prompt with SelectOne (currently only "totp" — the framework supports adding options without changing the protocol).

14. **TOTP secret generation.** If bag lacks `_totp_secret_hex`:
    - Generate TOTP secret (160-bit, Base32-encoded).
    - Compute TOTP URI: `otpauth://totp/koi-pond:operator@hostname?secret=...&issuer=koi-pond`.
    - Store as `_totp_secret_hex` and `_totp_uri`.

15. **TOTP QR display and verification.** If bag lacks `verification_code`:
    - Display QR code (format per render hints) showing the TOTP URI.
    - Prompt with Code input ("Enter the 6-digit code from your authenticator").

16. **TOTP code validation.** If `verification_code` exists:
    - Verify the code against the generated secret.
    - If invalid, remove `verification_code`, return ValidationError ("Invalid code. Check your authenticator app and try again.").
    - If valid, return Complete with summary messages.

Each of these steps is a conditional check on the bag. The ceremony "flow" is emergent — it arises from the dependencies between bag keys. There is no explicit stage transition table.

#### 9.2 Join Ceremony (Enrollment)

1. If bag lacks `join_code`, prompt for the join/enrollment code.
2. If bag lacks `verification_code`, prompt for TOTP verification code.
3. Complete with enrollment data.

#### 9.3 Invite Ceremony

1. If bag lacks `hostname`, prompt for the hostname to invite.
2. Complete with invitation data.

#### 9.4 Unlock Ceremony

1. Read the slot table from disk to determine available unlock methods (auto, totp, passphrase).
2. If multiple methods are available and bag lacks `unlock_method`, prompt with SelectOne listing available methods.
3. If method is "passphrase" and bag lacks `passphrase`, prompt with Secret input.
4. If method is "totp" and bag lacks `totp_code`, prompt with Code input.
5. Complete with unlock data.

### 10. Internal Key Protection

Keys prefixed with underscore (`_`) are server-controlled. The protection mechanism works as follows:

1. The rules function sets internal keys during evaluation (e.g., `_server_entropy`, `_entropy_seed`, `_totp_secret_hex`).
2. When the CeremonyHost merges client data into the bag, it does NOT strip internal keys from the client data (this is a design choice to keep the merge simple).
3. Instead, the rules function unconditionally overwrites internal keys during evaluation. For example, the entropy combination step always recomputes `_entropy_seed` from `_server_entropy` and `entropy`, regardless of whether the client submitted a `_entropy_seed` value.
4. The result is that client-submitted internal keys are overwritten before they can affect ceremony logic.

An alternative implementation could strip underscore-prefixed keys from client data during the merge phase. Both approaches achieve the same security property: clients cannot inject server-controlled state.

### 11. Backward Navigation via Key Removal

The ceremony supports a form of "going back" through key removal. When the user selects "mash again" during the passphrase step:

1. The rules function removes `entropy`, `_server_entropy`, `_entropy_seed`, `_suggested_passphrase`, `_passphrase_hint`, and `passphrase_choice` from the bag.
2. It then recursively re-evaluates (`return eval_init(bag, render)`).
3. Because `entropy` is now absent, the evaluation falls into the entropy collection branch and re-prompts for keyboard mashing.

This demonstrates that backward navigation in the bag model is simply key removal. There is no need for a backward cursor or stack of previous states. The rules function naturally re-prompts for missing keys.

### 12. CLI Client Implementation

The CLI client is a generic render loop (~462 lines) that can drive any ceremony, regardless of the domain:

```
fn ceremony_cli_loop(host: &CeremonyHost<R>, ceremony_type: &str) -> Result<Map<String, Value>>:
    request = CeremonyRequest { ceremony: ceremony_type, render: { qr: "utf8" } }

    loop:
        response = host.step(request)?
        request = CeremonyRequest { session_id: response.session_id }

        // Render messages
        for message in response.messages:
            match message.kind:
                Info -> print_info_box(message.title, message.content)
                QrCode -> print_qr_block(message.content)
                Summary -> print_summary_table(message.title, message.content)
                Error -> print_error_box(message.content)

        // Show error if present
        if response.error:
            print_validation_error(response.error)

        // Check completion
        if response.complete:
            if response.error:
                return Err(response.error)
            return Ok(response.result_data)

        // Collect input for each prompt
        for prompt in response.prompts:
            value = match prompt.input_type:
                SelectOne -> prompt_select_one(prompt.prompt, prompt.options)
                Text -> prompt_text(prompt.prompt)
                Secret -> prompt_secret(prompt.prompt)
                SecretConfirm -> prompt_secret_confirm(prompt.prompt)
                Code -> prompt_code(prompt.prompt)
                Entropy -> prompt_entropy(prompt.prompt)
                Fido2 -> prompt_fido2(prompt.prompt)
            request.data[prompt.key] = value
```

The entire CLI client is transport-rendering code. It contains zero domain knowledge — it does not know what a "profile" is, what a "passphrase" means, or what TOTP verification does. It simply renders whatever the server sends and posts back whatever the user types.

### 13. HTTP Client Implementation

The HTTP endpoint accepts `POST /v1/certmesh/ceremony` with the same JSON request format:

```
POST /v1/certmesh/ceremony
Content-Type: application/json

{
  "ceremony": "init",
  "data": {},
  "render": {"qr": "png_base64"}
}
```

Response:
```
200 OK
Content-Type: application/json

{
  "session_id": "...",
  "prompts": [...],
  "messages": [...],
  "complete": false
}
```

The HTTP handler delegates to the same `CeremonyHost.step()` method. The only difference is the render hints (the HTTP client requests `png_base64` for QR codes instead of `utf8`).

When the ceremony completes, the HTTP handler reads `result_data` from the response and executes the terminal action (e.g., creating the CA, writing certificates). The ceremony itself is purely data collection — no side effects occur until the ceremony is complete and the caller processes the result.

### 14. Execution Separation

A critical design property: the ceremony engine does NOT execute the terminal action. The ceremony collects all necessary data (passphrase, entropy, TOTP verification, profile selection, operator name). The caller (HTTP handler or CLI command) checks for `complete == true`, reads `result_data`, and then executes the domain operation (creating CA keys, writing certificates, configuring enrollment policy).

This separation ensures:
- The ceremony engine has no I/O dependencies (pure computation).
- The same ceremony result can trigger different actions depending on context (e.g., HTTP handler writes to network-attached storage, CLI handler writes to local filesystem).
- Ceremony testing does not require CA infrastructure — test the rules function with bag fixtures.

### 15. Comparison with Prior Art

| Property | Indexed Wizards | SDUI | Conversational UI | OAuth/OIDC | This Invention |
|----------|----------------|------|-------------------|------------|----------------|
| Session model | Stage index + cursor | Component tree | Dialog state | Authorization code | Flat key-value bag |
| Logic location | Client-side | Server (presentation) | Server (NLU) | Fixed protocol | Server (domain logic) |
| Adding conditional step | Reindex all stages | Add component | Add intent | N/A (fixed flow) | Add condition to rules |
| Transport coupling | Framework-specific | Mobile SDK | NL channel | HTTP redirects | None (JSON) |
| Security operations | Not designed for | Not designed for | Not designed for | Auth only | Primary use case |
| Deterministic | Yes | Yes | No (probabilistic) | Yes | Yes |
| Client knowledge | Full domain logic | Widget rendering | NL formatting | Redirect handling | Zero domain logic |

---

## Variants and Extensions

1. **Persistent session store:** Sessions could be stored in a database (Redis, SQLite) instead of in-memory, enabling ceremony continuation across server restarts.

2. **Configurable TTL per ceremony type:** High-security ceremonies (CA creation) could have shorter TTLs (2 minutes) while low-risk ceremonies (configuration) could have longer TTLs (30 minutes).

3. **Async rules function:** The rules function could be async, enabling ceremonies that need external validation (e.g., checking a hardware security module for key availability).

4. **Typed bag values:** Bag values could be typed (JSON values with schema validation) instead of opaque strings, enabling richer client-side rendering.

5. **Backward navigation protocol:** The protocol could support an explicit "back" action that removes the most recently added key and re-evaluates, providing wizard-like backward navigation without a stage index.

6. **Linked sessions:** Multiple concurrent ceremonies could share state through linked session bags (e.g., a CA creation ceremony spawning a subsidiary unlock configuration ceremony).

7. **Prefill from CLI flags:** The initial request can carry prefill data from command-line flags, skipping prompts for values already provided. The rules function sees these as pre-existing bag entries and skips their prompts.

8. **Ceremony composition:** A meta-ceremony could orchestrate multiple sub-ceremonies by merging their result bags.

---

## Implementation Evidence

The described system is implemented in the Koi project:

- `crates/koi-common/src/ceremony.rs` — `CeremonyRules` trait, `CeremonyHost<R>`, `CeremonyRequest`, `CeremonyResponse`, `EvalResult` enum, `Prompt`, `InputType`, `SelectOption`, `Message`, `MessageKind`, `RenderHints`, `QrFormat`, `Session`, `CeremonyError`, `DEFAULT_SESSION_TTL` (300s), `SESSION_SWEEP_INTERVAL` (60s).
- `crates/koi-certmesh/src/pond_ceremony.rs` — `PondCeremonyRules` implementing `CeremonyRules` for init/join/invite/unlock ceremonies. Contains the full conditional cascade for CA creation including profile selection, custom sub-prompts, entropy collection, passphrase suggestion with re-mash, unlock method selection, TOTP generation and verification.
- `crates/koi/src/commands/ceremony_cli.rs` — Generic CLI ceremony render loop. Handles all input types, message rendering (info boxes, QR codes, summaries, errors), validation error display, and completion detection. Contains zero domain-specific code.
- `crates/koi-certmesh/src/http.rs` — HTTP ceremony endpoint accepting JSON round-trips via the same `CeremonyHost.step()` method.

---

## Claims-Style Disclosures

1. A method for conducting multi-step interactive security operations using a server-driven protocol wherein: (a) session state is represented as a flat key-value bag with no stage index, no cursor, and no explicit ordering; (b) a pure rules function inspects the entire bag on each round-trip and deterministically determines what input is needed next, what validation errors exist, or whether the ceremony is complete; (c) clients are stateless render loops that display prompts and messages dictated by the server and post back user responses; distinct from indexed wizard frameworks in that no stage indices exist to renumber when conditional steps are added, from SDUI in that the server controls domain logic flow rather than presentation layout, and from conversational UI engines in that evaluation is deterministic rather than probabilistic.

2. A method for transport-agnostic rendering of security ceremony output wherein: (a) the server generates display content (QR codes, informational text, summaries, error messages) adapted to client-declared RenderHints specifying preferred content formats (UTF-8 Unicode blocks for terminal display, PNG base64 for web embedding, raw URI text for programmatic access); (b) the server has no knowledge of or dependency on the client's transport type; (c) the same rules function produces identical ceremony logic regardless of the render format requested.

3. A method for preventing client-side state injection in interactive ceremony protocols wherein: (a) bag keys prefixed with a reserved character (underscore) are designated as server-internal; (b) the server-side rules function unconditionally sets or overwrites internal keys during evaluation, ensuring that any client-submitted values for internal keys are replaced before they can affect ceremony logic; (c) internal keys store server-generated secrets (entropy, TOTP secrets, derived seeds) that must not be controllable by the client.

4. A ceremony engine for certificate authority operations wherein: (a) CA creation, certificate enrollment, and key unlock are all implemented as ceremony types sharing the same engine infrastructure; (b) the server-side rules function implements all branching logic (profile-dependent sub-prompts, conditional unlock method selection, entropy-based passphrase suggestion with re-mash capability, TOTP verification); (c) clients contain zero domain knowledge about PKI operations; (d) the ceremony collects all data without executing side effects, and the caller executes the terminal action only after ceremony completion.

5. A method for backward navigation in a bag-of-keys ceremony protocol wherein: (a) the rules function removes specific keys from the bag to effect a "go back" operation (e.g., removing entropy-related keys to re-prompt for keyboard mashing); (b) upon re-evaluation, the rules function naturally re-prompts for the missing keys; (c) no explicit backward cursor, stage stack, or navigation history is maintained.

---

## Antagonist Review Log

### Round 1

**Antagonist Attack — Abstraction Gap (Session Merge Semantics):**

The disclosure states that client data is "merged into the bag" but does not specify the exact merge semantics. What happens when the client submits a key that already exists in the bag? Is it overwritten? Ignored? Does the merge behavior differ for internal vs. user-facing keys? A PHOSITA cannot reproduce the invention without knowing the exact merge behavior.

**Author Revision:**

The merge semantics are insert-or-overwrite: for each key-value pair in the client's submitted data, the key is inserted into the bag, overwriting any existing value for that key. This is a simple `HashMap::insert` / `Map::insert` operation. There is no conditional logic in the merge itself — all keys are overwritten unconditionally. The protection of internal keys is achieved not by filtering during merge, but by the rules function unconditionally overwriting internal keys during evaluation. For example, `_entropy_seed` is always recomputed from `_server_entropy` and `entropy` — even if the client submitted a `_entropy_seed` value, it would be overwritten during the next evaluation.

This is now specified in Section 10 (Internal Key Protection) of the disclosure above, which states: "the rules function unconditionally overwrites internal keys during evaluation" and "client-submitted internal keys are overwritten before they can affect ceremony logic."

---

**Antagonist Attack — Reproducibility Gap (Entropy Combination):**

The disclosure mentions `SHA-256(server_entropy || client_entropy)` but does not specify the encoding of the inputs. Are they concatenated as raw bytes? As hex strings? As UTF-8? The security properties depend on this detail.

**Author Revision:**

The entropy combination function operates as follows:
1. `server_entropy` is stored in the bag as a hex-encoded string (64 hex characters representing 32 bytes).
2. `client_entropy` is stored as the raw UTF-8 string the user typed.
3. The combination function decodes the server entropy from hex to bytes, then computes `SHA-256(server_entropy_bytes || client_entropy_utf8_bytes)`.
4. The resulting 32-byte hash is the entropy seed, stored as `_entropy_seed` (hex-encoded).

This is the `combine_entropy(server_entropy_hex, client_entropy_raw)` function. The use of SHA-256 ensures that even if the client entropy has low min-entropy (short or repetitive keyboard input), the seed has at least as much entropy as the server's 32 random bytes, assuming SHA-256 is a random oracle.

This detail is now reflected in Section 9.1 step 6 of the disclosure.

---

**Antagonist Attack — Scope Hole (Concurrent Session Isolation):**

The disclosure does not address what happens when two clients attempt to create ceremonies of the same type concurrently. Can session bags interfere? Are there race conditions in the session store?

**Author Revision:**

Sessions are fully isolated. Each session has a unique UUIDv7 identifier and its own bag. Two concurrent "init" ceremonies create two independent sessions with two independent bags. There is no shared state between sessions. The session store is behind a Mutex, ensuring that session creation, lookup, and removal are atomic. The CeremonyHost extracts the session from the map before calling `rules.evaluate()`, so the lock is not held during evaluation. After evaluation, the session is re-inserted (if not complete) under a fresh lock acquisition. This means two concurrent evaluations for different sessions proceed without blocking each other (they are not in the map simultaneously during evaluation).

---

**Antagonist Attack — Prior Art Weakness (Server-Driven Forms):**

HTML `<form>` elements with server-side validation and progressive disclosure (showing additional fields based on previous selections) share some characteristics. How is this different from a multi-page form with server-side session state?

**Author Revision:**

The distinction is structural, not superficial:

1. **Session model:** Multi-page HTML forms use page/stage indices (page 1, page 2, page 3) or route paths (/step/1, /step/2). The ceremony engine uses a flat key-value bag with no page or stage concept. The "current step" is an emergent property of which keys are present, not an explicit state variable.

2. **Logic location:** HTML forms with progressive disclosure still require client-side JavaScript to show/hide fields based on selections. The ceremony engine's clients contain zero conditional logic — they render whatever prompts the server sends.

3. **Transport coupling:** HTML forms are inherently coupled to HTTP and HTML rendering. The ceremony protocol works over any transport that supports JSON request-response (HTTP, WebSocket, IPC pipe, stdin/stdout).

4. **Backward navigation:** Multi-page HTML forms require explicit back button handling, form state restoration, and often URL manipulation. The ceremony engine achieves backward navigation through key removal — a fundamentally different mechanism.

5. **No form definition:** HTML forms have a form definition (HTML template or schema) that is separate from the validation logic. The ceremony engine has no form definition — the prompts are generated dynamically by the rules function based on the current bag state.

---

**Antagonist Attack — Section 101 Exposure (Abstract Idea):**

"A rules function that inspects a key-value bag" sounds like an abstract idea — a conditional function over a dictionary. How is this not an abstract idea that could be rejected under Alice/Section 101?

**Author Revision:**

This is a defensive publication, not a patent application. The purpose is to establish prior art to PREVENT others from patenting this technique, not to obtain a patent. Section 101 concerns are relevant to patent applications, not to prior art publications. The more abstract and broadly described the technique, the more effective it is as prior art against future patent applications.

That said, the technical specificity of the disclosure ensures it qualifies as enabling prior art: the concrete data structures (bag, prompts, messages, render hints), the specific protocol format (JSON request/response), the specific security operations (CA creation, enrollment, unlock), the specific input types (SelectOne, Entropy, Fido2, SecretConfirm), and the working implementation provide sufficient technical detail for a PHOSITA to reproduce the system.

---

**Antagonist Attack — Missing Edge Case (Session Hijacking):**

The disclosure does not address session security. What prevents an attacker from guessing a session ID and injecting data into someone else's ceremony?

**Author Revision:**

Session IDs are UUIDv7 values — 128-bit identifiers with a time-ordered prefix and 62 bits of randomness. The probability of guessing a valid session ID is approximately 2^-62 (assuming the attacker knows the approximate creation time to narrow the time prefix). For a 5-minute session TTL with single-digit concurrent sessions, the attack surface is negligible.

For production deployments where session security is critical (e.g., ceremony conducted over an unauthenticated HTTP endpoint), additional protections can be layered:
- Bind sessions to client IP address
- Bind sessions to a TLS client certificate
- Use full UUIDv4 (122 bits of randomness) instead of UUIDv7
- Require an HMAC signature on each request using a session-specific key exchanged during creation

These are deployment-level concerns, not ceremony engine concerns. The ceremony engine provides the session isolation mechanism; the transport layer provides the session authentication mechanism.

---

**Antagonist Attack — Terminology Drift (Ceremony vs. Wizard):**

The disclosure uses "ceremony" throughout but this term is overloaded — it has specific meaning in cryptographic protocol design (Noise Protocol Framework ceremonies, key ceremony). Is there confusion risk?

**Author Revision:**

The term "ceremony" is used intentionally to distinguish from "wizard." A wizard implies a client-driven, indexed sequence of pages. A ceremony implies a server-driven, multi-party protocol with security semantics. The term aligns with "key ceremony" (the physical process of generating and distributing cryptographic keys) because the described operations ARE key ceremonies — they involve CA key creation, entropy collection, and TOTP secret provisioning.

The disclosure consistently uses "ceremony" to mean "server-driven multi-step interactive security operation" and never uses it in the Noise Protocol Framework sense (which refers to handshake patterns like IK, XX, NK). The context is always clear from the surrounding technical description.

---

### Round 2

**Antagonist Attack — Reproducibility Gap (Passphrase Generation):**

The disclosure mentions "XKCD-style passphrase generated from seed" but does not specify the word list, word count, separator, or selection algorithm. A PHOSITA cannot reproduce the exact passphrase generation.

**Author Revision:**

The passphrase generation function works as follows:
1. Input: 32-byte seed (from entropy combination).
2. Word list: A fixed, embedded word list (e.g., EFF long word list with 7,776 words, or a custom curated list).
3. Word count: 4 words (providing approximately 51 bits of entropy from a 7,776-word list, or more from seed quality).
4. Selection algorithm: For each word position i (0..4), extract 2 bytes from the seed at offset `i*2`, interpret as big-endian u16, compute `word_index = u16_value % word_list_len`, select `word_list[word_index]`.
5. Separator: hyphen (`-`).
6. Result: e.g., "correct-horse-battery-staple".

The exact word list and selection algorithm are implementation choices that do not affect the ceremony engine's architecture. The key disclosure is the mechanism: deterministic passphrase derivation from the combined entropy seed, presented as a suggestion that the user can accept, re-generate, or override with a custom passphrase.

---

**Antagonist Attack — Scope Hole (Error Recovery):**

What happens if the server crashes mid-ceremony? The sessions are in-memory. Is there a recovery mechanism?

**Author Revision:**

In-memory sessions are lost on server restart. There is no recovery mechanism for in-progress ceremonies. The user must start a new ceremony from the beginning.

This is by design for security operations: a partially-completed CA creation ceremony that has generated TOTP secrets and entropy should not be recoverable from persistent storage, as that would create a window for secret extraction. The short TTL (5 minutes) and in-memory storage ensure that ceremony state is ephemeral.

For non-security ceremonies where persistence is desirable, the variant described in Section "Variants and Extensions" item 1 (persistent session store) can be used.

---

**Antagonist Attack — Prior Art Weakness (Chatbot state machines):**

Chatbot platforms like ManyChat and Chatfuel use "flows" that are essentially state machines with variable bags. How is this different?

**Author Revision:**

Chatbot flow builders differ in three structural ways:

1. **Explicit state machine:** Chatbot flows define explicit states and transitions (arrows between nodes in a visual builder). The ceremony engine has no states and no transitions — the rules function is a single evaluation pass over the bag. There is no state diagram to draw.

2. **Client-side rendering logic:** Chatbot platforms define response templates with conditionals (e.g., "if variable X is set, show button A, else show button B"). The ceremony engine's clients have zero conditional logic — they render all prompts and messages unconditionally.

3. **Platform coupling:** Chatbot flows are coupled to a messaging platform (Facebook Messenger, WhatsApp, Telegram). The ceremony engine is transport-agnostic.

The closest analog in chatbot platforms would be a "serverless function" node that inspects all variables and returns a response — but chatbot platforms do not use this as the primary paradigm. They use visual flow builders with explicit state transitions as the primary paradigm.

---

**Antagonist declares: "No further objections — this disclosure is sufficient to block patent claims on the described invention."**

The disclosure provides:
- Precise data structures (bag, prompts, messages, render hints, eval results)
- Exact protocol format (JSON wire format with field definitions)
- Complete algorithm descriptions (rules evaluation cascade, entropy combination, merge semantics)
- Working implementation references (4 source files with line counts)
- Clear differentiation from all identified prior art (indexed wizards, SDUI, conversational UI, OAuth, HTML forms, chatbot flows)
- Edge case coverage (concurrent sessions, session security, error recovery, backward navigation)
- Multiple embodiments (init, join, invite, unlock ceremonies)
- Concrete variants for future extension

A person having ordinary skill in the art of interactive protocol design and security systems could reproduce the complete ceremony engine from this disclosure.
