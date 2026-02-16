# Ceremony Protocol

Interactive multi-step operations (creating a CA, joining a mesh, unlocking) use a server-driven ceremony engine. The design separates transport (CLI terminal I/O, HTTP JSON) from domain logic (what to ask, how to validate, when to complete).

---

## Architecture

The engine lives in `koi-common/src/ceremony.rs`. Domain ceremonies implement the `CeremonyRules` trait.

```
Client (CLI/HTTP)          CeremonyHost<Rules>           Domain Rules
  │                              │                           │
  │── CeremonyRequest ───────▶│── merge bag ────────────▶│
  │                              │   evaluate(bag) ◀────────│
  │◀─ CeremonyResponse ───────│                           │
```

The core model is a **bag of key-value pairs** (session state). There is no stage index or linear pipeline. Every client submission merges into the bag and triggers re-evaluation by the rules function.

---

## Key types

| Type                  | Purpose                                                   |
| --------------------- | --------------------------------------------------------- |
| `CeremonyHost<R>`     | Generic host managing sessions (UUIDv7 IDs, 5-minute TTL) |
| `CeremonyRules` trait | `evaluate(type, bag, render_hints) → EvalResult`          |
| `CeremonyRequest`     | Inbound: session ID, ceremony type, data map              |
| `CeremonyResponse`    | Outbound: prompts, messages, completion status            |
| `Prompt`              | Single input request with `InputType`                     |
| `Message`             | Informational display (info, QR code, summary, error)     |
| `EvalResult`          | `NeedInput`, `ValidationError`, `Complete`, `Fatal`       |

---

## Wire types

### Request

```json
{
  "session_id": "0195abc...",
  "ceremony": "init",
  "data": { "profile": "just_me" }
}
```

First request uses `"data": {}` to begin a session.

### Response

```json
{
  "session_id": "0195abc...",
  "prompts": [
    {
      "key": "passphrase",
      "prompt": "Choose a passphrase",
      "input_type": "secret_confirm",
      "required": true
    }
  ],
  "messages": [
    { "kind": "info", "title": "Profile", "content": "Just Me selected" }
  ],
  "complete": false
}
```

---

## Input types

| Type             | Purpose                          |
| ---------------- | -------------------------------- |
| `select_one`     | Numbered list with default       |
| `select_many`    | Multi-select list                |
| `text`           | Free-form text                   |
| `secret`         | Masked input                     |
| `secret_confirm` | Masked with confirmation         |
| `code`           | Short code (e.g., TOTP 6-digit)  |
| `entropy`        | Raw keyboard mashing for entropy |
| `fido2`          | FIDO2 assertion                  |

## Message types

| Kind      | Purpose                                 |
| --------- | --------------------------------------- |
| `info`    | Informational text                      |
| `qr_code` | QR code (UTF-8 art, PNG base64, or URI) |
| `summary` | Styled summary box                      |
| `error`   | Error message                           |

---

## Session management

- Sessions use UUIDv7 IDs (time-ordered)
- Default TTL: 5 minutes
- Expired sessions swept every 60 seconds
- No persistent storage - sessions exist in memory only

---

## Pond ceremonies

`PondCeremonyRules` in `koi-certmesh/src/pond_ceremony.rs` implements four ceremonies:

| Ceremony | Purpose                   | Key bag entries                                                   |
| -------- | ------------------------- | ----------------------------------------------------------------- |
| `init`   | Create a new CA           | profile, operator, entropy, passphrase, unlock method, TOTP setup |
| `join`   | Enroll into existing mesh | endpoint, auth code, certificate                                  |
| `invite` | Generate invitation       | passphrase, invite token                                          |
| `unlock` | Unlock a locked CA        | method selection, credential                                      |

The `init` ceremony supports four profiles:

| Profile           | Enrollment   | Approval     | Unlock       |
| ----------------- | ------------ | ------------ | ------------ |
| `just_me`         | Closed       | No           | Auto-unlock  |
| `my_team`         | Open         | No           | Passphrase   |
| `my_organization` | Open         | Required     | Passphrase   |
| `custom`          | Configurable | Configurable | Configurable |

---

## CLI render loop

`ceremony_cli.rs` is a "dumb render loop" - it sends requests, renders prompts (with color, box drawing, QR codes), collects terminal input, and repeats until completion. The CLI never contains domain logic; all branching, validation, and content decisions live in the rules function.

This separation means the same ceremony works identically from CLI and HTTP with the same business logic.
