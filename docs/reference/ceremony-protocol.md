# Ceremony protocol

Koi's guided certificate operations use a server-driven dialogue. Clients render prompts and submit values; domain rules decide what is required and when an operation is complete. This is an advanced protocol reference, not a requirement for the container discovery preview.

## Evaluation model

[The shared ceremony engine](../../crates/koi-common/src/ceremony.rs) owns sessions. A session is a bag of JSON key/value data, not a numbered implementation stage. Each submission merges values and re-evaluates `CeremonyRules`.

| Type | Role |
| --- | --- |
| `CeremonyHost<R>` | Session storage, expiry and rule dispatch |
| `CeremonyRequest` | Optional session ID/type, submitted data and render hints |
| `CeremonyResponse` | Session ID, prompts/messages and completion information |
| `EvalResult` | Need input, validation error, complete or fatal result |

Start with a ceremony name and empty data; subsequent requests retain the returned session ID.

```json
{"ceremony":"init","data":{}}
```

Prompt keys belong to the selected domain rules. Clients should render the returned prompts rather than assuming a fixed question order. Validation failure keeps the dialogue distinct from successful completion; a completed or expired session cannot be silently reused.

## Rendering vocabulary

Input types include `select_one`, `select_many`, `text`, `secret`, `secret_confirm`, `code` and `entropy`. Messages include informational text, QR content, summaries and errors. Treat secret/code/entropy values as sensitive: do not put the session bag into logs, screenshots or analytics.

The default session TTL is 300 seconds and the sweep interval is 60 seconds. Sessions are memory-only. A daemon restart requires a new dialogue; it must not be interpreted as permission to repeat an already-committed destructive operation.

## Certmesh rules

[InitCeremonyRules](../../crates/koi-certmesh/src/init_ceremony.rs) accepts `init`, `join`, `invite` and `unlock`. The rules own prompts, normalization, validation and completion. Transport authentication still applies to the HTTP operation that hosts the dialogue.

Named presets map to ordinary enrollment/approval/auto-unlock values:

| Preset | Enrollment | Approval | Unlock |
| --- | --- | --- | --- |
| `just_me` | Open | No | Auto-unlock |
| `my_team` | Open | Yes | Auto-unlock |
| `my_organization` | Closed | Yes | Passphrase |
| `custom` | Chosen explicitly | Chosen explicitly | Chosen explicitly |

These are configuration presets, not enterprise role isolation or independently enforced profile classes. Enrollment has no timed auto-close or CIDR/domain scope controls. Review [security](security-model.md) and [envelope encryption](envelope-encryption.md) when choosing unattended unlock.
