---
globs: crates/koi-mdns/src/http.rs
alwaysApply: false
---

# HTTP Adapter Rules

## Domain-Owned Routes

Each domain crate defines its own HTTP routes. The binary crate mounts them:

```rust
// crates/koi-mdns/src/http.rs - defines relative routes
pub fn routes(core: Arc<MdnsCore>) -> Router {
    Router::new()
        .route("/browse", get(browse_handler))
        .route("/services", post(register_handler))
        // ...
        .with_state(core)
}

// crates/koi/src/adapters/http.rs - mounts at /v1/mdns/
app = app.nest("/v1/mdns", koi_mdns::http::routes(core));
```

## Handler Signatures

```rust
// JSON response
async fn handler(
    State(core): State<Arc<MdnsCore>>,
    Query(params): Query<ParamsStruct>,
) -> impl IntoResponse { ... }

// SSE stream
async fn stream_handler(
    State(core): State<Arc<MdnsCore>>,
    Query(params): Query<ParamsStruct>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> { ... }
```

## Response Conventions

- Success: return `Json(PipelineResponse::clean(Response::variant(...)))`
- Error: return `(StatusCode, Json(error_to_pipeline(&e)))`
- SSE: use `PipelineResponse` with `status` field for stream lifecycle
- The `Response` enum handles serialization shape (wrapped vs flat) - don't fight it

## Pipeline Helpers (Free Functions)

Since `PipelineResponse<B>` is defined in `koi-common`, domain-specific helpers are free functions:

```rust
// crates/koi-mdns/src/protocol.rs
pub fn browse_event_to_pipeline(event: MdnsEvent) -> MdnsPipelineResponse;
pub fn subscribe_event_to_pipeline(event: MdnsEvent) -> MdnsPipelineResponse;
pub fn error_to_pipeline(e: &MdnsError) -> MdnsPipelineResponse;
```

## Lease Policy

HTTP registrations use heartbeat leases by default:

- Lease: `DEFAULT_HEARTBEAT_LEASE` (90s)
- Grace: `DEFAULT_HEARTBEAT_GRACE` (30s)
- Client must `PUT /v1/mdns/services/{id}/heartbeat` to renew before expiry

## Query Parameters

- `idle_for`: SSE idle timeout in seconds (0 = infinite, absent = 5s default)
- Use the `idle_duration()` helper to convert
