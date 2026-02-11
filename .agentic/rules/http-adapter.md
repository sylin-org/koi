---
globs: src/adapters/http.rs
alwaysApply: false
---
# HTTP Adapter Rules

## Router Pattern
All routes mount under Axum `Router` with `Arc<MdnsCore>` as shared state.

```rust
Router::new()
    .route("/health", get(health))
    .route("/v1/services", post(register))
    .route("/v1/services/search", get(browse))
    // ...
    .with_state(core)
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
- Success: return `Json(Response::variant(...))`
- Error: return `(StatusCode, Json(Response::error(...)))`
- SSE: use `PipelineResponse` with `status` field for stream lifecycle
- The `Response` enum handles serialization shape (wrapped vs flat) — don't fight it

## Lease Policy
HTTP registrations use heartbeat leases by default:
- Lease: `DEFAULT_HEARTBEAT_LEASE` (90s)
- Grace: `DEFAULT_HEARTBEAT_GRACE` (30s)
- Client must `PUT /v1/services/{id}` to renew before expiry

## Query Parameters
- `idle_for`: SSE idle timeout in seconds (0 = infinite, absent = 5s default)
- Use the `idle_duration()` helper to convert
