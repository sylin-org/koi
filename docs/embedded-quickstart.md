# Koi Embedded Quickstart

Use `koi-embedded` to run Koi in-process with sane defaults and an event-driven API.

## Minimal

```rust
let koi = koi_embedded::Builder::new().build()?;
let handle = koi.start().await?;
```

## Configure capabilities

```rust
let koi = koi_embedded::Builder::new()
    .mdns(true)
    .dns_enabled(true)
    .health(false)
    .certmesh(false)
    .proxy(false)
    .build()?;
```

## DNS configuration

```rust
let koi = koi_embedded::Builder::new()
    .dns(|cfg| cfg.zone("lan").port(5353))
    .dns_auto_start(true)
    .build()?;
```

## Events

```rust
let koi = koi_embedded::Builder::new()
    .events(|event| println!("koi event: {event:?}"))
    .build()?;
```

## Clean shutdown

```rust
let handle = koi.start().await?;
handle.shutdown().await?;
```

## Integration guide

See the [embedded integration guide](embedded-integration-guide.md) for full in-process validation, HTTP/IPC adapter coverage, and production tips.
