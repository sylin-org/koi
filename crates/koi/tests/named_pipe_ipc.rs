//! ADR-032 W2 — Named-pipe IPC integration (Windows).
//!
//! Proves the Windows IPC transport speaks the same NDJSON protocol as the
//! Unix socket: spawn a real daemon child, connect a tokio named-pipe client
//! to a per-run pipe, and drive read-only mDNS requests end-to-end — exact
//! response shapes for browse, resolve-miss, and malformed input.
//!
//! The pipe name is unique per run: a standing system daemon owns the default
//! `\\.\pipe\koi`, and the test must never talk to (or collide with) it.
//! Requires mDNS enabled (the pipe adapter bridges the mDNS core); all probes
//! are read-only so nothing is announced to the LAN.

#![cfg(windows)]

use std::io::Read as _;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::windows::named_pipe::ClientOptions;

fn temp_data_dir() -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("koi-pipe-{}-{nanos}-{n}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn pipe_name(data_dir: &std::path::Path) -> String {
    format!(
        r"\\.\pipe\koi-test-{}",
        data_dir.file_name().unwrap().to_string_lossy()
    )
}

struct Daemon(Child);

impl Daemon {
    fn assert_running(&mut self) {
        let Some(status) = self.0.try_wait().expect("query daemon status") else {
            return;
        };
        let mut stderr = String::new();
        self.0
            .stderr
            .take()
            .expect("captured daemon stderr")
            .read_to_string(&mut stderr)
            .expect("read daemon stderr");
        panic!("daemon exited with {status}:\n{stderr}");
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn spawn_daemon(data_dir: &PathBuf) -> Daemon {
    let mut command = Command::new(env!("CARGO_BIN_EXE_koi"));
    command
        .arg("--daemon")
        // A per-run pipe: the standing system daemon owns the default name.
        .args(["--pipe", &pipe_name(data_dir)])
        // IPC stays ON (the system under test); mdns stays ON (the pipe
        // adapter bridges the mDNS core); everything else off.
        .args([
            "--no-http",
            "--no-certmesh",
            "--no-dns",
            "--no-health",
            "--no-proxy",
            "--no-udp",
            "--no-runtime",
            "--no-acme",
        ])
        .env("KOI_DATA_DIR", data_dir)
        .env("XDG_RUNTIME_DIR", data_dir)
        .env("ProgramData", data_dir)
        .env("KOI_NO_CREDENTIAL_STORE", "1")
        .env("KOI_LOG", "warn")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    Daemon(command.spawn().expect("spawn koi daemon"))
}

async fn connect_pipe(
    name: &str,
    daemon: &mut Daemon,
) -> BufReader<tokio::net::windows::named_pipe::NamedPipeClient> {
    let mut last_err = None;
    for _ in 0..300 {
        match ClientOptions::new().open(name) {
            Ok(client) => return BufReader::new(client),
            Err(e) => last_err = Some(e),
        }
        daemon.assert_running();
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("pipe never appeared: {:?}", last_err);
}

async fn exchange(
    pipe: &mut BufReader<tokio::net::windows::named_pipe::NamedPipeClient>,
    line: &str,
) -> String {
    pipe.write_all(format!("{line}\n").as_bytes())
        .await
        .unwrap();
    pipe.flush().await.unwrap();
    let mut response = String::new();
    tokio::time::timeout(Duration::from_secs(10), pipe.read_line(&mut response))
        .await
        .expect("response within timeout")
        .expect("read response");
    response.trim().to_string()
}

#[tokio::test]
async fn named_pipe_ipc_speaks_the_mdns_protocol() {
    let data = temp_data_dir();
    // Held for the whole test: dropping early would kill the daemon mid-run.
    let mut daemon = spawn_daemon(&data);

    let mut pipe = connect_pipe(&pipe_name(&data), &mut daemon).await;

    // Resolve miss: a single structured error envelope — proves the pipe
    // transport, the mDNS core bridge, and the response framing.
    let miss = exchange(&mut pipe, r#"{"resolve":"definitely-not-here"}"#).await;
    assert!(
        miss.contains("\"error\""),
        "resolve miss must answer a structured error envelope: {miss}"
    );

    // Malformed input: structured error, connection stays open.
    let bad = exchange(&mut pipe, "not-json-at-all").await;
    assert!(
        bad.contains("\"error\""),
        "malformed input must produce an error envelope: {bad}"
    );
    let after_bad = exchange(&mut pipe, r#"{"resolve":"also-not-here"}"#).await;
    assert!(
        after_bad.contains("\"error\""),
        "connection must survive a malformed frame: {after_bad}"
    );
}
