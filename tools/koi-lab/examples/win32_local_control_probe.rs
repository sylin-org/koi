//! Win32 local-control probe: exercises the installed daemon's authenticated
//! named pipe (ADR-040) against the real service.
//!
//! Proves the pipe contract physically: the recorded operator receives the
//! access hand-off (endpoint, DAT, resolved data root) without reading the
//! owner-private breadcrumb, mDNS session registrations through the pipe are
//! drained after an abrupt client death, and the explicit pipe DACL rejects a
//! different unelevated account before any bytes are answered.
//!
//! The DAT is never printed — only its length. Every phase prints one JSON
//! evidence line; the process exits non-zero when a phase fails its contract.

#[cfg(target_os = "windows")]
mod windows {
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpStream;
    use std::time::{Duration, Instant};

    const PIPE_PATH: &str = r"\\.\pipe\koi";
    const POLL_SLICE: Duration = Duration::from_millis(500);
    const REGISTER_VISIBLE_TIMEOUT: Duration = Duration::from_secs(15);
    const DRAIN_TIMEOUT: Duration = Duration::from_secs(25);
    const CHILD_HOLD: Duration = Duration::from_secs(3);
    const PROBE_SERVICE_NAME: &str = "Local Control Drain Probe";
    const PROBE_PORT: u16 = 43199;

    /// Optional sink for cross-account runs that cannot inherit the caller's
    /// shell; stdout remains the primary evidence stream.
    static EVIDENCE_FILE: std::sync::OnceLock<Option<std::path::PathBuf>> =
        std::sync::OnceLock::new();

    fn evidence(phase: &str, fields: &[(&str, serde_json::Value)]) {
        let mut map = serde_json::Map::new();
        map.insert("phase".to_string(), phase.into());
        for (key, value) in fields {
            map.insert((*key).to_string(), value.clone());
        }
        let line = serde_json::to_string(&map).unwrap_or_default();
        println!("{line}");
        if let Some(path) = EVIDENCE_FILE.get().and_then(|path| path.as_ref()) {
            if let Ok(mut file) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
            {
                let _ = file.write_all(
                    format!(
                        "{line}
"
                    )
                    .as_bytes(),
                );
            }
        }
    }

    struct PipeClient {
        reader: BufReader<std::fs::File>,
        writer: std::fs::File,
    }

    impl PipeClient {
        /// Connect and perform one line-oriented request/response exchange.
        fn round_trip(line: &str) -> Result<(serde_json::Value, Self), String> {
            let file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(PIPE_PATH)
                .map_err(|error| format!("pipe open failed: {error}"))?;
            let file2 = file.try_clone().map_err(|error| format!("{error}"))?;
            let mut client = PipeClient {
                reader: BufReader::new(file),
                writer: file2,
            };
            let value = client
                .request(line)
                .map_err(|error| format!("pipe exchange failed: {error}"))?;
            Ok((value, client))
        }

        fn request(&mut self, line: &str) -> Result<serde_json::Value, String> {
            self.writer
                .write_all(line.as_bytes())
                .and_then(|_| self.writer.write_all(b"\n"))
                .and_then(|_| self.writer.flush())
                .map_err(|error| format!("{error}"))?;
            let mut response = String::new();
            self.reader
                .read_line(&mut response)
                .map_err(|error| format!("{error}"))?;
            serde_json::from_str(response.trim()).map_err(|error| format!("{error}"))
        }
    }

    fn access_line() -> &'static str {
        r#"{"request":"access","version":1}"#
    }

    fn info_line() -> &'static str {
        r#"{"request":"info","version":1}"#
    }

    /// Loopback HTTP GET through a raw socket — the same surface the daemon
    /// serves; no third-party client dependency needed for the probe.
    fn http_get(token: &str, path: &str) -> Result<serde_json::Value, String> {
        let mut stream = TcpStream::connect("127.0.0.1:5641").map_err(|e| format!("{e}"))?;
        let request = format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {token}\r\nConnection: close\r\n\r\n");
        stream
            .write_all(request.as_bytes())
            .map_err(|e| format!("{e}"))?;
        let mut raw = Vec::new();
        stream.read_to_end(&mut raw).map_err(|e| format!("{e}"))?;
        let text = String::from_utf8_lossy(&raw);
        let body = text
            .split_once("\r\n\r\n")
            .map(|(_, body)| body)
            .unwrap_or("");
        serde_json::from_str(body).map_err(|error| format!("status body: {error}"))
    }

    fn alive_count(token: &str) -> Result<u64, String> {
        let status = http_get(token, "/v1/mdns/admin/status")?;
        Ok(status["registrations"]["alive"]
            .as_u64()
            .ok_or("status carried no alive count")?)
    }

    pub fn run(mode: &str, evidence_path: Option<&str>) {
        let _ = EVIDENCE_FILE.set(evidence_path.map(std::path::PathBuf::from));
        match mode {
            "access" => phase_access(),
            "info" => phase_info(),
            "drain" => phase_drain(),
            "announce-then-die" => child_announce_then_die(),
            // Negative gate: exit 0 only when the pipe rejects this account.
            "expect-denied" => phase_expect_denied(),
            other => {
                evidence(
                    "usage",
                    &[("error", format!("unknown mode {other}").into())],
                );
                std::process::exit(2);
            }
        }
    }

    /// Negative gate for unrecorded accounts: the explicit pipe DACL must
    /// reject the open before any bytes are answered.
    fn phase_expect_denied() {
        match PipeClient::round_trip(access_line()) {
            Ok((value, _)) => {
                evidence(
                    "expect_denied",
                    &[
                        ("outcome", "access was granted".into()),
                        (
                            "result",
                            "FAIL: unauthorized account reached the pipe".into(),
                        ),
                    ],
                );
                let _ = value;
                std::process::exit(5);
            }
            Err(error) => {
                evidence(
                    "expect_denied",
                    &[
                        ("outcome", format!("rejected: {error}").into()),
                        ("result", "PASS".into()),
                    ],
                );
                std::process::exit(0);
            }
        }
    }

    /// The recorded operator receives the access hand-off over the pipe.
    /// The DAT itself is never printed.
    fn phase_access() {
        match PipeClient::round_trip(access_line()) {
            Ok((value, _)) => {
                let ok = value.get("response").and_then(|r| r.as_str()) == Some("access")
                    && value
                        .get("endpoint")
                        .and_then(|e| e.as_str())
                        .is_some_and(|e| !e.is_empty())
                    && value
                        .get("token")
                        .and_then(|t| t.as_str())
                        .is_some_and(|t| !t.is_empty());
                evidence(
                    "access",
                    &[
                        ("response", value["response"].clone()),
                        ("endpoint", value["endpoint"].clone()),
                        ("token_len", value["token"].as_str().map(|t| t.len()).into()),
                        ("data_root", value["data_root"].clone()),
                        ("result", if ok { "PASS" } else { "FAIL" }.into()),
                    ],
                );
                if !ok {
                    std::process::exit(1);
                }
            }
            Err(error) => {
                evidence("access", &[("result", format!("FAIL: {error}").into())]);
                std::process::exit(1);
            }
        }
    }

    fn phase_info() {
        match PipeClient::round_trip(info_line()) {
            Ok((value, _)) => {
                let ok = value.get("response").and_then(|r| r.as_str()) == Some("info")
                    && value
                        .get("data_root")
                        .and_then(|d| d.as_str())
                        .is_some_and(|d| !d.is_empty());
                evidence(
                    "info",
                    &[
                        ("response", value["response"].clone()),
                        ("data_root", value["data_root"].clone()),
                        ("config_path", value["config_path"].clone()),
                        ("result", if ok { "PASS" } else { "FAIL" }.into()),
                    ],
                );
                if !ok {
                    std::process::exit(1);
                }
            }
            Err(error) => {
                evidence("info", &[("result", format!("FAIL: {error}").into())]);
                std::process::exit(1);
            }
        }
    }

    /// Register a probe service over the pipe from a child process that dies
    /// without goodbye; the daemon must drain the session's registration back
    /// to the pre-child baseline.
    fn phase_drain() {
        let (access, _) = match PipeClient::round_trip(access_line()) {
            Ok(pair) => pair,
            Err(error) => {
                evidence("drain", &[("result", format!("FAIL: {error}").into())]);
                std::process::exit(1);
            }
        };
        let token = access["token"].as_str().unwrap_or_default().to_string();
        let baseline = match alive_count(&token) {
            Ok(count) => count,
            Err(error) => {
                evidence("drain", &[("result", format!("FAIL: {error}").into())]);
                std::process::exit(1);
            }
        };

        let mut child = std::process::Command::new(std::env::current_exe().unwrap_or_default())
            .arg("announce-then-die")
            .spawn()
            .expect("spawn drain child");
        let deadline = Instant::now() + REGISTER_VISIBLE_TIMEOUT;
        let mut visible = false;
        while Instant::now() < deadline {
            match alive_count(&token) {
                Ok(count) if count > baseline => {
                    visible = true;
                    break;
                }
                Ok(_) => std::thread::sleep(POLL_SLICE),
                Err(error) => {
                    evidence("drain", &[("result", format!("FAIL: {error}").into())]);
                    let _ = child.kill();
                    std::process::exit(1);
                }
            }
        }
        if !visible {
            evidence(
                "drain",
                &[(
                    "result",
                    format!("FAIL: probe registration never became visible (baseline {baseline})")
                        .into(),
                )],
            );
            let _ = child.kill();
            std::process::exit(1);
        }

        // The child dies on its own after its hold window; wait it out, then
        // require the daemon to drain the dead session's registration.
        let _ = child.wait();
        let deadline = Instant::now() + DRAIN_TIMEOUT;
        loop {
            match alive_count(&token) {
                Ok(count) if count <= baseline => {
                    evidence(
                        "drain",
                        &[
                            ("baseline_alive", baseline.into()),
                            ("drained_alive", count.into()),
                            ("result", "PASS".into()),
                        ],
                    );
                    return;
                }
                Ok(_) if Instant::now() < deadline => {
                    std::thread::sleep(POLL_SLICE);
                }
                Ok(count) => {
                    evidence(
                        "drain",
                        &[
                            ("baseline_alive", baseline.into()),
                            ("alive_after_timeout", count.into()),
                            ("result", "FAIL: dead session was not drained".into()),
                        ],
                    );
                    std::process::exit(1);
                }
                Err(error) => {
                    evidence("drain", &[("result", format!("FAIL: {error}").into())]);
                    std::process::exit(1);
                }
            }
        }
    }

    fn child_announce_then_die() {
        let line = serde_json::json!({
            "register": {
                "name": PROBE_SERVICE_NAME,
                "type": "_mcp._tcp",
                "port": PROBE_PORT,
                "txt": { "source": "local-control-probe" },
            }
        })
        .to_string();
        let (_, mut client) = match PipeClient::round_trip(&line) {
            Ok(pair) => pair,
            Err(error) => {
                evidence("child", &[("result", format!("FAIL: {error}").into())]);
                std::process::exit(1);
            }
        };
        // Keep the connection open past the registration acknowledgement,
        // then die without any unregister or clean close so the daemon sees
        // an abrupt EOF.
        std::thread::sleep(CHILD_HOLD);
        let _ = client.request(r#"{"resolve":"probe-warm-read.local"}"#);
        std::process::exit(0);
    }
}

#[cfg(target_os = "windows")]
fn main() {
    let mode = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "access".to_string());
    let evidence_path = std::env::args().nth(2);
    windows::run(&mode, evidence_path.as_deref());
}

#[cfg(not(target_os = "windows"))]
fn main() {
    eprintln!("win32_local_control_probe is available only on Windows");
}
