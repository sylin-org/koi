//! Bounded discovery reads for an explicit, native device comparison.
//! The peer reader deliberately has no credential parameter or redirect support.
use crate::{ClientError, KoiClient, Result};
use koi_common::integration::MdnsDiscoverySnapshot;
use std::io::Read;
use std::time::Duration;

const LIMIT: u64 = 1024 * 1024;
const DEADLINE: Duration = Duration::from_secs(4);

/// Read only the public discovery projection at a catalog-selected Koi endpoint.
/// An HTTP refusal remains an error; this never retries with local credentials.
pub fn read_peer(endpoint: &str) -> Result<MdnsDiscoverySnapshot> {
    read(&KoiClient::new(endpoint), DEADLINE)
}

impl KoiClient {
    /// Same bounded projection, using this client's local authority if present.
    pub fn comparison_snapshot(&self) -> Result<MdnsDiscoverySnapshot> {
        read(self, DEADLINE)
    }
}

fn read(client: &KoiClient, deadline: Duration) -> Result<MdnsDiscoverySnapshot> {
    let agent = ureq::AgentBuilder::new()
        .redirects(0)
        .timeout(deadline)
        .timeout_connect(deadline)
        .timeout_read(deadline)
        .build();
    let mut request = agent.get(&format!("{}/v1/mdns/snapshot", client.endpoint));
    if !client.token.is_empty() {
        request = request.set(crate::DAT_HEADER, &client.token);
    }
    let response = request.call().map_err(|error| match error {
        ureq::Error::Status(401 | 403, _) => ClientError::Unauthorized,
        error => crate::map_error(error),
    })?;
    if response.status() != 200 {
        return Err(ClientError::Decode(
            "discovery read did not return a snapshot".into(),
        ));
    }
    let mut bytes = Vec::new();
    response
        .into_reader()
        .take(LIMIT + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| ClientError::Decode(error.to_string()))?;
    if bytes.len() as u64 > LIMIT {
        return Err(ClientError::Decode(
            "discovery snapshot exceeds size limit".into(),
        ));
    }
    let value: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|error| ClientError::Decode(error.to_string()))?;
    crate::require_fields(
        &value,
        &["revision", "service_types", "records", "sources"],
        "comparison snapshot",
    )?;
    for record in value["records"]
        .as_array()
        .ok_or_else(|| ClientError::Decode("records must be an array".into()))?
    {
        crate::require_fields(record, &["name", "type", "txt"], "comparison record")?;
    }
    serde_json::from_value(value).map_err(|error| ClientError::Decode(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;
    fn server(
        status: u16,
        body: String,
        delay: Duration,
    ) -> (String, std::thread::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let worker = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut reader = BufReader::new(socket.try_clone().unwrap());
            let mut request = String::new();
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                request.push_str(&line);
                if line == "\r\n" || line.is_empty() {
                    break;
                }
            }
            std::thread::sleep(delay);
            let reply = format!("HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nLocation: /redirected\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
            let _ = socket.write_all(reply.as_bytes());
            request
        });
        (endpoint, worker)
    }
    fn empty() -> String {
        r#"{"revision":0,"service_types":[],"records":[],"sources":[{"query":"_http._tcp.local.","provider":"test","generation":0,"available":true}]}"#.into()
    }
    #[test]
    fn empty_snapshot_is_readable_and_peer_request_has_no_local_authority() {
        let (endpoint, worker) = server(200, empty(), Duration::ZERO);
        let snapshot = read_peer(&endpoint).unwrap();
        assert_eq!(snapshot.revision, 0);
        assert!(snapshot.records.is_empty());
        let request = worker.join().unwrap().to_lowercase();
        assert!(request.starts_with("get /v1/mdns/snapshot http/1.1"));
        assert!(!request.contains("x-koi-token"));
        assert!(!request.contains("authorization:"));
    }
    #[test]
    fn refused_auth_redirect_and_missing_snapshot_never_become_empty_success() {
        for (status, body) in [
            (401, empty()),
            (403, empty()),
            (302, empty()),
            (200, "{}".into()),
            (
                200,
                r#"{"revision":0,"service_types":[],"records":null,"sources":[]}"#.into(),
            ),
        ] {
            let (endpoint, worker) = server(status, body, Duration::ZERO);
            let result = read_peer(&endpoint);
            assert!(result.is_err(), "status {status}");
            if matches!(status, 401 | 403) {
                assert!(matches!(result, Err(ClientError::Unauthorized)));
            }
            worker.join().unwrap();
        }
    }
    #[test]
    fn slow_and_oversized_responses_are_bounded() {
        let (endpoint, worker) = server(200, empty(), Duration::from_millis(100));
        assert!(read(&KoiClient::new(&endpoint), Duration::from_millis(20)).is_err());
        worker.join().unwrap();
        let (endpoint, worker) = server(200, " ".repeat(LIMIT as usize + 1), Duration::ZERO);
        assert!(read_peer(&endpoint).is_err());
        worker.join().unwrap();
    }
    #[test]
    fn local_reader_keeps_its_local_authority() {
        let (endpoint, worker) = server(200, empty(), Duration::ZERO);
        KoiClient::with_token(&endpoint, "fixture-local-token")
            .comparison_snapshot()
            .unwrap();
        assert!(worker
            .join()
            .unwrap()
            .contains("X-Koi-Token: fixture-local-token"));
    }
}
