#[allow(dead_code)] // Wired from daemon.rs when certmesh CA is initialized + unlocked
pub mod acme;
pub mod cli;
pub mod dashboard;
pub mod dispatch;
pub mod http;
pub mod mcp_http;
#[allow(dead_code)] // Wired from main.rs when certmesh TLS material is available
pub mod mtls;
pub mod pipe;
pub mod prometheus_sd;
pub mod trust_plane;
