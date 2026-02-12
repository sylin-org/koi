use std::io::Write;

use chrono::Utc;

use koi_common::paths;

use crate::service::ServiceStatus;

const HEALTH_LOG_FILENAME: &str = "health.log";

fn health_log_path() -> std::path::PathBuf {
    paths::koi_log_dir().join(HEALTH_LOG_FILENAME)
}

pub fn append_transition(
    name: &str,
    old_state: ServiceStatus,
    new_state: ServiceStatus,
    reason: &str,
) -> Result<(), std::io::Error> {
    let path = health_log_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)?;

    let line = format!(
        "{} | {} | {:?} -> {:?} | {}\n",
        Utc::now().to_rfc3339(),
        name,
        old_state,
        new_state,
        reason
    );
    file.write_all(line.as_bytes())?;
    Ok(())
}

pub fn read_log() -> Result<String, std::io::Error> {
    let path = health_log_path();
    if !path.exists() {
        return Ok(String::new());
    }
    std::fs::read_to_string(path)
}
