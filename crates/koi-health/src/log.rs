use std::io::Write;
use std::path::Path;

use chrono::Utc;

use crate::service::ServiceStatus;

pub(crate) fn append_transition(
    path: &Path,
    name: &str,
    old_state: ServiceStatus,
    new_state: ServiceStatus,
    reason: &str,
) -> Result<(), std::io::Error> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;

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

pub(crate) async fn read_log(path: &Path) -> Result<String, std::io::Error> {
    match tokio::fs::read_to_string(path).await {
        Ok(entries) => Ok(entries),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn transition_log_uses_only_the_injected_path() {
        let root = koi_common::test::ensure_data_dir("koi-health-log-tests")
            .join(format!("injected-{}", koi_common::id::generate_short_id()));
        let selected = root.join("selected/health.log");
        let sibling = root.join("other/health.log");

        append_transition(
            &selected,
            "api",
            ServiceStatus::Unknown,
            ServiceStatus::Up,
            "reachable",
        )
        .expect("append transition");

        assert!(read_log(&selected).await.unwrap().contains("api"));
        assert_eq!(read_log(&sibling).await.unwrap(), "");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn transition_log_wire_value_requires_string_entries_and_round_trips() {
        let expected = crate::HealthTransitionLog {
            entries: "2026-09-04T00:00:00Z | api | Up -> Down | refused\n".to_string(),
        };
        let encoded = serde_json::to_string(&expected).expect("serialize transition log");
        let decoded: crate::HealthTransitionLog =
            serde_json::from_str(&encoded).expect("deserialize transition log");

        assert_eq!(decoded, expected);
        assert!(serde_json::from_str::<crate::HealthTransitionLog>("{}").is_err());
        assert!(serde_json::from_str::<crate::HealthTransitionLog>(r#"{"entries":[]}"#).is_err());
    }
}
