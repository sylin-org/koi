use serde::de::DeserializeOwned;
use serde::Serialize;
use std::io;
use std::path::Path;

pub fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T, io::Error> {
    let json = std::fs::read_to_string(path)?;
    serde_json::from_str(&json).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

pub fn read_json_if_exists<T: DeserializeOwned>(path: &Path) -> Result<Option<T>, io::Error> {
    if !path.exists() {
        return Ok(None);
    }
    read_json(path).map(Some)
}

pub fn read_json_or_default<T: DeserializeOwned + Default>(path: &Path) -> Result<T, io::Error> {
    match read_json_if_exists(path)? {
        Some(value) => Ok(value),
        None => Ok(T::default()),
    }
}

pub fn write_json_pretty<T: Serialize>(path: &Path, value: &T) -> Result<(), io::Error> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string_pretty(value)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, json)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_path(name: &str) -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        std::env::temp_dir().join(format!("koi-persist-{name}-{nanos}"))
    }

    #[test]
    fn read_json_invalid_returns_invalid_data() {
        let dir = temp_path("invalid");
        let path = dir.join("bad.json");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(&path, "{broken json").unwrap();

        let err = read_json::<serde_json::Value>(&path).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn read_json_or_default_missing_returns_default() {
        let dir = temp_path("missing");
        let path = dir.join("missing.json");

        let value: Vec<String> = read_json_or_default(&path).unwrap();
        assert!(value.is_empty());
    }

    #[test]
    fn write_json_pretty_creates_parent_dir() {
        let path = temp_path("write").join("nested").join("value.json");
        write_json_pretty(&path, &vec!["a", "b"]).unwrap();
        assert!(path.exists());
    }

    #[test]
    fn write_json_pretty_fails_on_directory_path() {
        let dir = temp_path("dir");
        std::fs::create_dir_all(&dir).unwrap();

        let result = write_json_pretty(&dir, &vec!["a"]);
        assert!(result.is_err());
    }
}
