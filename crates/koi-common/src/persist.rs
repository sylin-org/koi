use serde::de::DeserializeOwned;
use serde::Serialize;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

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

    // Write to a UNIQUE temp file in the same directory, then atomically rename
    // into place. The temp name is unique per (process, write) so concurrent
    // writers to the same `path` don't collide on a shared temp file — a shared
    // temp caused the second `rename` to fail with ENOENT once the first writer
    // had already renamed it away.
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let mut tmp_name = path.as_os_str().to_os_string();
    tmp_name.push(format!(
        ".{}.{}.tmp",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let tmp = PathBuf::from(tmp_name);
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

    #[test]
    fn write_json_pretty_concurrent_same_path_no_error() {
        // Regression: a deterministic temp file made concurrent writers to the
        // same path race on rename() (the loser hit ENOENT). With a unique temp
        // per write, many threads can write the same path without error.
        let dir = temp_path("concurrent");
        std::fs::create_dir_all(&dir).unwrap();
        let path = std::sync::Arc::new(dir.join("shared.json"));

        let handles: Vec<_> = (0..16)
            .map(|i| {
                let p = std::sync::Arc::clone(&path);
                std::thread::spawn(move || write_json_pretty(&p, &vec![i]))
            })
            .collect();

        for h in handles {
            h.join().unwrap().expect("concurrent write must not error");
        }
        assert!(path.exists());
        // The file is valid JSON written by exactly one of the writers.
        let _: Vec<i32> = read_json(&path).expect("final file is valid JSON");
    }
}
