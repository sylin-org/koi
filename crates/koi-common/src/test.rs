use std::path::PathBuf;
use std::sync::OnceLock;

pub fn ensure_data_dir(prefix: &str) -> PathBuf {
    static DATA_DIR: OnceLock<PathBuf> = OnceLock::new();

    DATA_DIR
        .get_or_init(|| {
            let mut base = if let Ok(existing) = std::env::var("KOI_DATA_DIR") {
                PathBuf::from(existing)
            } else {
                let base = std::env::temp_dir().join(format!(
                    "{}-{}",
                    prefix,
                    std::process::id()
                ));
                std::env::set_var("KOI_DATA_DIR", &base);
                base
            };

            if std::fs::create_dir_all(&base).is_err() {
                base = std::env::temp_dir().join(format!(
                    "{}-{}",
                    prefix,
                    std::process::id()
                ));
                std::env::set_var("KOI_DATA_DIR", &base);
                let _ = std::fs::create_dir_all(&base);
            }

            base
        })
        .clone()
}
