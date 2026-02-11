/// Length of short hex IDs generated from UUID v4 (e.g., "a1b2c3d4").
const SHORT_ID_LEN: usize = 8;

/// Generate a short 8-character hex ID from UUID v4.
pub fn generate_short_id() -> String {
    uuid::Uuid::new_v4().to_string()[..SHORT_ID_LEN].to_string()
}
