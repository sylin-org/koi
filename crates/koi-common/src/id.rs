/// Length of short hex IDs generated from UUID v4 (e.g., "a1b2c3d4").
const SHORT_ID_LEN: usize = 8;

/// Generate a short 8-character hex ID from UUID v4.
pub fn generate_short_id() -> String {
    uuid::Uuid::new_v4().to_string()[..SHORT_ID_LEN].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn generate_short_id_has_correct_length() {
        let id = generate_short_id();
        assert_eq!(id.len(), SHORT_ID_LEN);
    }

    #[test]
    fn generate_short_id_is_lowercase_hex() {
        let id = generate_short_id();
        assert!(
            id.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "ID should be lowercase hex: {id}"
        );
    }

    #[test]
    fn generate_short_id_produces_unique_ids() {
        let ids: HashSet<String> = (0..100).map(|_| generate_short_id()).collect();
        assert_eq!(ids.len(), 100, "100 generated IDs should all be unique");
    }
}
