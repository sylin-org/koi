/// Length of short hex IDs generated from UUID v7 (e.g., "0196a3b4").
const SHORT_ID_LEN: usize = 8;

/// Generate a short 8-character hex ID from UUID v7.
///
/// Takes the last 8 hex characters of the UUID, which come from the
/// random portion — ensuring uniqueness even when multiple IDs are
/// generated within the same millisecond. The UUID itself is still
/// time-ordered via its v7 timestamp prefix.
pub fn generate_short_id() -> String {
    let full = uuid::Uuid::now_v7().simple().to_string();
    full[full.len() - SHORT_ID_LEN..].to_string()
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
