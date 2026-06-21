//! EFF large wordlist (7,776 words) for XKCD-style passphrase generation.
//!
//! Source: <https://www.eff.org/dice> (CC BY 3.0)
//! Each word provides ~12.9 bits of entropy (log2(7776)).
//!
//! The list is bundled as a plain-text file (one word per line) and parsed once on first
//! use via [`LazyLock`], instead of a 7,776-element source array.

use std::sync::LazyLock;

/// EFF large wordlist — 7,776 words, ~12.9 bits per word. Parsed once from the bundled
/// `eff_large_wordlist.txt` on first access.
pub static EFF_WORDLIST: LazyLock<Vec<&'static str>> =
    LazyLock::new(|| include_str!("eff_large_wordlist.txt").lines().collect());

#[cfg(test)]
mod tests {
    use super::EFF_WORDLIST;

    #[test]
    fn wordlist_has_7776_words() {
        assert_eq!(EFF_WORDLIST.len(), 7776);
    }

    #[test]
    fn wordlist_boundary_and_sample_words() {
        assert_eq!(EFF_WORDLIST[0], "abacus");
        assert_eq!(EFF_WORDLIST[EFF_WORDLIST.len() - 1], "zoom");
        assert!(EFF_WORDLIST.contains(&"t-shirt"));
    }
}
