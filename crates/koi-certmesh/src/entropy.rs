//! Entropy collection for CA key generation.
//!
//! Three modes:
//! - **KeyboardMashing**: Operator mashes keyboard; timing + key entropy mixed with OS RNG.
//!   The collected entropy seeds passphrase generation.
//! - **AutoGenerate**: Uses OS RNG only — no interaction. Seeds passphrase generation.
//! - **Manual**: Operator provides their own passphrase. Entropy derived from passphrase + OS RNG.
//!
//! The first two modes produce an entropy seed that is used to deterministically
//! generate an XKCD-style passphrase (via the EFF large wordlist). The passphrase
//! protects the key at rest; the entropy seed determines the key itself.

use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};

use crate::wordlist::EFF_WORDLIST;

/// How to collect entropy from the operator.
pub enum EntropyMode {
    /// Read raw keypresses with timing entropy. Interactive.
    /// Returns entropy seed; caller generates passphrase from it.
    KeyboardMashing,
    /// Use OS RNG only — no interaction.
    /// Returns entropy seed; caller generates passphrase from it.
    AutoGenerate,
    /// Hash a user-provided passphrase string. Non-interactive.
    Manual(String),
}

/// Target entropy in bytes.
const ENTROPY_BYTES: usize = 32;

/// Minimum keystrokes for keyboard mashing mode.
const MIN_KEYSTROKES: usize = 64;

/// Collect entropy from the operator and mix with OS RNG.
///
/// Returns 32 bytes of mixed entropy suitable for key generation.
///
/// For `KeyboardMashing` mode, this reads raw terminal input and
/// shows a progress bar. For non-interactive environments (tests, CI),
/// use `Manual` mode.
pub fn collect_entropy(mode: EntropyMode) -> Result<[u8; ENTROPY_BYTES], std::io::Error> {
    match mode {
        EntropyMode::KeyboardMashing => collect_keyboard_entropy(),
        EntropyMode::AutoGenerate => collect_os_entropy(),
        EntropyMode::Manual(passphrase) => Ok(hash_passphrase(&passphrase)),
    }
}

/// Generate an XKCD-style passphrase from an entropy seed.
///
/// Format: `word-word-word-NN` using the EFF large wordlist (7,776 words).
/// Each word provides ~12.9 bits of entropy. Three words + a two-digit
/// number yields ~45 bits — above the 40-bit minimum.
///
/// The entropy seed is hashed to derive word indices, ensuring the
/// passphrase is deterministically tied to the collected entropy.
pub fn generate_passphrase(entropy_seed: &[u8; ENTROPY_BYTES]) -> String {
    // Use the entropy seed to deterministically pick words.
    // Hash it again so the passphrase indices aren't directly the key seed.
    let mut hasher = Sha256::new();
    hasher.update(b"passphrase-derivation");
    hasher.update(entropy_seed);
    let derived = hasher.finalize();

    let word_count = EFF_WORDLIST.len(); // 7776

    // Pick 3 words from sequential 4-byte chunks
    let w1 =
        u32::from_le_bytes([derived[0], derived[1], derived[2], derived[3]]) as usize % word_count;
    let w2 =
        u32::from_le_bytes([derived[4], derived[5], derived[6], derived[7]]) as usize % word_count;
    let w3 = u32::from_le_bytes([derived[8], derived[9], derived[10], derived[11]]) as usize
        % word_count;
    let number = u16::from_le_bytes([derived[12], derived[13]]) % 100;

    format!(
        "{}-{}-{}-{:02}",
        EFF_WORDLIST[w1], EFF_WORDLIST[w2], EFF_WORDLIST[w3], number
    )
}

/// Generate a memorization hint for a `word-word-word-NN` passphrase.
pub fn memorization_hint(passphrase: &str) -> String {
    let parts: Vec<&str> = passphrase.split('-').collect();
    if parts.len() == 4 {
        format!(
            "\"A {} at {}, {} #{}\"",
            capitalize(parts[0]),
            parts[1],
            parts[2],
            parts[3]
        )
    } else {
        String::new()
    }
}

fn capitalize(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        None => String::new(),
        Some(c) => c.to_uppercase().to_string() + chars.as_str(),
    }
}

/// Keyboard mashing: read raw keypresses with timing entropy.
fn collect_keyboard_entropy() -> Result<[u8; ENTROPY_BYTES], std::io::Error> {
    use crossterm::event::{self, Event, KeyCode, KeyEvent};
    use crossterm::terminal;
    use indicatif::{ProgressBar, ProgressStyle};
    use std::time::Instant;

    println!("\n  Mash your keyboard randomly... GO!\n");

    let pb = ProgressBar::new(MIN_KEYSTROKES as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("  {bar:40.cyan/blue} {pos}/{len}")
            .unwrap_or_else(|_| ProgressStyle::default_bar()),
    );

    terminal::enable_raw_mode()?;
    let mut hasher = Sha256::new();
    let mut collected = 0usize;
    let start = Instant::now();

    loop {
        if event::poll(std::time::Duration::from_millis(100)).map_err(std::io::Error::other)? {
            if let Event::Key(KeyEvent { code, .. }) =
                event::read().map_err(std::io::Error::other)?
            {
                // Mix key identity
                match code {
                    KeyCode::Char(c) => hasher.update([c as u8]),
                    _ => hasher.update([0xFF]),
                }

                // Mix timing (nanosecond precision)
                let elapsed = start.elapsed().as_nanos();
                hasher.update(elapsed.to_le_bytes());

                collected += 1;
                pb.set_position(collected.min(MIN_KEYSTROKES) as u64);

                // Auto-exit once we have enough keystrokes — no Enter required
                if collected >= MIN_KEYSTROKES {
                    break;
                }
            }
        }
    }

    terminal::disable_raw_mode()?;
    pb.finish_and_clear();
    println!("\n  Done! Processing entropy...");

    // Brief pause so the user stops mashing before the next prompt appears
    std::thread::sleep(std::time::Duration::from_millis(1000));

    // Drain any buffered crossterm events so they don't leak into stdin
    while event::poll(std::time::Duration::from_millis(50)).unwrap_or(false) {
        let _ = event::read();
    }

    println!("\n  ✓ Collected entropy from {collected} keystrokes");

    // Mix with OS RNG
    let mut os_entropy = [0u8; 32];
    OsRng.fill_bytes(&mut os_entropy);
    hasher.update(os_entropy);

    let result = hasher.finalize();
    let mut output = [0u8; ENTROPY_BYTES];
    output.copy_from_slice(&result);

    Ok(output)
}

/// Auto-generate: collect entropy from OS RNG only.
fn collect_os_entropy() -> Result<[u8; ENTROPY_BYTES], std::io::Error> {
    let mut output = [0u8; ENTROPY_BYTES];
    OsRng.fill_bytes(&mut output);

    // Hash to mix distribution uniformly
    let mut hasher = Sha256::new();
    hasher.update(output);
    // Add a second round of OS RNG for defense in depth
    let mut extra = [0u8; 32];
    OsRng.fill_bytes(&mut extra);
    hasher.update(extra);

    let result = hasher.finalize();
    output.copy_from_slice(&result);
    Ok(output)
}

/// Hash a passphrase with SHA-256, mixed with OS RNG.
pub fn hash_passphrase(passphrase: &str) -> [u8; ENTROPY_BYTES] {
    let mut hasher = Sha256::new();
    hasher.update(passphrase.as_bytes());

    let mut os_entropy = [0u8; 32];
    OsRng.fill_bytes(&mut os_entropy);
    hasher.update(os_entropy);

    let result = hasher.finalize();
    let mut output = [0u8; ENTROPY_BYTES];
    output.copy_from_slice(&result);
    output
}

/// Estimate entropy bits for a user-provided passphrase.
pub fn estimate_entropy_bits(passphrase: &str) -> u32 {
    let mut charset = 0u32;
    if passphrase.chars().any(|c| c.is_ascii_lowercase()) {
        charset += 26;
    }
    if passphrase.chars().any(|c| c.is_ascii_uppercase()) {
        charset += 26;
    }
    if passphrase.chars().any(|c| c.is_ascii_digit()) {
        charset += 10;
    }
    if passphrase
        .chars()
        .any(|c| !c.is_ascii_alphanumeric() && !c.is_whitespace())
    {
        charset += 32;
    }
    if charset == 0 {
        return 0;
    }
    let n = passphrase.chars().count() as f64;
    (n * (charset as f64).log2()).round() as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manual_entropy_produces_32_bytes() {
        let entropy = collect_entropy(EntropyMode::Manual("test passphrase".into())).unwrap();
        assert_eq!(entropy.len(), 32);
    }

    #[test]
    fn different_passphrases_produce_different_entropy() {
        // Note: due to OS RNG mixing, even the same passphrase produces
        // different output each time. But different passphrases should
        // definitely be different.
        let e1 = collect_entropy(EntropyMode::Manual("passphrase one".into())).unwrap();
        let e2 = collect_entropy(EntropyMode::Manual("passphrase two".into())).unwrap();
        assert_ne!(e1, e2);
    }

    #[test]
    fn hash_passphrase_is_32_bytes() {
        let hash = hash_passphrase("test");
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn auto_generate_entropy_produces_32_bytes() {
        let entropy = collect_os_entropy().unwrap();
        assert_eq!(entropy.len(), 32);
    }

    #[test]
    fn generate_passphrase_produces_word_word_word_nn() {
        let seed = [42u8; 32];
        let passphrase = generate_passphrase(&seed);
        let parts: Vec<&str> = passphrase.split('-').collect();
        assert_eq!(
            parts.len(),
            4,
            "expected word-word-word-NN, got: {passphrase}"
        );
        // Last part should be a two-digit number
        let num: u32 = parts[3].parse().expect("last part should be a number");
        assert!(num < 100, "number should be < 100");
        // Each word should be in the EFF wordlist
        for word in &parts[..3] {
            assert!(
                EFF_WORDLIST.contains(word),
                "word '{word}' not in EFF wordlist"
            );
        }
    }

    #[test]
    fn generate_passphrase_is_deterministic() {
        let seed = [99u8; 32];
        let p1 = generate_passphrase(&seed);
        let p2 = generate_passphrase(&seed);
        assert_eq!(p1, p2, "same seed should produce same passphrase");
    }

    #[test]
    fn different_seeds_produce_different_passphrases() {
        let s1 = [1u8; 32];
        let s2 = [2u8; 32];
        let p1 = generate_passphrase(&s1);
        let p2 = generate_passphrase(&s2);
        assert_ne!(
            p1, p2,
            "different seeds should produce different passphrases"
        );
    }

    #[test]
    fn memorization_hint_format() {
        let hint = memorization_hint("compass-twilight-harvest-82");
        assert_eq!(hint, "\"A Compass at twilight, harvest #82\"");
    }

    #[test]
    fn estimate_entropy_lowercase_only() {
        // 8 lowercase chars → 8 * log2(26) ≈ 37.6 → 38 bits
        let bits = estimate_entropy_bits("abcdefgh");
        assert!(bits > 35 && bits < 45, "got {bits}");
    }

    #[test]
    fn estimate_entropy_mixed() {
        // 12 mixed chars → 12 * log2(94) ≈ 78.7
        let bits = estimate_entropy_bits("Hello-World1");
        assert!(bits > 70, "got {bits}");
    }

    #[test]
    fn estimate_entropy_empty() {
        assert_eq!(estimate_entropy_bits(""), 0);
    }
}
