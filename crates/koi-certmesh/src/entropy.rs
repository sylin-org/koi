//! Entropy collection for CA key generation.
//!
//! Three modes:
//! - **KeyboardMashing**: Operator mashes keyboard; timing + key entropy mixed with OS RNG
//! - **AutoPassphrase**: XKCD-style word list generated and displayed
//! - **Manual**: Operator provides their own passphrase

use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};

/// How to collect entropy from the operator.
pub enum EntropyMode {
    /// Read raw keypresses with timing entropy. Interactive.
    KeyboardMashing,
    /// Generate and display an XKCD-style passphrase. Semi-interactive.
    AutoPassphrase,
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
        EntropyMode::AutoPassphrase => collect_passphrase_entropy(),
        EntropyMode::Manual(passphrase) => Ok(hash_passphrase(&passphrase)),
    }
}

/// Keyboard mashing: read raw keypresses with timing entropy.
fn collect_keyboard_entropy() -> Result<[u8; ENTROPY_BYTES], std::io::Error> {
    use crossterm::event::{self, Event, KeyCode, KeyEvent};
    use crossterm::terminal;
    use indicatif::{ProgressBar, ProgressStyle};
    use std::time::Instant;

    println!("\nLet's generate a strong foundation.");
    println!("Mash your keyboard randomly... GO!\n");

    let pb = ProgressBar::new(MIN_KEYSTROKES as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{bar:40.cyan/blue} {pos}/{len}")
            .unwrap_or_else(|_| ProgressStyle::default_bar()),
    );

    terminal::enable_raw_mode()?;
    let mut hasher = Sha256::new();
    let mut collected = 0usize;
    let start = Instant::now();

    loop {
        if event::poll(std::time::Duration::from_millis(100))
            .map_err(std::io::Error::other)?
        {
            if let Event::Key(KeyEvent { code, .. }) =
                event::read().map_err(std::io::Error::other)?
            {
                // Mix key identity
                match code {
                    KeyCode::Char(c) => hasher.update([c as u8]),
                    KeyCode::Enter if collected >= MIN_KEYSTROKES => break,
                    _ => hasher.update([0xFF]),
                }

                // Mix timing (nanosecond precision)
                let elapsed = start.elapsed().as_nanos();
                hasher.update(elapsed.to_le_bytes());

                collected += 1;
                pb.set_position(collected.min(MIN_KEYSTROKES) as u64);

                if collected >= MIN_KEYSTROKES && matches!(code, KeyCode::Enter) {
                    break;
                }
            }
        }
    }

    terminal::disable_raw_mode()?;
    pb.finish_and_clear();

    println!("\nCollected entropy from {} keystrokes", collected);

    // Mix with OS RNG
    let mut os_entropy = [0u8; 32];
    OsRng.fill_bytes(&mut os_entropy);
    hasher.update(os_entropy);

    let result = hasher.finalize();
    let mut output = [0u8; ENTROPY_BYTES];
    output.copy_from_slice(&result);

    Ok(output)
}

/// Auto-generated passphrase: XKCD-style words.
fn collect_passphrase_entropy() -> Result<[u8; ENTROPY_BYTES], std::io::Error> {
    // Simple word list for passphrase generation
    const WORDS: &[&str] = &[
        "correct", "horse", "battery", "staple", "orange", "diamond",
        "forest", "meadow", "river", "mountain", "sunset", "thunder",
        "crystal", "velvet", "garden", "bridge", "harbor", "falcon",
        "marble", "silver", "copper", "anchor", "beacon", "castle",
        "dragon", "ember", "frost", "gentle", "hollow", "ivory",
        "jungle", "kettle", "lantern", "mystic", "noble", "oracle",
    ];

    let mut rng_bytes = [0u8; 8];
    OsRng.fill_bytes(&mut rng_bytes);

    // Pick 6 words using OS RNG
    let mut words = Vec::with_capacity(6);
    for _ in 0..6 {
        let mut idx_bytes = [0u8; 8];
        OsRng.fill_bytes(&mut idx_bytes);
        let idx = u64::from_le_bytes(idx_bytes) as usize % WORDS.len();
        words.push(WORDS[idx]);
    }

    let passphrase = words.join("-");
    println!("\nGenerated passphrase (record this securely):\n");
    println!("  {passphrase}\n");

    Ok(hash_passphrase(&passphrase))
}

/// Hash a passphrase with SHA-256, mixed with OS RNG.
fn hash_passphrase(passphrase: &str) -> [u8; ENTROPY_BYTES] {
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
}
