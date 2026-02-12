pub fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

pub fn hex_decode(input: &str) -> Result<Vec<u8>, String> {
    let input = input.trim();
    if !input.len().is_multiple_of(2) {
        return Err("hex string must have even length".to_string());
    }

    let mut out = Vec::with_capacity(input.len() / 2);
    let bytes = input.as_bytes();
    for i in (0..bytes.len()).step_by(2) {
        let hi = (bytes[i] as char).to_digit(16);
        let lo = (bytes[i + 1] as char).to_digit(16);
        let Some(hi) = hi else {
            return Err(format!("invalid hex character: {}", bytes[i] as char));
        };
        let Some(lo) = lo else {
            return Err(format!("invalid hex character: {}", bytes[i + 1] as char));
        };
        out.push(((hi << 4) | lo) as u8);
    }
    Ok(out)
}
