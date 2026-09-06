use base64::Engine as _;
use maud::{Markup, PreEscaped};

pub fn render() -> Markup {
    // Only source-owned markup and original bytes enter the raw-markup boundary.
    let sprite =
        base64::engine::general_purpose::STANDARD.encode(include_bytes!("../../assets/koi.png"));
    PreEscaped(include_str!("../../assets/card.html").replace(
        "src=\"koi.png\"",
        &format!("src=\"data:image/png;base64,{sprite}\""),
    ))
}
