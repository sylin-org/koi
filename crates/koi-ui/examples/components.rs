//! Produce an offline component document. `snapshot` consumes a real schema-1 DTO
//! from stdin; no fallback fixture can masquerade as live evidence.
use koi_ui::{Links, View};
use std::io::Read;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mode = std::env::args().nth(1).unwrap_or_else(|| "loading".into());
    let intent = koi_ui::home::HomeRequest::parse(&std::env::args().nth(2).unwrap_or_default())?;
    let catalog;
    let view = match mode.as_str() {
        "loading" => View::Loading,
        "unavailable" => View::Unavailable,
        "snapshot" => {
            let mut input = String::new();
            std::io::stdin().read_to_string(&mut input)?;
            catalog = serde_json::from_str(&input)?;
            View::Snapshot(&catalog)
        }
        _ => return Err("choose loading, unavailable or snapshot (JSON on stdin)".into()),
    };
    println!(
        "{}",
        koi_ui::render_home(
            view,
            Links {
                refresh: Some("./"),
                advanced: "/",
                browser_access: None,
            },
            &intent.query(),
        )
    );
    Ok(())
}
