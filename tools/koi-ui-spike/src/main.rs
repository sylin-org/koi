use koi_client::KoiClient;
use koi_ui_spike::View;

fn main() -> std::process::ExitCode {
    let renderer = std::env::args().nth(1).unwrap_or_else(|| "maud".into());
    let render: fn(View<'_>) -> String = match renderer.as_str() {
        #[cfg(feature = "maud-renderer")]
        "maud" => koi_ui_spike::maud_view::render,
        #[cfg(feature = "dioxus-renderer")]
        "dioxus" => koi_ui_spike::dioxus_view::render,
        _ => {
            eprintln!("Choose a compiled renderer: maud or dioxus.");
            return std::process::ExitCode::from(2);
        }
    };
    // Existing client owns credential discovery/schema checks. No alternate daemon,
    // fixture fallback, token argument or raw server error/body in rendered output.
    match KoiClient::from_local().and_then(|client| client.catalog_snapshot()) {
        Ok(catalog) => {
            println!("{}", render(View::Snapshot(&catalog)));
            eprintln!(
                "Rendered a real local snapshot ({} services).",
                catalog.services.len()
            );
            std::process::ExitCode::SUCCESS
        }
        Err(_) => {
            println!("{}", render(View::Unavailable));
            eprintln!("Local catalog unavailable; no live-row acceptance claimed.");
            std::process::ExitCode::FAILURE
        }
    }
}
