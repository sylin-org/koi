//! Produce an offline component document. Snapshot mode reads a real schema-1 DTO
//! from stdin; a failed live read never falls back to the invented layout fixture.
use koi_ui::{EndpointActions, Links, OperatorActions, UiState, View};
use std::io::Read;

#[path = "support/catalog.rs"]
mod sample_catalog;
#[path = "support/mdns.rs"]
mod sample_mdns;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let mode = args.next().unwrap_or_else(|| "loading".into());
    let state = UiState::parse_query(&args.next().unwrap_or_default())?;
    let browser_transport = match args.next().as_deref() {
        None => false,
        Some("browser") => true,
        _ => return Err("the optional transport argument must be browser".into()),
    };
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
        "fixture" | "mdns-fixture" => {
            catalog = sample_catalog::fixture();
            View::Snapshot(&catalog)
        }
        _ => return Err("choose loading, unavailable, snapshot (JSON on stdin), or fixture; optionally supply a UI query string as the second argument".into()),
    };
    let operator = (mode == "mdns-fixture").then(|| koi_ui::OperatorSnapshot {
        mdns: Some(sample_mdns::fixture()),
        ..Default::default()
    });
    let mut html = koi_ui::render_with_operator_state(
        view,
        operator.as_ref(),
        Links {
            refresh: if browser_transport { None } else { Some("./") },
            endpoint_actions: if browser_transport {
                EndpointActions::Browser
            } else {
                EndpointActions::None
            },
            preference_actions: browser_transport,
            operator_actions: if browser_transport {
                OperatorActions::Browser
            } else {
                OperatorActions::None
            },
        },
        &state,
    );
    if mode == "fixture" || mode == "mdns-fixture" {
        // Source-owned notice outside the application shell. The production
        // renderer never creates sample data or a fallback on failed live reads.
        html = html.replacen(
            "<body>",
            "<body data-offline-fixture=\"true\"><aside data-fixture-notice style=\"padding:4px 12px;font:12px system-ui;color:#f4f4f5;background:#30251a\">Invented offline fixture · 36 services on 6 sample hosts · layout evidence only; no live discovery or Koi operations.</aside>",
            1,
        );
    }
    println!("{html}");
    Ok(())
}
