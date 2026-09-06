use maud::{html, Markup};

pub const NAVIGATION: [(&str, &str); 4] = [
    ("home", "Home"),
    ("devices", "Devices"),
    ("settings", "Settings"),
    ("about", "About"),
];

pub fn render() -> Markup {
    html! {
        a.skip href="#content" { "Skip to content" }
        header.lampband {
            span.lamp aria-hidden="true" { span.lamp-core {} }
            span.state-word { "Koi" }
            nav aria-label="Primary" {
                @for (id, label) in NAVIGATION {
                    a.tab href=(format!("#{id}")) { (label) }
                }
            }
        }
    }
}
