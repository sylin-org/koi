use maud::{html, Markup};

pub fn render() -> Markup {
    html! {
        section #about aria-labelledby="about-title" {
            h2 #about-title { "About" }
            p { "Koi helps applications and devices find, trust and talk across your private network." }
            p { "Interface version " (env!("CARGO_PKG_VERSION")) }
            (crate::components::mascot_card::render())
        }
    }
}
