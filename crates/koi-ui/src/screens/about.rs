use crate::View;
use maud::{html, Markup};

/// Source-owned destinations shared with the native documentation handoff.
pub struct DocumentationLink {
    pub title: &'static str,
    pub description: &'static str,
    pub url: &'static str,
}

pub const DOCUMENTATION: &[(&str, &[DocumentationLink])] = &[
    (
        "Get it working",
        &[
            DocumentationLink {
                title: "Start with a container",
                description: "Label an application and find its address.",
                url: "https://github.com/sylin-org/koi/blob/main/CONTAINERS.md",
            },
            DocumentationLink {
                title: "Install and run Koi",
                description: "Set up the service on your own machine.",
                url:
                    "https://github.com/sylin-org/koi/blob/main/docs/guides/install-and-service.md",
            },
            DocumentationLink {
                title: "Find your way around",
                description: "Discovery, naming and everyday operations.",
                url: "https://github.com/sylin-org/koi/blob/main/GUIDE.md",
            },
        ],
    ),
    (
        "Understand your network",
        &[
            DocumentationLink {
                title: "Certmesh identities",
                description: "Enrollment, renewal and the authority you control.",
                url: "https://github.com/sylin-org/koi/blob/main/docs/guides/certmesh.md",
            },
            DocumentationLink {
                title: "Names and DNS",
                description: "How services get a name on your network.",
                url: "https://github.com/sylin-org/koi/blob/main/docs/guides/dns.md",
            },
            DocumentationLink {
                title: "When something fails",
                description: "Inspect the evidence and find a next step.",
                url: "https://github.com/sylin-org/koi/blob/main/docs/guides/troubleshooting.md",
            },
        ],
    ),
    (
        "The project",
        &[
            DocumentationLink {
                title: "Source and documentation",
                description: "Read the code and explore the full guide.",
                url: "https://github.com/sylin-org/koi",
            },
            DocumentationLink {
                title: "The rest of the toolkit",
                description: "Koi's siblings, built under the same principles.",
                url: "https://sylin.org/",
            },
        ],
    ),
];

pub fn is_documentation_url(url: &str) -> bool {
    DOCUMENTATION
        .iter()
        .flat_map(|(_, links)| *links)
        .any(|link| link.url == url)
}

pub fn render(view: View<'_>) -> Markup {
    html! {
        section #about.about aria-labelledby="about-title" {
            (crate::components::mascot_card::render())
            div.about-copy {
                h1 #about-title data-ui-heading tabindex="-1" { "Koi" }
                p.about-lede { "Find the applications on your network, see what they are doing, and open the one you need. Koi runs on your machines, with the evidence close at hand." }
                dl.about-facts {
                    dt { "Interface" } dd { (koi_common::build::version()) }
                    @match view {
                        View::Snapshot(catalog) => {
                            dt { "Services" } dd { (catalog.services.len()) " in this snapshot" }
                            dt { "Hosts" } dd { (catalog.devices.len()) " in the catalog" }
                            dt { "Favorites" } dd { (catalog.services.iter().filter(|service| service.favorite).count()) " saved services" }
                            dt { "Snapshot" } dd { time datetime=(catalog.generated_at.to_rfc3339()) { (catalog.generated_at.format("%Y-%m-%d · %H:%M:%S UTC")) } }
                        },
                        View::Loading => { dt { "Catalog" } dd { "Reading snapshot…" } },
                        View::Unavailable => { dt { "Catalog" } dd { "Unavailable · refresh to try again" } },
                    }
                    dt { "License" } dd { "Apache-2.0 OR MIT" }
                }
                p.about-note { "When you need shared identity, Certmesh brings enrolled machines under an authority you control. Membership, application reachability and browser trust remain separate facts." }
                div.about-links {
                    @for (group, links) in DOCUMENTATION {
                        section.about-group {
                            h2 { (group) }
                            @for link in *links {
                                a.about-link href=(link.url) target="_blank" rel="noopener noreferrer" {
                                    span.about-link-title { (link.title) }
                                    span.about-link-blurb { (link.description) }
                                    span.sr-only { " (opens in browser)" }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
