//! Browser entry points use the authenticated local operator, never guessed ports.
use crate::cli::{Cli, WebSubcommand};
use koi_common::browser_access::BrowserAccessSettings;
use std::io::IsTerminal;

fn client(cli: &Cli) -> anyhow::Result<koi_client::KoiClient> {
    if cli.standalone || cli.endpoint.is_some() {
        anyhow::bail!("Browser access is managed on the Koi computer. Run this command there, locally or through SSH, without --endpoint or --standalone.");
    }
    super::require_client(None, None)
}
pub fn launch(cli: &Cli) -> anyhow::Result<()> {
    let client = client(cli)?;
    let mut settings = client.browser_access_status()?.settings;
    if !settings.enabled {
        settings.enabled = true;
        client.browser_access_settings(&settings)?;
    }
    let invitation = client.browser_invitation(false)?;
    let url = format!("{}&open=1", invitation.url);
    open::that(&url).map_err(|_| anyhow::anyhow!("Could not open the default browser. Run `koi web invite` to show a one-use link and QR."))?;
    crate::format::print_browser_opened();
    Ok(())
}
pub fn run(cli: &Cli, command: &WebSubcommand) -> anyhow::Result<()> {
    let client = client(cli)?;
    match command {
        WebSubcommand::Status => output(&client.browser_access_status()?, cli.json),
        WebSubcommand::Enable { phone } => output(
            &client.browser_access_settings(&BrowserAccessSettings {
                enabled: true,
                phone: *phone,
            })?,
            cli.json,
        ),
        WebSubcommand::Disable => output(
            &client.browser_access_settings(&BrowserAccessSettings::default())?,
            cli.json,
        ),
        WebSubcommand::Disconnect { id } => output(&client.browser_disconnect(id)?, cli.json),
        WebSubcommand::Invite { phone, force } => {
            if !*force && !std::io::stdout().is_terminal() {
                anyhow::bail!("An invitation grants one browser access. Use a terminal, or --force to intentionally include it in redirected output.");
            }
            let invitation = client.browser_invitation(*phone)?;
            if cli.json {
                super::print_json(&invitation)
            } else {
                crate::format::print_browser_invitation(&invitation, *phone);
                Ok(())
            }
        }
    }
}
fn output(
    status: &koi_common::browser_access::BrowserAccessStatus,
    json: bool,
) -> anyhow::Result<()> {
    if json {
        super::print_json(status)
    } else {
        crate::format::print_browser_access(status);
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    #[test]
    fn explicit_remote_and_standalone_cannot_borrow_local_authority() {
        for args in [
            vec!["koi", "--endpoint", "http://example.test", "web", "status"],
            vec!["koi", "--standalone", "web", "status"],
        ] {
            assert!(client(&Cli::try_parse_from(args).unwrap()).is_err());
        }
    }
}
