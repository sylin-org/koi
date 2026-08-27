//! W12 probe: minimal instant-acme newAccount + dns-01 flow against a
//! running ACME server, with verbose errors. Args: <directory-url> <ca-pem-path>

use anyhow::Context;
use instant_acme::{Account, ChallengeType, Identifier, NewAccount, NewOrder};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // The koi-lab dependency graph links both aws-lc-rs and ring; rustls 0.23
    // refuses to guess. The daemon installs its own provider; a standalone
    // client must too.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let args: Vec<String> = std::env::args().collect();
    let (directory, ca_pem) = (args[1].clone(), args[2].clone());

    println!("directory: {directory}");
    let (account, _creds): (Account, _) = Account::builder_with_root(std::path::Path::new(&ca_pem))
        .context("builder_with_root")?
        .create(
            &NewAccount {
                contact: &[],
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            directory.clone(),
            None,
        )
        .await
        .context("newAccount failed")?;
    println!("newAccount OK");

    let name = format!("probe-{}.internal", std::process::id());
    let mut order = account
        .new_order(&NewOrder::new(&[Identifier::Dns(name.clone())]))
        .await
        .context("newOrder failed")?;
    println!("newOrder OK for {name}");

    let mut authorizations = order.authorizations();
    while let Some(result) = authorizations.next().await {
        let mut authorization = result.context("authorization failed")?;
        let Some(mut challenge) = authorization.challenge(ChallengeType::Dns01) else {
            println!("dns-01 challenge not offered");
            return Ok(());
        };
        let identifier = challenge.identifier().to_string();
        let dns_name = format!("_acme-challenge.{identifier}");
        let value = challenge.key_authorization().dns_value();
        println!("challenge ready: TXT {dns_name} = {value}");
        println!("(publish via the daemon API, then set_ready)");
        break;
    }
    println!("done");
    Ok(())
}
