use koi_embedded::{Builder, ServiceMode};
use tokio_stream::StreamExt;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let koi = Builder::new()
        .service_mode(ServiceMode::EmbeddedOnly)
        .build()?;
    let handle = koi.start().await?;

    let mut events = handle.events();
    tokio::spawn(async move {
        while let Some(Ok(event)) = events.next().await {
            println!("event: {event:?}");
        }
    });

    Ok(())
}
