//! Run the relay.
//!
//! Environment:
//! - `RELAY_ADDR` — address to listen on (default `127.0.0.1:8080`). Put it
//!   behind Caddy or another TLS proxy in production; never expose plain HTTP.
//! - `RELAY_DB`   — SQLite file (default `relay.db`).
//! - `RUST_LOG`   — log filter (default `info`).

use std::path::PathBuf;

use messenger_relay::{serve, Relay};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();

    let addr = std::env::var("RELAY_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".into());
    let db_path = PathBuf::from(std::env::var("RELAY_DB").unwrap_or_else(|_| "relay.db".into()));

    let relay = Relay::open(&db_path)?;
    if let Some(code) = relay.bootstrap_invite()? {
        println!("No users yet. First invite code (valid 7 days): {code}");
    }

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("relay listening on http://{}", listener.local_addr()?);
    serve(listener, relay).await?;
    Ok(())
}
