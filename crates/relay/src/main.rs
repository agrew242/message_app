//! Run the relay.
//!
//! Environment:
//! - `RELAY_ADDR` — address to listen on (default `127.0.0.1:8080`). Put it
//!   behind Caddy or another TLS proxy in production; never expose plain HTTP.
//! - `RELAY_DB`   — SQLite file (default `relay.db`).
//! - `RELAY_ALLOWED_ORIGINS` — comma-separated web app origins allowed to
//!   call the API from a browser, e.g. `https://app.example.com`.
//! - `RELAY_VAPID_SUBJECT` — contact for push services, e.g.
//!   `mailto:you@example.com`.
//! - `RUST_LOG`   — log filter (default `info`).
//!
//! `messenger-relay backup <file>` writes a consistent copy of the database
//! to `<file>`, even while the relay is running.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context};
use messenger_relay::{serve, Relay, RelayConfig};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let db_path = PathBuf::from(std::env::var("RELAY_DB").unwrap_or_else(|_| "relay.db".into()));
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        None => {}
        Some("backup") => {
            let dest = args.next().context("usage: messenger-relay backup <file>")?;
            messenger_relay::db::backup(&db_path, Path::new(&dest))?;
            println!("Backed up {} to {dest}", db_path.display());
            return Ok(());
        }
        Some(other) => bail!("unknown command {other:?}; run with no arguments, or `backup <file>`"),
    }

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();

    let addr = std::env::var("RELAY_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".into());

    let relay = Relay::open_with(&db_path, RelayConfig::from_env())?;
    if let Some(code) = relay.bootstrap_invite()? {
        println!("No users yet. First invite code (valid 7 days): {code}");
    }

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("relay listening on http://{}", listener.local_addr()?);
    serve(listener, relay).await?;
    Ok(())
}
