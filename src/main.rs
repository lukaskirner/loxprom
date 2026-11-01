mod auth;
mod client;
mod config;
mod http;
mod protocol;
mod store;
mod structure;

use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;
use tracing::info;

use crate::config::Config;
use crate::store::Store;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let mut cfg = Config::parse();
    cfg.password = std::env::var("LOXONE_PASSWORD").context("LOXONE_PASSWORD must be set")?;
    let cfg = Arc::new(cfg);

    let store = Arc::new(Store::new());
    tokio::spawn(client::run(cfg.clone(), store.clone()));

    let listener = tokio::net::TcpListener::bind(&cfg.listen)
        .await
        .with_context(|| format!("binding {}", cfg.listen))?;
    info!("serving /metrics on {}", cfg.listen);
    axum::serve(listener, http::router(store)).with_graceful_shutdown(shutdown()).await?;
    Ok(())
}

async fn shutdown() {
    use tokio::signal::unix::{SignalKind, signal};
    let mut term = signal(SignalKind::terminate()).expect("install SIGTERM handler");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = term.recv() => {}
    }
}
