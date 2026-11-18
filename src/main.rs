mod config;
mod ctap2;
mod ctaphid;
mod hid;
mod keys;
mod store;
mod up;

use clap::Parser;
use config::Config;
use std::sync::Arc;

fn main() -> anyhow::Result<()> {
    let cfg = Config::parse();

    let filter = match cfg.verbose {
        0 => "sshkeystore=info",
        1 => "sshkeystore=debug",
        _ => "sshkeystore=trace",
    };
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(filter)),
        )
        .with_target(false)
        .init();

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(run(cfg))
}

async fn run(cfg: Config) -> anyhow::Result<()> {
    let db_path = cfg.database_path()?;
    let store = Arc::new(std::sync::Mutex::new(store::CredentialStore::open(
        &db_path,
    )?));

    tracing::info!(db = %db_path.display(), "sshkeystore starting");
    tracing::info!("virtual FIDO2 UHID device will be registered on /dev/uhid");

    let transport = hid::start_hid_transport()?;

    let result = ctaphid::run(
        transport.incoming_rx,
        transport.outgoing_tx,
        store,
        cfg.pinentry.clone(),
    )
    .await;

    let _ = transport.task.await;
    result
}
