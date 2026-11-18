use clap::{ArgAction, Parser};
use std::path::PathBuf;

#[derive(Parser, Debug, Clone)]
#[command(
    name = "sshkeystore",
    about = "Virtual FIDO2 UHID authenticator backed by SQLite"
)]
pub struct Config {
    /// Increase log verbosity (-v debug, -vv trace).
    #[arg(short, long, action = ArgAction::Count)]
    pub verbose: u8,

    /// Override the default SQLite database path.
    #[arg(long)]
    pub db: Option<PathBuf>,

    /// pinentry binary used to confirm user presence.
    #[arg(long, default_value = "pinentry")]
    pub pinentry: String,
}

impl Config {
    pub fn database_path(&self) -> anyhow::Result<PathBuf> {
        if let Some(path) = &self.db {
            return Ok(path.clone());
        }
        let dirs = directories::ProjectDirs::from("", "", "sshkeystore")
            .ok_or_else(|| anyhow::anyhow!("cannot determine the XDG data directory"))?;
        Ok(dirs.data_dir().join("sshkeystore.sqlite"))
    }
}
