use crate::ctap2::types::Ctap2Error;
use crate::ctaphid::encode_keepalive;
use pinentry::ConfirmationDialog;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;

const KEEPALIVE_PROCESSING: u8 = 0x01;
const KEEPALIVE_UPNEEDED: u8 = 0x02;
const PROMPT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Holds the KEEPALIVE task open for the lifetime of the CTAP2 command.
pub struct UserPresenceProof {
    _private: (),
    stop_tx: Option<tokio::sync::oneshot::Sender<()>>,
}

impl Drop for UserPresenceProof {
    fn drop(&mut self) {
        if let Some(tx) = self.stop_tx.take() {
            let _ = tx.send(());
        }
    }
}

fn start_keepalive(
    outgoing_tx: &mpsc::Sender<[u8; 64]>,
    cid: u32,
) -> (Arc<AtomicU8>, tokio::sync::oneshot::Sender<()>) {
    let (stop_tx, mut stop_rx) = tokio::sync::oneshot::channel::<()>();
    let tx = outgoing_tx.clone();
    let status = Arc::new(AtomicU8::new(KEEPALIVE_UPNEEDED));
    let status2 = Arc::clone(&status);

    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_millis(100));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let s = status2.load(Ordering::Relaxed);
                    tx.send(encode_keepalive(cid, s)).await.ok();
                }
                _ = &mut stop_rx => break,
            }
        }
    });

    (status, stop_tx)
}

async fn run_pinentry<T, F>(action: F) -> Result<T, Ctap2Error>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, pinentry::Error> + Send + 'static,
{
    let join = tokio::task::spawn_blocking(action);
    match tokio::time::timeout(PROMPT_TIMEOUT, join).await {
        Err(_) => Err(Ctap2Error::UserActionTimeout),
        Ok(Err(_)) => Err(Ctap2Error::OperationDenied),
        Ok(Ok(Err(error))) => {
            tracing::warn!(%error, "pinentry failed");
            Err(Ctap2Error::OperationDenied)
        }
        Ok(Ok(Ok(value))) => Ok(value),
    }
}

fn missing_binary() -> pinentry::Error {
    pinentry::Error::Io(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        "pinentry binary not found",
    ))
}

pub async fn require_user_presence(
    title: &str,
    description: &str,
    pinentry_bin: &str,
    outgoing_tx: &mpsc::Sender<[u8; 64]>,
    cid: u32,
    cancel: &Arc<AtomicBool>,
) -> Result<UserPresenceProof, Ctap2Error> {
    let (status, stop_tx) = start_keepalive(outgoing_tx, cid);

    let title = title.to_string();
    let description = description.to_string();
    let bin = pinentry_bin.to_string();

    let confirmed = run_pinentry(move || {
        let mut dialog = ConfirmationDialog::with_binary(&bin).ok_or_else(missing_binary)?;
        dialog
            .with_title(&title)
            .with_ok("Confirm")
            .with_cancel("Cancel");
        dialog.confirm(&description)
    })
    .await?;

    if cancel.load(Ordering::Relaxed) {
        return Err(Ctap2Error::KeepaliveCancel);
    }
    if !confirmed {
        return Err(Ctap2Error::OperationDenied);
    }

    status.store(KEEPALIVE_PROCESSING, Ordering::Relaxed);
    Ok(UserPresenceProof {
        _private: (),
        stop_tx: Some(stop_tx),
    })
}
