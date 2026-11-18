mod attestation;
mod authenticator_data;
pub mod get_assertion;
mod get_info;
pub mod make_credential;
pub mod types;

use crate::ctaphid::channel::Message;
use crate::store::CredentialStore;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use types::{
    Ctap2Error, GetAssertionRequest, MakeCredentialRequest, CMD_GET_ASSERTION, CMD_GET_INFO,
    CMD_MAKE_CREDENTIAL,
};

pub async fn dispatch_cbor(
    msg: Message,
    store: &Arc<Mutex<CredentialStore>>,
    pinentry_bin: &str,
    outgoing_tx: &mpsc::Sender<[u8; 64]>,
    cancel: &Arc<AtomicBool>,
) -> Vec<u8> {
    match dispatch_inner(msg, store, pinentry_bin, outgoing_tx, cancel).await {
        Ok(response) => response,
        Err(error) => {
            tracing::warn!("CTAP2 error: {error}");
            vec![error.status_byte()]
        }
    }
}

async fn dispatch_inner(
    msg: Message,
    store: &Arc<Mutex<CredentialStore>>,
    pinentry_bin: &str,
    outgoing_tx: &mpsc::Sender<[u8; 64]>,
    cancel: &Arc<AtomicBool>,
) -> Result<Vec<u8>, Ctap2Error> {
    if msg.payload.is_empty() {
        return Err(Ctap2Error::MissingParameter);
    }

    let command = msg.payload[0];
    let body = &msg.payload[1..];

    match command {
        CMD_GET_INFO => Ok(get_info::handle_get_info()),
        CMD_MAKE_CREDENTIAL => {
            let request = MakeCredentialRequest::try_from(body)?;
            make_credential::handle_make_credential(
                request,
                store,
                pinentry_bin,
                msg.cid,
                outgoing_tx,
                cancel,
            )
            .await
        }
        CMD_GET_ASSERTION => {
            let request = GetAssertionRequest::try_from(body)?;
            get_assertion::handle_get_assertion(
                request,
                store,
                pinentry_bin,
                msg.cid,
                outgoing_tx,
                cancel,
            )
            .await
        }
        other => Err(Ctap2Error::Cbor(format!("unknown command {other:#04x}"))),
    }
}
