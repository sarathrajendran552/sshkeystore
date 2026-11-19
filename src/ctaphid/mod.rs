pub mod channel;
mod packet;
mod types;

use crate::store::CredentialStore;
use channel::{ChannelError, ChannelManager, Message};
use packet::{encode_error, encode_response, parse_packet, Packet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use types::*;

enum DispatchResult {
    Response(Vec<[u8; 64]>),
    Cbor(Message),
}

pub(crate) fn encode_keepalive(cid: u32, status: u8) -> [u8; 64] {
    encode_response(cid, CMD_KEEPALIVE, &[status])[0]
}

pub async fn run(
    mut incoming_rx: mpsc::Receiver<[u8; 64]>,
    outgoing_tx: mpsc::Sender<[u8; 64]>,
    store: Arc<Mutex<CredentialStore>>,
    ctap_state: Arc<Mutex<crate::ctap2::CtapState>>,
    pinentry_bin: String,
) -> anyhow::Result<()> {
    let mut manager = ChannelManager::new();
    let cancel = Arc::new(AtomicBool::new(false));
    let cbor_busy = Arc::new(AtomicBool::new(false));

    tracing::info!("CTAPHID loop running; waiting for ssh-keygen");

    while let Some(report) = incoming_rx.recv().await {
        match process_report(&mut manager, &report) {
            DispatchResult::Response(packets) => {
                for packet in packets {
                    if outgoing_tx.send(packet).await.is_err() {
                        return Ok(());
                    }
                }
            }
            DispatchResult::Cbor(message) => {
                if cbor_busy.swap(true, Ordering::Relaxed) {
                    outgoing_tx
                        .send(encode_error(message.cid, ERR_CHANNEL_BUSY))
                        .await
                        .ok();
                    continue;
                }

                cancel.store(false, Ordering::Relaxed);
                let tx = outgoing_tx.clone();
                let store = Arc::clone(&store);
                let ctap_state = Arc::clone(&ctap_state);
                let cancel = Arc::clone(&cancel);
                let busy = Arc::clone(&cbor_busy);
                let pinentry_bin = pinentry_bin.clone();
                let cid = message.cid;

                tokio::spawn(async move {
                    let response = crate::ctap2::dispatch_cbor(
                        message,
                        &store,
                        &pinentry_bin,
                        &tx,
                        &cancel,
                        &ctap_state,
                    )
                    .await;
                    tracing::trace!(len = response.len(), head = %response.iter().take(24).map(|b| format!("{b:02x}")).collect::<String>(), "CTAP2 response");
                    for packet in encode_response(cid, CMD_CBOR, &response) {
                        tx.send(packet).await.ok();
                    }
                    busy.store(false, Ordering::Relaxed);
                });
            }
        }
    }

    tracing::info!("CTAPHID loop exiting");
    Ok(())
}

fn process_report(manager: &mut ChannelManager, report: &[u8; 64]) -> DispatchResult {
    match parse_packet(report) {
        Packet::Init(init) => {
            if init.cid == RESERVED_CID {
                return DispatchResult::Response(vec![encode_error(
                    BROADCAST_CID,
                    ERR_INVALID_CHANNEL,
                )]);
            }
            if init.cid != BROADCAST_CID && !manager.exists(init.cid) {
                return DispatchResult::Response(vec![encode_error(init.cid, ERR_INVALID_CHANNEL)]);
            }

            match manager.feed_init(init.cid, init.cmd, init.bcnt, init.data) {
                Ok(Some(message)) => dispatch_message(manager, message),
                Ok(None) => DispatchResult::Response(vec![]),
                Err(error) => DispatchResult::Response(vec![encode_error(
                    init.cid,
                    channel_error_code(&error),
                )]),
            }
        }
        Packet::Cont(cont) => {
            if cont.cid == BROADCAST_CID || cont.cid == RESERVED_CID {
                return DispatchResult::Response(vec![encode_error(cont.cid, ERR_INVALID_CHANNEL)]);
            }
            match manager.feed_cont(cont.cid, cont.seq, cont.data) {
                Ok(Some(message)) => dispatch_message(manager, message),
                Ok(None) => DispatchResult::Response(vec![]),
                Err(error) => DispatchResult::Response(vec![encode_error(
                    cont.cid,
                    channel_error_code(&error),
                )]),
            }
        }
    }
}

fn dispatch_message(manager: &mut ChannelManager, message: Message) -> DispatchResult {
    tracing::debug!(
        cid = format!("{:#010x}", message.cid),
        cmd = format!("{:#04x}", message.cmd),
        len = message.payload.len(),
        "CTAPHID dispatch"
    );
    match message.cmd {
        CMD_INIT => DispatchResult::Response(handle_init(manager, message)),
        CMD_PING => {
            DispatchResult::Response(encode_response(message.cid, CMD_PING, &message.payload))
        }
        CMD_CANCEL => {
            tracing::debug!(cid = format!("{:#010x}", message.cid), "CANCEL");
            DispatchResult::Response(vec![])
        }
        CMD_CBOR => DispatchResult::Cbor(message),
        CMD_WINK => DispatchResult::Response(encode_response(message.cid, CMD_WINK, &[])),
        _ => DispatchResult::Response(vec![encode_error(message.cid, ERR_INVALID_CMD)]),
    }
}

fn handle_init(manager: &mut ChannelManager, message: Message) -> Vec<[u8; 64]> {
    if message.payload.len() < 8 {
        return vec![encode_error(message.cid, ERR_INVALID_LEN)];
    }

    let new_cid = match manager.allocate() {
        Ok(cid) => cid,
        Err(_) => return vec![encode_error(message.cid, ERR_CHANNEL_BUSY)],
    };

    let mut response = [0u8; 17];
    response[0..8].copy_from_slice(&message.payload[0..8]);
    response[8..12].copy_from_slice(&new_cid.to_be_bytes());
    response[12] = CTAPHID_PROTOCOL_VERSION;
    response[13] = 0;
    response[14] = 1;
    response[15] = 0;
    response[16] = CAPABILITIES;

    tracing::debug!(
        cid = format!("{new_cid:#010x}"),
        caps = format!("{CAPABILITIES:#04x}"),
        "CTAPHID channel allocated"
    );
    encode_response(message.cid, CMD_INIT, &response)
}

fn channel_error_code(error: &ChannelError) -> u8 {
    match error {
        ChannelError::Busy => ERR_CHANNEL_BUSY,
        ChannelError::InvalidChannel => ERR_INVALID_CHANNEL,
        ChannelError::UnexpectedCont => ERR_INVALID_CMD,
        ChannelError::InvalidLen => ERR_INVALID_LEN,
        ChannelError::InvalidSeq => ERR_INVALID_PAR,
        ChannelError::Timeout => ERR_OTHER,
    }
}
