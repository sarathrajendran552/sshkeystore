use super::authenticator_data::build_get_assertion_auth_data;
use super::types::{Ctap2Error, GetAssertionRequest};
use crate::keys::CredentialKey;
use crate::store::{CredentialRecord, CredentialStore};
use ciborium::value::Value;
use sha2::{Digest, Sha256};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

fn select_credential(
    store: &CredentialStore,
    rp_id_hash: &[u8; 32],
    allow_list: &[Vec<u8>],
) -> Result<Option<CredentialRecord>, Ctap2Error> {
    if allow_list.is_empty() {
        Ok(store
            .get_by_rp_hash(rp_id_hash)?
            .into_iter()
            .find(|cred| cred.discoverable))
    } else {
        for id in allow_list {
            if let Some(cred) = store.get_by_id(id)? {
                if cred.rp_id_hash.as_slice() == rp_id_hash.as_slice() {
                    return Ok(Some(cred));
                }
            }
        }
        Ok(None)
    }
}

pub async fn handle_get_assertion(
    req: GetAssertionRequest,
    store: &Arc<Mutex<CredentialStore>>,
    pinentry_bin: &str,
    cid: u32,
    outgoing_tx: &mpsc::Sender<[u8; 64]>,
    cancel: &Arc<AtomicBool>,
) -> Result<Vec<u8>, Ctap2Error> {
    let rp_id_hash: [u8; 32] = Sha256::digest(req.rp_id.as_bytes()).into();

    let cred = {
        let store = store.lock().unwrap();
        select_credential(&store, &rp_id_hash, &req.allow_list)?.ok_or(Ctap2Error::NoCredentials)?
    };

    let account = cred
        .user_display
        .as_deref()
        .or(cred.user_name.as_deref())
        .unwrap_or("(unknown)");
    let title = "sshkeystore - SSH sign-in";
    let description = format!(
        "Allow this computer to sign an SSH challenge?\n\n\
         Application: {}\nAccount: {account}\n\n\
         Confirm to sign with the key stored in SQLite.",
        cred.rp_id
    );

    let proof = crate::up::require_user_presence(
        title,
        &description,
        pinentry_bin,
        outgoing_tx,
        cid,
        cancel,
    )
    .await?;

    let key = CredentialKey::from_private(&cred.private_key)
        .map_err(|e| Ctap2Error::Key(e.to_string()))?;

    let sign_count = store
        .lock()
        .unwrap()
        .increment_sign_count(&cred.credential_id)?;

    let auth_data = build_get_assertion_auth_data(&rp_id_hash, sign_count);
    let mut to_sign = auth_data.clone();
    to_sign.extend_from_slice(&req.client_data_hash);
    let signature = key.sign(&to_sign);

    let mut entries = vec![
        (
            Value::Integer(1i64.into()),
            Value::Map(vec![
                // CTAP2 canonical CBOR requires shorter text keys first.
                (
                    Value::Text("id".into()),
                    Value::Bytes(cred.credential_id.clone()),
                ),
                (Value::Text("type".into()), Value::Text("public-key".into())),
            ]),
        ),
        (Value::Integer(2i64.into()), Value::Bytes(auth_data)),
        (Value::Integer(3i64.into()), Value::Bytes(signature)),
    ];

    if cred.discoverable {
        let mut user_map = vec![(Value::Text("id".into()), Value::Bytes(cred.user_id.clone()))];
        if let Some(name) = &cred.user_name {
            user_map.push((Value::Text("name".into()), Value::Text(name.clone())));
        }
        if let Some(display) = &cred.user_display {
            user_map.push((
                Value::Text("displayName".into()),
                Value::Text(display.clone()),
            ));
        }
        entries.push((Value::Integer(4i64.into()), Value::Map(user_map)));
    }

    let mut response = vec![0x00u8];
    ciborium::into_writer(&Value::Map(entries), &mut response)
        .map_err(|e| Ctap2Error::Cbor(e.to_string()))?;

    tracing::info!(
        rp_id = %cred.rp_id,
        sign_count = sign_count,
        "ASSERTION SIGNED"
    );

    drop(proof);
    Ok(response)
}
