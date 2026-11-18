use super::attestation::build_attestation_object;
use super::authenticator_data::build_make_cred_auth_data;
use super::types::{Ctap2Error, MakeCredentialRequest};
use crate::keys::CredentialKey;
use crate::store::{hex, CredentialRecord, CredentialStore};
use sha2::{Digest, Sha256};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

#[allow(clippy::too_many_arguments)]
pub async fn handle_make_credential(
    req: MakeCredentialRequest,
    store: &Arc<Mutex<CredentialStore>>,
    pinentry_bin: &str,
    cid: u32,
    outgoing_tx: &mpsc::Sender<[u8; 64]>,
    cancel: &Arc<AtomicBool>,
) -> Result<Vec<u8>, Ctap2Error> {
    let alg = req.selected_alg.ok_or(Ctap2Error::UnsupportedAlgorithm)?;
    let rp_id_hash: [u8; 32] = Sha256::digest(req.rp_id.as_bytes()).into();

    {
        let store = store.lock().unwrap();
        for excluded in &req.exclude_list {
            if let Some(cred) = store.get_by_id(excluded)? {
                if cred.rp_id_hash.as_slice() == rp_id_hash.as_slice() {
                    return Err(Ctap2Error::CredentialExcluded);
                }
            }
        }
    }

    let account = req
        .user_display
        .as_deref()
        .or(req.user_name.as_deref())
        .unwrap_or("(unknown)");
    let site = match req.rp_name.as_deref() {
        Some(name) => format!("{name} ({})", req.rp_id),
        None => req.rp_id.clone(),
    };
    let title = "sshkeystore - new SSH key";
    let description = format!(
        "Allow this computer to create a new FIDO2 key?\n\n\
         Application: {site}\nAccount: {account}\nAlgorithm: {}\n\n\
         Confirm to create the key and store it in the SQLite database.",
        match alg {
            crate::keys::ALG_EDDSA => "EdDSA (-8)",
            crate::keys::ALG_ED25519 => "Ed25519 (-19)",
            _ => "unknown",
        }
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

    let key = CredentialKey::generate();
    let mut credential_id = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut credential_id);

    let auth_data = build_make_cred_auth_data(&rp_id_hash, &credential_id, &key.public(), alg);
    let mut to_sign = auth_data.clone();
    to_sign.extend_from_slice(&req.client_data_hash);
    let signature = key.sign(&to_sign);
    let attestation = build_attestation_object(&auth_data, &signature, alg)?;

    let created_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let record = CredentialRecord {
        credential_id: credential_id.to_vec(),
        rp_id: req.rp_id.clone(),
        rp_id_hash: rp_id_hash.to_vec(),
        user_id: req.user_id,
        user_name: req.user_name,
        user_display: req.user_display,
        alg,
        private_key: key.private().to_vec(),
        public_key: key.public().to_vec(),
        sign_count: 0,
        discoverable: req.resident_key,
        created_at,
    };

    store.lock().unwrap().insert(&record)?;

    tracing::info!(
        rp_id = %record.rp_id,
        account = %record
            .user_display
            .as_deref()
            .or(record.user_name.as_deref())
            .unwrap_or("(unknown)"),
        credential_id = %hex(&record.credential_id),
        alg = alg,
        discoverable = record.discoverable,
        "KEY CREATED (stored in SQLite)"
    );

    drop(proof);

    let mut response = vec![0x00u8];
    response.extend_from_slice(&attestation);
    Ok(response)
}
