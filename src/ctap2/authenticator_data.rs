use crate::keys;

pub const AAGUID: [u8; 16] = *b"sshkeystore-v0.1";

pub fn build_make_cred_auth_data(
    rp_id_hash: &[u8; 32],
    credential_id: &[u8],
    public_key: &[u8; 32],
    alg: i64,
    cred_prot: Option<u8>,
) -> Vec<u8> {
    let cose_key = keys::encode_cose_key(alg, public_key);
    let mut data = Vec::new();
    data.extend_from_slice(rp_id_hash);
    let mut flags = 0x41; // UP and AT
    if cred_prot.is_some() {
        flags |= 0x80; // ED (extension data)
    }
    data.push(flags);
    data.extend_from_slice(&[0, 0, 0, 0]); // signCount
    data.extend_from_slice(&AAGUID);
    data.extend_from_slice(&(credential_id.len() as u16).to_be_bytes());
    data.extend_from_slice(credential_id);
    data.extend_from_slice(&cose_key);
    if let Some(level) = cred_prot {
        let ext = ciborium::value::Value::Map(vec![(
            ciborium::value::Value::Text("credProtect".into()),
            ciborium::value::Value::Integer(level.into()),
        )]);
        ciborium::into_writer(&ext, &mut data).expect("extension encoding is infallible");
    }
    data
}

pub fn build_get_assertion_auth_data(rp_id_hash: &[u8; 32], sign_count: u32) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(rp_id_hash);
    data.push(0x01); // UP
    data.extend_from_slice(&sign_count.to_be_bytes());
    data
}
