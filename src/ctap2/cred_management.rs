use super::types::Ctap2Error;
use crate::store::{CredentialRecord, CredentialStore};
use ciborium::value::Value;

const SUB_GET_METADATA: i64 = 0x01;
const SUB_RP_BEGIN: i64 = 0x02;
const SUB_RP_NEXT: i64 = 0x03;
const SUB_RK_BEGIN: i64 = 0x04;
const SUB_RK_NEXT: i64 = 0x05;

#[derive(Default)]
pub struct CredmanState {
    rps: Vec<(String, Vec<u8>)>,
    rp_index: usize,
    rks: Vec<CredentialRecord>,
    rk_index: usize,
}

fn parse_map(data: &[u8]) -> Result<Vec<(Value, Value)>, Ctap2Error> {
    match ciborium::from_reader(data).map_err(|e| Ctap2Error::Cbor(e.to_string()))? {
        Value::Map(map) => Ok(map),
        _ => Err(Ctap2Error::Cbor("expected map".into())),
    }
}

fn get(map: &[(Value, Value)], key: i64) -> Option<&Value> {
    let target = Value::Integer(key.into());
    map.iter().find(|(k, _)| k == &target).map(|(_, v)| v)
}

fn get_int(map: &[(Value, Value)], key: i64) -> Option<i64> {
    match get(map, key)? {
        Value::Integer(value) => i64::try_from(*value).ok(),
        _ => None,
    }
}

fn get_bytes(map: &[(Value, Value)], key: i64) -> Option<&[u8]> {
    match get(map, key)? {
        Value::Bytes(bytes) => Some(bytes),
        _ => None,
    }
}

fn encode_response(map: Value) -> Result<Vec<u8>, Ctap2Error> {
    let mut buf = vec![0x00u8];
    ciborium::into_writer(&map, &mut buf).map_err(|e| Ctap2Error::Cbor(e.to_string()))?;
    Ok(buf)
}

fn user_entity(cred: &CredentialRecord) -> Value {
    let mut entries = vec![(Value::Text("id".into()), Value::Bytes(cred.user_id.clone()))];
    if let Some(name) = &cred.user_name {
        entries.push((Value::Text("name".into()), Value::Text(name.clone())));
    }
    if let Some(display) = &cred.user_display {
        entries.push((
            Value::Text("displayName".into()),
            Value::Text(display.clone()),
        ));
    }
    Value::Map(entries)
}

fn public_key(cred: &CredentialRecord) -> Value {
    Value::Map(vec![
        (Value::Integer(1i64.into()), Value::Integer(1i64.into())), // kty: OKP
        (Value::Integer(3i64.into()), Value::Integer(cred.alg.into())),
        (Value::Integer((-1i64).into()), Value::Integer(6i64.into())), // crv: Ed25519
        (
            Value::Integer((-2i64).into()),
            Value::Bytes(cred.public_key.clone()),
        ),
    ])
}

fn rk_entry(cred: &CredentialRecord, total: usize) -> Value {
    Value::Map(vec![
        (Value::Integer(6i64.into()), user_entity(cred)),
        (
            Value::Integer(7i64.into()),
            Value::Map(vec![
                (
                    Value::Text("id".into()),
                    Value::Bytes(cred.credential_id.clone()),
                ),
                (Value::Text("type".into()), Value::Text("public-key".into())),
            ]),
        ),
        (Value::Integer(8i64.into()), public_key(cred)),
        (
            Value::Integer(9i64.into()),
            Value::Integer((total as i64).into()),
        ),
        (
            Value::Integer(10i64.into()),
            Value::Integer((cred.cred_prot as i64).into()),
        ),
    ])
}

fn rp_entry(rp_id: &str, rp_id_hash: &[u8], total: usize) -> Value {
    Value::Map(vec![
        (
            Value::Integer(3i64.into()),
            Value::Map(vec![
                (Value::Text("id".into()), Value::Text(rp_id.to_string())),
                (Value::Text("name".into()), Value::Text(rp_id.to_string())),
            ]),
        ),
        (
            Value::Integer(4i64.into()),
            Value::Bytes(rp_id_hash.to_vec()),
        ),
        (
            Value::Integer(5i64.into()),
            Value::Integer((total as i64).into()),
        ),
    ])
}

pub fn handle_credential_management(
    body: &[u8],
    store: &CredentialStore,
    state: &mut CredmanState,
) -> Result<Vec<u8>, Ctap2Error> {
    let map = parse_map(body)?;
    let subcommand = get_int(&map, 1).ok_or(Ctap2Error::MissingParameter)?;

    match subcommand {
        SUB_GET_METADATA => {
            let existing = store.count_discoverable()?;
            encode_response(Value::Map(vec![
                (
                    Value::Integer(1i64.into()),
                    Value::Integer((existing as i64).into()),
                ),
                (
                    Value::Integer(2i64.into()),
                    Value::Integer((100i64 - existing as i64).into()),
                ),
            ]))
        }
        SUB_RP_BEGIN => {
            state.rps = store.discoverable_rps()?;
            state.rp_index = 0;
            let total = state.rps.len();
            if total == 0 {
                return encode_response(Value::Map(vec![(
                    Value::Integer(5i64.into()),
                    Value::Integer(0i64.into()),
                )]));
            }
            let (rp_id, rp_hash) = state.rps[0].clone();
            state.rp_index = 1;
            encode_response(rp_entry(&rp_id, &rp_hash, total))
        }
        SUB_RP_NEXT => {
            if state.rp_index >= state.rps.len() {
                return encode_response(Value::Map(vec![]));
            }
            let total = state.rps.len();
            let (rp_id, rp_hash) = state.rps[state.rp_index].clone();
            state.rp_index += 1;
            encode_response(rp_entry(&rp_id, &rp_hash, total))
        }
        SUB_RK_BEGIN => {
            let rp_hash = match get(&map, 2) {
                Some(Value::Bytes(bytes)) => bytes.as_slice(),
                Some(Value::Map(rp)) => get_bytes(rp, 1).ok_or(Ctap2Error::MissingParameter)?,
                _ => return Err(Ctap2Error::MissingParameter),
            };
            let mut rks = store.get_by_rp_hash(rp_hash)?;
            rks.retain(|cred| cred.discoverable);
            state.rks = rks;
            state.rk_index = 0;
            let total = state.rks.len();
            if total == 0 {
                return encode_response(Value::Map(vec![(
                    Value::Integer(9i64.into()),
                    Value::Integer(0i64.into()),
                )]));
            }
            let entry = rk_entry(&state.rks[0], total);
            state.rk_index = 1;
            encode_response(entry)
        }
        SUB_RK_NEXT => {
            if state.rk_index >= state.rks.len() {
                return encode_response(Value::Map(vec![]));
            }
            let total = state.rks.len();
            let entry = rk_entry(&state.rks[state.rk_index], total);
            state.rk_index += 1;
            encode_response(entry)
        }
        _ => Err(Ctap2Error::InvalidCommand),
    }
}
