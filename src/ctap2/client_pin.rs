use super::types::Ctap2Error;
use aes::cipher::{block_padding::NoPadding, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use ciborium::value::Value;
use p256::ecdh::diffie_hellman;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{PublicKey, SecretKey};
use sha2::{Digest, Sha256};

const PIN_PROTOCOL: i64 = 1;
const SUB_GET_RETRIES: i64 = 0x01;
const SUB_GET_KEY_AGREEMENT: i64 = 0x02;
const SUB_GET_PIN_TOKEN: i64 = 0x05;

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

#[derive(Default)]
pub struct ClientPinState {
    agreement: Option<SecretKey>,
    token: Option<[u8; 32]>,
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

fn encode_cose_key(public: &PublicKey) -> Result<Value, Ctap2Error> {
    let point = public.to_encoded_point(false);
    let x = point
        .x()
        .ok_or_else(|| Ctap2Error::Cbor("missing EC x coordinate".into()))?;
    let y = point
        .y()
        .ok_or_else(|| Ctap2Error::Cbor("missing EC y coordinate".into()))?;
    Ok(Value::Map(vec![
        (Value::Integer(1i64.into()), Value::Integer(2i64.into())), // kty: EC2
        (Value::Integer(3i64.into()), Value::Integer((-25i64).into())), // alg: ECDH-ES+HKDF-256
        (Value::Integer((-1i64).into()), Value::Integer(1i64.into())), // crv: P-256
        (Value::Integer((-2i64).into()), Value::Bytes(x.to_vec())),
        (Value::Integer((-3i64).into()), Value::Bytes(y.to_vec())),
    ]))
}

fn decode_peer_key(value: &Value) -> Result<PublicKey, Ctap2Error> {
    let Value::Map(map) = value else {
        return Err(Ctap2Error::Cbor("key agreement is not a map".into()));
    };
    let x = get_bytes(map, -2).ok_or_else(|| Ctap2Error::Cbor("missing x".into()))?;
    let y = get_bytes(map, -3).ok_or_else(|| Ctap2Error::Cbor("missing y".into()))?;
    if x.len() != 32 || y.len() != 32 {
        return Err(Ctap2Error::Cbor("invalid P-256 coordinate length".into()));
    }
    let mut sec1 = Vec::with_capacity(65);
    sec1.push(0x04);
    sec1.extend_from_slice(x);
    sec1.extend_from_slice(y);
    PublicKey::from_sec1_bytes(&sec1).map_err(|e| Ctap2Error::Cbor(e.to_string()))
}

fn aes_encrypt(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>, Ctap2Error> {
    if !data.len().is_multiple_of(16) {
        return Err(Ctap2Error::Cbor("AES input is not block aligned".into()));
    }
    let mut buf = data.to_vec();
    let len = buf.len();
    Aes256CbcEnc::new_from_slices(key, &[0u8; 16])
        .map_err(|e| Ctap2Error::Cbor(e.to_string()))?
        .encrypt_padded_mut::<NoPadding>(&mut buf, len)
        .map_err(|e| Ctap2Error::Cbor(e.to_string()))?;
    Ok(buf)
}

fn aes_decrypt(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>, Ctap2Error> {
    if !data.len().is_multiple_of(16) {
        return Err(Ctap2Error::Cbor("AES input is not block aligned".into()));
    }
    let mut buf = data.to_vec();
    Aes256CbcDec::new_from_slices(key, &[0u8; 16])
        .map_err(|e| Ctap2Error::Cbor(e.to_string()))?
        .decrypt_padded_mut::<NoPadding>(&mut buf)
        .map_err(|e| Ctap2Error::Cbor(e.to_string()))?;
    Ok(buf)
}

fn shared_secret(secret: &SecretKey, peer: &PublicKey) -> [u8; 32] {
    let shared = diffie_hellman(secret.to_nonzero_scalar(), peer.as_affine());
    Sha256::digest(shared.raw_secret_bytes()).into()
}

pub fn handle_client_pin(body: &[u8], state: &mut ClientPinState) -> Result<Vec<u8>, Ctap2Error> {
    let map = parse_map(body)?;
    let protocol = get_int(&map, 1).ok_or(Ctap2Error::MissingParameter)?;
    let subcommand = get_int(&map, 2).ok_or(Ctap2Error::MissingParameter)?;

    if protocol != PIN_PROTOCOL {
        return Err(Ctap2Error::PinAuthInvalid);
    }

    match subcommand {
        SUB_GET_RETRIES => encode_response(Value::Map(vec![(
            Value::Integer(3i64.into()),
            Value::Integer(8i64.into()),
        )])),
        SUB_GET_KEY_AGREEMENT => {
            let secret = SecretKey::random(&mut rand::thread_rng());
            let public = secret.public_key();
            let cose = encode_cose_key(&public)?;
            state.agreement = Some(secret);
            encode_response(Value::Map(vec![(Value::Integer(1i64.into()), cose)]))
        }
        SUB_GET_PIN_TOKEN => {
            let secret = state.agreement.as_ref().ok_or(Ctap2Error::PinAuthInvalid)?;
            let peer = get(&map, 3).ok_or(Ctap2Error::MissingParameter)?;
            let peer = decode_peer_key(peer)?;
            let shared = shared_secret(secret, &peer);

            if let Some(encrypted_pin_hash) = get_bytes(&map, 6) {
                let pin_hash = aes_decrypt(&shared, encrypted_pin_hash)
                    .map_err(|_| Ctap2Error::PinAuthInvalid)?;
                if pin_hash.len() < 16 {
                    return Err(Ctap2Error::PinAuthInvalid);
                }
            }

            let mut token = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut token);
            let encrypted_token = aes_encrypt(&shared, &token)?;
            state.token = Some(token);
            encode_response(Value::Map(vec![(
                Value::Integer(2i64.into()),
                Value::Bytes(encrypted_token),
            )]))
        }
        _ => Err(Ctap2Error::InvalidCommand),
    }
}
