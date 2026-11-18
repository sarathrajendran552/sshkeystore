use super::types::Ctap2Error;
use ciborium::value::Value;

/// Build a "packed" self-attestation object.
///
/// The signature is made by the newly created credential key over
/// `authData || clientDataHash`, which is what libfido2's
/// `fido_cred_verify_self` verifies for OpenSSH ed25519-sk enrollment.
pub fn build_attestation_object(
    auth_data: &[u8],
    sig: &[u8],
    alg: i64,
) -> Result<Vec<u8>, Ctap2Error> {
    let map = Value::Map(vec![
        (Value::Integer(1i64.into()), Value::Text("packed".into())),
        (
            Value::Integer(2i64.into()),
            Value::Bytes(auth_data.to_vec()),
        ),
        (
            Value::Integer(3i64.into()),
            Value::Map(vec![
                (Value::Text("alg".into()), Value::Integer(alg.into())),
                (Value::Text("sig".into()), Value::Bytes(sig.to_vec())),
            ]),
        ),
    ]);
    let mut buf = Vec::new();
    ciborium::into_writer(&map, &mut buf).map_err(|e| Ctap2Error::Cbor(e.to_string()))?;
    Ok(buf)
}
