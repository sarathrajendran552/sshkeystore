use ciborium::value::Value;

/// Returns `0x00 || CBOR(authenticatorGetInfo response)`.
pub fn handle_get_info() -> Vec<u8> {
    let map = Value::Map(vec![
        (
            Value::Integer(1i64.into()),
            Value::Array(vec![Value::Text("FIDO_2_0".into())]),
        ),
        (
            Value::Integer(2i64.into()),
            Value::Array(vec![Value::Text("credProtect".into())]),
        ),
        (
            Value::Integer(3i64.into()),
            Value::Bytes(super::authenticator_data::AAGUID.to_vec()),
        ),
        (
            Value::Integer(4i64.into()),
            Value::Map(vec![
                (Value::Text("rk".into()), Value::Bool(true)),
                (Value::Text("up".into()), Value::Bool(true)),
                (Value::Text("uv".into()), Value::Bool(false)),
                (Value::Text("plat".into()), Value::Bool(false)),
                (Value::Text("credMgmt".into()), Value::Bool(true)),
                (Value::Text("clientPin".into()), Value::Bool(true)),
            ]),
        ),
        (Value::Integer(5i64.into()), Value::Integer(1200i64.into())),
        (
            Value::Integer(6i64.into()),
            Value::Array(vec![Value::Integer(1i64.into())]),
        ),
    ]);
    let mut buf = vec![0x00u8];
    ciborium::into_writer(&map, &mut buf).expect("GetInfo encoding is infallible");
    buf
}
