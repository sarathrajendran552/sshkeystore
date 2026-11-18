use ciborium::value::Value;

pub const CMD_MAKE_CREDENTIAL: u8 = 0x01;
pub const CMD_GET_ASSERTION: u8 = 0x02;
pub const CMD_GET_INFO: u8 = 0x04;

#[derive(Debug, thiserror::Error)]
pub enum Ctap2Error {
    #[error("missing parameter")]
    MissingParameter,
    #[error("unsupported algorithm")]
    UnsupportedAlgorithm,
    #[error("credential excluded")]
    CredentialExcluded,
    #[error("operation denied")]
    OperationDenied,
    #[error("user action timeout")]
    UserActionTimeout,
    #[error("keepalive cancel")]
    KeepaliveCancel,
    #[error("no credentials")]
    NoCredentials,
    #[error("invalid length")]
    InvalidLength,
    #[error("cbor: {0}")]
    Cbor(String),
    #[error("store: {0}")]
    Store(#[from] crate::store::StoreError),
    #[error("key: {0}")]
    Key(String),
}

impl Ctap2Error {
    pub fn status_byte(&self) -> u8 {
        match self {
            Self::MissingParameter => 0x14,
            Self::UnsupportedAlgorithm => 0x26,
            Self::CredentialExcluded => 0x19,
            Self::OperationDenied => 0x27,
            Self::UserActionTimeout => 0x2A,
            Self::KeepaliveCancel => 0x2D,
            Self::NoCredentials => 0x2E,
            Self::InvalidLength => 0x03,
            Self::Cbor(_) => 0x11,
            Self::Store(_) | Self::Key(_) => 0x7F,
        }
    }
}

#[derive(Debug)]
pub struct MakeCredentialRequest {
    pub client_data_hash: Vec<u8>,
    pub rp_id: String,
    pub rp_name: Option<String>,
    pub user_id: Vec<u8>,
    pub user_name: Option<String>,
    pub user_display: Option<String>,
    pub resident_key: bool,
    pub exclude_list: Vec<Vec<u8>>,
    pub selected_alg: Option<i64>,
}

#[derive(Debug)]
pub struct GetAssertionRequest {
    pub rp_id: String,
    pub client_data_hash: Vec<u8>,
    pub allow_list: Vec<Vec<u8>>,
}

fn parse_cbor(data: &[u8]) -> Result<Vec<(Value, Value)>, Ctap2Error> {
    let value: Value = ciborium::from_reader(data).map_err(|e| Ctap2Error::Cbor(e.to_string()))?;
    match value {
        Value::Map(map) => Ok(map),
        _ => Err(Ctap2Error::Cbor("expected map".into())),
    }
}

fn get(map: &[(Value, Value)], key: i64) -> Option<&Value> {
    let target = Value::Integer(key.into());
    map.iter().find(|(k, _)| k == &target).map(|(_, v)| v)
}

fn get_str<'a>(map: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    map.iter()
        .find(|(k, _)| matches!(k, Value::Text(s) if s == key))
        .map(|(_, v)| v)
}

fn as_bytes(value: &Value) -> Option<&[u8]> {
    match value {
        Value::Bytes(bytes) => Some(bytes),
        _ => None,
    }
}

fn as_text(value: &Value) -> Option<&str> {
    match value {
        Value::Text(text) => Some(text),
        _ => None,
    }
}

fn as_bool(value: &Value) -> Option<bool> {
    match value {
        Value::Bool(value) => Some(*value),
        _ => None,
    }
}

fn as_map(value: &Value) -> Option<&[(Value, Value)]> {
    match value {
        Value::Map(map) => Some(map),
        _ => None,
    }
}

fn as_array(value: &Value) -> Option<&[Value]> {
    match value {
        Value::Array(array) => Some(array),
        _ => None,
    }
}

impl TryFrom<&[u8]> for MakeCredentialRequest {
    type Error = Ctap2Error;

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        let map = parse_cbor(data)?;

        let client_data_hash = as_bytes(get(&map, 1).ok_or(Ctap2Error::MissingParameter)?)
            .ok_or(Ctap2Error::MissingParameter)?
            .to_vec();
        if client_data_hash.len() != 32 {
            return Err(Ctap2Error::InvalidLength);
        }

        let rp_map = as_map(get(&map, 2).ok_or(Ctap2Error::MissingParameter)?)
            .ok_or(Ctap2Error::MissingParameter)?;
        let rp_id = as_text(get_str(rp_map, "id").ok_or(Ctap2Error::MissingParameter)?)
            .ok_or(Ctap2Error::MissingParameter)?
            .to_string();
        let rp_name = get_str(rp_map, "name")
            .and_then(as_text)
            .map(str::to_string);

        let user_map = as_map(get(&map, 3).ok_or(Ctap2Error::MissingParameter)?)
            .ok_or(Ctap2Error::MissingParameter)?;
        let user_id = as_bytes(get_str(user_map, "id").ok_or(Ctap2Error::MissingParameter)?)
            .ok_or(Ctap2Error::MissingParameter)?
            .to_vec();
        let user_name = get_str(user_map, "name")
            .and_then(as_text)
            .map(str::to_string);
        let user_display = get_str(user_map, "displayName")
            .and_then(as_text)
            .map(str::to_string);

        // Prefer EdDSA (-8), which is what OpenSSH requests for ed25519-sk.
        // Accept -19 as an alias as well.
        let selected_alg = get(&map, 4).and_then(as_array).and_then(|params| {
            let mut found = None;
            for param in params {
                let Some(entry) = as_map(param) else {
                    continue;
                };
                let Some(alg) = get_str(entry, "alg").and_then(|value| match value {
                    Value::Integer(alg) => i64::try_from(*alg).ok(),
                    _ => None,
                }) else {
                    continue;
                };
                if alg == crate::keys::ALG_EDDSA {
                    return Some(alg);
                }
                if crate::keys::is_supported_alg(alg) && found.is_none() {
                    found = Some(alg);
                }
            }
            found
        });

        let exclude_list = get(&map, 5)
            .and_then(as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(|item| {
                        let entry = as_map(item)?;
                        get_str(entry, "id")
                            .and_then(as_bytes)
                            .map(|id| id.to_vec())
                    })
                    .collect()
            })
            .unwrap_or_default();

        let resident_key = get(&map, 7)
            .and_then(as_map)
            .and_then(|options| get_str(options, "rk"))
            .and_then(as_bool)
            .unwrap_or(false);

        Ok(Self {
            client_data_hash,
            rp_id,
            rp_name,
            user_id,
            user_name,
            user_display,
            resident_key,
            exclude_list,
            selected_alg,
        })
    }
}

impl TryFrom<&[u8]> for GetAssertionRequest {
    type Error = Ctap2Error;

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        let map = parse_cbor(data)?;

        let rp_id = as_text(get(&map, 1).ok_or(Ctap2Error::MissingParameter)?)
            .ok_or(Ctap2Error::MissingParameter)?
            .to_string();

        let client_data_hash = as_bytes(get(&map, 2).ok_or(Ctap2Error::MissingParameter)?)
            .ok_or(Ctap2Error::MissingParameter)?
            .to_vec();
        if client_data_hash.len() != 32 {
            return Err(Ctap2Error::InvalidLength);
        }

        let allow_list = get(&map, 3)
            .and_then(as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(|item| {
                        let entry = as_map(item)?;
                        get_str(entry, "id")
                            .and_then(as_bytes)
                            .map(|id| id.to_vec())
                    })
                    .collect()
            })
            .unwrap_or_default();

        Ok(Self {
            rp_id,
            client_data_hash,
            allow_list,
        })
    }
}
