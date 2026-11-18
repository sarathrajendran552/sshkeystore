use ed25519_dalek::{Signer, SigningKey};
use rand::RngCore;

pub const ALG_EDDSA: i64 = -8;
pub const ALG_ED25519: i64 = -19;

pub fn is_supported_alg(alg: i64) -> bool {
    matches!(alg, ALG_EDDSA | ALG_ED25519)
}

pub struct CredentialKey {
    signing: SigningKey,
    public: [u8; 32],
}

impl CredentialKey {
    pub fn generate() -> Self {
        let mut seed = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut seed);
        Self::from_private(&seed).expect("32-byte seed is always valid")
    }

    pub fn from_private(seed: &[u8]) -> anyhow::Result<Self> {
        let seed: [u8; 32] = seed
            .try_into()
            .map_err(|_| anyhow::anyhow!("Ed25519 private key must be 32 bytes"))?;
        let signing = SigningKey::from_bytes(&seed);
        let public = signing.verifying_key().to_bytes();
        Ok(Self { signing, public })
    }

    pub fn public(&self) -> [u8; 32] {
        self.public
    }

    pub fn private(&self) -> [u8; 32] {
        self.signing.to_bytes()
    }

    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.signing.sign(message).to_bytes().to_vec()
    }
}

/// Encode an Ed25519 public key as a COSE_Key CBOR map.
pub fn encode_cose_key(alg: i64, public: &[u8; 32]) -> Vec<u8> {
    let map = ciborium::value::Value::Map(vec![
        (1i64.into(), 1i64.into()),               // kty: OKP
        (3i64.into(), alg.into()),                // alg: EdDSA / Ed25519
        ((-1i64).into(), 6i64.into()),            // crv: Ed25519
        ((-2i64).into(), public.to_vec().into()), // x
    ]);
    let mut buf = Vec::new();
    ciborium::into_writer(&map, &mut buf).expect("COSE key encoding is infallible");
    buf
}
