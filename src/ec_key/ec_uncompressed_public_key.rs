use anyhow::{bail, Result};
use bc_ur::prelude::*;

use crate::{ECKeyBase, ECKey, tags, ECPublicKeyBase, ECPublicKey};

/// A compressed elliptic curve digital signature algorithm (ECDSA) uncompressed public key.
///
/// This is considered a "legacy" key type, and is not recommended for use.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ECUncompressedPublicKey([u8; Self::KEY_SIZE]);

impl ECUncompressedPublicKey {
    pub const fn from_data(data: [u8; Self::KEY_SIZE]) -> Self {
        Self(data)
    }
}

impl std::fmt::Display for ECUncompressedPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.hex())
    }
}

impl std::fmt::Debug for ECUncompressedPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ECUncompressedPublicKey({})", self.hex())
    }
}

impl ECKeyBase for ECUncompressedPublicKey {
    const KEY_SIZE: usize = bc_crypto::ECDSA_UNCOMPRESSED_PUBLIC_KEY_SIZE;

    fn from_data_ref(data: impl AsRef<[u8]>) -> Result<Self> where Self: Sized {
        let data = data.as_ref();
        if data.len() != Self::KEY_SIZE {
            bail!("Invalid ECDSA uncompressed public key size");
        }
        let mut key = [0u8; Self::KEY_SIZE];
        key.copy_from_slice(data);
        Ok(Self(key))
    }

    fn data(&self) -> &[u8] {
        &self.0
    }
}

impl ECKey for ECUncompressedPublicKey {
    fn public_key(&self) -> ECPublicKey {
        bc_crypto::ecdsa_compress_public_key(&self.0).into()
    }
}

impl ECPublicKeyBase for ECUncompressedPublicKey {
    fn uncompressed_public_key(&self) -> ECUncompressedPublicKey {
        self.clone()
    }
}

impl From<[u8; Self::KEY_SIZE]> for ECUncompressedPublicKey {
    fn from(value: [u8; Self::KEY_SIZE]) -> Self {
        Self::from_data(value)
    }
}

impl AsRef<[u8]> for ECUncompressedPublicKey {
    fn as_ref(&self) -> &[u8] {
        self.data()
    }
}

impl CBORTagged for ECUncompressedPublicKey {
    fn cbor_tags() -> Vec<Tag> {
        vec![tags::EC_KEY, tags::EC_KEY_V1]
    }
}

impl From<ECUncompressedPublicKey> for CBOR {
    fn from(value: ECUncompressedPublicKey) -> Self {
        value.tagged_cbor()
    }
}

impl CBORTaggedEncodable for ECUncompressedPublicKey {
    fn untagged_cbor(&self) -> CBOR {
        let mut m = Map::new();
        m.insert(3, CBOR::to_byte_string(self.0));
        m.into()
    }
}
