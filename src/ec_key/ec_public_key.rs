use anyhow::bail;
use bc_crypto::ECDSA_SIGNATURE_SIZE;
use bc_ur::prelude::*;

use crate::{ECKeyBase, ECKey, ECPublicKeyBase, tags};

/// A compressed elliptic curve digital signature algorithm (ECDSA) compressed public key.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ECPublicKey([u8; Self::KEY_SIZE]);

impl ECPublicKey {
    /// Restores an ECDSA public key from a vector of bytes.
    pub const fn from_data(data: [u8; Self::KEY_SIZE]) -> Self {
        Self(data)
    }
}

impl ECPublicKey {
    /// Verifies the given ECDSA signature for the given message using this ECDSA public key.
    pub fn verify<D>(&self, signature: &[u8; ECDSA_SIGNATURE_SIZE], message: D) -> bool
    where
        D: AsRef<[u8]>,
    {
        bc_crypto::ecdsa_verify(&self.0, signature, message)
    }
}

impl std::fmt::Display for ECPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.hex())
    }
}

impl std::fmt::Debug for ECPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ECPublicKey({})", self.hex())
    }
}

impl ECKeyBase for ECPublicKey {
    const KEY_SIZE: usize = bc_crypto::ECDSA_PUBLIC_KEY_SIZE;

    fn from_data_ref(data: impl AsRef<[u8]>) -> anyhow::Result<Self> where Self: Sized {
        let data = data.as_ref();
        if data.len() != Self::KEY_SIZE {
            bail!("Invalid ECDSA public key size");
        }
        let mut key = [0u8; Self::KEY_SIZE];
        key.copy_from_slice(data);
        Ok(Self(key))
    }

    fn data(&self) -> &[u8] {
        self.into()
    }
}

impl ECKey for ECPublicKey {
    fn public_key(&self) -> ECPublicKey {
        self.clone()
    }
}

impl ECPublicKeyBase for ECPublicKey {
    fn uncompressed_public_key(&self) -> crate::ECUncompressedPublicKey {
        bc_crypto::ecdsa_decompress_public_key(&self.0).into()
    }
}

impl<'a> From<&'a ECPublicKey> for &'a [u8; ECPublicKey::KEY_SIZE] {
    fn from(value: &'a ECPublicKey) -> Self {
        &value.0
    }
}

impl From<[u8; Self::KEY_SIZE]> for ECPublicKey {
    fn from(value: [u8; Self::KEY_SIZE]) -> Self {
        Self::from_data(value)
    }
}

impl<'a> From<&'a ECPublicKey> for &'a [u8] {
    fn from(value: &'a ECPublicKey) -> Self {
        &value.0
    }
}

impl CBORTagged for ECPublicKey {
    const CBOR_TAG: Tag = tags::EC_KEY_V1;
}

impl CBOREncodable for ECPublicKey {
    fn cbor(&self) -> CBOR {
        self.tagged_cbor()
    }
}

impl From<ECPublicKey> for CBOR {
    fn from(value: ECPublicKey) -> Self {
        value.cbor()
    }
}

impl CBORTaggedEncodable for ECPublicKey {
    fn untagged_cbor(&self) -> CBOR {
        let mut m = Map::new();
        m.insert(3, CBOR::byte_string(self.0));
        m.cbor()
    }
}

impl UREncodable for ECPublicKey { }
