use anyhow::{bail, Result};
use bc_crypto::ECDSA_SIGNATURE_SIZE;
use bc_ur::prelude::*;

use crate::{tags, ECKey, ECKeyBase, ECPublicKeyBase, Signature, Verifier};

pub const ECDSA_PUBLIC_KEY_SIZE: usize = bc_crypto::ECDSA_PUBLIC_KEY_SIZE;

/// A compressed elliptic curve digital signature algorithm (ECDSA) compressed public key.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ECPublicKey([u8; ECDSA_PUBLIC_KEY_SIZE]);

impl ECPublicKey {
    /// Restores an ECDSA public key from an array of bytes.
    pub const fn from_data(data: [u8; ECDSA_PUBLIC_KEY_SIZE]) -> Self {
        Self(data)
    }

    /// Returns the ECDSA public key as an array of bytes.
    pub fn data(&self) -> &[u8; ECDSA_PUBLIC_KEY_SIZE] {
        &self.0
    }
}

impl ECPublicKey {
    /// Verifies the given ECDSA signature for the given message using this ECDSA public key.
    pub fn verify(&self, signature: &[u8; ECDSA_SIGNATURE_SIZE], message: impl AsRef<[u8]>) -> bool {
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

    fn from_data_ref(data: impl AsRef<[u8]>) -> Result<Self> where Self: Sized {
        let data = data.as_ref();
        if data.len() != ECDSA_PUBLIC_KEY_SIZE {
            bail!("Invalid ECDSA public key size");
        }
        let mut key = [0u8; ECDSA_PUBLIC_KEY_SIZE];
        key.copy_from_slice(data);
        Ok(Self(key))
    }

    fn data(&self) -> &[u8] {
        self.into()
    }
}

impl Verifier for ECPublicKey {
    fn verify(&self, signature: &Signature, message: &dyn AsRef<[u8]>) -> bool {
        match signature {
            Signature::ECDSA(sig) => self.verify(sig, message),
            _ => false,
        }
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

impl From<[u8; ECDSA_PUBLIC_KEY_SIZE]> for ECPublicKey {
    fn from(value: [u8; ECDSA_PUBLIC_KEY_SIZE]) -> Self {
        Self::from_data(value)
    }
}

impl<'a> From<&'a ECPublicKey> for &'a [u8] {
    fn from(value: &'a ECPublicKey) -> Self {
        &value.0
    }
}

impl CBORTagged for ECPublicKey {
    fn cbor_tags() -> Vec<Tag> {
        tags_for_values(&[tags::TAG_EC_KEY, tags::TAG_EC_KEY_V1])
    }
}

impl From<ECPublicKey> for CBOR {
    fn from(value: ECPublicKey) -> Self {
        value.tagged_cbor()
    }
}

impl CBORTaggedEncodable for ECPublicKey {
    fn untagged_cbor(&self) -> CBOR {
        let mut m = Map::new();
        m.insert(3, CBOR::to_byte_string(self.0));
        m.into()
    }
}
