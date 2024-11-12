use anyhow::{bail, Result};
use bc_rand::{RandomNumberGenerator, SecureRandomNumberGenerator};
use bc_ur::prelude::*;

use crate::{ECKeyBase, ECKey, tags, SchnorrPublicKey, ECPublicKey};

pub const ECDSA_PRIVATE_KEY_SIZE: usize = bc_crypto::ECDSA_PRIVATE_KEY_SIZE;

/// An elliptic curve digital signature algorithm (ECDSA) private key.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ECPrivateKey([u8; ECDSA_PRIVATE_KEY_SIZE]);

impl ECPrivateKey {
    /// Creates a new random ECDSA private key.
    pub fn new() -> Self {
        let mut rng = SecureRandomNumberGenerator;
        Self::new_using(&mut rng)
    }

    /// Creates a new random ECDSA private key using the given random number generator.
    pub fn new_using(rng: &mut impl RandomNumberGenerator) -> Self {
        let mut key = [0u8; ECDSA_PRIVATE_KEY_SIZE];
        rng.fill_random_data(&mut key);
        Self::from_data(key)
    }

    /// Returns the ECDSA private key as an array of bytes.
    pub fn data(&self) -> &[u8; ECDSA_PRIVATE_KEY_SIZE] {
        &self.0
    }

    /// Restores an ECDSA private key from an array of bytes.
    pub const fn from_data(data: [u8; ECDSA_PRIVATE_KEY_SIZE]) -> Self {
        Self(data)
    }

    /// Restores an ECDSA private key from a reference to an array of bytes.
    pub fn from_data_ref(data: impl AsRef<[u8]>) -> Result<Self> {
        let data = data.as_ref();
        if data.len() != ECDSA_PRIVATE_KEY_SIZE {
            bail!("Invalid EC private key size");
        }
        let mut arr = [0u8; ECDSA_PRIVATE_KEY_SIZE];
        arr.copy_from_slice(data);
        Ok(Self::from_data(arr))
    }

    /// Derives a new `SigningPrivateKey` from the given key material.
    pub fn derive_from_key_material(key_material: impl AsRef<[u8]>) -> Self {
        Self::from_data(bc_crypto::x25519_derive_signing_private_key(key_material))
    }
}

impl ECPrivateKey {
    /// Derives the Schnorr public key from this ECDSA private key.
    pub fn schnorr_public_key(&self) -> SchnorrPublicKey {
        bc_crypto::schnorr_public_key_from_private_key(self.into()).into()
    }

    /// ECDSA signs the given message using this ECDSA private key.
    pub fn ecdsa_sign(&self, message: impl AsRef<[u8]>) -> [u8; bc_crypto::ECDSA_SIGNATURE_SIZE] {
        bc_crypto::ecdsa_sign(&self.0, message.as_ref())
    }

    /// Schnorr signs the given message using this ECDSA private key, the given
    /// tag, and the given random number generator.
    pub fn schnorr_sign_using(
        &self,
        message: impl AsRef<[u8]>,
        rng: &mut dyn RandomNumberGenerator,
    ) -> [u8; bc_crypto::SCHNORR_SIGNATURE_SIZE] {
        bc_crypto::schnorr_sign_using(&self.0, message, rng)
    }

    /// Schnorr signs the given message using this ECDSA private key and the given tag.
    pub fn schnorr_sign(
        &self,
        message: impl AsRef<[u8]>,
    ) -> [u8; bc_crypto::SCHNORR_SIGNATURE_SIZE] {
        let mut rng = SecureRandomNumberGenerator;
        self.schnorr_sign_using(message, &mut rng)
    }
}

impl From<[u8; ECDSA_PRIVATE_KEY_SIZE]> for ECPrivateKey {
    fn from(data: [u8; ECDSA_PRIVATE_KEY_SIZE]) -> Self {
        Self::from_data(data)
    }
}

impl AsRef<[u8]> for ECPrivateKey {
    fn as_ref(&self) -> &[u8] {
        self.data()
    }
}

impl std::fmt::Display for ECPrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.hex())
    }
}

impl std::fmt::Debug for ECPrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ECPrivateKey({})", self.hex())
    }
}

impl Default for ECPrivateKey {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> From<&'a ECPrivateKey> for &'a [u8; ECDSA_PRIVATE_KEY_SIZE] {
    fn from(value: &'a ECPrivateKey) -> Self {
        &value.0
    }
}

impl<'a> From<&'a ECPrivateKey> for &'a [u8] {
    fn from(value: &'a ECPrivateKey) -> Self {
        value.as_ref()
    }
}

impl ECKeyBase for ECPrivateKey {
    const KEY_SIZE: usize = bc_crypto::ECDSA_PRIVATE_KEY_SIZE;

    fn from_data_ref(data: impl AsRef<[u8]>) -> Result<Self> where Self: Sized {
        let data = data.as_ref();
        if data.len() != ECDSA_PRIVATE_KEY_SIZE {
            bail!("Invalid EC private key size");
        }
        let mut key = [0u8; ECDSA_PRIVATE_KEY_SIZE];
        key.copy_from_slice(data);
        Ok(Self(key))
    }

    fn data(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl ECKey for ECPrivateKey {
    fn public_key(&self) -> ECPublicKey {
        bc_crypto::ecdsa_public_key_from_private_key(&self.0).into()
    }
}

impl CBORTagged for ECPrivateKey {
    fn cbor_tags() -> Vec<Tag> {
        tags_for_values(&[tags::TAG_EC_KEY, tags::TAG_EC_KEY_V1])
    }
}

impl From<ECPrivateKey> for CBOR {
    fn from(value: ECPrivateKey) -> Self {
        value.tagged_cbor()
    }
}

impl CBORTaggedEncodable for ECPrivateKey {
    fn untagged_cbor(&self) -> CBOR {
        let mut m = Map::new();
        m.insert(2, true);
        m.insert(3, CBOR::to_byte_string(self.0));
        m.into()
    }
}
