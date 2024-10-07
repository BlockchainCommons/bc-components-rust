use anyhow::{bail, Result};
use bc_rand::{RandomNumberGenerator, SecureRandomNumberGenerator};

use crate::Ed25519PublicKey;

pub const ED25519_PRIVATE_KEY_SIZE: usize = bc_crypto::ED25519_PRIVATE_KEY_SIZE;

/// An Ed25519 private key.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Ed25519PrivateKey([u8; ED25519_PRIVATE_KEY_SIZE]);

impl Ed25519PrivateKey {
    /// Creates a new random Ed25519 private key.
    pub fn new() -> Self {
        let mut rng = SecureRandomNumberGenerator;
        Self::new_using(&mut rng)
    }

    /// Creates a new random Ed25519 private key using the given random number generator.
    pub fn new_using(rng: &mut impl RandomNumberGenerator) -> Self {
        let mut key = [0u8; ED25519_PRIVATE_KEY_SIZE];
        rng.fill_random_data(&mut key);
        Self::from_data(key)
    }

    /// Returns the Ed25519 private key as an array of bytes.
    pub fn data(&self) -> &[u8; ED25519_PRIVATE_KEY_SIZE] {
        &self.0
    }

    /// Restores an Ed25519 private key from an array of bytes.
    pub const fn from_data(data: [u8; ED25519_PRIVATE_KEY_SIZE]) -> Self {
        Self(data)
    }

    /// Restores an Ed25519 private key from a reference to an array of bytes.
    pub fn from_data_ref(data: impl AsRef<[u8]>) -> Result<Self> {
        let data = data.as_ref();
        if data.len() != ED25519_PRIVATE_KEY_SIZE {
            bail!("Invalid Ed25519 private key size");
        }
        let mut arr = [0u8; ED25519_PRIVATE_KEY_SIZE];
        arr.copy_from_slice(data);
        Ok(Self::from_data(arr))
    }

    /// Derives a new `SigningPrivateKey` from the given key material.
    pub fn derive_from_key_material(key_material: impl AsRef<[u8]>) -> Self {
        Self::from_data(bc_crypto::x25519_derive_signing_private_key(key_material))
    }

    pub fn hex(&self) -> String {
        hex::encode(self.data())
    }

    pub fn from_hex(hex: impl AsRef<str>) -> Result<Self> {
        let data = hex::decode(hex.as_ref())?;
        Self::from_data_ref(data)
    }
}

impl Ed25519PrivateKey {
    /// Derives the public key from this Ed25519 private key.
    pub fn public_key(&self) -> Ed25519PublicKey {
        bc_crypto::ed25519_public_key_from_private_key(self.into()).into()
    }
}

impl From<[u8; ED25519_PRIVATE_KEY_SIZE]> for Ed25519PrivateKey {
    fn from(data: [u8; ED25519_PRIVATE_KEY_SIZE]) -> Self {
        Self::from_data(data)
    }
}

impl AsRef<[u8]> for Ed25519PrivateKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Display for Ed25519PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.hex())
    }
}

impl std::fmt::Debug for Ed25519PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Ed25519PrivateKey({})", self.hex())
    }
}

impl Default for Ed25519PrivateKey {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> From<&'a Ed25519PrivateKey> for &'a [u8; ED25519_PRIVATE_KEY_SIZE] {
    fn from(value: &'a Ed25519PrivateKey) -> Self {
        &value.0
    }
}

impl<'a> From<&'a Ed25519PrivateKey> for &'a [u8] {
    fn from(value: &'a Ed25519PrivateKey) -> Self {
        &value.0
    }
}
