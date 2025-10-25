use bc_rand::{RandomNumberGenerator, SecureRandomNumberGenerator};

use crate::{Digest, Ed25519PublicKey, Error, Reference, ReferenceProvider, Result};

pub const ED25519_PRIVATE_KEY_SIZE: usize = bc_crypto::ED25519_PRIVATE_KEY_SIZE;

/// An Ed25519 private key for creating digital signatures.
///
/// Ed25519 is a public-key signature system based on the Edwards curve over the
/// finite field GF(2^255 - 19). It provides the following features:
///
/// - Fast single-signature verification
/// - Fast key generation
/// - High security level (equivalent to 128 bits of symmetric security)
/// - Collision resilience - hash function collisions don't break security
/// - Protection against side-channel attacks
/// - Small signatures (64 bytes) and small keys (32 bytes)
///
/// This implementation allows:
/// - Creating random Ed25519 private keys
/// - Deriving the corresponding public key
/// - Signing messages
/// - Converting between various formats
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Ed25519PrivateKey([u8; ED25519_PRIVATE_KEY_SIZE]);

impl Ed25519PrivateKey {
    /// Creates a new random Ed25519 private key.
    pub fn new() -> Self {
        let mut rng = SecureRandomNumberGenerator;
        Self::new_using(&mut rng)
    }

    /// Creates a new random Ed25519 private key using the given random number
    /// generator.
    pub fn new_using(rng: &mut impl RandomNumberGenerator) -> Self {
        let mut key = [0u8; ED25519_PRIVATE_KEY_SIZE];
        rng.fill_random_data(&mut key);
        Self::from_data(key)
    }

    /// Returns the Ed25519 private key as an array of bytes.
    pub fn data(&self) -> &[u8; ED25519_PRIVATE_KEY_SIZE] { &self.0 }

    /// Get the Ed25519 private key as a byte slice.
    pub fn as_bytes(&self) -> &[u8] { self.as_ref() }

    /// Restores an Ed25519 private key from an array of bytes.
    pub const fn from_data(data: [u8; ED25519_PRIVATE_KEY_SIZE]) -> Self {
        Self(data)
    }

    /// Restores an Ed25519 private key from a reference to an array of bytes.
    pub fn from_data_ref(data: impl AsRef<[u8]>) -> Result<Self> {
        let data = data.as_ref();
        if data.len() != ED25519_PRIVATE_KEY_SIZE {
            return Err(Error::invalid_size(
                "Ed25519 private key",
                ED25519_PRIVATE_KEY_SIZE,
                data.len(),
            ));
        }
        let mut arr = [0u8; ED25519_PRIVATE_KEY_SIZE];
        arr.copy_from_slice(data);
        Ok(Self::from_data(arr))
    }

    /// Derives a new `SigningPrivateKey` from the given key material.
    pub fn derive_from_key_material(key_material: impl AsRef<[u8]>) -> Self {
        Self::from_data(bc_crypto::derive_signing_private_key(key_material))
    }

    pub fn hex(&self) -> String { hex::encode(self.data()) }

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

    pub fn sign(
        &self,
        message: impl AsRef<[u8]>,
    ) -> [u8; bc_crypto::ED25519_SIGNATURE_SIZE] {
        bc_crypto::ed25519_sign(&self.0, message.as_ref())
    }
}

/// Implements conversion from a byte array to an Ed25519PrivateKey.
impl From<[u8; ED25519_PRIVATE_KEY_SIZE]> for Ed25519PrivateKey {
    fn from(data: [u8; ED25519_PRIVATE_KEY_SIZE]) -> Self {
        Self::from_data(data)
    }
}

/// Implements AsRef<[u8]> to allow Ed25519PrivateKey to be treated as a byte
/// slice.
impl AsRef<[u8]> for Ed25519PrivateKey {
    fn as_ref(&self) -> &[u8] { &self.0 }
}

/// Implements Debug to output the key with a type label.
impl std::fmt::Debug for Ed25519PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Ed25519PrivateKey({})", self.hex())
    }
}

/// Implements Default to create a new random Ed25519PrivateKey.
impl Default for Ed25519PrivateKey {
    fn default() -> Self { Self::new() }
}

/// Implements conversion from an Ed25519PrivateKey reference to a byte array
/// reference.
impl<'a> From<&'a Ed25519PrivateKey> for &'a [u8; ED25519_PRIVATE_KEY_SIZE] {
    fn from(value: &'a Ed25519PrivateKey) -> Self { &value.0 }
}

/// Implements conversion from an Ed25519PrivateKey reference to a byte slice.
impl<'a> From<&'a Ed25519PrivateKey> for &'a [u8] {
    fn from(value: &'a Ed25519PrivateKey) -> Self { &value.0 }
}

impl ReferenceProvider for Ed25519PrivateKey {
    fn reference(&self) -> Reference {
        Reference::from_digest(Digest::from_image(
            self.data()
        ))
    }
}

impl std::fmt::Display for Ed25519PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Ed25519PrivateKey({})", self.ref_hex_short())
    }
}
