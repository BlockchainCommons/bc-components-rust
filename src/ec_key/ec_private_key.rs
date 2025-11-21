use bc_rand::{RandomNumberGenerator, SecureRandomNumberGenerator};
use bc_ur::prelude::*;

use crate::{
    Digest, ECKey, ECKeyBase, ECPublicKey, Error, Reference, ReferenceProvider,
    Result, SchnorrPublicKey, tags,
};

/// The size of an ECDSA private key in bytes (32 bytes).
pub const ECDSA_PRIVATE_KEY_SIZE: usize = bc_crypto::ECDSA_PRIVATE_KEY_SIZE;

/// A private key for elliptic curve digital signature algorithms.
///
/// An `ECPrivateKey` is a 32-byte secret value that can be used to:
///
/// - Generate its corresponding public key
/// - Sign messages using the ECDSA signature scheme
/// - Sign messages using the Schnorr signature scheme (BIP-340)
///
/// These keys use the secp256k1 curve, which is the same curve used in Bitcoin
/// and other cryptocurrencies. The secp256k1 curve is defined by the Standards
/// for Efficient Cryptography Group (SECG).
///
/// # Security
///
/// Private keys should be kept secret and never exposed. They represent
/// proof of ownership and control over any associated assets or identities.
///
/// # Examples
///
/// Creating a new random private key:
///
/// ```
/// use bc_components::ECPrivateKey;
///
/// // Generate a random private key
/// let private_key = ECPrivateKey::new();
/// ```
///
/// Signing a message with ECDSA:
///
/// ```
/// use bc_components::ECPrivateKey;
///
/// // Generate a random private key
/// let private_key = ECPrivateKey::new();
///
/// // Sign a message
/// let message = b"Hello, world!";
/// let signature = private_key.ecdsa_sign(message);
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ECPrivateKey([u8; ECDSA_PRIVATE_KEY_SIZE]);

impl ECPrivateKey {
    /// Creates a new random ECDSA private key.
    ///
    /// Uses a secure random number generator to generate the key.
    pub fn new() -> Self {
        let mut rng = SecureRandomNumberGenerator;
        Self::new_using(&mut rng)
    }

    /// Creates a new random ECDSA private key using the given random number
    /// generator.
    ///
    /// This allows for deterministic key generation when using a seeded RNG.
    pub fn new_using(rng: &mut impl RandomNumberGenerator) -> Self {
        let mut key = [0u8; ECDSA_PRIVATE_KEY_SIZE];
        rng.fill_random_data(&mut key);
        Self::from_data(key)
    }

    /// Returns the ECDSA private key as an array of bytes.
    pub fn data(&self) -> &[u8; ECDSA_PRIVATE_KEY_SIZE] { &self.0 }

    /// Get the ECDSA private key as a byte slice.
    pub fn as_bytes(&self) -> &[u8] { self.as_ref() }

    /// Restores an ECDSA private key from an array of bytes.
    ///
    /// This method performs no validation on the input data.
    pub const fn from_data(data: [u8; ECDSA_PRIVATE_KEY_SIZE]) -> Self {
        Self(data)
    }

    /// Restores an ECDSA private key from a reference to an array of bytes.
    ///
    /// Returns an error if the data is not exactly 32 bytes.
    pub fn from_data_ref(data: impl AsRef<[u8]>) -> Result<Self> {
        let data = data.as_ref();
        if data.len() != ECDSA_PRIVATE_KEY_SIZE {
            return Err(Error::invalid_size(
                "EC private key",
                ECDSA_PRIVATE_KEY_SIZE,
                data.len(),
            ));
        }
        let mut arr = [0u8; ECDSA_PRIVATE_KEY_SIZE];
        arr.copy_from_slice(data);
        Ok(Self::from_data(arr))
    }

    /// Derives a new private key from the given key material.
    ///
    /// This method uses the provided key material to deterministically
    /// generate a valid private key for the secp256k1 curve.
    pub fn derive_from_key_material(key_material: impl AsRef<[u8]>) -> Self {
        Self::from_data(bc_crypto::derive_signing_private_key(key_material))
    }
}

impl ECPrivateKey {
    /// Derives the Schnorr public key from this ECDSA private key.
    ///
    /// Schnorr public keys are used with the BIP-340 Schnorr signature scheme.
    /// Unlike ECDSA public keys, Schnorr public keys are 32 bytes ("x-only")
    /// rather than 33 bytes.
    pub fn schnorr_public_key(&self) -> SchnorrPublicKey {
        bc_crypto::schnorr_public_key_from_private_key(self.into()).into()
    }

    /// Signs a message using the ECDSA signature scheme.
    ///
    /// Returns a 70-72 byte signature in DER format.
    pub fn ecdsa_sign(
        &self,
        message: impl AsRef<[u8]>,
    ) -> [u8; bc_crypto::ECDSA_SIGNATURE_SIZE] {
        bc_crypto::ecdsa_sign(&self.0, message.as_ref())
    }

    /// Signs a message using the Schnorr signature scheme with a custom random
    /// number generator.
    ///
    /// This method implements the BIP-340 Schnorr signature scheme, which
    /// provides several advantages over ECDSA including linearity (allowing
    /// for signature aggregation) and non-malleability.
    ///
    /// Returns a 64-byte signature.
    pub fn schnorr_sign_using(
        &self,
        message: impl AsRef<[u8]>,
        rng: &mut dyn RandomNumberGenerator,
    ) -> [u8; bc_crypto::SCHNORR_SIGNATURE_SIZE] {
        bc_crypto::schnorr_sign_using(&self.0, message, rng)
    }

    /// Signs a message using the Schnorr signature scheme.
    ///
    /// Uses a secure random number generator for nonce generation.
    ///
    /// Returns a 64-byte signature.
    pub fn schnorr_sign(
        &self,
        message: impl AsRef<[u8]>,
    ) -> [u8; bc_crypto::SCHNORR_SIGNATURE_SIZE] {
        let mut rng = SecureRandomNumberGenerator;
        self.schnorr_sign_using(message, &mut rng)
    }
}

/// Converts a fixed-size byte array to an `ECPrivateKey`.
impl From<[u8; ECDSA_PRIVATE_KEY_SIZE]> for ECPrivateKey {
    /// Converts a 32-byte array into an EC private key.
    fn from(data: [u8; ECDSA_PRIVATE_KEY_SIZE]) -> Self {
        Self::from_data(data)
    }
}

/// Provides a reference to the key data as a byte slice.
impl AsRef<[u8]> for ECPrivateKey {
    /// Returns a reference to the key as a byte slice.
    fn as_ref(&self) -> &[u8] { self.0.as_ref() }
}

/// Formats the key for debugging, showing type name and hexadecimal value.
impl std::fmt::Debug for ECPrivateKey {
    /// Displays the key with type information and hexadecimal value.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ECPrivateKey({})", self.hex())
    }
}

/// Implements the `Default` trait, creating a random key.
impl Default for ECPrivateKey {
    /// Creates a new random key as the default value.
    fn default() -> Self { Self::new() }
}

/// Converts a reference to an `ECPrivateKey` to a reference to a fixed-size
/// byte array.
impl<'a> From<&'a ECPrivateKey> for &'a [u8; ECDSA_PRIVATE_KEY_SIZE] {
    /// Returns a reference to the underlying byte array.
    fn from(value: &'a ECPrivateKey) -> Self { &value.0 }
}

/// Converts a reference to an `ECPrivateKey` to a reference to a byte slice.
impl<'a> From<&'a ECPrivateKey> for &'a [u8] {
    /// Returns a reference to the key as a byte slice.
    fn from(value: &'a ECPrivateKey) -> Self { value.as_ref() }
}

/// Implements the `ECKeyBase` trait methods.
impl ECKeyBase for ECPrivateKey {
    /// The size of an EC private key (32 bytes).
    const KEY_SIZE: usize = bc_crypto::ECDSA_PRIVATE_KEY_SIZE;

    /// Creates a key from a byte slice, with validation.
    fn from_data_ref(data: impl AsRef<[u8]>) -> Result<Self>
    where
        Self: Sized,
    {
        let data = data.as_ref();
        if data.len() != ECDSA_PRIVATE_KEY_SIZE {
            return Err(Error::invalid_size(
                "EC private key",
                ECDSA_PRIVATE_KEY_SIZE,
                data.len(),
            ));
        }
        let mut key = [0u8; ECDSA_PRIVATE_KEY_SIZE];
        key.copy_from_slice(data);
        Ok(Self(key))
    }

    /// Returns the key as a byte slice.
    fn data(&self) -> &[u8] { self.0.as_ref() }
}

/// Implements the `ECKey` trait for deriving public keys.
impl ECKey for ECPrivateKey {
    /// Derives the corresponding ECDSA compressed public key.
    fn public_key(&self) -> ECPublicKey {
        bc_crypto::ecdsa_public_key_from_private_key(&self.0).into()
    }
}

/// Defines CBOR tags for EC keys.
impl CBORTagged for ECPrivateKey {
    /// Returns the CBOR tags for EC keys.
    fn cbor_tags() -> Vec<Tag> {
        tags_for_values(&[tags::TAG_EC_KEY, tags::TAG_EC_KEY_V1])
    }
}

/// Converts an `ECPrivateKey` to CBOR.
impl From<ECPrivateKey> for CBOR {
    /// Converts to tagged CBOR.
    fn from(value: ECPrivateKey) -> Self { value.tagged_cbor() }
}

/// Implements CBOR encoding for EC private keys.
impl CBORTaggedEncodable for ECPrivateKey {
    /// Creates the untagged CBOR representation.
    ///
    /// The format is a map with:
    /// - Key 2: boolean true (indicates private key)
    /// - Key 3: byte string of the key data
    fn untagged_cbor(&self) -> CBOR {
        let mut m = Map::new();
        m.insert(2, true);
        m.insert(3, CBOR::to_byte_string(self.0));
        m.into()
    }
}

impl ReferenceProvider for ECPrivateKey {
    fn reference(&self) -> Reference {
        Reference::from_digest(Digest::from_image(
            self.tagged_cbor().to_cbor_data(),
        ))
    }
}

impl std::fmt::Display for ECPrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ECPrivateKey({})", self.ref_hex_short())
    }
}
