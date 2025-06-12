use std::rc::Rc;

use anyhow::{Result, bail};
use bc_crypto::x25519_new_private_key_using;
use bc_rand::{RandomNumberGenerator, SecureRandomNumberGenerator};
use bc_ur::prelude::*;

use crate::{
    Decrypter, EncapsulationPrivateKey, SymmetricKey, X25519PublicKey, tags,
};

/// A private key for X25519 key agreement operations.
///
/// X25519 is an elliptic-curve Diffie-Hellman key exchange protocol based on
/// Curve25519 as defined in [RFC 7748](https://datatracker.ietf.org/doc/html/rfc7748). It allows
/// two parties to establish a shared secret key over an insecure channel.
///
/// Key features of X25519:
/// - High security (128-bit security level)
/// - High performance
/// - Small key sizes (32 bytes)
/// - Protection against various side-channel attacks
/// - Relatively simple implementation compared to other elliptic curve systems
///
/// This implementation provides:
/// - Generation of random X25519 private keys
/// - Derivation of the corresponding public key
/// - Shared key generation with another party's public key
/// - CBOR serialization and deserialization
/// - Various utility and conversion methods
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct X25519PrivateKey([u8; Self::KEY_SIZE]);

impl X25519PrivateKey {
    pub const KEY_SIZE: usize = 32;

    /// Generate a new random `X25519PrivateKey`.
    pub fn new() -> Self {
        let mut rng = SecureRandomNumberGenerator;
        Self::new_using(&mut rng)
    }

    /// Generate a new random `X25519PrivateKey` and corresponding
    /// `X25519PublicKey`.
    pub fn keypair() -> (X25519PrivateKey, X25519PublicKey) {
        let private_key = X25519PrivateKey::new();
        let public_key = private_key.public_key();
        (private_key, public_key)
    }

    /// Generate a new random `X25519PrivateKey` and corresponding
    /// `X25519PublicKey` using the given random number generator.
    pub fn keypair_using(
        rng: &mut impl RandomNumberGenerator,
    ) -> (X25519PrivateKey, X25519PublicKey) {
        let private_key = X25519PrivateKey::new_using(rng);
        let public_key = private_key.public_key();
        (private_key, public_key)
    }

    /// Generate a new random `X25519PrivateKey` using the given random number
    /// generator.
    pub fn new_using(rng: &mut impl RandomNumberGenerator) -> Self {
        Self(x25519_new_private_key_using(rng))
    }

    /// Restore an `X25519PrivateKey` from a fixed-size array of bytes.
    pub const fn from_data(data: [u8; Self::KEY_SIZE]) -> Self { Self(data) }

    /// Restore an `X25519PrivateKey` from a reference to an array of bytes.
    pub fn from_data_ref(data: impl AsRef<[u8]>) -> Result<Self> {
        let data = data.as_ref();
        if data.len() != Self::KEY_SIZE {
            bail!("Invalid X25519 private key size");
        }
        let mut arr = [0u8; Self::KEY_SIZE];
        arr.copy_from_slice(data);
        Ok(Self::from_data(arr))
    }

    /// Get a reference to the fixed-size array of bytes.
    pub fn data(&self) -> &[u8; Self::KEY_SIZE] { self.into() }

    /// Get the X25519 private key as a byte slice.
    pub fn as_bytes(&self) -> &[u8] { self.as_ref() }

    /// Restore an `X25519PrivateKey` from a hex string.
    ///
    /// # Panics
    ///
    /// Panics if the hex string is invalid or the length is not
    /// `X25519PrivateKey::KEY_SIZE * 2`.
    pub fn from_hex(hex: impl AsRef<str>) -> Self {
        Self::from_data_ref(hex::decode(hex.as_ref()).unwrap()).unwrap()
    }

    /// Get the hex string representation of the `X25519PrivateKey`.
    pub fn hex(&self) -> String { hex::encode(self.data()) }

    /// Get the `X25519PublicKey` corresponding to this `X25519PrivateKey`.
    pub fn public_key(&self) -> X25519PublicKey {
        X25519PublicKey::from_data(
            bc_crypto::x25519_public_key_from_private_key(self.into()),
        )
    }

    /// Derive an `X25519PrivateKey` from the given key material.
    pub fn derive_from_key_material(key_material: impl AsRef<[u8]>) -> Self {
        Self::from_data(bc_crypto::derive_agreement_private_key(key_material))
    }

    /// Derive a shared symmetric key from this `X25519PrivateKey` and the given
    /// `X25519PublicKey`.
    pub fn shared_key_with(
        &self,
        public_key: &X25519PublicKey,
    ) -> SymmetricKey {
        SymmetricKey::from_data(bc_crypto::x25519_shared_key(
            self.into(),
            public_key.into(),
        ))
    }
}

impl AsRef<[u8]> for X25519PrivateKey {
    fn as_ref(&self) -> &[u8] { &self.0 }
}

/// Implements the Decrypter trait to support key encapsulation mechanisms.
impl Decrypter for X25519PrivateKey {
    fn encapsulation_private_key(&self) -> EncapsulationPrivateKey {
        EncapsulationPrivateKey::X25519(self.clone())
    }
}

/// Implements Default to create a new random X25519PrivateKey.
impl Default for X25519PrivateKey {
    fn default() -> Self { Self::new() }
}

/// Implements conversion from an X25519PrivateKey reference to a byte array
/// reference.
impl<'a> From<&'a X25519PrivateKey> for &'a [u8; X25519PrivateKey::KEY_SIZE] {
    fn from(value: &'a X25519PrivateKey) -> Self { &value.0 }
}

/// Implements conversion from a reference-counted X25519PrivateKey to an owned
/// X25519PrivateKey.
impl From<Rc<X25519PrivateKey>> for X25519PrivateKey {
    fn from(value: Rc<X25519PrivateKey>) -> Self { value.as_ref().clone() }
}

/// Implements `AsRef<X25519PrivateKey>` to allow self-reference.
impl AsRef<X25519PrivateKey> for X25519PrivateKey {
    fn as_ref(&self) -> &Self { self }
}

/// Implements the CBORTagged trait to provide CBOR tag information.
impl CBORTagged for X25519PrivateKey {
    fn cbor_tags() -> Vec<Tag> {
        tags_for_values(&[tags::TAG_X25519_PRIVATE_KEY])
    }
}

/// Implements conversion from X25519PrivateKey to CBOR for serialization.
impl From<X25519PrivateKey> for CBOR {
    fn from(value: X25519PrivateKey) -> Self { value.tagged_cbor() }
}

/// Implements CBORTaggedEncodable to provide CBOR encoding functionality.
impl CBORTaggedEncodable for X25519PrivateKey {
    fn untagged_cbor(&self) -> CBOR { CBOR::to_byte_string(self.data()) }
}

/// Implements `TryFrom<CBOR>` for X25519PrivateKey to support conversion from
/// CBOR data.
impl TryFrom<CBOR> for X25519PrivateKey {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> dcbor::Result<Self> {
        Self::from_tagged_cbor(cbor)
    }
}

/// Implements CBORTaggedDecodable to provide CBOR decoding functionality.
impl CBORTaggedDecodable for X25519PrivateKey {
    fn from_untagged_cbor(untagged_cbor: CBOR) -> dcbor::Result<Self> {
        let data = CBOR::try_into_byte_string(untagged_cbor)?;
        Ok(Self::from_data_ref(data)?)
    }
}

/// Implements Debug to output the key with a type label.
impl std::fmt::Debug for X25519PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "X25519PrivateKey({})", self.hex())
    }
}

/// Implements conversion from an X25519PrivateKey reference to an owned
/// X25519PrivateKey.
impl From<&X25519PrivateKey> for X25519PrivateKey {
    fn from(key: &X25519PrivateKey) -> Self { key.clone() }
}

/// Implements conversion from an X25519PrivateKey to a byte vector.
impl From<X25519PrivateKey> for Vec<u8> {
    fn from(key: X25519PrivateKey) -> Self { key.0.to_vec() }
}

/// Implements conversion from an X25519PrivateKey reference to a byte vector.
impl From<&X25519PrivateKey> for Vec<u8> {
    fn from(key: &X25519PrivateKey) -> Self { key.0.to_vec() }
}
