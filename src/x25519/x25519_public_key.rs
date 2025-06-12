use std::rc::Rc;

use anyhow::{Result, bail};
use bc_ur::prelude::*;

use crate::{EncapsulationPublicKey, Encrypter, tags};

/// A public key for X25519 key agreement operations.
///
/// X25519 is an elliptic-curve Diffie-Hellman key exchange protocol based on
/// Curve25519 as defined in [RFC 7748](https://datatracker.ietf.org/doc/html/rfc7748). It allows
/// two parties to establish a shared secret key over an insecure channel.
///
/// The X25519 public key is generated from a corresponding private key and is
/// designed to be:
/// - Compact (32 bytes)
/// - Fast to use in key agreement operations
/// - Resistant to various cryptographic attacks
///
/// This implementation provides:
/// - Creation of X25519 public keys from raw data
/// - CBOR serialization and deserialization
/// - Support for the Encrypter trait for key encapsulation
/// - Various utility and conversion methods
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct X25519PublicKey([u8; Self::KEY_SIZE]);

impl X25519PublicKey {
    pub const KEY_SIZE: usize = 32;

    /// Restore an `X25519PublicKey` from a fixed-size array of bytes.
    pub const fn from_data(data: [u8; Self::KEY_SIZE]) -> Self { Self(data) }

    /// Restore an `X25519PublicKey` from a reference to an array of bytes.
    pub fn from_data_ref(data: impl AsRef<[u8]>) -> Result<Self> {
        let data = data.as_ref();
        if data.len() != Self::KEY_SIZE {
            bail!("Invalid X25519 public key size");
        }
        let mut arr = [0u8; Self::KEY_SIZE];
        arr.copy_from_slice(data);
        Ok(Self::from_data(arr))
    }

    /// Get a reference to the fixed-size array of bytes.
    pub fn data(&self) -> &[u8; Self::KEY_SIZE] { self.into() }

    /// Get the X25519 public key as a byte slice.
    pub fn as_bytes(&self) -> &[u8] { self.as_ref() }

    /// Restore an `X25519PublicKey` from a hex string.
    ///
    /// # Panics
    ///
    /// Panics if the hex string is invalid or the length is not
    /// `X25519PublicKey::KEY_SIZE * 2`.
    pub fn from_hex(hex: impl AsRef<str>) -> Self {
        Self::from_data_ref(hex::decode(hex.as_ref()).unwrap()).unwrap()
    }

    /// Get the hex string representation of the `X25519PublicKey`.
    pub fn hex(&self) -> String { hex::encode(self.data()) }
}

impl AsRef<[u8]> for X25519PublicKey {
    fn as_ref(&self) -> &[u8] { &self.0 }
}

/// Implements conversion from a reference-counted X25519PublicKey to an owned
/// X25519PublicKey.
impl From<Rc<X25519PublicKey>> for X25519PublicKey {
    fn from(value: Rc<X25519PublicKey>) -> Self { value.as_ref().clone() }
}

/// Implements conversion from an X25519PublicKey reference to a byte array
/// reference.
impl<'a> From<&'a X25519PublicKey> for &'a [u8; X25519PublicKey::KEY_SIZE] {
    fn from(value: &'a X25519PublicKey) -> Self { &value.0 }
}

/// Implements `AsRef<X25519PublicKey>` to allow self-reference.
impl AsRef<X25519PublicKey> for X25519PublicKey {
    fn as_ref(&self) -> &X25519PublicKey { self }
}

/// Implements the CBORTagged trait to provide CBOR tag information.
impl CBORTagged for X25519PublicKey {
    fn cbor_tags() -> Vec<Tag> {
        tags_for_values(&[tags::TAG_X25519_PUBLIC_KEY])
    }
}

/// Implements conversion from X25519PublicKey to CBOR for serialization.
impl From<X25519PublicKey> for CBOR {
    fn from(value: X25519PublicKey) -> Self { value.tagged_cbor() }
}

/// Implements CBORTaggedEncodable to provide CBOR encoding functionality.
impl CBORTaggedEncodable for X25519PublicKey {
    fn untagged_cbor(&self) -> CBOR { CBOR::to_byte_string(self.data()) }
}

/// Implements `TryFrom<CBOR>` for X25519PublicKey to support conversion from
/// CBOR data.
impl TryFrom<CBOR> for X25519PublicKey {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> dcbor::Result<Self> {
        Self::from_tagged_cbor(cbor)
    }
}

/// Implements CBORTaggedDecodable to provide CBOR decoding functionality.
impl CBORTaggedDecodable for X25519PublicKey {
    fn from_untagged_cbor(untagged_cbor: CBOR) -> dcbor::Result<Self> {
        let data = CBOR::try_into_byte_string(untagged_cbor)?;
        Ok(Self::from_data_ref(data)?)
    }
}

/// Implements Debug to output the key with a type label.
impl std::fmt::Debug for X25519PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "X25519PublicKey({})", self.hex())
    }
}

/// Implements conversion from an X25519PublicKey reference to an owned
/// X25519PublicKey.
impl From<&X25519PublicKey> for X25519PublicKey {
    fn from(key: &X25519PublicKey) -> Self { key.clone() }
}

/// Implements conversion from an X25519PublicKey to a byte vector.
impl From<X25519PublicKey> for Vec<u8> {
    fn from(key: X25519PublicKey) -> Self { key.0.to_vec() }
}

/// Implements conversion from an X25519PublicKey reference to a byte vector.
impl From<&X25519PublicKey> for Vec<u8> {
    fn from(key: &X25519PublicKey) -> Self { key.0.to_vec() }
}

/// Implements the Encrypter trait to support key encapsulation mechanisms.
impl Encrypter for X25519PublicKey {
    fn encapsulation_public_key(&self) -> EncapsulationPublicKey {
        EncapsulationPublicKey::X25519(self.clone())
    }
}
