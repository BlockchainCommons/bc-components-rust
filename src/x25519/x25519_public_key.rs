use std::rc::Rc;
use bc_ur::prelude::*;
use crate::{tags, Encrypter};
use anyhow::{ bail, Error, Result };

/// A Curve25519 public key used for X25519 key agreement.
///
/// <https://datatracker.ietf.org/doc/html/rfc7748>
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct X25519PublicKey([u8; Self::KEY_SIZE]);

impl X25519PublicKey {
    pub const KEY_SIZE: usize = 32;

    /// Restore an `AgreementPublicKey` from a fixed-size array of bytes.
    pub const fn from_data(data: [u8; Self::KEY_SIZE]) -> Self {
        Self(data)
    }

    /// Restore an `AgreementPublicKey` from a reference to an array of bytes.
    pub fn from_data_ref(data: impl AsRef<[u8]>) -> Result<Self> {
        let data = data.as_ref();
        if data.len() != Self::KEY_SIZE {
            bail!("Invalid agreement public key size");
        }
        let mut arr = [0u8; Self::KEY_SIZE];
        arr.copy_from_slice(data);
        Ok(Self::from_data(arr))
    }

    /// Get a reference to the fixed-size array of bytes.
    pub fn data(&self) -> &[u8; Self::KEY_SIZE] {
        self.into()
    }

    /// Restore an `AgreementPublicKey` from a hex string.
    ///
    /// # Panics
    ///
    /// Panics if the hex string is invalid or the length is not `AgreementPublicKey::KEY_SIZE * 2`.
    pub fn from_hex(hex: impl AsRef<str>) -> Self {
        Self::from_data_ref(hex::decode(hex.as_ref()).unwrap()).unwrap()
    }

    /// Get the hex string representation of the `AgreementPublicKey`.
    pub fn hex(&self) -> String {
        hex::encode(self.data())
    }
}

impl From<Rc<X25519PublicKey>> for X25519PublicKey {
    fn from(value: Rc<X25519PublicKey>) -> Self {
        value.as_ref().clone()
    }
}

impl<'a> From<&'a X25519PublicKey> for &'a [u8; X25519PublicKey::KEY_SIZE] {
    fn from(value: &'a X25519PublicKey) -> Self {
        &value.0
    }
}

impl AsRef<X25519PublicKey> for X25519PublicKey {
    fn as_ref(&self) -> &X25519PublicKey {
        self
    }
}

impl CBORTagged for X25519PublicKey {
    fn cbor_tags() -> Vec<Tag> {
        tags_for_values(&[tags::TAG_AGREEMENT_PUBLIC_KEY])
    }
}

impl From<X25519PublicKey> for CBOR {
    fn from(value: X25519PublicKey) -> Self {
        value.tagged_cbor()
    }
}

impl CBORTaggedEncodable for X25519PublicKey {
    fn untagged_cbor(&self) -> CBOR {
        CBOR::to_byte_string(self.data())
    }
}

impl TryFrom<CBOR> for X25519PublicKey {
    type Error = Error;

    fn try_from(cbor: CBOR) -> Result<Self, Self::Error> {
        Self::from_tagged_cbor(cbor)
    }
}

impl CBORTaggedDecodable for X25519PublicKey {
    fn from_untagged_cbor(untagged_cbor: CBOR) -> Result<Self> {
        let data = CBOR::try_into_byte_string(untagged_cbor)?;
        Self::from_data_ref(data)
    }
}

impl std::fmt::Debug for X25519PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AgreementPublicKey({})", self.hex())
    }
}

// Convert from a reference to a byte vector to a AgreementPublicKey.
impl From<&X25519PublicKey> for X25519PublicKey {
    fn from(key: &X25519PublicKey) -> Self {
        key.clone()
    }
}

// Convert from a byte vector to a AgreementPublicKey.
impl From<X25519PublicKey> for Vec<u8> {
    fn from(key: X25519PublicKey) -> Self {
        key.0.to_vec()
    }
}

// Convert from a reference to a byte vector to a AgreementPublicKey.
impl From<&X25519PublicKey> for Vec<u8> {
    fn from(key: &X25519PublicKey) -> Self {
        key.0.to_vec()
    }
}

impl Encrypter for X25519PublicKey {
    fn agreement_public_key(&self) -> &X25519PublicKey {
        self
    }
}
